"""Safe, bounded page collection.

The browser is treated as hostile territory: no form submission, no downloads,
no service workers, all subrequests checked against SSRF rules, and media
blocked. If Chromium is unavailable the caller receives a static HTTP rendering
so assessment can continue with reduced evidence.
"""

from __future__ import annotations

import asyncio
import io
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from .config import Settings
from .security import (
    UnsafeURLError,
    check_request_url_sync,
    normalize_url,
    registrable_domain,
    sanitize_text,
    validate_public_url,
)

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 WebsiteTrustAssessment/0.1"
)
MAX_REDIRECTS = 5
_MAX_SCREENSHOT_HEIGHT = 3000


@dataclass
class FormField:
    name: str = ""
    type: str = "text"
    placeholder: str = ""
    autocomplete: str = ""
    required: bool = False
    hidden: bool = False
    label: str = ""


@dataclass
class FormInfo:
    action: str = ""
    method: str = "get"
    fields: list[FormField] = field(default_factory=list)
    text: str = ""
    has_password: bool = False
    has_email: bool = False
    has_card: bool = False
    has_cvv: bool = False
    has_file: bool = False
    has_hidden: bool = False

    @property
    def sensitive(self) -> bool:
        return self.has_password or self.has_card or self.has_cvv or self.has_email


@dataclass
class ImageInfo:
    src: str = ""
    alt: str = ""
    width: int = 0
    height: int = 0
    visible: bool = True


@dataclass
class CrawlData:
    requested_url: str
    final_url: str
    domain: str
    engine: str = "http"
    status: int | None = None
    title: str = ""
    lang: str = ""
    meta: dict[str, str] = field(default_factory=dict)
    html: str = ""
    visible_text: str = ""
    hidden_text: str = ""
    html_comments: str = ""
    links: list[dict[str, Any]] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    stylesheets: list[str] = field(default_factory=list)
    iframes: list[dict[str, Any]] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    images: list[ImageInfo] = field(default_factory=list)
    network_urls: list[str] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    storage_keys: list[str] = field(default_factory=list)
    hidden_elements: list[dict[str, str]] = field(default_factory=list)
    checkboxes: list[dict[str, Any]] = field(default_factory=list)
    countdown_elements: list[dict[str, str]] = field(default_factory=list)
    sticky_elements: list[dict[str, str]] = field(default_factory=list)
    dialogs: list[str] = field(default_factory=list)
    headings: list[str] = field(default_factory=list)
    buttons: list[str] = field(default_factory=list)
    password_field_count: int = 0
    page_height: int = 0
    favicon_urls: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie_names: list[str] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    blocked_requests: list[str] = field(default_factory=list)
    screenshot: str | None = None
    ocr_text: str = ""
    error: str | None = None
    errors: list[str] = field(default_factory=list)
    elapsed_ms: int = 0

    @property
    def text(self) -> str:
        return "\n".join(part for part in (self.visible_text, self.ocr_text) if part)

    @property
    def has_credential_form(self) -> bool:
        return any(form.has_password for form in self.forms)

    @property
    def has_payment_form(self) -> bool:
        return any(form.has_card or form.has_cvv for form in self.forms)

    @property
    def all_links_text(self) -> str:
        return " ".join(str(link.get("text", "")) for link in self.links)

    def page_fingerprint(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
            "status": self.status,
            "title": self.title[:200],
            "final_url": self.final_url,
            "forms": len(self.forms),
            "password_fields": self.password_field_count,
            "checkboxes": len(self.checkboxes),
            "links": len(self.links),
            "scripts": len(self.scripts),
            "iframes": len(self.iframes),
            "images": len(self.images),
            "network_requests": len(self.network_urls),
            "cookies": len(self.cookies),
            "hidden_elements": len(self.hidden_elements),
            "screenshot": bool(self.screenshot),
            "blocked_requests": len(self.blocked_requests),
        }


@dataclass
class FetchResult:
    final_url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    set_cookies: list[str] = field(default_factory=list)
    content: bytes = b""
    content_type: str = ""
    redirect_chain: list[str] = field(default_factory=list)
    truncated: bool = False
    error: str | None = None


def _http_client(timeout: float) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        verify=False,  # certificate validity is assessed separately, never silently trusted
        trust_env=False,  # do not let environment proxies bypass SSRF checks
        headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.8"},
    )


async def fetch_bytes(
    url: str,
    *,
    max_bytes: int = 1_500_000,
    timeout: float = 10.0,
    accept: str = "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
    max_redirects: int = MAX_REDIRECTS,
) -> FetchResult:
    """Fetch with manual redirect validation. Never sends credentials."""
    chain: list[str] = []
    current = url
    try:
        async with _http_client(timeout) as client:
            for _ in range(max_redirects + 1):
                await validate_public_url(current)
                chain.append(current)
                response = await client.get(current, headers={"Accept": accept})
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    await response.aclose()
                    if not location:
                        return FetchResult(
                            final_url=current,
                            status=response.status_code,
                            redirect_chain=chain,
                            error="redirect_without_location",
                        )
                    current = normalize_url(urljoin(current, location))
                    continue
                headers = {k.lower(): v for k, v in response.headers.items() if k.lower() != "set-cookie"}
                set_cookies = response.headers.get_list("set-cookie")
                content_type = headers.get("content-type", "")
                chunks = bytearray()
                truncated = False
                async for chunk in response.aiter_bytes():
                    remaining = max_bytes + 1 - len(chunks)
                    if remaining <= 0:
                        truncated = True
                        break
                    chunks.extend(chunk[:remaining])
                    if len(chunks) > max_bytes:
                        truncated = True
                        break
                await response.aclose()
                return FetchResult(
                    final_url=current,
                    status=response.status_code,
                    headers=headers,
                    set_cookies=set_cookies,
                    content=bytes(chunks[:max_bytes]),
                    content_type=content_type,
                    redirect_chain=chain,
                    truncated=truncated,
                )
    except UnsafeURLError as exc:
        return FetchResult(final_url=current, status=0, redirect_chain=chain, error=str(exc))
    except (httpx.HTTPError, ValueError, OSError) as exc:
        return FetchResult(
            final_url=current,
            status=0,
            redirect_chain=chain,
            error=f"{type(exc).__name__}: {str(exc)[:160]}",
        )
    return FetchResult(final_url=current, status=0, redirect_chain=chain, error="too_many_redirects")


def decode_body(content: bytes, content_type: str = "") -> str:
    charset = "utf-8"
    match = re.search(r"charset=([\w-]+)", content_type, re.IGNORECASE)
    if match:
        charset = match.group(1)
    try:
        return content.decode(charset, errors="replace")
    except LookupError:
        return content.decode("utf-8", errors="replace")


def _empty_page(url: str, domain: str, engine: str) -> CrawlData:
    return CrawlData(requested_url=url, final_url=url, domain=domain, engine=engine)


_PW_JS = r"""
() => {
  const MAX_TEXT = 90000;
  const clean = (s, n) => (s || '').replace(/\s+/g, ' ').trim().slice(0, n);
  const abs = (u) => { try { return new URL(u, document.baseURI).href; } catch (e) { return ''; } };
  const styleOf = (el) => { try { return getComputedStyle(el); } catch (e) { return null; } };
  const visible = (el) => {
    if (!el || !el.getBoundingClientRect) return false;
    const st = styleOf(el);
    if (!st) return false;
    if (st.display === 'none' || st.visibility === 'hidden' || st.visibility === 'collapse') return false;
    if (parseFloat(st.opacity || '1') <= 0.02) return false;
    if (parseFloat(st.fontSize || '16') <= 0.5) return false;
    if (el.getAttribute('aria-hidden') === 'true') return false;
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return false;
    return true;
  };
  const reasonHidden = (el) => {
    const st = styleOf(el);
    if (!st) return '';
    if (st.display === 'none') return 'display:none';
    if (st.visibility === 'hidden' || st.visibility === 'collapse') return 'visibility';
    if (parseFloat(st.opacity || '1') <= 0.02) return 'opacity';
    if (parseFloat(st.fontSize || '16') <= 0.5) return 'font-size:0';
    if (el.getAttribute('aria-hidden') === 'true') return 'aria-hidden';
    const r = el.getBoundingClientRect();
    if (r.width < 1 || r.height < 1) return 'zero-size';
    const fg = st.color || '';
    const bg = st.backgroundColor || '';
    if (fg && bg && fg === bg && bg !== 'rgba(0, 0, 0, 0)' && !/rgba\(0, 0, 0, 0\)/.test(bg)) return 'color-match';
    return 'offscreen-or-other';
  };
  const meta = {};
  for (const m of Array.from(document.querySelectorAll('meta')).slice(0, 50)) {
    const key = (m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv') || m.getAttribute('charset') || '').toLowerCase();
    if (!key) continue;
    const value = m.getAttribute('content') || m.getAttribute('charset') || '';
    if (value && !(key in meta)) meta[key] = clean(value, 500);
  }
  const comments = [];
  try {
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
    let node;
    while ((node = walker.nextNode()) && comments.length < 40) {
      const value = clean(node.nodeValue, 600);
      if (value) comments.push(value);
    }
  } catch (e) {}

  const hiddenEls = [];
  const hiddenTextParts = [];
  const candidates = Array.from(document.querySelectorAll(
    'div,span,p,section,article,h1,h2,h3,h4,h5,h6,a,button,label,li,td,th,small,strong,em,form'
  )).slice(0, 5000);
  for (const el of candidates) {
    if (hiddenEls.length >= 50) break;
    const txt = clean(el.textContent, 400);
    if (!txt) continue;
    if (visible(el)) continue;
    if (el.parentElement && hiddenEls.some((h) => h.el === el.parentElement)) continue;
    const reason = reasonHidden(el);
    hiddenEls.push({ tag: el.tagName.toLowerCase(), id: clean(el.id, 80), cls: clean(el.className?.toString?.() || '', 100), text: txt, reason, el });
    if (hiddenTextParts.join(' ').length < 24000) hiddenTextParts.push(txt);
  }

  const links = [];
  for (const a of Array.from(document.querySelectorAll('a[href]')).slice(0, 400)) {
    const href = abs(a.getAttribute('href') || '');
    if (!/^https?:/i.test(href)) continue;
    links.push({ href, text: clean(a.innerText || a.getAttribute('aria-label'), 120), rel: clean(a.rel, 60), target: clean(a.target, 20) });
  }

  const forms = [];
  for (const f of Array.from(document.forms).slice(0, 15)) {
    const fields = [];
    const raw = Array.from(f.elements).slice(0, 80);
    for (const el of raw) {
      if (!el.tagName) continue;
      const tag = el.tagName.toLowerCase();
      const type = (el.type || tag).toLowerCase();
      const labelText = el.labels && el.labels.length ? clean(el.labels[0].innerText, 120) : clean(el.getAttribute('aria-label'), 120);
      fields.push({
        name: clean(el.name, 100), type, placeholder: clean(el.getAttribute('placeholder'), 120),
        autocomplete: clean(el.getAttribute('autocomplete'), 60), required: !!el.required,
        hidden: !visible(el) || type === 'hidden', label: labelText, tag
      });
    }
    forms.push({
      action: f.action ? abs(f.action) : location.href,
      method: (f.method || 'get').toLowerCase(),
      id: clean(f.id, 100), name: clean(f.name, 100),
      text: clean(f.innerText, 1500), fields
    });
  }

  const checkboxData = [];
  for (const el of Array.from(document.querySelectorAll('input[type=checkbox]')).slice(0, 40)) {
    const labelText = el.labels && el.labels.length ? clean(el.labels[0].innerText, 200) : clean(el.getAttribute('aria-label') || el.value, 200);
    checkboxData.push({ name: clean(el.name, 100), id: clean(el.id, 100), checked: !!el.checked, hidden: !visible(el), label: labelText, in_form: !!el.form });
  }

  const images = [];
  for (const el of Array.from(document.querySelectorAll('img')).slice(0, 80)) {
    const src = abs(el.currentSrc || el.getAttribute('src') || '');
    if (!/^https?:/i.test(src)) continue;
    images.push({ src, alt: clean(el.getAttribute('alt'), 200), width: el.naturalWidth || el.width || 0, height: el.naturalHeight || el.height || 0, visible: visible(el) });
  }

  const iframes = [];
  for (const el of Array.from(document.querySelectorAll('iframe')).slice(0, 20)) {
    const src = abs(el.getAttribute('src') || '');
    if (!/^https?:/i.test(src)) continue;
    iframes.push({ src, title: clean(el.getAttribute('title'), 150), hidden: !visible(el), width: el.width || 0, height: el.height || 0 });
  }

  const scripts = [];
  const inline = [];
  for (const el of Array.from(document.querySelectorAll('script')).slice(0, 120)) {
    if (el.src) { const src = abs(el.src); if (/^https?:/i.test(src)) scripts.push(src); }
    else if (el.textContent && inline.length < 50) inline.push(el.textContent.slice(0, 25000));
  }

  const styles = [];
  for (const el of Array.from(document.querySelectorAll('link[rel~="stylesheet"]')).slice(0, 60)) {
    const href = abs(el.href || '');
    if (/^https?:/i.test(href)) styles.push(href);
  }

  const favicons = [];
  for (const el of Array.from(document.querySelectorAll('link[rel~="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]')).slice(0, 8)) {
    const href = abs(el.href || '');
    if (/^https?:/i.test(href)) favicons.push(href);
  }

  const countdowns = [];
  for (const el of Array.from(document.querySelectorAll('[data-countdown], [id*="countdown" i], [class*="countdown" i], [class*="timer" i], [class*="flash-sale" i]')).slice(0, 15)) {
    if (!visible(el)) continue;
    const txt = clean(el.innerText, 250);
    if (txt) countdowns.push({ tag: el.tagName.toLowerCase(), id: clean(el.id, 80), cls: clean(el.className?.toString?.() || '', 100), text: txt });
  }

  const sticky = [];
  for (const el of Array.from(document.querySelectorAll('header,footer,aside,nav,div,section,form')).slice(0, 2000)) {
    if (sticky.length >= 10) break;
    if (!visible(el)) continue;
    const st = styleOf(el);
    if (!st || (st.position !== 'fixed' && st.position !== 'sticky')) continue;
    const txt = clean(el.innerText, 250);
    if (txt.length < 4) continue;
    sticky.push({ tag: el.tagName.toLowerCase(), id: clean(el.id, 80), text: txt });
  }

  const headings = Array.from(document.querySelectorAll('h1,h2')).slice(0, 25).map((el) => clean(el.innerText, 200)).filter(Boolean);
  const buttons = Array.from(document.querySelectorAll('button, input[type=submit], a[role=button], [class*="btn" i]')).slice(0, 60).map((el) => clean(el.innerText || el.value || el.getAttribute('aria-label'), 120)).filter(Boolean);

  let storageKeys = [];
  try { storageKeys = Object.keys(localStorage).slice(0, 30); } catch (e) {}
  try { storageKeys = storageKeys.concat(Object.keys(sessionStorage).slice(0, 20)); } catch (e) {}

  let passwordCount = 0;
  for (const el of Array.from(document.querySelectorAll('input[type=password]'))) {
    if (!el.disabled) passwordCount += 1;
  }

  return {
    title: clean(document.title, 300),
    lang: clean(document.documentElement.lang, 20),
    meta,
    html: document.documentElement.outerHTML.slice(0, 850000),
    visible_text: clean(document.body ? document.body.innerText : '', MAX_TEXT),
    hidden_text: hiddenTextParts.join(' ').slice(0, 26000),
    html_comments: comments.join('\n').slice(0, 12000),
    links, scripts, inline_scripts: inline, stylesheets: styles, forms, images, iframes,
    hidden_elements: hiddenEls.map(({el, ...rest}) => rest),
    checkboxes: checkboxData,
    countdown_elements: countdowns,
    sticky_elements: sticky,
    headings, buttons,
    storage_keys: storageKeys,
    password_field_count: passwordCount,
    page_height: Math.max(document.body ? document.body.scrollHeight : 0, document.documentElement ? document.documentElement.scrollHeight : 0),
    favicon_urls: favicons
  };
}
"""


def _parse_field(raw: dict[str, Any]) -> FormField:
    return FormField(
        name=str(raw.get("name") or "")[:100],
        type=str(raw.get("type") or "text").lower()[:30],
        placeholder=str(raw.get("placeholder") or "")[:120],
        autocomplete=str(raw.get("autocomplete") or "")[:60],
        required=bool(raw.get("required")),
        hidden=bool(raw.get("hidden")),
        label=str(raw.get("label") or "")[:120],
    )


_CARD_RE = re.compile(r"card[\s_-]?(number|no)|cc-number|cardnumber|credit\s*card|debit\s*card", re.IGNORECASE)
_CVV_RE = re.compile(r"\bcvv\b|\bcvc\b|security\s*code|card\s*code|card\s*verification", re.IGNORECASE)
_EMAIL_RE = re.compile(r"e-?mail", re.IGNORECASE)


def _build_form(raw: dict[str, Any]) -> FormInfo:
    fields = [_parse_field(item) for item in raw.get("fields", []) if isinstance(item, dict)]
    haystack = " ".join(
        f"{f.name} {f.placeholder} {f.autocomplete} {f.label}" for f in fields
    )
    input_types = {f.type for f in fields}
    return FormInfo(
        action=str(raw.get("action") or "")[:2000],
        method=str(raw.get("method") or "get").lower()[:10],
        fields=fields,
        text=str(raw.get("text") or "")[:1500],
        has_password="password" in input_types,
        has_email="email" in input_types or bool(_EMAIL_RE.search(haystack)),
        has_card=bool(_CARD_RE.search(haystack)),
        has_cvv=bool(_CVV_RE.search(haystack)),
        has_file="file" in input_types,
        has_hidden=any(f.hidden for f in fields),
    )


async def crawl(url: str, cfg: Settings) -> CrawlData:
    started = time.monotonic()
    final_url = url
    domain = ""
    try:
        parts = await validate_public_url(url)
        final_url = parts.url
        domain = parts.registrable_domain
    except UnsafeURLError as exc:
        page = _empty_page(url, "", "none")
        page.error = f"unsafe_url: {exc}"
        page.elapsed_ms = int((time.monotonic() - started) * 1000)
        return page

    if cfg.enable_playwright:
        try:
            page = await _crawl_playwright(url, domain, cfg)
        except Exception as exc:  # browser failure must not abort the assessment
            page = await _crawl_http(url, domain, cfg)
            page.errors.append(f"browser_fallback: {type(exc).__name__}")
    else:
        page = await _crawl_http(url, domain, cfg)

    page.elapsed_ms = int((time.monotonic() - started) * 1000)
    page.final_url = page.final_url or url
    page.domain = page.domain or registrable_domain(page.final_url) or domain
    return page


def parse_html_page(
    html: str,
    url: str,
    *,
    domain: str = "",
    status: int = 200,
    headers: dict[str, str] | None = None,
    engine: str = "static",
) -> CrawlData:
    """Produce the same page record a static crawl would, without any network access.

    The controlled injection corpus authors pages locally, so it must exercise the real
    parsing path rather than a test-only copy of it.
    """
    page = _empty_page(url, domain or registrable_domain(url), engine)
    page.status = status
    page.headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    _parse_static_html(page, html, url)
    page.html = html[:1_000_000]
    return page


async def _crawl_playwright(url: str, domain: str, cfg: Settings) -> CrawlData:
    from playwright.async_api import async_playwright
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError

    page_data = _empty_page(url, domain, "playwright")
    screenshot_dir = cfg.screenshots_dir
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    screenshot_name = f"scan_{uuid.uuid4().hex}.png"
    screenshot_path = screenshot_dir / screenshot_name

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--disable-gpu",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-sync",
                "--disable-default-apps",
                "--mute-audio",
                "--no-first-run",
                "--disable-features=NetworkPrediction,SpeculativePreconnect",
            ],
        )
        context = await browser.new_context(
            viewport={"width": 1365, "height": 1000},
            user_agent=USER_AGENT,
            locale="en-US",
            timezone_id="UTC",
            ignore_https_errors=True,
            accept_downloads=False,
            service_workers="block",
            java_script_enabled=True,
            extra_http_headers={"DNT": "1"},
        )
        network: list[str] = []
        blocked: list[str] = []
        dialogs: list[str] = []

        async def route_handler(route, request):
            try:
                check_request_url_sync(request.url)
            except UnsafeURLError:
                blocked.append(request.url[:300])
                await route.abort("blockedbyclient")
                return
            if request.resource_type in {"media"}:
                await route.abort("blockedbyclient")
                return
            await route.continue_()

        await context.route("**/*", route_handler)

        page = await context.new_page()

        def close_popup(new_page):
            if new_page is not page:
                asyncio.create_task(new_page.close())

        context.on("page", close_popup)

        def on_request(request):
            if len(network) < 500 and request.url.startswith(("http://", "https://")):
                network.append(request.url[:1200])

        page.on("request", on_request)

        async def on_dialog(dialog):
            if len(dialogs) < 5:
                dialogs.append(sanitize_text(dialog.message, 300))
            try:
                await dialog.dismiss()
            except Exception:
                pass

        page.on("dialog", lambda dialog: asyncio.create_task(on_dialog(dialog)))
        page.on("popup", lambda popup: asyncio.create_task(popup.close()))

        response = None
        try:
            response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=cfg.crawl_timeout_ms,
                referer=None,
            )
            await page.wait_for_timeout(min(cfg.page_settle_ms, 3000))
            try:
                await page.wait_for_load_state("networkidle", timeout=2500)
            except PlaywrightTimeoutError:
                pass
        except PlaywrightTimeoutError:
            page_data.errors.append("navigation_timeout")
        except Exception as exc:
            page_data.errors.append(f"navigation_error: {type(exc).__name__}")

        try:
            page_data.final_url = page.url if page.url.startswith(("http://", "https://")) else url
        except Exception:
            page_data.final_url = url
        try:
            page_data.domain = registrable_domain(page_data.final_url) or domain
        except Exception:
            page_data.domain = domain
        if response is not None:
            page_data.status = response.status
            try:
                page_data.headers = {
                    k.lower(): v
                    for k, v in (await response.all_headers()).items()
                    if k.lower() not in {"set-cookie"}
                }
            except Exception:
                page_data.headers = {}

        try:
            raw = await page.evaluate(_PW_JS)
            _apply_browser_result(page_data, raw)
        except Exception as exc:
            page_data.errors.append(f"dom_extract_error: {type(exc).__name__}")

        try:
            cookies = await context.cookies()
            page_data.cookies = [
                {
                    "name": str(cookie.get("name", ""))[:80],
                    "domain": str(cookie.get("domain", ""))[:200],
                    "secure": bool(cookie.get("secure")),
                    "http_only": bool(cookie.get("httpOnly")),
                    "same_site": str(cookie.get("sameSite", "")),
                    "session": int(cookie.get("expires", -1)) <= 0,
                }
                for cookie in cookies[:200]
            ]
            page_data.set_cookie_names = [cookie["name"] for cookie in page_data.cookies]
        except Exception:
            pass

        try:
            if 0 < page_data.page_height <= _MAX_SCREENSHOT_HEIGHT:
                try:
                    png = await page.screenshot(
                        full_page=True, type="png", animations="disabled", caret="hide"
                    )
                except Exception:
                    png = await page.screenshot(
                        full_page=False, type="png", animations="disabled", caret="hide"
                    )
            else:
                png = await page.screenshot(
                    full_page=False, type="png", animations="disabled", caret="hide"
                )
        except Exception:
            png = b""
        if png:
            saved = _save_screenshot(png, screenshot_path)
            if saved:
                page_data.screenshot = screenshot_name

        if not page_data.visible_text and not page_data.html:
            page_data.error = "no_page_content"
        page_data.network_urls = list(dict.fromkeys(network))
        page_data.blocked_requests = blocked
        page_data.dialogs = dialogs
        page_data.redirect_chain = [] if page_data.final_url == url else [url, page_data.final_url]

        await context.close()
        await browser.close()
    return page_data


def _apply_browser_result(page: CrawlData, raw: dict[str, Any]) -> None:
    page.title = str(raw.get("title") or "")[:300]
    page.lang = str(raw.get("lang") or "")[:20]
    page.meta = {str(k)[:80]: str(v)[:500] for k, v in (raw.get("meta") or {}).items()}
    page.html = str(raw.get("html") or "")[:850_000]
    page.visible_text = sanitize_text(str(raw.get("visible_text") or ""), 90_000)
    page.hidden_text = sanitize_text(str(raw.get("hidden_text") or ""), 26_000)
    page.html_comments = sanitize_text(str(raw.get("html_comments") or ""), 12_000)
    page.links = [link for link in raw.get("links", []) if isinstance(link, dict)][:250]
    page.scripts = [str(s)[:1200] for s in raw.get("scripts", [])][:120]
    page.inline_scripts = [str(s)[:25_000] for s in raw.get("inline_scripts", [])][:50]
    page.stylesheets = [str(s)[:1200] for s in raw.get("stylesheets", [])][:60]
    page.forms = [_build_form(item) for item in raw.get("forms", []) if isinstance(item, dict)][:15]
    page.images = [
        ImageInfo(
            src=str(item.get("src") or "")[:1500],
            alt=str(item.get("alt") or "")[:200],
            width=int(item.get("width") or 0),
            height=int(item.get("height") or 0),
            visible=bool(item.get("visible", True)),
        )
        for item in raw.get("images", [])
        if isinstance(item, dict) and str(item.get("src", "")).startswith(("http://", "https://"))
    ][:80]
    page.iframes = [item for item in raw.get("iframes", []) if isinstance(item, dict)][:20]
    page.hidden_elements = [item for item in raw.get("hidden_elements", []) if isinstance(item, dict)][:50]
    page.checkboxes = [item for item in raw.get("checkboxes", []) if isinstance(item, dict)][:40]
    page.countdown_elements = [item for item in raw.get("countdown_elements", []) if isinstance(item, dict)][:15]
    page.sticky_elements = [item for item in raw.get("sticky_elements", []) if isinstance(item, dict)][:10]
    page.headings = [str(h)[:200] for h in raw.get("headings", [])][:25]
    page.buttons = [str(b)[:120] for b in raw.get("buttons", [])][:60]
    page.storage_keys = [str(k)[:100] for k in raw.get("storage_keys", [])][:50]
    page.password_field_count = int(raw.get("password_field_count") or 0)
    page.page_height = int(raw.get("page_height") or 0)
    page.favicon_urls = [str(u)[:1200] for u in raw.get("favicon_urls", [])][:8]


def _save_screenshot(png: bytes, path: Path) -> bool:
    try:
        from PIL import Image

        image = Image.open(io.BytesIO(png))
        image = image.convert("RGB")
        if image.height > _MAX_SCREENSHOT_HEIGHT:
            image = image.crop((0, 0, image.width, _MAX_SCREENSHOT_HEIGHT))
        if image.width > 1600:
            ratio = 1600 / image.width
            image = image.resize((1600, max(1, int(image.height * ratio))))
        image.save(path, "PNG", optimize=True)
        return True
    except Exception:
        return False


async def _crawl_http(url: str, domain: str, cfg: Settings) -> CrawlData:
    page = _empty_page(url, domain, "http")
    result = await fetch_bytes(
        url,
        max_bytes=cfg.max_response_bytes,
        timeout=min(15.0, cfg.crawl_timeout_ms / 1000),
    )
    page.final_url = result.final_url
    page.domain = registrable_domain(result.final_url) or domain
    page.status = result.status or None
    page.headers = result.headers
    page.redirect_chain = result.redirect_chain
    page.blocked_requests = []
    if result.error:
        page.error = f"fetch_failed: {result.error[:300]}"
        return page
    content_type = result.content_type.lower()
    if "html" not in content_type and "xml" not in content_type:
        page.error = f"unsupported_content_type: {content_type[:100]}"
        return page
    if result.truncated:
        page.errors.append("response_truncated")
    html = decode_body(result.content, result.content_type)
    page.html = html[: cfg.max_html_chars]
    try:
        _parse_static_html(page, html, result.final_url)
    except Exception as exc:
        page.error = f"html_parse_failed: {type(exc).__name__}"
    cookie_names: list[str] = []
    for raw_cookie in result.set_cookies[:40]:
        name = raw_cookie.split("=", 1)[0].strip()
        if name and name not in cookie_names:
            cookie_names.append(name)
    page.set_cookie_names = cookie_names
    page.cookies = [
        {"name": name, "domain": page.domain, "secure": False, "http_only": False, "same_site": "", "session": True}
        for name in cookie_names
    ]
    if result.status >= 400:
        page.errors.append(f"http_status_{result.status}")
    if not page.visible_text and not page.title:
        page.error = page.error or "no_static_content"
    return page


def _parse_static_html(page: CrawlData, html: str, final_url: str) -> None:
    soup = BeautifulSoup(html, "lxml")
    base_tag = soup.find("base", href=True)
    base_url = final_url
    if base_tag:
        try:
            base_url = normalize_url(urljoin(final_url, str(base_tag["href"])))
        except UnsafeURLError:
            base_url = final_url

    def resolve(value: str) -> str:
        try:
            candidate = urljoin(base_url, value.strip())
            return candidate if candidate.startswith(("http://", "https://")) else ""
        except Exception:
            return ""

    title_tag = soup.find("title")
    page.title = sanitize_text(title_tag.get_text(" ", strip=True), 300) if title_tag else ""
    html_tag = soup.find("html")
    page.lang = str(html_tag.get("lang", ""))[:20] if html_tag else ""

    meta: dict[str, str] = {}
    for tag in soup.find_all("meta", limit=50):
        key = (
            tag.get("name") or tag.get("property") or tag.get("http-equiv") or tag.get("charset") or ""
        ).lower()
        value = tag.get("content") or tag.get("charset") or ""
        if key and value and key not in meta:
            meta[str(key)[:80]] = sanitize_text(str(value), 500)
    page.meta = meta

    comments: list[str] = []
    try:
        from bs4 import Comment

        for node in soup.find_all(string=lambda text: isinstance(text, Comment))[:40]:
            value = sanitize_text(str(node), 600)
            if value:
                comments.append(value)
    except Exception:
        pass
    page.html_comments = "\n".join(comments)[:12_000]

    hidden_parts: list[str] = []
    hidden_elements: list[dict[str, str]] = []
    hidden_tags = []
    for tag in soup.find_all(True):
        if tag.name in {"script", "style", "noscript", "template"}:
            continue
        style = str(tag.get("style", "")).lower().replace(" ", "")
        reason = ""
        if "display:none" in style:
            reason = "display:none"
        elif "visibility:hidden" in style:
            reason = "visibility"
        elif tag.has_attr("hidden"):
            reason = "hidden-attribute"
        elif str(tag.get("aria-hidden", "")).lower() == "true":
            reason = "aria-hidden"
        if not reason:
            continue
        text = sanitize_text(tag.get_text(" ", strip=True), 400)
        if not text:
            continue
        hidden_tags.append(tag)
        if len(hidden_elements) < 50:
            hidden_elements.append(
                {
                    "tag": tag.name,
                    "id": str(tag.get("id", ""))[:80],
                    "cls": " ".join(tag.get("class", []))[:100],
                    "text": text,
                    "reason": reason,
                }
            )
        if len(" ".join(hidden_parts)) < 24_000:
            hidden_parts.append(text)
    page.hidden_elements = hidden_elements
    page.hidden_text = " ".join(hidden_parts)[:26_000]

    for tag in soup.find_all(["h1", "h2"], limit=25):
        text = sanitize_text(tag.get_text(" ", strip=True), 200)
        if text:
            page.headings.append(text)
    for tag in soup.find_all(["button", "input"])[:60]:
        if tag.name == "input" and str(tag.get("type", "")).lower() not in {"submit", "button"}:
            continue
        text = sanitize_text(tag.get_text(" ", strip=True) or str(tag.get("value", "")), 120)
        if text:
            page.buttons.append(text)

    for anchor in soup.find_all("a", href=True, limit=400):
        href = resolve(str(anchor.get("href", "")))
        if not href:
            continue
        page.links.append(
            {
                "href": href[:2000],
                "text": sanitize_text(anchor.get_text(" ", strip=True), 120),
                "rel": " ".join(anchor.get("rel", []))[:60],
                "target": str(anchor.get("target", ""))[:20],
            }
        )
        if len(page.links) >= 250:
            break

    for script in soup.find_all("script", limit=120):
        if script.get("src"):
            src = resolve(str(script["src"]))
            if src:
                page.scripts.append(src[:1200])
        else:
            content = script.string or script.get_text()
            if content and len(page.inline_scripts) < 50:
                page.inline_scripts.append(content[:25_000])

    for link in soup.find_all("link", limit=100):
        href = resolve(str(link.get("href", "")))
        rel = " ".join(link.get("rel", [])).lower()
        if not href:
            continue
        if "stylesheet" in rel:
            page.stylesheets.append(href[:1200])
        if "icon" in rel:
            page.favicon_urls.append(href[:1200])

    for iframe in soup.find_all("iframe", limit=20):
        src = resolve(str(iframe.get("src", "")))
        if src:
            page.iframes.append(
                {
                    "src": src[:1500],
                    "title": sanitize_text(str(iframe.get("title", "")), 150),
                    "hidden": iframe.has_attr("hidden"),
                    "width": 0,
                    "height": 0,
                }
            )

    for image in soup.find_all("img", limit=80):
        src = resolve(str(image.get("src", "") or image.get("data-src", "")))
        if not src:
            continue
        try:
            width = int(str(image.get("width", "0")).replace("px", ""))
        except ValueError:
            width = 0
        try:
            height = int(str(image.get("height", "0")).replace("px", ""))
        except ValueError:
            height = 0
        page.images.append(
            ImageInfo(
                src=src[:1500],
                alt=sanitize_text(str(image.get("alt", "")), 200),
                width=width,
                height=height,
            )
        )

    for form in soup.find_all("form", limit=15):
        action = resolve(str(form.get("action", ""))) or final_url
        fields: list[FormField] = []
        for element in form.find_all(["input", "select", "textarea", "button"])[:80]:
            tag = element.name
            field_type = str(element.get("type", tag)).lower()
            fields.append(
                FormField(
                    name=str(element.get("name", ""))[:100],
                    type=field_type,
                    placeholder=str(element.get("placeholder", ""))[:120],
                    autocomplete=str(element.get("autocomplete", ""))[:60],
                    required=element.has_attr("required"),
                    hidden=field_type == "hidden" or element.has_attr("hidden"),
                    label=sanitize_text(str(element.get("aria-label", "")), 120),
                )
            )
        page.forms.append(
            FormInfo(
                action=action[:2000],
                method=str(form.get("method", "get")).lower()[:10],
                fields=fields,
                text=sanitize_text(form.get_text(" ", strip=True), 1500),
                has_password=any(f.type == "password" for f in fields),
                has_email=any(f.type == "email" or _EMAIL_RE.search(f.name) for f in fields),
                has_card=bool(_CARD_RE.search(" ".join(f"{f.name} {f.placeholder}" for f in fields))),
                has_cvv=bool(_CVV_RE.search(" ".join(f"{f.name} {f.placeholder}" for f in fields))),
                has_file=any(f.type == "file" for f in fields),
                has_hidden=any(f.hidden for f in fields),
            )
        )

    for checkbox in soup.find_all("input", attrs={"type": "checkbox"}, limit=40):
        label = ""
        checkbox_id = str(checkbox.get("id", ""))
        if checkbox_id:
            label_tag = soup.find("label", attrs={"for": checkbox_id})
            if label_tag:
                label = label_tag.get_text(" ", strip=True)
        if not label and checkbox.parent and getattr(checkbox.parent, "name", "") == "label":
            label = checkbox.parent.get_text(" ", strip=True)
        page.checkboxes.append(
            {
                "name": str(checkbox.get("name", ""))[:100],
                "id": checkbox_id[:100],
                "checked": checkbox.has_attr("checked"),
                "hidden": checkbox.has_attr("hidden"),
                "label": sanitize_text(label, 200),
                "in_form": bool(checkbox.find_parent("form")),
            }
        )

    page.password_field_count = len(soup.find_all("input", attrs={"type": "password"}))
    network = [final_url]
    for url_value in [*page.scripts, *page.stylesheets, *page.favicon_urls]:
        if url_value:
            network.append(url_value)
    for image in page.images:
        network.append(image.src)
    for iframe in page.iframes:
        network.append(str(iframe.get("src", "")))
    page.network_urls = list(dict.fromkeys(network))[:500]

    for tag in hidden_tags:
        try:
            tag.decompose()
        except Exception:
            pass
    for tag in soup(["script", "style", "noscript", "template", "svg", "canvas"]):
        tag.decompose()
    page.visible_text = sanitize_text(
        soup.get_text("\n", strip=True) if soup else "", 90_000
    )


async def fetch_text(url: str, *, max_bytes: int = 1_200_000, timeout: float = 9.0) -> tuple[FetchResult, str]:
    result = await fetch_bytes(url, max_bytes=max_bytes, timeout=timeout)
    if result.error:
        return result, ""
    return result, decode_body(result.content, result.content_type)


def content_type_is_html(content_type: str) -> bool:
    lowered = content_type.lower()
    return "html" in lowered or "xml" in lowered


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
