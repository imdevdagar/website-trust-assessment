"use strict";

const DEFAULTS = {
  serverUrl: "http://127.0.0.1:8000",
  autoProtect: true,
  showOverlay: true,
};

const CACHE_KEY = "trustlens_guard_cache_v1";
const CACHE_TTL_MS = 15 * 60 * 1000;
const CACHE_LIMIT = 200;
const SCAN_TIMEOUT_MS = 90 * 1000;
const OVERLAY_MARK_PREFIX = "trustlens_overlay_";

const tabStates = new Map();

function normalizeServer(raw) {
  const value = String(raw || DEFAULTS.serverUrl).trim();
  if (!value) throw new Error("Enter the local server address.");
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(value) ? value : `http://${value}`;
  let parsed;
  try {
    parsed = new URL(withScheme);
  } catch (error) {
    throw new Error("That is not a valid server address.");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("The server address must use http:// or https://.");
  }
  if (!["127.0.0.1", "localhost"].includes(parsed.hostname)) {
    throw new Error("For privacy, Website Trust Assessment Guard only connects to localhost.");
  }
  return parsed.origin;
}

async function getSettings() {
  const stored = await chrome.storage.local.get(DEFAULTS);
  let serverUrl = DEFAULTS.serverUrl;
  try {
    serverUrl = normalizeServer(stored.serverUrl);
  } catch (error) {
    serverUrl = DEFAULTS.serverUrl;
  }
  return {
    serverUrl,
    autoProtect: Boolean(stored.autoProtect),
    showOverlay: Boolean(stored.showOverlay),
  };
}

async function saveSettings(patch) {
  const previous = await getSettings();
  const next = {
    serverUrl:
      patch && typeof patch.serverUrl === "string"
        ? normalizeServer(patch.serverUrl)
        : previous.serverUrl,
    autoProtect:
      patch && patch.autoProtect !== undefined
        ? Boolean(patch.autoProtect)
        : previous.autoProtect,
    showOverlay:
      patch && patch.showOverlay !== undefined
        ? Boolean(patch.showOverlay)
        : previous.showOverlay,
  };
  await chrome.storage.local.set(next);
  if (next.serverUrl !== previous.serverUrl) {
    await chrome.storage.local.remove(CACHE_KEY);
  }
  const tabs = await queryTabs({});
  await Promise.all(tabs.map((tab) => refreshBadgeForTab(tab.id, tab).catch(() => undefined)));
  return next;
}

function getTab(tabId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(tab);
      }
    });
  });
}

function queryTabs(queryInfo) {
  return new Promise((resolve) => {
    chrome.tabs.query(queryInfo, (tabs) => resolve(tabs || []));
  });
}

function isPrivateHostname(hostname) {
  const host = String(hostname || "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!host) return true;
  if (host === "localhost" || host === "::1" || host.endsWith(".local") || host.endsWith(".internal")) {
    return true;
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const parts = host.split(".").map(Number);
    if (parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
    if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
    if (parts[0] === 198 && (parts[1] === 18 || parts[1] === 19)) return true;
    if (parts[0] >= 224) return true;
    return false;
  }
  if (host.includes(":")) {
    if (host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80")) return true;
  }
  if (!host.includes(".")) return true;
  return false;
}

function pageInfo(rawUrl) {
  try {
    const url = new URL(rawUrl);
    if (!["http:", "https:"].includes(url.protocol)) return null;
    if (isPrivateHostname(url.hostname)) return null;
    return { url: url.href, hostname: url.hostname };
  } catch (error) {
    return null;
  }
}

function safeAction(value) {
  return ["browse", "signup", "purchase"].includes(value) ? value : "browse";
}

async function readCache() {
  const stored = await chrome.storage.local.get(CACHE_KEY);
  const cache = stored[CACHE_KEY];
  return cache && typeof cache === "object" ? cache : {};
}

function cacheKey(hostname, action) {
  return `${hostname}|${safeAction(action)}`;
}

async function getCached(hostname, action) {
  const cache = await readCache();
  const entry = cache[cacheKey(hostname, action)];
  if (!entry || !entry.result || typeof entry.savedAt !== "number") return null;
  if (Date.now() - entry.savedAt > CACHE_TTL_MS) return null;
  return entry.result;
}

async function putCached(hostname, action, result) {
  const cache = await readCache();
  cache[cacheKey(hostname, action)] = { savedAt: Date.now(), result };
  const entries = Object.entries(cache)
    .filter(([, entry]) => entry && typeof entry.savedAt === "number")
    .sort((a, b) => b[1].savedAt - a[1].savedAt)
    .slice(0, CACHE_LIMIT);
  await chrome.storage.local.set({ [CACHE_KEY]: Object.fromEntries(entries) });
}

function sanitizeResult(raw) {
  if (!raw || typeof raw !== "object") {
    throw new Error("The local engine returned an invalid assessment.");
  }
  const verdict = ["allow", "warn", "block"].includes(raw.verdict) ? raw.verdict : "warn";
  const risk = Number(raw.overall_risk);
  const confidence = Number(raw.confidence);
  return {
    verdict,
    overall_risk: Number.isFinite(risk) ? Math.max(0, Math.min(100, risk)) : 0,
    overall_level: String(raw.overall_level || "unknown").slice(0, 20),
    confidence: Number.isFinite(confidence) ? Math.max(0, Math.min(1, confidence)) : 0,
    headline: String(raw.headline || "Assessment complete").slice(0, 300),
    reasons: Array.isArray(raw.reasons)
      ? raw.reasons.filter((item) => typeof item === "string").slice(0, 6).map((item) => item.slice(0, 300))
      : [],
    assessment_id: String(raw.assessment_id || "").slice(0, 80),
    url: String(raw.url || "").slice(0, 2048),
    domain: String(raw.domain || "").slice(0, 253),
    assessed_at: String(raw.assessed_at || new Date().toISOString()),
  };
}

async function callGuard(url, action, force) {
  const settings = await getSettings();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);
  try {
    let response;
    try {
      response = await fetch(`${settings.serverUrl}/v1/guard`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, requested_action: safeAction(action), force_refresh: Boolean(force) }),
        signal: controller.signal,
      });
    } catch (error) {
      if (error && error.name === "AbortError") {
        throw new Error("Assessment timed out. The site may be slow or blocking the crawler.");
      }
      throw new Error("Could not reach the local assessment engine. Start it with: python -m trustlens.cli serve");
    }
    const text = await response.text();
    let payload = null;
    try {
      payload = JSON.parse(text);
    } catch (error) {
      payload = null;
    }
    if (!response.ok) {
      let detail = "";
      if (payload && typeof payload.detail === "string") detail = payload.detail;
      else if (payload && Array.isArray(payload.detail)) {
        detail = payload.detail.map((item) => item.msg || "").filter(Boolean).join("; ");
      }
      if (response.status === 429) {
        detail = detail || "Too many scans. Wait a minute and try again.";
      }
      throw new Error(detail || `The local engine returned HTTP ${response.status}.`);
    }
    return sanitizeResult(payload);
  } finally {
    clearTimeout(timer);
  }
}

function badgeSpec(result) {
  if (!result) return { text: "?", color: "#64748b", title: "Website Trust Assessment: no assessment" };
  if (result.verdict === "block") {
    return {
      text: "X",
      color: "#b42318",
      title: `Website Trust Assessment: HIGH RISK ${Math.round(result.overall_risk)}/100 — ${result.headline}`,
    };
  }
  if (result.verdict === "warn") {
    return {
      text: "!",
      color: "#b54708",
      title: `Website Trust Assessment: CAUTION ${Math.round(result.overall_risk)}/100 — ${result.headline}`,
    };
  }
  return {
    text: "OK",
    color: "#067647",
    title: `Website Trust Assessment: low risk ${Math.round(result.overall_risk)}/100 — ${result.headline}`,
  };
}

async function applyBadge(tabId, result) {
  const spec = badgeSpec(result);
  await setBadge(tabId, spec.text, spec.color, spec.title);
}

async function setBadge(tabId, text, color, title) {
  try {
    await chrome.action.setBadgeText({ tabId, text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color });
    if (chrome.action.setBadgeTextColor) {
      try {
        await chrome.action.setBadgeTextColor({ tabId, color: "#ffffff" });
      } catch (error) {
        /* optional API */
      }
    }
    await chrome.action.setTitle({ tabId, title });
  } catch (error) {
    /* tab may have closed */
  }
}

async function clearBadge(tabId, title) {
  await setBadge(tabId, "", "#64748b", title || "Website Trust Assessment Guard");
}

function overlaySession() {
  return chrome.storage.session || chrome.storage.local;
}

async function overlayAlreadyShown(tabId, hostname) {
  try {
    const key = `${OVERLAY_MARK_PREFIX}${tabId}_${hostname}`;
    const stored = await overlaySession().get(key);
    return Boolean(stored[key]);
  } catch (error) {
    return false;
  }
}

async function markOverlayShown(tabId, hostname) {
  try {
    const key = `${OVERLAY_MARK_PREFIX}${tabId}_${hostname}`;
    await overlaySession().set({ [key]: Date.now() });
  } catch (error) {
    /* session storage may be unavailable */
  }
}

async function maybeShowOverlay(tabId, pageUrl, result, settings) {
  if (!settings.showOverlay) return;
  if (!["warn", "block"].includes(result.verdict)) return;
  let hostname = "";
  try {
    hostname = new URL(pageUrl).hostname;
  } catch (error) {
    return;
  }
  if (await overlayAlreadyShown(tabId, hostname)) return;
  await markOverlayShown(tabId, hostname);
  const dashboardUrl = `${settings.serverUrl}/dashboard?url=${encodeURIComponent(pageUrl)}`;
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      func: trustLensOverlay,
      args: [
        {
          verdict: result.verdict,
          domain: result.domain || hostname,
          risk: Math.round(result.overall_risk),
          confidence: Math.round(result.confidence * 100),
          headline: result.headline,
          reasons: result.reasons,
          dashboardUrl,
        },
      ],
    });
  } catch (error) {
    /* restricted pages cannot host an overlay */
  }
}

async function scanTab(tabId, options) {
  const opts = options || {};
  const action = safeAction(opts.action);
  const tab = await getTab(tabId);
  const page = pageInfo(tab && tab.url);
  if (!page) {
    tabStates.set(tabId, {
      status: "unsupported",
      action,
      url: tab ? tab.url : "",
      error: "This page cannot be assessed.",
    });
    await clearBadge(tabId, "Website Trust Assessment: this page cannot be assessed");
    return { ok: false, error: "This page cannot be assessed." };
  }
  const existing = tabStates.get(tabId);
  if (existing && existing.status === "scanning" && existing.url === page.url && existing.action === action) {
    return { ok: true, pending: true, status: "scanning" };
  }

  await setBadge(tabId, "…", "#475569", "Website Trust Assessment: scanning this page");
  tabStates.set(tabId, { status: "scanning", action, url: page.url });
  try {
    const result = await callGuard(page.url, action, opts.force !== false);
    await putCached(page.hostname, action, result);

    let current = null;
    try {
      current = await getTab(tabId);
    } catch (error) {
      current = null;
    }
    if (!current || current.url !== page.url) {
      tabStates.set(tabId, { status: "idle", action, url: current ? current.url : "" });
      return { ok: true, stale: true, result };
    }

    tabStates.set(tabId, { status: "ready", action, url: page.url, result });
    await applyBadge(tabId, result);
    const settings = await getSettings();
    if (opts.auto && settings.autoProtect) {
      await maybeShowOverlay(tabId, page.url, result, settings);
    }
    return { ok: true, result };
  } catch (error) {
    const message = error && error.message ? error.message : "Assessment failed.";
    tabStates.set(tabId, { status: "error", action, url: page.url, error: message });
    await setBadge(tabId, "?", "#64748b", "Website Trust Assessment: assessment unavailable");
    return { ok: false, error: message };
  }
}

async function refreshBadgeForTab(tabId, tab) {
  const settings = await getSettings();
  if (!settings.autoProtect) {
    await clearBadge(tabId, "Website Trust Assessment: auto-protect is off");
    return;
  }
  const page = pageInfo(tab && tab.url);
  if (!page) {
    await clearBadge(tabId, "Website Trust Assessment: this page cannot be assessed");
    return;
  }
  const cached = await getCached(page.hostname, "browse");
  if (cached) {
    await applyBadge(tabId, cached);
  } else {
    await clearBadge(tabId, "Website Trust Assessment: page not assessed yet");
  }
}

async function handleNavigation(tabId, tab) {
  const settings = await getSettings();
  if (!settings.autoProtect) {
    await clearBadge(tabId, "Website Trust Assessment: auto-protect is off");
    return;
  }
  const page = pageInfo(tab && tab.url);
  if (!page) {
    await clearBadge(tabId, "Website Trust Assessment: this page cannot be assessed");
    return;
  }
  const existing = tabStates.get(tabId);
  if (
    existing &&
    existing.url === page.url &&
    existing.action === "browse" &&
    (existing.status === "scanning" || existing.status === "ready")
  ) {
    if (existing.status === "ready" && existing.result) {
      await applyBadge(tabId, existing.result);
    }
    return;
  }
  const cached = await getCached(page.hostname, "browse");
  if (cached) {
    tabStates.set(tabId, { status: "ready", action: "browse", url: page.url, result: cached });
    await applyBadge(tabId, cached);
    await maybeShowOverlay(tabId, page.url, cached, settings);
    return;
  }
  await scanTab(tabId, { action: "browse", force: false, auto: true });
}

async function handleGetStatus(tabId, requestedAction) {
  const tab = await getTab(tabId);
  const settings = await getSettings();
  const action = safeAction(requestedAction);
  const page = pageInfo(tab && tab.url);
  const base = {
    tab: {
      id: tabId,
      url: tab && tab.url ? tab.url : "",
      title: tab && tab.title ? tab.title : "",
      domain: page ? page.hostname : "",
    },
    action,
    settings,
    autoProtect: settings.autoProtect,
  };
  if (!page) {
    return { ...base, status: "unsupported", error: "This page cannot be assessed." };
  }
  const existing = tabStates.get(tabId);
  if (existing && existing.action === action && existing.url === page.url) {
    if (existing.status === "scanning") return { ...base, status: "scanning" };
    if (existing.status === "ready" && existing.result) {
      return { ...base, status: "ready", result: existing.result };
    }
    if (existing.status === "error") {
      return { ...base, status: "error", error: existing.error };
    }
  }
  const cached = await getCached(page.hostname, action);
  if (cached) return { ...base, status: "ready", result: cached, cached: true };
  return { ...base, status: "idle" };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    try {
      if (!message || typeof message !== "object") {
        sendResponse({ error: "Invalid message." });
        return;
      }
      if (message.type === "getStatus") {
        sendResponse(await handleGetStatus(message.tabId, message.action));
        return;
      }
      if (message.type === "scanTab") {
        sendResponse(await scanTab(message.tabId, {
          action: message.action,
          force: true,
          auto: false,
        }));
        return;
      }
      if (message.type === "saveSettings") {
        const settings = await saveSettings(message.settings || {});
        sendResponse({ ok: true, settings });
        return;
      }
      sendResponse({ error: "Unknown message." });
    } catch (error) {
      sendResponse({ error: error && error.message ? error.message : "Unexpected error." });
    }
  })();
  return true;
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab || !tab.url) return;
  handleNavigation(tabId, tab).catch(() => undefined);
});

chrome.tabs.onActivated.addListener(({ tabId }) => {
  getTab(tabId)
    .then((tab) => handleNavigation(tabId, tab))
    .catch(() => undefined);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
});

async function scanActiveTab() {
  const settings = await getSettings();
  if (!settings.autoProtect) return;
  const tabs = await queryTabs({ active: true, lastFocusedWindow: true });
  const tab = tabs.find((item) => item && typeof item.id === "number");
  if (!tab) return;
  await handleNavigation(tab.id, tab);
}

chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.local.get(Object.keys(DEFAULTS));
  const init = {};
  for (const [key, value] of Object.entries(DEFAULTS)) {
    if (stored[key] === undefined) init[key] = value;
  }
  if (Object.keys(init).length) await chrome.storage.local.set(init);
  scanActiveTab().catch(() => undefined);
});

chrome.runtime.onStartup.addListener(() => {
  scanActiveTab().catch(() => undefined);
});

function trustLensOverlay(payload) {
  if (window.top !== window) return;
  if (document.getElementById("trustlens-guard-overlay")) return;
  const isBlock = payload && payload.verdict === "block";
  const host = document.createElement("div");
  host.id = "trustlens-guard-overlay";
  host.style.cssText =
    "all: initial; position: fixed; inset: 0; z-index: 2147483647; pointer-events: none;";
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = `
    :host { all: initial; }
    * { box-sizing: border-box; }
    .backdrop {
      position: fixed; inset: 0; display: flex; align-items: center; justify-content: center;
      padding: 20px; background: rgba(15, 23, 42, 0.58); pointer-events: auto;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    }
    .corner {
      position: fixed; right: 18px; bottom: 18px; width: min(382px, calc(100vw - 36px));
      pointer-events: auto;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    }
    .card {
      width: 100%; background: #fff; color: #101828; border-radius: 14px;
      border: 1px solid #e4e7ec; border-left: 5px solid #b54708;
      box-shadow: 0 20px 60px rgba(15, 23, 42, 0.32); padding: 18px;
    }
    .card.block { border-left-color: #b42318; max-width: 540px; }
    .head { display: flex; align-items: center; gap: 9px; margin-bottom: 10px; }
    .logo {
      display: inline-flex; align-items: center; justify-content: center;
      width: 28px; height: 28px; border-radius: 8px; background: #0f172a;
      color: #5eead4; font-size: 11px; font-weight: 800; letter-spacing: 0.02em;
    }
    .brand { color: #344054; font-size: 12px; font-weight: 700; }
    .risk {
      margin-left: auto; padding: 3px 8px; border-radius: 999px;
      background: #fffaeb; color: #b54708; font-size: 9px; font-weight: 800;
      letter-spacing: 0.07em; text-transform: uppercase;
    }
    .block .risk { background: #fef3f2; color: #b42318; }
    h2 {
      margin: 0 0 5px; color: #101828; font-size: 18px; line-height: 1.3;
      letter-spacing: -0.02em; font-weight: 750;
    }
    .meta { color: #667085; font-size: 12px; margin: 0 0 10px; }
    ul { margin: 0 0 14px; padding-left: 18px; color: #344054; font-size: 12.5px; line-height: 1.55; }
    li { margin-bottom: 4px; }
    .actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
    button, a.button {
      appearance: none; border-radius: 8px; padding: 8px 12px; font-size: 12px;
      font-weight: 700; cursor: pointer; text-decoration: none; font-family: inherit;
      border: 1px solid transparent; display: inline-flex; align-items: center;
    }
    .primary { background: #0f766e; color: #fff; border-color: #0b5f59; }
    .primary.block { background: #b42318; border-color: #912018; color: #fff; }
    .secondary { background: #fff; color: #344054; border-color: #d0d5dd; }
    .link { background: transparent; color: #0f766e; border-color: transparent; padding-left: 2px; }
    .foot { margin-top: 11px; color: #98a2b3; font-size: 10px; line-height: 1.45; }
    @media (max-width: 500px) {
      .corner { right: 10px; bottom: 10px; width: calc(100vw - 20px); }
      .card { padding: 15px; }
      h2 { font-size: 16px; }
    }
  `;

  const wrap = document.createElement("div");
  wrap.className = isBlock ? "backdrop" : "corner";
  const card = document.createElement("section");
  card.className = isBlock ? "card block" : "card";
  card.setAttribute("role", isBlock ? "alertdialog" : "alert");
  card.setAttribute("aria-label", "Website trust risk warning");

  const head = document.createElement("div");
  head.className = "head";
  const logo = document.createElement("span");
  logo.className = "logo";
  logo.textContent = "WT";
  const brand = document.createElement("span");
  brand.className = "brand";
  brand.textContent = "Website Trust Assessment Guard";
  const risk = document.createElement("span");
  risk.className = "risk";
  risk.textContent = isBlock ? "High risk" : "Caution";
  head.append(logo, brand, risk);

  const title = document.createElement("h2");
  title.textContent = String(payload.headline || "Risk signals were detected on this page");
  const meta = document.createElement("p");
  meta.className = "meta";
  meta.textContent = `${String(payload.domain || "")} · risk ${Number(payload.risk) || 0}/100 · confidence ${Number(payload.confidence) || 0}%`;

  card.append(head, title, meta);

  const reasons = Array.isArray(payload.reasons) ? payload.reasons.slice(0, 4) : [];
  if (reasons.length) {
    const list = document.createElement("ul");
    for (const reason of reasons) {
      const item = document.createElement("li");
      item.textContent = String(reason);
      list.append(item);
    }
    card.append(list);
  }

  const actions = document.createElement("div");
  actions.className = "actions";
  if (isBlock) {
    const leave = document.createElement("button");
    leave.type = "button";
    leave.className = "primary block";
    leave.textContent = "Leave this site";
    leave.addEventListener("click", () => {
      try {
        window.location.replace("about:blank");
      } catch (error) {
        host.remove();
      }
    });
    const proceed = document.createElement("button");
    proceed.type = "button";
    proceed.className = "secondary";
    proceed.textContent = "Continue at my own risk";
    proceed.addEventListener("click", () => host.remove());
    actions.append(leave, proceed);
  } else {
    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.className = "primary";
    dismiss.textContent = "Dismiss";
    dismiss.addEventListener("click", () => host.remove());
    actions.append(dismiss);
  }
  if (payload.dashboardUrl) {
    const details = document.createElement("a");
    details.className = "link button";
    details.href = String(payload.dashboardUrl);
    details.target = "_blank";
    details.rel = "noopener noreferrer";
    details.textContent = "View assessment";
    actions.append(details);
  }
  card.append(actions);

  const foot = document.createElement("p");
  foot.className = "foot";
  foot.textContent = "Advisory only. Automated signals can be wrong; verify important decisions independently.";
  card.append(foot);

  wrap.append(card);
  root.append(style, wrap);
  document.documentElement.append(host);
}
