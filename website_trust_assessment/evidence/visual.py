"""Screenshot OCR for image-only content.

Tesseract runs locally in a worker thread. The OCR output is matched against
the visible text so that a normal page is not penalised twice, and only short
novel matches are surfaced. The OCR body is kept in memory for this scan and
is never persisted as part of the assessment.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
from pathlib import Path

from ..schemas import Dimension, Evidence, Severity
from ..security import sanitize_text
from .base import ScanContext, truncate

try:
    import pytesseract
except Exception:  # OCR is optional; the rest of the assessment still runs
    pytesseract = None


class OCRUnavailable(RuntimeError):
    pass


OCR_SIGNALS: tuple[dict[str, object], ...] = (
    {
        "code": "ocr_remote_access_lure",
        "title": "Image text instructs the visitor to install remote-access software",
        "pattern": re.compile(
            r"\b(?:anydesk|teamviewer|rustdesk|logmein|supremo|remote (?:access|desktop)|screen sharing)\b",
            re.IGNORECASE,
        ),
        "risk": 24.0,
        "severity": Severity.HIGH,
        "dimension": Dimension.SECURITY,
        "detail": "Software that grants remote control was named in image-rendered text. "
        "Remote-access tools are a standard component of tech-support scams; legitimate support "
        "rarely requires an unsolicited remote session.",
        "tags": ["ocr", "image_only", "remote_access", "tech_support_scam"],
    },
    {
        "code": "ocr_gift_card_demand",
        "title": "Image text requests payment by gift card",
        "pattern": re.compile(
            r"\b(?:gift|itunes|amazon|google play|steam)[ -]?cards?\b"
            r"[^.]{0,120}\b(?:code|scratch|send|buy|pay|redeem|pin)\b",
            re.IGNORECASE,
        ),
        "risk": 22.0,
        "severity": Severity.HIGH,
        "dimension": Dimension.SECURITY,
        "detail": "The screenshot contains instructions to pay with a gift card. "
        "Gift-card codes are difficult to recover and are a hallmark of payment fraud.",
        "tags": ["ocr", "image_only", "payment", "gift_card"],
    },
    {
        "code": "ocr_seed_phrase_request",
        "title": "Image text asks for a wallet recovery phrase",
        "pattern": re.compile(
            r"\b(?:enter|send|share|provide|type|recover|verify|confirm)\b[^.]{0,60}"
            r"\b(?:seed|recovery|secret|mnemonic)[ -]?(?:phrase|words?|code)\b|"
            r"\b(?:seed|recovery|secret|mnemonic)[ -]?(?:phrase|words?|code)\b"
            r"[^.]{0,60}\b(?:enter|send|share|provide|type|recover|verify|confirm)\b",
            re.IGNORECASE,
        ),
        "risk": 27.0,
        "severity": Severity.CRITICAL,
        "dimension": Dimension.SECURITY,
        "detail": "A recovery phrase is requested in image-rendered text. A recovery phrase grants full "
        "control of a crypto wallet; no legitimate service needs it to verify or unlock an account.",
        "tags": ["ocr", "image_only", "credentials", "crypto"],
    },
    {
        "code": "ocr_otp_request",
        "title": "Image text asks the visitor to share a password or one-time code",
        "pattern": re.compile(
            r"\b(?:send|share|provide|reply with|read out|tell us)\b[^.]{0,50}"
            r"\b(?:password|otp|one[ -]?time (?:code|password)|verification code|security code|pin)\b",
            re.IGNORECASE,
        ),
        "risk": 20.0,
        "severity": Severity.HIGH,
        "dimension": Dimension.SECURITY,
        "detail": "Image text requests a password or one-time code. Legitimate staff never need a "
        "visitor's password or authentication code.",
        "tags": ["ocr", "image_only", "credentials", "otp"],
    },
    {
        "code": "ocr_crypto_transfer",
        "title": "Image text directs a cryptocurrency transfer",
        "pattern": re.compile(
            r"\b(?:send|transfer|pay|deposit)\b[^.]{0,80}"
            r"\b(?:bitcoin|btc|usdt|eth|ethereum|crypto|wallet)\b|"
            r"\b(?:bitcoin|btc|usdt|eth|ethereum|crypto|wallet)\b[^.]{0,80}"
            r"\b(?:send|transfer|pay|deposit|address)\b",
            re.IGNORECASE,
        ),
        "risk": 18.0,
        "severity": Severity.HIGH,
        "dimension": Dimension.SECURITY,
        "detail": "The screenshot contains instructions to send cryptocurrency. Transfers are irreversible, "
        "and crypto payment demands are common in extortion and investment fraud.",
        "tags": ["ocr", "image_only", "payment", "crypto"],
    },
    {
        "code": "ocr_support_call_lure",
        "title": "Image text urges the visitor to call a support number",
        "pattern": re.compile(
            r"\b(?:call|dial|phone)\b[^.]{0,60}"
            r"\b(?:support|help desk|technician|customer care|microsoft|apple|amazon)\b"
            r"[^.]{0,80}(?:\+?\d[\d\s()\-]{6,}|\bnow\b|\bimmediately\b|\btoll[ -]?free\b)",
            re.IGNORECASE,
        ),
        "risk": 13.0,
        "severity": Severity.MEDIUM,
        "dimension": Dimension.SECURITY,
        "detail": "The screenshot asks the visitor to call a support number. Unsolicited support phone "
        "numbers are frequently used to gain remote access or payment.",
        "tags": ["ocr", "image_only", "phone", "tech_support_scam"],
    },
    {
        "code": "ocr_account_threat",
        "title": "Image text threatens account suspension within a short deadline",
        "pattern": re.compile(
            r"\b(?:account|profile|card|subscription)\b[^.]{0,60}"
            r"\b(?:suspended|locked|limited|closed|blocked|deactivated)\b"
            r"[^.]{0,100}\b(?:within|in)\s+\d+\s+(?:minutes?|hours?)\b",
            re.IGNORECASE,
        ),
        "risk": 12.0,
        "severity": Severity.MEDIUM,
        "dimension": Dimension.MANIPULATION,
        "detail": "Image text uses a short suspension deadline against an account. Countdown pressure "
        "is designed to prevent verification through independent channels.",
        "tags": ["ocr", "image_only", "urgency", "account_threat"],
    },
    {
        "code": "ocr_qr_payment",
        "title": "Image text directs payment through a QR code",
        "pattern": re.compile(
            r"\b(?:scan|use)\b[^.]{0,50}\bqr(?: code)?\b[^.]{0,80}"
            r"\b(?:pay|payment|deposit|send|scan)\b|"
            r"\bqr code\b[^.]{0,60}\b(?:pay|payment|deposit)\b",
            re.IGNORECASE,
        ),
        "risk": 11.0,
        "severity": Severity.MEDIUM,
        "dimension": Dimension.MANIPULATION,
        "detail": "The screenshot directs payment through a QR code. QR destinations cannot be inspected "
        "before scanning and are commonly used to route payments away from legitimate checkout.",
        "tags": ["ocr", "image_only", "payment", "qr"],
    },
    {
        "code": "ocr_guaranteed_return",
        "title": "Image text promises guaranteed investment returns",
        "pattern": re.compile(
            r"\b(?:guaranteed|assured|risk[-\s]?free|fixed)\b[^.]{0,70}"
            r"\b(?:returns?|profits?|income|roi)\b|"
            r"\bdouble\s+your\s+(?:money|investment|capital|crypto|bitcoin)\b",
            re.IGNORECASE,
        ),
        "risk": 18.0,
        "severity": Severity.HIGH,
        "dimension": Dimension.SECURITY,
        "detail": "The screenshot promises guaranteed or risk-free investment returns. That wording is common in "
        "investment fraud; verify the seller independently before sending money.",
        "tags": ["ocr", "image_only", "investment", "financial_fraud"],
    },
    {
        "code": "ocr_upi_payment",
        "title": "Image text directs a UPI or QR payment",
        "pattern": re.compile(
            r"\b[a-z0-9][a-z0-9._-]{1,}@(?:oksbi|okhdfcbank|okicici|okaxis|ybl|paytm|ibl|axl|upi|apl)"
            r"(?![\w.])|"
            r"\bscan\b[^.]{0,50}\bqr(?:\s+code)?\b[^.]{0,80}"
            r"\b(?:pay|payment|deposit|send|transfer)\b",
            re.IGNORECASE,
        ),
        "risk": 14.0,
        "severity": Severity.MEDIUM,
        "dimension": Dimension.SECURITY,
        "detail": "The screenshot directs payment to a UPI address or QR code. Verify the payee inside your own "
        "UPI app; direct transfers are difficult to reverse.",
        "tags": ["ocr", "image_only", "payment", "upi"],
    },
    {
        "code": "ocr_messaging_support",
        "title": "Image text routes support to a messaging app",
        "pattern": re.compile(
            r"\b(?:contact|message|reach|support|chat)\b[^.]{0,60}\b(?:telegram|whatsapp)\b",
            re.IGNORECASE,
        ),
        "risk": 8.0,
        "severity": Severity.LOW,
        "dimension": Dimension.MANIPULATION,
        "detail": "Support is directed to a personal messaging app. This moves the conversation away "
        "from traceable, accountable support channels.",
        "tags": ["ocr", "image_only", "support", "off_platform"],
    },
)

_TOKEN_RE = re.compile(r"[a-z0-9]{3,}")


def _resolve_tesseract() -> None:
    if pytesseract is None:
        return
    configured = os.getenv("TESSERACT_CMD")
    candidates = [configured] if configured else []
    if os.name == "nt":
        candidates.extend(
            [
                r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            ]
        )
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            pytesseract.pytesseract.tesseract_cmd = candidate
            return
    if shutil.which("tesseract") is None and not Path(pytesseract.pytesseract.tesseract_cmd).exists():
        raise OCRUnavailable("tesseract binary not found")


def tesseract_available() -> bool:
    if pytesseract is None:
        return False
    try:
        _resolve_tesseract()
        return True
    except OCRUnavailable:
        return False


def _ocr_sync(path: Path) -> str:
    if pytesseract is None:
        raise OCRUnavailable("pytesseract is not installed")
    _resolve_tesseract()
    try:
        from PIL import Image, ImageOps

        with Image.open(path) as image:
            image.load()
            gray = image.convert("L")
            if max(gray.size) > 3000 and gray.height > 2400:
                ratio = 2400 / gray.height
                gray = gray.resize((max(1, int(gray.width * ratio)), 2400))
            gray = ImageOps.autocontrast(gray)
            return pytesseract.image_to_string(gray, lang="eng", config="--psm 3")
    except OCRUnavailable:
        raise
    except Exception as exc:
        message = str(exc).lower()
        if "tesseractnotfound" in type(exc).__name__.lower() or "tesseract is not installed" in message:
            raise OCRUnavailable("tesseract binary not found") from exc
        raise


def _novel(phrase: str, visible_lower: str, visible_tokens: set[str]) -> bool:
    lowered = phrase.lower().strip()
    if not lowered:
        return False
    if lowered in visible_lower:
        return False
    tokens = _TOKEN_RE.findall(lowered)
    if tokens and sum(token in visible_tokens for token in tokens) / len(tokens) >= 0.7:
        return False
    return True


async def extract(ctx: ScanContext) -> list[Evidence]:
    evidence: list[Evidence] = []
    if not ctx.page.screenshot:
        ctx.add_source("ocr", False)
        ctx.add_missing("Screenshot OCR was unavailable, so image-only content was not inspected")
        return evidence
    path = ctx.settings.screenshots_dir / ctx.page.screenshot
    if not path.exists():
        ctx.add_source("ocr", False)
        ctx.add_missing("Saved screenshot was not found, so image-only content was not inspected")
        return evidence
    if pytesseract is None:
        ctx.add_source("ocr", False)
        ctx.add_missing("OCR engine is not installed, so image-only content was not inspected")
        return evidence

    try:
        raw_text = await asyncio.wait_for(
            asyncio.to_thread(_ocr_sync, path),
            timeout=24.0,
        )
    except TimeoutError:
        ctx.add_source("ocr", False)
        ctx.add_missing("Screenshot OCR timed out")
        return evidence
    except OCRUnavailable:
        ctx.add_source("ocr", False)
        ctx.add_missing("Tesseract OCR is not available, so image-only content was not inspected")
        return evidence
    except Exception as exc:
        ctx.add_source("ocr", False)
        ctx.errors["visual"] = f"ocr_failed: {type(exc).__name__}"
        ctx.add_missing("Screenshot OCR failed")
        return evidence

    text = sanitize_text(raw_text, 24_000)
    if not text.strip():
        ctx.add_source("ocr", True)
        ctx.add_missing("Screenshot contained no machine-readable text")
        ctx.notes["ocr"] = {"characters": 0, "signals": []}
        return evidence

    ctx.page.ocr_text = text
    ctx.add_source("ocr", True)
    flat = re.sub(r"\s+", " ", text)
    visible_lower = ctx.page.visible_text.lower()
    visible_tokens = set(_TOKEN_RE.findall(visible_lower))
    matched: list[dict[str, object]] = []
    seen_spans: list[tuple[int, int]] = []
    for signal in OCR_SIGNALS:
        pattern = signal["pattern"]
        assert isinstance(pattern, re.Pattern)
        for match in pattern.finditer(flat):
            if any(start <= match.start() < end for start, end in seen_spans):
                continue
            phrase = match.group(0)
            if not _novel(phrase, visible_lower, visible_tokens):
                continue
            seen_spans.append((match.start(), match.end()))
            matched.append(
                {
                    "signal": signal,
                    "snippet": truncate(
                        flat[max(0, match.start() - 45) : match.end() + 65],
                        190,
                    ),
                }
            )
            break

    matched.sort(key=lambda item: float(item["signal"]["risk"]), reverse=True)  # type: ignore[index]
    for item in matched[:4]:
        signal = item["signal"]
        assert isinstance(signal, dict)
        snippet = str(item["snippet"])
        evidence.append(
            ctx.evidence(
                dimension=signal["dimension"],  # type: ignore[arg-type]
                code=str(signal["code"]),
                title=str(signal["title"]),
                detail=f"{signal['detail']} Image text: \"{snippet}\"",
                severity=signal["severity"],  # type: ignore[arg-type]
                risk_points=float(signal["risk"]),
                confidence=0.7,
                source="screenshot_ocr",
                provenance={
                    "snippet": snippet,
                    "signal": signal["code"],
                    "ocr_characters": len(text),
                    "visible_text_characters": len(ctx.page.visible_text),
                },
                tags=list(signal["tags"]),  # type: ignore[arg-type]
            )
        )

    signals = [str(item["signal"]["code"]) for item in matched[:8]]  # type: ignore[index]
    ctx.notes["ocr"] = {
        "characters": len(text),
        "signals": signals,
        "image_heavy": len(text) > 400 and len(ctx.page.visible_text) < 250,
    }
    return evidence
