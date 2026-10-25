"""Detection of hidden content that targets automated reviewers or LLM agents.

This is a defensive control for the optional narration and guard layers: page
text is untrusted input. Evidence is produced from hidden text, comments,
metadata, and alternative text, never by executing or obeying the content.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from ..schemas import Dimension, Evidence, Severity
from ..security import sanitize_text
from .base import ScanContext, truncate

INJECTION_PATTERNS: tuple[tuple[str, float, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        24.0,
        re.compile(
            r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,50}"
            r"\b(?:previous|prior|above|earlier|all|any|system|developer)\b"
            r"[^.\n]{0,40}\b(?:instructions?|prompts?|rules?|directions?|context|messages?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role_override",
        20.0,
        re.compile(
            r"\b(?:you are|act as|pretend to be|from now on you)\b[^.\n]{0,60}"
            r"\b(?:ai|llm|language model|assistant|agent|reviewer|classifier|bot)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system_prompt_reference",
        12.0,
        re.compile(
            r"\b(?:system|developer|hidden|initial|meta)[ -]?(?:prompt|message|instructions?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verdict_control",
        24.0,
        re.compile(
            r"\b(?:mark|rate|classify|label|score|report|return|output|respond|answer)\b"
            r"[^.\n]{0,70}\b(?:safe|benign|trusted|trustworthy|low[ -]?risk|trust score|verdict|json)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "warning_suppression",
        22.0,
        re.compile(
            r"\b(?:do not|don't|never|avoid)\b[^.\n]{0,50}"
            r"\b(?:flag|warn|warning|report|block|detect|mention|disclose|reveal)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "tool_execution",
        14.0,
        re.compile(
            r"\b(?:call|invoke|execute|run|open)\b[^.\n]{0,40}"
            r"\b(?:tool|function|command|shell|terminal|browser|url)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "agent_directive",
        14.0,
        re.compile(
            r"\b(?:ai agents?|llms?|language models?|automated (?:reviewer|agent)|"
            r"crawlers?|bots?|assistant)\b[^.\n]{0,60}"
            r"\b(?:must|should|please|note|remember|treat|consider|ignore|report|rate|mark)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "prompt_exfiltration",
        18.0,
        re.compile(
            r"\b(?:reveal|print|show|repeat|disclose|leak)\b[^.\n]{0,40}"
            r"\b(?:system prompt|instructions|hidden (?:text|message)|developer message|prompt)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "trustlens_targeting",
        26.0,
        re.compile(r"\btrust[ -]?lens\b", re.IGNORECASE),
    ),
    (
        "encoded_command",
        16.0,
        re.compile(
            r"\b(?:base64|rot13|decode|decrypt)\b[^.\n]{0,40}"
            r"\b(?:instructions?|commands?|payload|prompt|message)\b",
            re.IGNORECASE,
        ),
    ),
)

STRONG_PATTERNS = {
    "instruction_override",
    "role_override",
    "verdict_control",
    "warning_suppression",
    "prompt_exfiltration",
    "trustlens_targeting",
}

BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{60,400}={0,2})(?![A-Za-z0-9+/=_-])")
DECODED_KEYWORD_RE = re.compile(
    r"\b(ignore|disregard|instruction|prompt|system|assistant|model|agent|reviewer|"
    r"trust|safe|benign|verdict|output|json|classify|score)\b",
    re.IGNORECASE,
)
ZW_RE = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f\u2060\u2061\u2062\u2063\u2064\ufeff\u00ad]"
)
ZW_IN_WORD_RE = re.compile(
    "(?<=[A-Za-z])[\u200b-\u200f\u2060\ufeff\u00ad]+(?=[A-Za-z])"
)
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
RTL_LANGS = ("ar", "he", "fa", "ur", "yi", "dv", "ps")


def _hidden_channels(ctx: ScanContext) -> dict[str, str]:
    channels: dict[str, str] = {}
    if ctx.page.hidden_text:
        channels["hidden_text"] = ctx.page.hidden_text
    if ctx.page.html_comments:
        channels["html_comment"] = ctx.page.html_comments
    meta_text = " ".join(str(value) for value in ctx.page.meta.values() if value)
    if meta_text:
        channels["metadata"] = meta_text
    alt_text = " ".join(image.alt for image in ctx.page.images if image.alt)
    if alt_text:
        channels["image_alt"] = alt_text
    iframe_text = " ".join(
        str(iframe.get("title", "")) for iframe in ctx.page.iframes if iframe.get("title")
    )
    if iframe_text:
        channels["iframe_title"] = iframe_text
    return channels


def _match_injections(
    channels: dict[str, str],
) -> tuple[list[dict[str, Any]], list[str], dict[str, float]]:
    matches: list[dict[str, Any]] = []
    pattern_names: list[str] = []
    weights: dict[str, float] = {}
    for name, weight, pattern in INJECTION_PATTERNS:
        found = False
        for channel, text in channels.items():
            for match in pattern.finditer(text):
                snippet = truncate(
                    re.sub(r"\s+", " ", text[max(0, match.start() - 60) : match.end() + 80]),
                    180,
                )
                matches.append(
                    {
                        "pattern": name,
                        "channel": channel,
                        "snippet": sanitize_text(snippet, 180),
                    }
                )
                found = True
                break
            if found:
                break
        if found:
            pattern_names.append(name)
            weights[name] = weight
    return matches, pattern_names, weights


def _base64_injections(channels: dict[str, str]) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for channel, text in channels.items():
        if channel == "image_alt":
            continue
        scanned = 0
        for match in BASE64_RE.finditer(text):
            scanned += 1
            if scanned > 40:
                break
            candidate = match.group(1)
            raw = candidate.replace("-", "+").replace("_", "/")
            raw += "=" * (-len(raw) % 4)
            try:
                decoded_bytes = base64.b64decode(raw, validate=True)
            except Exception:
                continue
            if not (24 <= len(decoded_bytes) <= 1200):
                continue
            try:
                decoded = decoded_bytes.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if not decoded:
                continue
            printable = sum(char.isprintable() or char.isspace() for char in decoded) / len(decoded)
            if printable < 0.92:
                continue
            keywords = {
                item.lower()
                for item in DECODED_KEYWORD_RE.findall(decoded)
                if len(item) >= 3
            }
            actionable = any(
                word in decoded.lower()
                for word in ("ignore", "instruction", "prompt", "assistant", "system", "verdict", "trust")
            )
            if len(keywords) < 3 or not actionable:
                continue
            snippet = sanitize_text(
                truncate(re.sub(r"\s+", " ", decoded), 160),
                160,
            )
            found.append({"channel": channel, "snippet": snippet})
            break
    return found


def _obfuscation_evidence(ctx: ScanContext) -> tuple[list[Evidence], dict[str, int]]:
    evidence: list[Evidence] = []
    visible = "\n".join(
        [
            ctx.page.title,
            ctx.page.visible_text,
            ctx.page.hidden_text,
            ctx.page.html_comments,
            " ".join(str(value) for value in ctx.page.meta.values() if value),
        ]
    )
    zero_width = len(ZW_RE.findall(visible))
    word_splits = len(ZW_IN_WORD_RE.findall(visible))
    bidi = len(BIDI_RE.findall(visible))
    stats = {"zero_width": zero_width, "zero_width_words": word_splits, "bidi": bidi}

    if word_splits >= 2:
        evidence.append(
            ctx.evidence(
                dimension=Dimension.MANIPULATION,
                code="zero_width_obfuscation",
                title="Zero-width characters split words in page text",
                detail=f"{word_splits} zero-width character sequences were inserted inside words. "
                "This can evade keyword matching and make hidden text harder for people to notice; "
                "it is occasionally used by templating bugs, so it is treated as a weak signal.",
                severity=Severity.LOW,
                risk_points=6.0,
                confidence=0.65,
                source="page_text",
                provenance={"sequences": word_splits, "total_zero_width": zero_width},
                tags=["hidden_text", "obfuscation"],
            )
        )
    lang = (ctx.page.lang or "").lower()
    if bidi and not lang.startswith(RTL_LANGS):
        evidence.append(
            ctx.evidence(
                dimension=Dimension.MANIPULATION,
                code="bidi_control_spoofing",
                title="Bidirectional control characters on a non-RTL page",
                detail=f"{bidi} bidirectional formatting control characters were found in text, title, or metadata. "
                "These can visually reorder text and disguise file names or addresses. The page language is "
                f"'{lang or 'unset'}', so normal right-to-left rendering does not explain them.",
                severity=Severity.MEDIUM,
                risk_points=13.0,
                confidence=0.7,
                source="page_text",
                provenance={"bidi_controls": bidi, "page_language": lang},
                tags=["hidden_text", "spoofing", "obfuscation"],
            )
        )
    ctx.notes["text_obfuscation"] = stats
    return evidence, stats


def extract(ctx: ScanContext) -> list[Evidence]:
    evidence: list[Evidence] = []
    channels = _hidden_channels(ctx)
    ctx.add_source("hidden_content", ctx.page_available)
    if not channels:
        return evidence

    matches, pattern_names, weights = _match_injections(channels)
    encoded = _base64_injections(channels)
    obfuscation, stats = _obfuscation_evidence(ctx)

    injection_channels = sorted({str(item["channel"]) for item in matches})
    if len(encoded) > 0:
        injection_channels = sorted({*injection_channels, *(item["channel"] for item in encoded)})

    if matches:
        channels_count = len({str(item["channel"]) for item in matches})
        base = max(weights.values()) if weights else 10.0
        if len(pattern_names) >= 2:
            base += 3.0
        if channels_count >= 2:
            base += 2.0
        if not set(pattern_names) & STRONG_PATTERNS:
            base = min(base, 12.0)
        risk = min(34.0, base)
        snippets = [str(item["snippet"]) for item in matches[:3] if item["snippet"]]
        detail = (
            "Content that is not visible to a normal visitor contains language aimed at automated "
            "reviewers or language models. "
            + (
                "Observed indicators: " + ", ".join(pattern_names[:6]) + ". "
                if pattern_names
                else ""
            )
            + (
                f"Example: \"{snippets[0]}\". " if snippets else ""
            )
            + "The text is quoted only as evidence; it was not executed or followed. "
            "This is a strong adversarial-content signal, though it does not by itself prove fraud."
        )
        evidence.append(
            ctx.evidence(
                dimension=Dimension.MANIPULATION,
                code="hidden_prompt_injection",
                title="Hidden instructions target automated reviewers",
                detail=detail,
                severity=Severity.HIGH if risk >= 18 else Severity.MEDIUM,
                risk_points=risk,
                confidence=0.85 if len(pattern_names) >= 2 or set(pattern_names) & STRONG_PATTERNS else 0.7,
                source="hidden_content",
                provenance={
                    "patterns": pattern_names,
                    "channels": injection_channels,
                    "snippets": snippets,
                },
                tags=["prompt_injection", "hidden_instruction", "agent_safety"],
            )
        )

    if encoded:
        evidence.append(
            ctx.evidence(
                dimension=Dimension.MANIPULATION,
                code="encoded_instruction_blob",
                title="Hidden encoded text decodes to reviewer instructions",
                detail="A long Base64-like string in hidden content decodes to printable text containing "
                "instruction or evaluation terms. "
                f"Decoded prefix: \"{encoded[0]['snippet']}\". Encoded payloads are a common way to hide "
                "instructions from plain keyword filters.",
                severity=Severity.HIGH,
                risk_points=25.0,
                confidence=0.8,
                source="hidden_content",
                provenance={
                    "channels": sorted({item["channel"] for item in encoded}),
                    "decoded_snippets": [item["snippet"] for item in encoded[:2]],
                },
                tags=["prompt_injection", "encoded_payload", "agent_safety"],
            )
        )

    evidence.extend(obfuscation)

    ctx.notes["prompt_injection"] = {
        "detected": bool(matches or encoded),
        "patterns": pattern_names,
        "channels": injection_channels,
        "encoded_blob": bool(encoded),
        "zero_width": stats["zero_width_words"],
        "bidi_controls": stats["bidi"],
    }
    return evidence
