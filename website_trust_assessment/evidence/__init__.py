"""Evidence extractors. Each module exposes extract(ctx) -> list[Evidence]."""

from . import (  # noqa: F401
    content,
    dark_patterns,
    domain_intel,
    http_headers,
    infrastructure,
    injection,
    policy,
    trackers,
    url_features,
    visual,
)

SYNC_EXTRACTORS = (
    ("url_features", url_features.extract),
    ("http_headers", http_headers.extract),
    ("content", content.extract),
    ("trackers", trackers.extract),
    ("dark_patterns", dark_patterns.extract),
    ("injection", injection.extract),
)

ASYNC_EXTRACTORS = (
    ("policy", policy.extract),
    ("visual", visual.extract),
    ("infrastructure", infrastructure.extract),
)

__all__ = [
    "SYNC_EXTRACTORS",
    "ASYNC_EXTRACTORS",
    "content",
    "dark_patterns",
    "domain_intel",
    "http_headers",
    "infrastructure",
    "injection",
    "policy",
    "trackers",
    "url_features",
    "visual",
]
