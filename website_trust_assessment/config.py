"""Runtime configuration. All paths are resolved so the API can be started from anywhere."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
KNOWLEDGE_DIR = PACKAGE_ROOT / "data" / "knowledge"
WEB_DIR = PACKAGE_ROOT / "web"


def _in_source_checkout() -> bool:
    return (PROJECT_ROOT / "pyproject.toml").is_file() and (PROJECT_ROOT / "data").is_dir()


def _user_data_root() -> Path:
    if os.name == "nt":
        base = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "WebsiteTrustAssessment"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "WebsiteTrustAssessment"
    base = os.getenv("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "website-trust-assessment"


def runtime_root() -> Path:
    """Writable home for the database, screenshots, and models.

    A source checkout keeps using its own `data/` directory so existing paths and research
    artifacts stay stable; an installed package uses the platform user-data directory.
    """
    override = os.getenv("WTAS_HOME")
    if override:
        return Path(override).expanduser().resolve()
    return PROJECT_ROOT if _in_source_checkout() else _user_data_root()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _resolve(path_value: str) -> Path:
    path = Path(path_value).expanduser()
    if not path.is_absolute():
        path = runtime_root() / path
    return path


@dataclass(frozen=True)
class Settings:
    root: Path = field(default_factory=runtime_root)
    data_dir: Path = field(default_factory=lambda: _resolve(os.getenv("WTAS_DATA", "data")))
    web_dir: Path = field(default_factory=lambda: _resolve(os.getenv("WTAS_WEB", str(WEB_DIR))))
    db_path: Path = field(default_factory=lambda: _resolve(os.getenv("WTAS_DB", "data/website_trust_assessment.db")))
    screenshots_dir: Path = field(
        default_factory=lambda: _resolve(os.getenv("WTAS_SCREENSHOTS", "data/screenshots"))
    )
    models_dir: Path = field(default_factory=lambda: _resolve(os.getenv("WTAS_MODELS", "models")))
    annotations_dir: Path = field(
        default_factory=lambda: _resolve(os.getenv("WTAS_ANNOTATIONS", "data/annotations"))
    )
    host: str = os.getenv("WTAS_HOST", "127.0.0.1")
    port: int = _env_int("WTAS_PORT", 8000)
    cache_ttl_seconds: int = _env_int("WTAS_CACHE_TTL", 3600)
    assess_timeout_seconds: float = _env_float("WTAS_ASSESS_TIMEOUT", 75.0)
    crawl_timeout_ms: int = _env_int("WTAS_CRAWL_TIMEOUT_MS", 25_000)
    page_settle_ms: int = _env_int("WTAS_PAGE_SETTLE_MS", 2_500)
    max_response_bytes: int = _env_int("WTAS_MAX_RESPONSE_BYTES", 2_500_000)
    max_html_chars: int = 900_000
    enable_playwright: bool = _env_bool("WTAS_ENABLE_PLAYWRIGHT", True)
    max_links: int = 250
    max_policy_fetch: int = 2
    llm_enabled: bool = _env_bool("WTAS_LLM_ENABLED", False)
    llm_model: str = os.getenv("WTAS_LLM_MODEL", "qwen2.5:1.5b-instruct")
    ollama_url: str = os.getenv("WTAS_OLLAMA_URL", "http://127.0.0.1:11434")
    allowed_origins: tuple[str, ...] = tuple(
        origin.strip()
        for origin in os.getenv("WTAS_ALLOWED_ORIGINS", "").split(",")
        if origin.strip()
    )
    rate_limit_per_minute: int = _env_int("WTAS_RATE_LIMIT", 30)
    assessment_concurrency: int = _env_int("WTAS_ASSESS_CONCURRENCY", 2)

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.screenshots_dir, self.db_path.parent, self.models_dir, self.annotations_dir):
            path.mkdir(parents=True, exist_ok=True)


def get_settings() -> Settings:
    return Settings()


_settings_cache: Settings | None = None


def settings() -> Settings:
    """Process-wide settings with directories created lazily."""
    global _settings_cache
    if _settings_cache is None:
        _settings_cache = get_settings()
        _settings_cache.ensure_dirs()
    return _settings_cache


def reload_settings() -> Settings:
    """Used by tests after environment changes."""
    global _settings_cache
    _settings_cache = None
    return settings()


def load_json_data(name: str) -> dict | list:
    import json

    for directory in (settings().data_dir, KNOWLEDGE_DIR):
        path = directory / name
        if path.is_file():
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
    raise FileNotFoundError(f"knowledge file not found: {name}")
