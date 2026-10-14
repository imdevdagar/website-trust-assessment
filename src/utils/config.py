"""
utils/config.py — Load and expose project configuration.
"""
import os
import yaml
from pathlib import Path


def _find_config() -> Path:
    """Walk up from cwd to find config.yaml."""
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        candidate = parent / "config.yaml"
        if candidate.exists():
            return candidate
    raise FileNotFoundError("config.yaml not found. Run from the project root.")


def load_config() -> dict:
    """Load and return the project configuration dictionary."""
    config_path = _find_config()
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


CONFIG = load_config()


def get(key_path: str, default=None):
    """
    Get a nested config value using dot-separated key path.
    Example: get("splitting.test_size") -> 0.20
    """
    keys = key_path.split(".")
    val = CONFIG
    for k in keys:
        if isinstance(val, dict) and k in val:
            val = val[k]
        else:
            return default
    return val
