"""
src/hybrid/threat_intelligence.py
Interface for threat intelligence providers.
The default DisabledThreatIntelProvider returns None for all lookups.
Future implementations can integrate public APIs.
"""
import sys
from pathlib import Path
from abc import ABC, abstractmethod

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logging import get_logger
logger = get_logger(__name__)


class ThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers."""

    @abstractmethod
    def lookup(self, url: str) -> dict:
        """
        Lookup a URL in threat intelligence sources.
        Returns a dict with relevant information, or None if not found.
        """
        pass

    @property
    @abstractmethod
    def is_enabled(self) -> bool:
        pass


class DisabledThreatIntelProvider(ThreatIntelProvider):
    """Default provider: threat intelligence is disabled."""

    def lookup(self, url: str) -> dict:
        return {"enabled": False, "result": None}

    @property
    def is_enabled(self) -> bool:
        return False


def get_provider(name: str = "disabled") -> ThreatIntelProvider:
    providers = {
        "disabled": DisabledThreatIntelProvider,
    }
    cls = providers.get(name.lower(), DisabledThreatIntelProvider)
    return cls()
