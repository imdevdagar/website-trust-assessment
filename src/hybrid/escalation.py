"""
src/hybrid/escalation.py
Hybrid escalation logic: if ML confidence is low, route to deeper analysis.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.hybrid.threat_intelligence import get_provider
from src.utils.logging import get_logger
logger = get_logger(__name__)


def escalate(
    prediction_result: dict,
    url: str,
    threat_intel_provider=None,
) -> dict:
    """
    If the prediction needs review, optionally consult threat intelligence.

    Args:
        prediction_result: Result from predict_with_abstention or predict_single.
        url: The original URL.
        threat_intel_provider: An optional ThreatIntelProvider instance.

    Returns:
        Updated prediction result dict.
    """
    if not prediction_result.get("needs_review", False):
        # High confidence — no escalation needed
        return prediction_result

    logger.info(f"Low confidence prediction for: {url}. Initiating escalation.")
    result = prediction_result.copy()

    if threat_intel_provider is None:
        threat_intel_provider = get_provider("disabled")

    if threat_intel_provider.is_enabled:
        ti_result = threat_intel_provider.lookup(url)
        result["threat_intel"] = ti_result
        logger.info(f"Threat intel result: {ti_result}")
    else:
        result["threat_intel"] = {"enabled": False, "message": "Threat intelligence is disabled."}
        logger.info("Threat intelligence is disabled; leaving as Needs Review.")

    return result
