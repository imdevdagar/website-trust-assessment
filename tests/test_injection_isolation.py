"""H4: hidden instruction text must be detectable and must stay isolated from the score.

Two properties are pinned. The generator pairs each injected page with the same page whose
slot is empty, so "only the hidden instruction was added" is structural rather than assumed.
And the engine must never let that text move anything except the injection evidence: dropping
the injection-related codes has to reproduce the baseline assessment exactly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from website_trust_assessment import crawler
from website_trust_assessment.config import settings
from website_trust_assessment.research import injection as corpus
from website_trust_assessment.schemas import Action

CASES = {case.id: case for case in corpus.build_cases()}


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("injection_fixtures")
    corpus.build_corpus(root)
    return root


@pytest.fixture(scope="module")
def report(built: Path) -> dict:
    return corpus.evaluate(built)


def manifest(root: Path) -> list[dict[str, str]]:
    return json.loads((root / "manifest.json").read_text(encoding="utf-8"))["cases"]


def _score(root: Path, record: dict[str, str], filename: str, drop: frozenset[str] = frozenset()):
    cfg = settings()
    html = (root / record[filename]).read_text(encoding="utf-8")
    return corpus.score(
        html,
        record["url"],
        cfg=cfg,
        headers=corpus.HEADERS[record["body"]],
        action=Action.BROWSE,
        drop=drop,
    )


EMPTY_SLOT_RENDERS = tuple(
    dict.fromkeys(template.format(TEXT="") for _slot, template in corpus.CHANNEL_SLOT.values())
)


def test_pairing_inserts_nothing_but_the_payload(built: Path) -> None:
    for record in manifest(built):
        baseline = (built / record["baseline_file"]).read_text(encoding="utf-8")
        injected = (built / record["injected_file"]).read_text(encoding="utf-8")
        payload = record["payload"]
        assert payload and payload in injected and payload not in baseline

        stripped = injected.replace(payload, "")
        for empty in EMPTY_SLOT_RENDERS:
            stripped = stripped.replace(empty, "")
        injected_lines = [line for line in stripped.splitlines() if line.strip()]
        baseline_lines = [line for line in baseline.splitlines() if line.strip()]
        assert injected_lines == baseline_lines, record["id"]


def test_detected_case_changes_only_injection_evidence(built: Path) -> None:
    record = next(item for item in manifest(built) if item["id"] == "p01")
    base = _score(built, record, "baseline_file")
    injected = _score(built, record, "injected_file")
    stripped = _score(built, record, "injected_file", drop=corpus.ALLOWED_DELTA_CODES)

    assert injected.injection_codes, "a hidden instruction must be recorded as evidence"
    assert set(injected.codes - base.codes) <= corpus.ALLOWED_DELTA_CODES
    assert not base.codes - injected.codes
    assert injected.assessment.overall_risk > base.assessment.overall_risk
    assert stripped.assessment.overall_risk == base.assessment.overall_risk
    assert stripped.verdict == base.verdict
    for name, dimension in stripped.assessment.dimensions.items():
        assert dimension.risk_score == base.assessment.dimensions[name].risk_score


def test_visible_instruction_prose_is_not_read_as_hidden(built: Path) -> None:
    record = next(item for item in manifest(built) if item["id"] == "n11")
    html = (built / record["injected_file"]).read_text(encoding="utf-8")
    page = crawler.parse_html_page(
        html, record["url"], headers=corpus.HEADERS[record["body"]], engine="fixture_static"
    )
    quoted = corpus.BENIGN_TEXT["security_article"]
    assert "ignore previous instructions" in page.visible_text.lower()
    assert "ignore previous instructions" not in page.hidden_text.lower()
    assert "ignore previous instructions" not in page.html_comments.lower()
    run = _score(built, record, "injected_file")
    assert not run.injection_codes


def test_whole_corpus_satisfies_the_isolation_gate(report: dict) -> None:
    result = report
    hidden_pairs = len(CASES) - sum(
        1 for case in CASES.values() if case.channel == "visible_block"
    )
    assert result["passed"], result["gate"]
    assert result["corpus"]["cases"] == len(CASES)
    assert result["score_invariance"]["comparable_pairs"] == hidden_pairs
    assert result["score_invariance"]["exact_score_match_after_removal"] == hidden_pairs
    assert result["score_invariance"]["max_abs_risk_delta_after_removal"] == 0.0
    assert result["obedience_check"]["max_trust_point_gain_from_any_fixture"] == 0.0
    assert result["obedience_check"]["cases_reduced_in_overall_risk"] == 0
    assert result["injection_contribution"]["cases_verdict_relaxed_to_allow"] == 0
    assert result["detection"]["all"]["recall"] >= 0.8
    assert result["detection"]["all"]["precision"] >= 0.9


def test_obfuscated_instructions_are_missed_but_traced(report: dict) -> None:
    result = report
    obfuscated = [row for row in result["rows"] if row["subtype"] == "obfuscated"]
    assert obfuscated
    for row in obfuscated:
        assert row["obfuscation_trace"], row["id"]
    assert result["obfuscation_counterfactual"]["detected_as_is"] < len(obfuscated)
