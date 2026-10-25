from __future__ import annotations

import asyncio
import csv
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from trustlens.cli import _batch, _read_batch_items, _split_gated_batch_items
from trustlens.research import candidates
from trustlens.research.candidates import (
    GATED_COLLECTION,
    Candidate,
    build_round2_manifest,
    load_curated_candidates,
    load_pilot_domains,
    parse_feed_candidates,
    sanitize_candidate_url,
    select_round2_candidates,
)
from trustlens.security import UnsafeURLError


def _candidate(stratum: str, domain: str) -> Candidate:
    return Candidate(
        candidate_id=f"r2_{domain}",
        url=f"https://{domain}/",
        domain=domain,
        stratum=stratum,
        candidate_family="synthetic",
        source="synthetic",
        source_date="2026-10-20",
        notes="Synthetic test candidate.",
        collection_gate=(
            GATED_COLLECTION if stratum == "scam_feed" else candidates.STANDARD_COLLECTION
        ),
        verification_required="true" if stratum == "scam_feed" else "false",
        rank=f"{stratum}:{domain}",
    )


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _curated_row(domain: str, stratum: str) -> dict[str, str]:
    return {
        "url": f"https://{domain}/",
        "stratum": stratum,
        "candidate_family": "synthetic",
        "source": "synthetic",
        "source_date": "2026-10-20",
        "notes": "Synthetic test candidate.",
    }


def test_sanitize_candidate_url_strips_query_and_rejects_unsafe_values() -> None:
    url, domain = sanitize_candidate_url(
        "https://example.com/verify?email=victim%40example.com#fragment"
    )
    assert url == "https://example.com/verify"
    assert domain == "example.com"
    assert sanitize_candidate_url("https://login.example.co.uk/path")[1] == "example.co.uk"
    with pytest.raises(UnsafeURLError):
        sanitize_candidate_url("https://user:pass@example.com/login")
    with pytest.raises(UnsafeURLError):
        sanitize_candidate_url("https://example.com:8443/login")
    with pytest.raises(UnsafeURLError):
        sanitize_candidate_url("http://8.8.8.8/login")
    with pytest.raises(UnsafeURLError):
        sanitize_candidate_url("https://example.com/reset/victim@example.com")


def test_feed_parser_filters_shared_hosts_overlap_and_pii() -> None:
    text = "\n".join(
        [
            "https://evil.weebly.com/login?session=1",
            "https://rebrand.ly/abc",
            "https://www.python.org/",
            "http://8.8.8.8/login",
            "https://example.com/reset/victim@example.com",
            "https://login.bank-secure.net/login?session=abc",
            "https://login.bank-secure.net/other?session=def",
            "not a url",
        ]
    )
    feed, stats = parse_feed_candidates(
        text,
        seed=3,
        source_date="2026-10-20",
        excluded_domains={"python.org"},
    )
    assert len(feed) == 1
    assert feed[0].domain == "bank-secure.net"
    assert feed[0].collection_gate == GATED_COLLECTION
    assert feed[0].verification_required == "true"
    assert "?" not in feed[0].url
    assert stats["lines"] == 8
    assert stats["unique_usable_domains"] == 1
    assert stats["rejected"]["shared_or_multitenant_domain"] == 2
    assert stats["rejected"]["excluded_overlap"] == 1
    assert stats["rejected"]["ip_literal"] == 1
    assert stats["rejected"]["email_in_path"] == 1
    assert stats["rejected"]["unsafe_or_malformed"] == 1


def test_selection_is_deterministic_and_reserve_is_disjoint() -> None:
    curated = [
        _candidate("ambiguous", f"ambiguous{index}.com") for index in range(3)
    ] + [_candidate("benign_control", f"benign{index}.com") for index in range(3)]
    feed = [_candidate("scam_feed", f"feed{index}.com") for index in range(5)]
    counts = {"scam_feed": 2, "ambiguous": 2, "benign_control": 2}
    reserve_counts = {"scam_feed": 2, "ambiguous": 1, "benign_control": 1}
    selected_a, reserve_a, _ = select_round2_candidates(
        curated, feed, counts=counts, reserve_counts=reserve_counts
    )
    selected_b, reserve_b, _ = select_round2_candidates(
        list(reversed(curated)),
        list(reversed(feed)),
        counts=counts,
        reserve_counts=reserve_counts,
    )
    assert [item.domain for item in selected_a] == [item.domain for item in selected_b]
    assert [item.domain for item in reserve_a] == [item.domain for item in reserve_b]
    assert len(selected_a) == 6
    assert len(reserve_a) == 4
    assert not {item.domain for item in selected_a} & {
        item.domain for item in reserve_a
    }


def test_build_manifest_marks_feed_candidates_gated_and_omits_raw_feed(
    tmp_path: Path,
) -> None:
    curated_path = tmp_path / "curated.csv"
    pilot_path = tmp_path / "pilot.csv"
    rows = [
        _curated_row(f"ambiguous{index}.com", "ambiguous") for index in range(3)
    ] + [_curated_row(f"benign{index}.com", "benign_control") for index in range(3)]
    _write_csv(
        curated_path,
        ["url", "stratum", "candidate_family", "source", "source_date", "notes"],
        rows,
    )
    _write_csv(pilot_path, ["url"], [{"url": "https://round1.com/"}])
    feed_text = "\n".join(
        f"https://feed{index}-scam.net/login?session=unique-feed-path-{index}"
        for index in range(4)
    )
    manifest = build_round2_manifest(
        feed_text=feed_text,
        feed_meta={
            "source": "synthetic feed",
            "url": "https://feed.invalid/list",
            "final_url": "https://feed.invalid/list",
            "retrieved_at": "2026-10-20T00:00:00+00:00",
            "source_date": "2026-10-20",
            "http_date": "",
            "sha256": "0" * 64,
        },
        curated_path=curated_path,
        pilot_path=pilot_path,
        out_dir=tmp_path / "out",
        seed=4,
        counts={"scam_feed": 2, "ambiguous": 2, "benign_control": 2},
        reserve_counts={"scam_feed": 2, "ambiguous": 1, "benign_control": 1},
    )
    out = tmp_path / "out"
    assert manifest["selected"] == {"scam_feed": 2, "ambiguous": 2, "benign_control": 2}
    assert manifest["safety"]["candidate_pages_fetched"] is False
    assert manifest["safety"]["gated_selected"] == 2
    assert manifest["feed"]["unique_usable_domains"] == 4
    with (out / "round2.csv").open(encoding="utf-8") as handle:
        selected = list(csv.DictReader(handle))
    assert len(selected) == 6
    assert sum(row["collection_gate"] == GATED_COLLECTION for row in selected) == 2
    assert all("?" not in row["url"] for row in selected)
    with (out / "round2_reserve.csv").open(encoding="utf-8") as handle:
        reserve = list(csv.DictReader(handle))
    assert len(reserve) == 4
    assert not {row["domain"] for row in selected} & {row["domain"] for row in reserve}
    manifest_text = (out / "round2_manifest.json").read_text(encoding="utf-8")
    assert "unique-feed-path" not in manifest_text
    assert GATED_COLLECTION not in manifest_text or "gate_value" in manifest_text
    assert json.loads(manifest_text)["outputs"]["pilot"]["rows"] == 6


def test_curated_source_cannot_contain_labels(tmp_path: Path) -> None:
    path = tmp_path / "curated.csv"
    _write_csv(
        path,
        ["url", "stratum", "candidate_family", "source", "source_date", "notes", "label"],
        [{**_curated_row("labeled.example", "benign_control"), "label": "benign"}],
    )
    with pytest.raises(ValueError, match="must not contain labels"):
        load_curated_candidates(path, seed=1)


def test_round2_manifest_artifact_contract() -> None:
    root = Path(__file__).resolve().parents[1]
    candidates_path = root / "data" / "candidates" / "round2.csv"
    reserve_path = root / "data" / "candidates" / "round2_reserve.csv"
    manifest_path = root / "data" / "candidates" / "round2_manifest.json"
    if not candidates_path.exists():
        pytest.skip("Round 2 manifest has not been generated in this checkout")
    with candidates_path.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    with reserve_path.open(encoding="utf-8") as handle:
        reserve = list(csv.DictReader(handle))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert len(rows) == 36
    assert len({row["domain"] for row in rows}) == 36
    assert len({row["candidate_id"] for row in rows}) == 36
    assert {row["stratum"] for row in rows} == {"scam_feed", "ambiguous", "benign_control"}
    assert sum(row["stratum"] == "scam_feed" for row in rows) == 20
    assert sum(row["collection_gate"] == GATED_COLLECTION for row in rows) == 20
    assert all("?" not in row["url"] and "#" not in row["url"] for row in rows)
    assert "label" not in rows[0]
    assert not {row["domain"] for row in rows} & load_pilot_domains(
        root / "data" / "candidates" / "pilot.csv"
    )
    assert not {row["domain"] for row in rows} & {row["domain"] for row in reserve}
    assert manifest["selected"] == {"scam_feed": 20, "ambiguous": 8, "benign_control": 8}
    assert manifest["domains_total"] == 36
    assert manifest["safety"]["candidate_pages_fetched"] is False
    assert manifest["safety"]["explicit_confirmation_required"] is True
    digest = hashlib.sha256(candidates_path.read_bytes()).hexdigest()
    assert manifest["outputs"]["pilot"]["sha256"] == digest
    assert manifest["outputs"]["reserve"]["rows"] == len(reserve)


def test_batch_records_honor_gate_without_visiting_pages(tmp_path: Path) -> None:
    path = tmp_path / "candidates.csv"
    _write_csv(
        path,
        ["url", "collection_gate"],
        [
            {"url": "https://safe.example/", "collection_gate": ""},
            {
                "url": "https://gated.example/",
                "collection_gate": GATED_COLLECTION,
            },
        ],
    )
    items = _read_batch_items(path)
    allowed, gated = _split_gated_batch_items(items, allow_gated=False)
    assert [item["url"] for item in allowed] == ["https://safe.example/"]
    assert [item["url"] for item in gated] == ["https://gated.example/"]
    allowed_all, gated_none = _split_gated_batch_items(items, allow_gated=True)
    assert len(allowed_all) == 2
    assert gated_none == []


def test_batch_refuses_an_all_gated_file_before_assessment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "gated.csv"
    _write_csv(
        path,
        ["url", "collection_gate"],
        [{"url": "https://gated.example/", "collection_gate": GATED_COLLECTION}],
    )
    args = SimpleNamespace(
        file=str(path),
        action="browse",
        out="",
        full=False,
        resume=False,
        force=False,
        limit=0,
        allow_gated=False,
    )
    assert asyncio.run(_batch(args)) == 1
    captured = capsys.readouterr()
    assert "Safety gate: skipped 1 candidate" in captured.out
    assert "no URLs found" in captured.err
