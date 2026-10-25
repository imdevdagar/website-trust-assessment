from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest

from trustlens.research.candidates import (
    GATED_COLLECTION,
    MAIN_BANDS,
    build_main_manifest,
    parse_tranco_rows,
)


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _exclusion_file(tmp_path: Path) -> Path:
    path = tmp_path / "pilot.csv"
    _write_csv(
        path,
        ["url"],
        [{"url": "https://pilot-one.com/"}, {"url": "https://pilot-two.com/"}],
    )
    return path


def _manifest(
    tmp_path: Path,
    *,
    counts: dict[str, int] | None = None,
    reserve_counts: dict[str, int] | None = None,
    openphish_text: str | None = None,
    urlhaus_text: str | None = None,
) -> dict:
    tranco = "\n".join(
        [
            "rank,domain",
            "1,alpha.com",
            "2,beta.com",
            "3,gamma.com",
            "4,pilot-one.com",
            "50001,delta.net",
            "50002,epsilon.net",
            "50003,zeta.net",
        ]
    )
    openphish = openphish_text or "\n".join(
        [
            "https://scam-one.net/login?session=abc",
            "https://scam-two.net/verify",
            "https://pilot-one.com/login",
            "https://scam-one.net/other",
        ]
    )
    urlhaus = urlhaus_text or "\n".join(
        [
            "https://scam-three.net/",
            "https://download.example.org/file.exe",
            "https://scam-two.net/",
        ]
    )
    return build_main_manifest(
        tranco_text=tranco,
        tranco_meta={
            "source": "Tranco top-1M",
            "url": "https://tranco.invalid/top-1m.csv.zip",
            "source_date": "2026-10-20",
            "sha256": "0" * 64,
        },
        feeds=[
            {
                "text": openphish,
                "meta": {
                    "source": "OpenPhish public feed",
                    "source_date": "2026-10-20",
                    "sha256": "1" * 64,
                },
                "source": "openphish_public_feed",
                "candidate_family": "unclassified_feed",
                "html_only": True,
            },
            {
                "text": urlhaus,
                "meta": {
                    "source": "URLhaus online CSV",
                    "source_date": "2026-10-20",
                    "sha256": "2" * 64,
                },
                "source": "urlhaus_public_feed",
                "candidate_family": "malware_download",
                "html_only": True,
            },
        ],
        exclusion_paths=[_exclusion_file(tmp_path)],
        out_dir=tmp_path / "out",
        seed=5,
        counts=counts or {"established": 2, "tail": 1, "scam_feed": 2},
        reserve_counts=reserve_counts
        or {"established": 1, "tail": 1, "scam_feed": 1},
    )


def test_parse_tranco_rows_filters_and_bands() -> None:
    text = "\n".join(
        [
            "rank,domain",
            "1,alpha.com",
            "50000,beta.co.uk",
            "50001,gamma.net",
            "1000000,delta.org",
            "1000001,out-of-range.com",
            "2,8.8.8.8",
            "3,alpha.com",
            "not-a-rank,bad.com",
            "4,",
        ]
    )
    rows, stats = parse_tranco_rows(text)
    assert [domain for _, domain, _ in rows] == [
        "alpha.com",
        "beta.co.uk",
        "gamma.net",
        "delta.org",
    ]
    assert rows[0][2] == "http://alpha.com/"
    assert stats["unique_domains"] == 4
    assert stats["rejected"]["header"] == 1
    assert stats["rejected"]["rank_out_of_range"] == 1
    assert stats["rejected"]["ip_literal"] == 1
    assert stats["rejected"]["duplicate_domain"] == 1
    assert stats["rejected"]["malformed_rank"] == 1
    assert stats["rejected"]["missing_domain"] == 1
    assert MAIN_BANDS["established"] == (1, 50000)
    assert MAIN_BANDS["tail"] == (50001, 1000000)


def test_main_manifest_is_disjoint_gated_and_hashed(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    out = tmp_path / "out"
    assert manifest["selected"] == {"established": 2, "tail": 1, "scam_feed": 2}
    assert manifest["reserve"] == {"established": 1, "tail": 1, "scam_feed": 1}
    assert manifest["domains_total"] == 5
    assert manifest["safety"]["candidate_pages_fetched"] is False
    assert manifest["safety"]["gated_selected"] == 2
    assert manifest["safety"]["explicit_confirmation_required"] is True
    assert manifest["tranco"]["excluded_overlap_domains"] == 1
    assert manifest["feed_duplicates_across_sources"] == 1
    assert {feed["source"] for feed in manifest["feeds"]} == {
        "openphish_public_feed",
        "urlhaus_public_feed",
    }

    with (out / "main.csv").open(encoding="utf-8") as handle:
        selected = list(csv.DictReader(handle))
    with (out / "main_reserve.csv").open(encoding="utf-8") as handle:
        reserve = list(csv.DictReader(handle))
    assert len(selected) == 5
    assert len(reserve) == 3
    assert "label" not in selected[0]
    assert all("?" not in row["url"] and "#" not in row["url"] for row in selected)
    assert sum(row["collection_gate"] == GATED_COLLECTION for row in selected) == 2
    assert sum(row["stratum"] == "scam_feed" for row in selected) == 2
    assert {row["stratum"] for row in selected} == {"established", "tail", "scam_feed"}
    assert not {row["domain"] for row in selected} & {
        row["domain"] for row in reserve
    }
    assert not {row["domain"] for row in selected} & {"pilot-one.com", "pilot-two.com"}
    assert len({row["domain"] for row in selected + reserve}) == 8
    assert manifest["outputs"]["selected"]["sha256"] == hashlib.sha256(
        (out / "main.csv").read_bytes()
    ).hexdigest()
    assert manifest["outputs"]["reserve"]["rows"] == 3
    stored = json.loads((out / "main_manifest.json").read_text(encoding="utf-8"))
    assert stored["domains_total"] == 5
    assert "file.exe" not in (out / "main.csv").read_text(encoding="utf-8")
    assert manifest["feeds"][1]["rejected"]["non_html_download_path"] == 1


def test_main_manifest_refuses_shortfalls(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not enough distinct candidates"):
        _manifest(
            tmp_path,
            counts={"established": 10, "tail": 1, "scam_feed": 1},
            reserve_counts={"established": 0, "tail": 0, "scam_feed": 0},
        )


def test_main_manifest_refuses_to_overwrite(tmp_path: Path) -> None:
    _manifest(tmp_path)
    with pytest.raises(FileExistsError):
        _manifest(tmp_path)
