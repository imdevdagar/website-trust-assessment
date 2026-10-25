from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.factories import make_assessment
from trustlens.research import candidates
from trustlens.research import feed_labels as fl

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


def _source(
    name: str = "openphish_public_feed",
    urls: list[str] | None = None,
    *,
    age_hours: float = 1.0,
    max_age_days: int = 7,
) -> fl.FeedSource:
    retrieved = NOW - timedelta(hours=age_hours)
    return fl.FeedSource(
        name=name,
        text="\n".join(urls or ["https://Login-Verify.example.com/account"]),
        retrieved_at=retrieved.isoformat(timespec="seconds"),
        source_date=retrieved.date().isoformat(),
        sha256="a" * 64,
        url=f"https://feeds.example/{name}",
        max_age_days=max_age_days,
    )


def test_one_row_per_domain_with_feed_provenance() -> None:
    rows, stats = fl.build_feed_labels(
        [_source(urls=["https://alpha-one.com/login", "http://alpha-one.com/other", "https://beta-two.com/"])],
        now=NOW,
    )
    assert [row["domain"] for row in rows] == ["alpha-one.com", "beta-two.com"]
    assert all(row["label"] == "malicious" and row["confidence"] == "1.00" for row in rows)
    assert rows[0]["url"] in {"http://alpha-one.com/other", "https://alpha-one.com/login"}
    assert stats["labeled_domains"] == 2
    assert stats["sources"]["openphish_public_feed"]["accepted_entries"] == 3
    assert stats["stale_sources"] == []


def test_shared_domains_keep_every_source() -> None:
    rows, stats = fl.build_feed_labels(
        [
            _source("openphish_public_feed", ["https://shared-host.com/a"]),
            _source("urlhaus_public_feed", ["https://shared-host.com/b", "https://only-here.com/"]),
        ],
        now=NOW,
    )
    by_domain = {row["domain"]: row for row in rows}
    assert "openphish_public_feed@" in by_domain["shared-host.com"]["source"]
    assert "urlhaus_public_feed@" in by_domain["shared-host.com"]["source"]
    assert stats["multi_feed_domains"] == 1
    assert stats["labeled_domains"] == 2


def test_unsafe_and_excluded_entries_are_counted_not_silently_dropped() -> None:
    rows, stats = fl.build_feed_labels(
        [
            _source(
                urls=[
                    "https://good-host.com/",
                    "ftp://wrong-scheme.test/",
                    "https://192.0.2.1/payload",
                    "https://93.184.216.34/payload",
                    "https://blocked-host.com/mail/victim@example.com",
                ]
            )
        ],
        excluded_domains={"good-host.com"},
        now=NOW,
    )
    assert rows == []
    reasons = " ".join(stats["rejections"])
    assert "excluded_overlap" in reasons
    assert "reserved IPs are not crawled" in reasons
    assert "IP-literal" in reasons
    assert stats["rejection_total"] == 5


def test_stale_feed_is_refused_rather_than_labelled() -> None:
    _, stats = fl.build_feed_labels([_source(age_hours=9999, max_age_days=7)], now=NOW)
    assert stats["stale_sources"] == ["openphish_public_feed"]
    assert stats["sources"]["openphish_public_feed"]["age_state"] == "stale"


def test_local_snapshot_without_a_timestamp_is_flagged_unknown_age(tmp_path: Path) -> None:
    snapshot = tmp_path / "feed.txt"
    snapshot.write_text("https://alpha-one.com/\n", encoding="utf-8")
    text, meta = fl.read_feed(snapshot, name="openphish_public_feed")
    assert meta["fetch_mode"] == "local_file" and meta["retrieved_at"] == ""
    _, stats = fl.build_feed_labels(
        [fl.FeedSource(name="openphish_public_feed", text=text, max_age_days=7)], now=NOW
    )
    assert stats["sources"]["openphish_public_feed"]["age_state"] == "unknown_age"
    assert stats["stale_sources"] == []


def test_missing_snapshot_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        fl.read_feed(tmp_path / "absent.txt", name="openphish_public_feed")


def test_saved_snapshot_path_is_carried_into_the_provenance(tmp_path: Path) -> None:
    snapshot = tmp_path / "openphish_abc.txt"
    snapshot.write_text("https://alpha-one.com/\n", encoding="utf-8")
    text, meta = fl.read_feed(snapshot, name="openphish_public_feed")
    source = fl.FeedSource(name="openphish_public_feed", text=text, retrieved_at="")
    assert fl.with_snapshot(source, snapshot).snapshot_file == str(snapshot)
    _, stats = fl.build_feed_labels(
        [fl.with_snapshot(source, snapshot)], now=NOW
    )
    assert stats["sources"]["openphish_public_feed"]["snapshot_file"] == str(snapshot)


def test_urlhaus_urls_are_read_from_the_headerless_csv() -> None:
    text = (
        "# comment\n"
        '"1","2026-10-01 00:00:00","https://pay-host.com/invoice.exe","online","2026-10-19",'
        '"exe","phishing","https://urlhaus.example/1","analyst"\n'
    )
    assert fl.urlhaus_urls(text) == ["https://pay-host.com/invoice.exe"]


def test_write_and_read_round_trip(tmp_path: Path) -> None:
    rows, _ = fl.build_feed_labels([_source(urls=["https://alpha-one.com/"])], now=NOW)
    path = tmp_path / "labels.csv"
    fl.write_labels(rows, path)
    assert fl.load_feed_label_domains(path) == {"alpha-one.com"}
    with pytest.raises(FileNotFoundError):
        fl.load_feed_label_domains(tmp_path / "nope.csv")


def test_no_sources_is_rejected() -> None:
    with pytest.raises(ValueError):
        fl.build_feed_labels([], now=NOW)


def test_leakage_check_passes_on_clean_assessments(tmp_path: Path) -> None:
    export = tmp_path / "assessments.jsonl"
    assessments = [make_assessment("alpha-one.com", malicious=True), make_assessment("beta-two.com")]
    export.write_text(
        "\n".join(assessment.model_dump_json() for assessment in assessments) + "\n",
        encoding="utf-8",
    )
    result = fl.assert_no_label_leakage([export], {"alpha-one.com", "nope-host.com"})
    assert result["passed"] is True
    assert result["assessments"] == 2
    assert result["leaked_assessments"] == 0


def test_leakage_check_fails_when_a_verdict_reached_the_score(tmp_path: Path) -> None:
    assessment = make_assessment(
        "leaky-host.com",
        malicious=True,
        extra_evidence=None,
        meta_extra={"floors": ["known_malicious_label"]},
    )
    export = tmp_path / "assessments.jsonl"
    export.write_text(assessment.model_dump_json() + "\n", encoding="utf-8")
    result = fl.assert_no_label_leakage([export], {"leaky-host.com"})
    assert result["passed"] is False
    assert result["leaked_assessments"] == 1
    assert any(reason.startswith("floor:") for reason in result["leaked_examples"][0]["reasons"])


def test_policy_block_states_the_label_meaning() -> None:
    _, stats = fl.build_feed_labels([_source()], now=NOW)
    assert "not a human trust judgement" in stats["policy"]["label_meaning"]
    assert stats["policy"]["unreachable_pages"] == (
        "a feed domain that cannot be assessed is dropped, never labelled benign"
    )
    assert json.dumps(stats)


def _write_labels(path: Path, urls: list[str]) -> Path:
    rows, _ = fl.build_feed_labels([_source(urls=urls)], now=NOW)
    fl.write_labels(rows, path)
    return path


def test_feed_candidates_are_batched_and_every_row_is_gated(tmp_path: Path) -> None:
    labels = _write_labels(
        tmp_path / "labels.csv",
        [f"https://host-{index}.com/login" for index in range(5)],
    )
    manifest = candidates.build_feed_candidates(
        labels_path=labels, out_dir=tmp_path, seed=42, batch_size=2
    )
    assert manifest["candidates"] == 5
    assert [batch["candidates"] for batch in manifest["batches"]] == [2, 2, 1]
    assert (tmp_path / "feed_manifest.json").exists()
    rows = [
        row
        for batch in manifest["batches"]
        for row in csv.DictReader(Path(batch["file"]).open(encoding="utf-8", newline=""))
    ]
    assert {row["collection_gate"] for row in rows} == {candidates.GATED_COLLECTION}
    assert {row["verification_required"] for row in rows} == {"false"}
    assert len({row["url"] for row in rows}) == 5


def test_plan_is_reproducible_from_the_same_seed(tmp_path: Path) -> None:
    labels = _write_labels(
        tmp_path / "labels.csv",
        ["https://alpha-one.com/login", "https://beta-two.com/x", "https://gamma-three.io/"],
    )
    first = candidates.build_feed_candidates(
        labels_path=labels, out_dir=tmp_path / "a", seed=42
    )
    second = candidates.build_feed_candidates(
        labels_path=labels, out_dir=tmp_path / "b", seed=42
    )
    assert [batch["sha256"] for batch in first["batches"]] == [
        batch["sha256"] for batch in second["batches"]
    ]


def test_payload_urls_crawl_the_domain_root_not_the_file(tmp_path: Path) -> None:
    labels = _write_labels(
        tmp_path / "labels.csv",
        ["https://drop-one.com/payload.exe", "https://page-two.com/login"],
    )
    manifest = candidates.build_feed_candidates(labels_path=labels, out_dir=tmp_path, seed=7)
    assert manifest["payload_urls_replaced_by_domain_root"] == 1
    rows = list(
        csv.DictReader(
            Path(manifest["batches"][0]["file"]).open(encoding="utf-8", newline="")
        )
    )
    by_domain = {row["domain"]: row["url"] for row in rows}
    assert by_domain["drop-one.com"] == "https://drop-one.com/"
    assert by_domain["page-two.com"] == "https://page-two.com/login"


def test_feed_candidates_reject_a_bad_batch_size(tmp_path: Path) -> None:
    labels = _write_labels(tmp_path / "labels.csv", ["https://alpha-one.com/"])
    with pytest.raises(ValueError):
        candidates.build_feed_candidates(labels_path=labels, out_dir=tmp_path, seed=1, batch_size=500)
    with pytest.raises(FileNotFoundError):
        candidates.build_feed_candidates(labels_path=tmp_path / "absent.csv", out_dir=tmp_path, seed=1)


def _write_human(path: Path, rows: list[tuple[str, str]]) -> Path:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["sample_id", "domain", "label", "source"])
        writer.writeheader()
        for index, (domain, label) in enumerate(rows, start=1):
            writer.writerow(
                {"sample_id": f"s_{index}", "domain": domain, "label": label, "source": "batch"}
            )
    return path


def test_cross_check_reports_disagreement_without_moving_labels(tmp_path: Path) -> None:
    labels = _write_labels(
        tmp_path / "labels.csv",
        ["https://listed-mal.com/x", "https://called-susp.com/y", "https://gone-benign.dev/"],
    )
    human = _write_human(
        tmp_path / "human.csv",
        [
            ("listed-mal.com", "malicious"),
            ("called-susp.com", "suspicious"),
            ("gone-benign.dev", "benign"),
            ("never-fed.org", "malicious"),
            ("blank-row.org", ""),
        ],
    )
    result = fl.cross_check_human_labels([human], labels)
    assert result["human_domains"] == 4
    assert result["overlap"] == 3
    assert result["human_label_by_feed_membership"]["malicious"] == {
        "in_feed": 1,
        "not_in_feed": 1,
    }
    coverage = result["human_malicious_still_in_feed"]
    assert (coverage["human_malicious_domains"], coverage["still_listed"], coverage["share"]) == (
        2,
        1,
        0.5,
    )
    assert [item["domain"] for item in result["human_not_malicious_but_feed_malicious"]] == [
        "called-susp.com",
        "gone-benign.dev",
    ]
    assert result["cohens_kappa_interpretable"] is False


def test_cross_check_rejects_a_missing_file(tmp_path: Path) -> None:
    labels = _write_labels(tmp_path / "labels.csv", ["https://alpha-one.com/"])
    with pytest.raises(FileNotFoundError):
        fl.cross_check_human_labels([tmp_path / "absent.csv"], labels)


def test_eval_labels_join_assessments_with_feed_membership(tmp_path: Path) -> None:
    labels = _write_labels(
        tmp_path / "labels.csv",
        [
            "https://listed-mal.com/x",
            "https://never-collected.com/y",
        ],
    )
    export = tmp_path / "assessments.jsonl"
    assessments = [make_assessment("listed-mal.com"), make_assessment("clean-host.org")]
    export.write_text(
        "\n".join(assessment.model_dump_json() for assessment in assessments) + "\n",
        encoding="utf-8",
    )
    rows, stats = fl.derive_evaluation_labels([export], labels, exclude_domains={"human-only.org"})
    assert {row["domain"]: row["label"] for row in rows} == {
        "clean-host.org": "benign",
        "listed-mal.com": "malicious",
    }
    assert stats["labels"] == {"benign": 1, "malicious": 1}
    assert stats["feed_domains_without_an_assessment"] == 1
    assert "absent from both feeds" in stats["benign_meaning"]
    assert rows[0]["source"] in {"absent_from_feeds", "feed_membership"}


def test_eval_labels_never_override_a_frozen_human_label(tmp_path: Path) -> None:
    labels = _write_labels(tmp_path / "labels.csv", ["https://listed-mal.com/x"])
    export = tmp_path / "assessments.jsonl"
    assessments = [make_assessment("listed-mal.com"), make_assessment("human-labelled.org")]
    export.write_text(
        "\n".join(assessment.model_dump_json() for assessment in assessments) + "\n",
        encoding="utf-8",
    )
    rows, stats = fl.derive_evaluation_labels(
        [export], labels, exclude_domains={"listed-mal.com", "unknown.org"}
    )
    assert [row["domain"] for row in rows] == ["human-labelled.org"]
    assert stats["excluded_human_labelled_domains"] == 1
