# feed_v3 large-scale evaluation protocol

Version 1.0 — 2026-10-26

Status: active for the feed_v3 evaluation. This addendum does not modify `feed_v2`, the frozen
human labels, or any result already reported from them. Retrieval timestamps are recorded in UTC
(2026-10-25); the approval and the local session date are 2026-10-26.

Change log:

- **1.0 (2026-10-26)** — first large-scale set. PhishTank replaces URLhaus, which retired. Targets
  5,000 usable domains with balanced positive and negative candidate pools, positive and negative
  reserves, and a pre-collection verification gate.
- **1.1 (2026-10-26)** — pilot-informed collection amendments, recorded before the main run: one
  root-URL retry for unresolved positives, and a fixed-ranking top-up rule if the registered
  reserves do not reach 2,500 usable positives. Neither adds a domain outside the 9,764-domain
  positive pool or changes a label.

This document extends [main-dataset-protocol.md](main-dataset-protocol.md) v2.2. Everything in that
document about leakage controls, the runtime label store, gated collection, SSRF checks, grouped
splits, and reporting language remains in force. Where the two differ, this addendum governs only
the feed_v3 evaluation.

---

## 1. Purpose

`feed_v2` has 830 samples over 826 domains, with a 123-sample test split. That is enough to show a
large separation between feature groups, but its confidence intervals are wide and it cannot
support claims about rarer error modes. feed_v3 exists to test whether the feed_v2 conclusions hold
on an independent set roughly six times larger.

The target is **5,000 usable registrable domains**, about 2,500 per class. Candidate pools are
oversampled to survive unreachable, parked, login-only, non-HTML, and decaying pages.

feed_v3 is an **independent evaluation set**, not an extension of `feed_v2`. Every domain in
`feed_v2`, in the earlier feed labels, in the frozen human sheets, and in every earlier candidate
manifest is excluded before sampling.

## 2. Label source

The positive class is public abuse-feed membership at the recorded retrieval time. The negative
class is absence from those feeds in the stated sampling frame. Neither is a human verdict.

### 2.1 PhishTank online-valid

- URL: `https://data.phishtank.com/data/online-valid.csv`. The endpoint redirected to a signed CDN
  object named `verified_online.csv`; the redirect target is recorded without its query string and
  the raw body is snapshotted.
- Only rows with `verified = yes` **and** `online = yes` are read. A row that is not both is not a
  positive.
- Retrieval 2026-10-25T18:47:30Z. Raw CSV: 56,210 data rows, 56,207 verified-and-online URLs,
  SHA-256 `9957e00f7484…`.
- After URL sanitising: 9,765 unique registrable domains. 41 domains reporting at least 50 distinct
  URLs were excluded as platforms. 40 further domains were already in prior work.
- URL-level rejections: 77 IP literals, 9 non-standard ports, 2 whitespace/control strings, 8
  credential-bearing URLs, 2 email-in-path URLs, and 21,661 URLs on shared or multi-tenant hosts.

### 2.2 OpenPhish public feed

- URL: `https://openphish.com/feed.txt`, which redirected to the project's GitHub raw feed.
- Retrieval 2026-10-25T18:47:31Z. 300 URLs, 16,100 bytes, SHA-256 `cac0b89f7e7c…`.
- After shared-host and prior-work filters: 108 accepted URL entries.
- OpenPhish contributes 80 domains that PhishTank did not list; 9 domains appear in both feeds. The
  merged label file has **9,764 domains**: 9,675 PhishTank-only, 80 OpenPhish-only, 9 in both.

### 2.3 Tranco top-1M (negative sampling frame)

- URL: `https://tranco-list.eu/top-1m.csv.zip`, daily list retrieved 2026-10-25T18:47:38Z,
  SHA-256 `68f9b0fda011…`.
- 1,000,000 lines, 999,999 unique domains (one duplicate rejected). Rank is a sampling frame only;
  it is never a feature and never a label.
- 10,952 domains excluded before sampling: the full 9,764-domain positive pool plus 1,188
  prior-work domains, which are disjoint. 998,505 rows remain.

### 2.4 URLhaus retirement

The URLhaus `csv_online`, `csv`, `csv_recent`, and `json_online` endpoints all returned **HTTP 410
Gone** on 2026-10-25, with no usable body. feed_v3 therefore uses no URLhaus data. This is a source
retirement, not a redefinition of the `feed_v2` labels, which stay frozen as retrieved on
2026-10-20.

### 2.5 Label meaning

- Positive: the domain had at least one URL listed by PhishTank as verified and online, or by
  OpenPhish, at retrieval. This reports phishing infrastructure; it is not a per-page trust verdict.
- Negative: the domain was absent from both feeds at retrieval and was sampled from Tranco. It is
  **not verified clean**. A clean domain that nobody reported is labelled negative, which biases
  the negative class toward established, popular domains.
- Labels are domain-level. The unit of analysis is the registrable domain.

## 3. Filters and independence

Candidate construction reads metadata only and never opens a page. `scripts/feed_v3_build.py`
applies:

- URL structure checks: http/https only, no credentials, no non-standard ports, no IP literals, no
  internal or private hosts, no email addresses in the path, and a public suffix in the bundled PSL.
- Shared-host and multi-tenant exclusion: the 130-domain platform list in
  `website_trust_assessment/research/candidates.py`, plus any feed domain reporting at least 50
  distinct URLs.
- Prior-work exclusion: 1,188 domains from 24 artifacts — the `feed_v2` dataset, the feed_v1 label
  file, all five frozen human sheets, and every earlier candidate manifest.
- Positive/negative and selected/reserve disjointness, asserted before collection.

The full positive **pool** (all 9,764 domains), not just the sampled positives, is excluded from the
Tranco negatives. This prevents a reported phishing domain from entering the negative class because
its particular sampled URL happened to be missed.

## 4. Sampling

Ranking within the positive pool is `sha256("feed_v3-positive:42:" + domain)`, ascending. Tranco
candidates use the existing rank-band selector with seed 42.

| Group | Frame | Selected | Reserve | Batches | Gate |
| --- | --- | ---: | ---: | ---: | --- |
| Positive (`feed_batch_XX.csv`) | PhishTank + OpenPhish | 3,000 | 1,500 | 30 + 15 | Gated |
| Negative (`neg_XX.csv`) | Tranco rank 1–50,000 (`established`) | 1,600 | 400 | 16 + 4 | Standard |
| Negative (`neg_XX.csv`) | Tranco rank 50,001–1,000,000 (`tail`) | 1,400 | 600 | 14 + 6 | Standard |
| **Total candidates** | | **6,000** | **2,500** | **85** | |

Every batch has at most 100 rows. Reserves are crawled only if the selected batches fall short of
2,500 usable domains in that class. The reserve choice is fixed by the same ranking before any
crawl, so top-up is not opportunistic.

## 5. Collection contract

Collection uses the shipped crawler with the existing safety rules:

- `browse` action only; no forms, no file downloads, no script-driven navigation.
- SSRF and public-IP validation stay enabled. Loopback and private-address crawling is never
  allowed, including for this set.
- Positive batches are marked
  `collection_gate=malicious_page_requires_explicit_confirmation`. The batch command refuses to open
  them without `--allow-gated`. The 2026-10-26 approval recorded in
  `data/candidates/feed_v3/collection_approval.json` covers this candidate set only.
- Each batch is at most 100 candidates and is run with `--full --resume`. Batches may run in waves of
  up to three concurrent processes (`FEED_V3_WORKERS`), each writing its own export and its own log;
  the batch size, gate, and safety rules are unchanged by concurrency. A failed domain is recorded
  with its error and is never relabelled benign.
- The selected and reserve batches are the 2026-10-26 approved scope. The fixed-ranking top-up is
  pre-registered in `collection_amendment_01.json` and draws only from the same already-retrieved
  pool; it adds no source, class, or domain outside that pool. Any other candidate needs fresh
  approval.

Commands:

```bash
# positive batch (gated; requires the recorded approval)
python -m website_trust_assessment.cli batch \
  data/candidates/feed_v3/feed_batch_01.csv \
  --out data/exports/feed_v3/feed_batch_01.jsonl --full --resume --allow-gated

# negative batch (standard safety rules)
python -m website_trust_assessment.cli batch \
  data/candidates/feed_v3/negatives/neg_01.csv \
  --out data/exports/feed_v3/neg_01.jsonl --full --resume

# positive reserve, only if needed
python -m website_trust_assessment.cli batch \
  data/candidates/feed_v3/reserve/feed_reserve_01.csv \
  --out data/exports/feed_v3/feed_reserve_01.jsonl --full --resume --allow-gated
```

A pilot of one positive and one negative batch is run first to measure yield, wall-clock time, DNS
failure rate, and disk growth before the full run.

### 5.1 Pilot result and root-URL retry

The 100-candidate positive pilot produced 45 usable domains (42.5%) from 106 export rows; the other
61 rows failed with `Could not resolve hostname`. The first 10 negatives produced 9/10 usable. Public
resolvers returned NXDOMAIN for the failed positive hosts, so the loss is takedown, not local DNS
filtering. Many failures were phishing subdomains whose registrable root still resolved.

Rule, fixed before the main run: when a positive candidate's recorded URL fails, one retry is made
against `scheme://registrable-domain/`, preserving the original scheme. The domain, its feed label,
and the gated marker are unchanged. The retry is a separate batch under
`data/exports/feed_v3/retry/` and is recorded in `collection_amendment_01.json`. Negatives already
use the registrable root and are not retried this way.

### 5.2 Yield contingency

At the pilot rate the selected positives plus reserves yield about 2,000 usable domains, so the
registered contingency is expected to run. If they yield fewer than 2,500 usable positives, the run
continues down the **fixed** positive ranking (`sha256` order chosen before collection, recorded in
`data/labels/feed_v3/topup_selection.json`) and crawls the next candidates from the same 9,764-domain
pool, in batches of at most 100, until 2,500 usable positives or the pool is exhausted. This top-up is
pre-registered in `collection_amendment_01.json` and is covered by the 2026-10-26 approval: it adds no
new source and no new domain outside the pool, keeps the gate and every safety rule, and does not
alter any label. Only phishing takedown, not a change of target, motivates it. Top-up batches carry
the `feed_topup_` prefix so the paper can report how many usable positives the selected set, the
reserves, and the top-up each supplied.

## 6. Pre-collection verification

`python scripts/feed_v3_build.py --verify` re-checks the manifests without fetching anything and
writes `data/labels/feed_v3/validation.json`. It asserts:

1. every batch file exists and matches its recorded SHA-256, row count, and domain count;
2. every URL re-passes the sanitising checks, matches its recorded domain, is canonical, and is not
   an IP literal;
3. every positive row carries the gated marker, every negative row the standard marker;
4. every positive domain appears in `labels.csv` as `malicious`;
5. positive, positive-reserve, negative, and negative-reserve sets are pairwise disjoint;
6. none of those sets intersects the 41 platform domains or the 1,188 prior-work domains;
7. no negative or negative-reserve domain is in the 9,764-domain positive pool;
8. the approval record hashes still match the manifests it approved.

The build is reproducible from the recorded snapshots:

```bash
PYTHONPATH=. python scripts/feed_v3_build.py --offline   # replay snapshots, then verify
PYTHONPATH=. python scripts/feed_v3_build.py --verify    # verify existing artifacts only
```

The verified state at approval time: 9,764 labels, 3,000 + 1,500 positive candidates, 3,000 + 1,000
negative candidates, 85 batches, and zero overlaps.

## 7. Leakage check and dataset build

Collection integrity is recorded first:

```bash
python scripts/feed_v3_outcome.py            # data/candidates/feed_v3/collection_outcome.json
python scripts/feed_v3_gate_compliance.py    # data/research/gate_compliance_feed_v3.json
```

The outcome file reports usable domains by approval group (selected, reserve, top-up, negative),
retry recoveries, and every failure reason with its count. The gate check asserts that every scored
positive row maps to a gated candidate and that no negative export contains a gated row.

The label unit is the candidate's registrable domain, so a crawl that lands on a different
registrable domain is not a sample for that label: it describes the redirect target. Such rows are
excluded rather than relabelled. The pilot snapshot had 9 of 180 positive and 25 of 237 negative
scored rows on a different final domain, including redirects to `google.com`, `walmart.com`, and
`yahoo.com`. `scripts/feed_v3_filter_exports.py` writes
`data/exports/feed_v3/analysis/positive.jsonl` and `negative.jsonl`, keeps only same-domain rows,
and records every exclusion with its reason in `analysis/exclusions.json` (negative target domains
are hashed). The primary dataset, labels, profile, and error analysis are built from those analysis
files; leakage and gate checks still read the raw exports.

Before training, `feed-check` must pass over every collected assessment, including the root-retry
exports:

```bash
python -m website_trust_assessment.cli research feed-check \
  --labels data/labels/feed_v3/labels.csv \
  --assessments data/exports/feed_v3/*.jsonl data/exports/feed_v3/retry/*.jsonl \
  --out data/labels/feed_v3/leakage_check.json
```

The feed label file is **never** loaded into the runtime `domain_labels` store. The store is the
only path by which a stored verdict can reach scoring, so importing the feed would leak the target.

The evaluation label file is produced by joining collected assessments with feed membership, using
the same command as feed_v2:

```bash
python -m website_trust_assessment.cli research feed-eval-labels \
  --labels data/labels/feed_v3/labels.csv \
  --assessments data/exports/feed_v3/*.jsonl data/exports/feed_v3/retry/*.jsonl \
  --out data/labels/feed_v3/eval_labels.csv
```

Then the dataset is built with a domain-grouped split:

```bash
python -m website_trust_assessment.cli research dataset \
  --assessments data/exports/feed_v3/*.jsonl data/exports/feed_v3/retry/*.jsonl \
  --labels data/labels/feed_v3/eval_labels.csv \
  --out data/datasets/feed_v3 --ratios 0.7,0.15,0.15 --seed 42
```

`scripts/feed_v3_build.sh` runs all of the above in order, then trains the primary run and a
seed-43 sensitivity run, profiles the dataset, and writes the test-split error analysis.

## 8. Analysis plan

The primary comparison is unchanged: feature group `signals` versus `url` on domain-grouped test
AUROC and AUPRC. Secondary outputs: `page`-only and `all` groups, the logistic hybrid, HistGradientBoosting,
calibration (ECE and reliability curve), bootstrap confidence intervals, and the full confusion
matrix at the shipped decision thresholds.

`feed_v2` remains the frozen artifact reported in the current manuscript. feed_v3 is reported as an
independent replication at larger scale. Results are compared descriptively; they are not pooled
with feed_v2 and do not retroactively change it. The H4 injection corpus is unaffected.

Feed-label churn is a known limitation. A second retrieval for feed_v3 can be measured with the
existing churn tooling after collection, but only as a separate artifact; it never moves a frozen
label.

## 9. Reporting rules

- Never describe the feed_v3 positive class as human-labelled.
- Never describe the negative class as verified clean. Use "feed-absent at retrieval" or
  "Tranco-sampled negative".
- Do not claim prevalence of malicious sites in the wild from this sample.
- Do not name negative-class examples; use hashes. Feed-listed positives may be named.
- Report the retrieval and crawl windows, the yield, and every dropped domain.
- Report that one annotator produced the 146-domain human subset in `feed_v2`; feed_v3 has no human
  labels and no inter-rater claim.

## 10. Limitations

1. Feed membership is a proxy, not ground truth, and reporting-community bias is inherited.
2. The positive class is phishing-oriented. URLhaus retirement removes the malware-download slice
   that feed_v2 had.
3. Negative domains are unverified; the Tranco frame over-represents popular sites.
4. Labels are domain-level, so residual shared-host and subdomain effects are possible.
5. There is one retrieval. A domain taken down or repaired between retrieval and crawl is
   mislabelled.
6. Phishing pages decay quickly, so the positive yield will be lower than the negative yield. The
   reserve exists for this reason, and yield is reported rather than hidden.
7. Crawling happens from one network vantage point; CDN and geolocation behaviour may differ
   elsewhere.
8. No human validation is added for feed_v3. The frozen human subset is disjoint by construction.

## 11. Artifacts

| Artifact | Path |
| --- | --- |
| Builder and verifier | `scripts/feed_v3_build.py` |
| Label file | `data/labels/feed_v3/labels.csv` |
| Selected / reserve positives | `data/labels/feed_v3/positives.csv`, `positives_reserve.csv` |
| Provenance | `data/labels/feed_v3/provenance.json` |
| Validation report | `data/labels/feed_v3/validation.json` |
| Positive batches | `data/candidates/feed_v3/feed_batch_01..30.csv` |
| Positive reserve batches | `data/candidates/feed_v3/reserve/feed_reserve_01..15.csv` |
| Negative batches | `data/candidates/feed_v3/negatives/neg_01..30.csv` |
| Negative reserve batches | `data/candidates/feed_v3/negatives/neg_reserve_01..10.csv` |
| Manifests | `data/candidates/feed_v3/feed_manifest.json`, `reserve/feed_reserve_manifest.json`, `negatives/negative_manifest.json` |
| Approval record | `data/candidates/feed_v3/collection_approval.json` |
| Raw feed snapshots | `data/labels/feed_v3/snapshots/` (gitignored, redistribution restricted) |
| Excluded domains | `data/labels/feed_v3/exclusions.csv` |
| Assessments | `data/exports/feed_v3/` (gitignored) |
| Dataset | `data/datasets/feed_v3/` |
| Training run | `data/research/runs/` |
