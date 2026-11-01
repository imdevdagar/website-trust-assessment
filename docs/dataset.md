# Website Trust Assessment System dataset datasheet

Version 1.2 — 2026-11-01. Describes the frozen `feed_v3` dataset, the primary evaluation set. Composition
numbers come from `data/datasets/feed_v3/manifest.json`; the dataset SHA-256 is recorded in
`data/datasets/feed_v3/artifacts_snapshot/manifest.json`. The earlier `feed_v2` build (830 samples /
826 domains) and `feed_v1` build are retained as lower-scale predecessors; they are described in
[feed-v3-protocol.md](feed-v3-protocol.md) and agree with `feed_v3` on every headline direction.

This document follows the Datasheets for Datasets structure (Gebru et al., 2021) and records the
choices that affect what the dataset can and cannot support. The dataset is a **convenience sample of
public websites**, not a random sample of the web and not a measurement of phishing prevalence.

---

## 1. Motivation

**For what purpose was the dataset created?** To evaluate whether evidence-grounded, multi-dimensional
website assessment can distinguish benign from malicious sites under a protocol that controls for
label leakage, domain overlap, and test-set reuse.

**Who created it?** Two final-year Computer Science students (the project team). The human labels are
author-produced by a single annotator; the primary evaluation labels come from public abuse feeds, with
the provenance rules in section 4.2. See [annotation-protocol.md](annotation-protocol.md) and
[main-dataset-protocol.md](main-dataset-protocol.md) for the limits of that process.

**Who funded it?** No external funding. No paid APIs, cloud inference, or dedicated GPU are used.

**What is the task?** Binary classification of registrable domains as `benign` versus `malicious` for
the primary experiment. A three-class `suspicious` label is collected but excluded from the primary
task; it is used for a sensitivity analysis and for describing ambiguous cases.

**What is not the task?** The dataset is not a malware corpus, a phishing-feed replication, a
population prevalence estimate, a privacy audit, or a legal compliance benchmark.

---

## 2. Composition

### 2.1 Instances

- **Sampling unit:** one registrable domain.
- **Assessment unit:** one captured page assessment for a domain and action (`browse`, `signup`, or
  `purchase`). The dataset allows up to five assessments per domain by default.
- **Label unit:** domain-level, from the consensus annotation.
- **Modalities:** URL, rendered DOM fingerprint, HTTP headers, certificate/DNS/registration metadata,
  page text, forms, tracker requests, policy links, screenshot/OCR features, hidden-content signals,
  and derived rule outputs.
- **Raw page content is not redistributed.** The dataset stores derived features and metadata. The local
  assessment database and screenshots remain on the collecting machines unless a separate, reviewed
  release is prepared.

### 2.2 Target size

| Quantity | Target | Achieved (`data/datasets/feed_v3`) |
| --- | --- | --- |
| Domains with primary labels | 5,000 usable | 5,129 (2,533 malicious / 2,596 benign) |
| Double-annotated domains | 20% | not met — single annotator, see section 9 |
| Usable assessments after exclusions | — | 5,129 samples from 11,402 collected rows; 5,511 assessments passed `research feed-check` |
| Domains per split (train/val/test) | approximately 70/15/15% | 3,590 / 770 / 769, grouped by registrable domain, seed 42 |

The positive pool is PhishTank `online-valid` plus OpenPhish, sampled from 9,764 labelled domains
retrieved 2026-10-25T18:47Z; the negative pool is Tranco top-1M. Of 3,000 selected positive candidates,
1,389 yielded a usable assessment; the registered reserve added 724 and the pre-registered fixed-ranking
top-up added 420, and the root-URL retry recovered 111 domains whose recorded path no longer resolved.
5,868 positive candidates were NXDOMAIN at crawl time — takedown, not local filtering — and are recorded
as drops, never relabelled benign. 382 assessments landed on a different registrable domain than the
candidate (open redirects and parked hosts) and are excluded by `scripts/feed_v3_filter_exports.py`,
which writes the analysis files every downstream step consumes; exclusions and their SHA-256s are in
`data/exports/feed_v3/analysis/exclusions.json`. The benign class means *absent from both feeds at
retrieval time*, never verified clean (protocol section 4.3).

Gate compliance for all 85 candidate/export pairs and the label-leakage check are verified by
`scripts/feed_v3_gate_compliance.py` and `research feed-check`
(`data/research/gate_compliance_feed_v3.json`, `data/labels/feed_v3/leakage_check.json`: 5,511
assessments, `leaked_assessments: 0`, runtime label store empty). Composition, HTTPS and TLS-trusted
prevalence, the shipped engine's escalation behaviour over every labelled row and the padlock baselines
are recomputed by `PYTHONPATH=. python scripts/dataset_profile.py` into
`data/research/profile_feed_v3.json`; cited artifacts are frozen in
`data/datasets/feed_v3/artifacts_snapshot/` by `scripts/feed_v3_freeze.py`. The sensitivity build
`data/datasets/feed_v3_s43` re-splits and retrains at seed 43. The predecessors `data/datasets/feed_v2`
(830 samples / 826 domains, 497 malicious / 333 benign) and `data/datasets/feed_v1` (743 / 742,
495 / 248) are retained; all three builds give the same reading on every headline direction. A
769-domain test split supports subgroup and tail analysis at widths the 123-domain split did not;
subgroup results are still reported with intervals and sample counts.

### 2.3 Sampling frame

Candidate domains come from three sources:

1. **Popular and established sites.** A public top-sites list (for example Tranco) sampled across
   categories such as banking, retail, education, government, news, health, and personal projects.
   Tranco is used only as a sampling frame; its ranking is not a feature.
2. **Small and newly observed sites.** Domains encountered through manual browsing, public link lists,
   and the team's own test sets. This adds small businesses, hosted subdomains, and sites with weaker
   transparency.
3. **Malicious candidates.** Public phishing/malware URL feeds and manually reported URLs are used to
   find candidates. Feed membership is not copied as the label; both annotators must verify the live
   page or record it as suspicious/unresolved.

The sample is deliberately enriched for malicious and ambiguous sites. It is not prevalence-weighted,
and no result should be read as "X% of the web is malicious".

#### 2.3.1 Round 2 pilot candidate manifest

The mixed calibration pilot uses 36 new registrable domains from
`data/candidates/round2.csv`:

| Stratum | Selected | Reserve | Collection |
| --- | ---: | ---: | --- |
| `scam_feed` | 20 | 20 | Gated; only after explicit team confirmation |
| `ambiguous` | 8 | 4 | Safe strata; standard annotation rules |
| `benign_control` | 8 | 4 | Safe strata; standard annotation rules |

The manifest is constructed by `wtas research candidates`. It fetches only public feed metadata,
never a candidate page. Candidate URLs are stored without query strings or fragments; IP literals,
credentials, non-standard ports, private hosts, paths containing email addresses, and Round 1 domains
are rejected. Feed hits on free hosts, URL shorteners, CDNs, and major multi-tenant platforms are also
removed because the sampling unit is the registrable domain and the hit belongs to a customer page,
not the platform.

The 2026-10-20 OpenPhish retrieval contained 300 rows and 105 usable domains after filtering. The
manifest records the feed digest, retrieval date, filter counts, source-file hashes, and selected
domains. Feed membership is candidate discovery, not a label. OpenPhish is phishing-oriented, so this
pilot is a mixed calibration slice rather than a balanced benchmark of every scam family.
`data/candidates/round2_reserve.csv` contains replacements that may be used only under the protocol
amendment rule in [annotation-protocol.md](annotation-protocol.md) section 5.2.

### 2.4 Inclusion and exclusion at collection

Include:

- publicly reachable `http://` or `https://` pages on standard ports;
- pages that render enough content for a meaningful assessment;
- domains for which both annotators can follow the codebook safely.

Exclude:

- pages requiring authentication, payment, or form submission to view;
- private, loopback, link-local, metadata, and internal hosts;
- non-HTML content, raw file downloads, and browser-internal pages;
- parked or for-sale placeholder pages, unless they are deliberately included as a separate stratum;
- sites that cannot be assessed without breaking the law or the annotator safety rules;
- duplicate URLs that canonicalise to the same domain/action/URL key;
- feed hits on shared hosting, URL shorteners, CDNs, or major multi-tenant platforms, because the
  registrable domain does not represent the party that controls the reported page.

### 2.5 Label distribution

The distribution is reported in `manifest.json` and in the paper's dataset table. Do not force a
balanced dataset by discarding benign sites; report the natural post-collection distribution and use
class-balanced training weights, AUPRC, and per-class recall to handle imbalance. If the malicious
class is very small, the dataset is underpowered regardless of the total sample count.

---

## 3. Collection process

1. Build or import a candidate URL list. Store the source and collection date.
2. Run `wtas batch` with `--full --resume` to persist complete assessment JSONL. Use one action per
   collection round; a second round may collect `signup` or `purchase` profiles for the same domains.
   For the Round 2 pilot, the default batch skips rows marked
   `malicious_page_requires_explicit_confirmation`; `--allow-gated` is required only after the team has
   explicitly approved access to the public feed stratum.
3. Confirm that the assessment timestamp is close to the annotation date. Recommended window: 48 hours.
   Websites change; a stale assessment is not evidence about the page the annotator saw.
4. Build the blinded annotation queue from the latest browse assessment per domain.
5. Annotate independently, compute agreement, adjudicate, and freeze consensus.
6. Build the dataset with explicit labels, leakage checks, and a fixed seed.
7. Archive the dataset JSONL, CSV, manifest, label file, configuration, code version, and hashes.

Collection is local and manual. The crawler identifies itself with a `WebsiteTrustAssessment/0.1` user-agent and
does not submit forms, download files, or execute page-provided instructions. It does not currently
enforce `robots.txt`; only public pages are collected for research, and the limitation is reported.

### 3.1 Timing and snapshots

The assessment and the label must refer to the same page state. If a site changes materially between
assessment and annotation, rescan it before labelling. If re-scanning is impossible, mark the sample
unresolved and exclude it rather than attaching an old label to new content. The dataset manifest
records assessment timestamps but does not currently enforce a maximum label–assessment gap; the
protocol does.

---

## 4. Preprocessing, cleaning, and labelling

- URL canonicalisation removes fragments, default ports, and userinfo; only HTTP/HTTPS on ports 80/443
  is accepted.
- Domains are reduced to their registrable domain using the bundled Public Suffix List snapshot in
  `website_trust_assessment/data/public_suffix_list.dat` (version in the file header, refreshed manually from
  publicsuffix.org). A stale or missing suffix can collapse distinct sites into one registrable domain,
  so the snapshot version is part of the dataset provenance.
- Duplicate `(domain, action, normalized_url)` records are collapsed, keeping the newest assessment.
- A per-domain cap (default 5) prevents a single site from dominating the dataset.
- Non-finite feature values cause exclusion rather than silent imputation.
- Missing values are represented explicitly for the most important observables (for example,
  `domain_age_unknown`), and page availability is a feature.
- Labels are normalised to `benign`, `suspicious`, or `malicious`; blank rows are ignored; invalid
  labels raise an error.
- `suspicious` is excluded from the primary binary task by default. With `--include-suspicious`, it is
  mapped to target 1 for a sensitivity analysis; this must be reported as a different task.

### 4.1 Leakage controls

The following are excluded from the main dataset (`exclusions.label_leakage`):

- evidence codes `known_malicious_label`, `known_suspicious_label`, and
  `malicious_infrastructure_overlap`;
- score floors whose name starts with `known_`;
- runtime `notes.infrastructure.known_label`;
- label-derived infrastructure neighbours (`neighbor_count` or `matched_on`).

The feature schema contains no `flag_known_*` or infrastructure-overlap columns. Reputation labels used
for runtime floors are therefore not available to the model. An ablation that re-enables leakage is
permitted only to demonstrate the size of the leak, never as the headline result.

Other potential shortcuts that are **not** label leakage but still require discussion:

- static brand/TLD/tracker lists encode human priors and may vary in coverage;
- official-domain matching uses a curated brand list, not a live registry;
- the sampling source can correlate with the label (feed candidates are more likely malicious);
- page availability, language, and Cloudflare challenges may correlate with site type.

Report these as dataset biases and test sensitivity where feasible.

### 4.2 Primary label source

Per [main-dataset-protocol.md](main-dataset-protocol.md) section 2.2 and
[feed-v3-protocol.md](feed-v3-protocol.md), the primary `malicious` label for `feed_v3` is
**membership of the PhishTank `online-valid` list or the OpenPhish feed at a recorded retrieval time**
(2026-10-25T18:47Z), not a human judgement. URLhaus is no longer a label source for this build — its
export endpoint returned HTTP 410 during the label-design pass — and remains a source only in the
`feed_v2` predecessor. `wtas research feed-labels` writes the label set; `wtas research feed-check`
asserts before every build that no feed verdict reached the assessments being scored.

- The sampling unit is unchanged (registrable domain); feed entries are reduced to registrable domains
  and deduplicated, so one domain is one label regardless of how many feed URLs report it.
- Human labels are retained as a separate validity subset column and never merged into the feed column.
- The feed CSV must **never** be imported with `import-labels`. Loading it into the runtime
  `domain_labels` store would let `known_malicious_label` evidence (55 risk points) hand the model the
  answer it is scored against.
- A feed domain that cannot be crawled is dropped, never labelled `benign`.
- Feed labels carry a timestamp; the crawl must fall inside the recorded freshness window (7 days by
  default) and the window is reported alongside the results.
- The `benign` pool is not drawn from feeds at all. For `feed_v3` it is a fixed-seed sample of the Tranco
  top-1M list (3,000 selected + 1,000 reserve), verified pairwise disjoint from the positive pool, from
  `feed_v2`, and from the human subset before any crawl started (`data/labels/feed_v3/validation.json`).
  A domain carrying a frozen human label receives no derived label either way.
- An assessment that lands on a different registrable domain than its candidate — open redirect, parked
  host, or an error page served by an unrelated domain — is excluded rather than used, because a
  domain-level label cannot describe the page actually captured. `scripts/feed_v3_filter_exports.py`
  removed 137 positive and 245 negative such rows.
- Because a feed label is only true at its retrieval time, transience is measured rather than assumed
  (protocol section 7.2). On the `feed_v2` label set, a second retrieval 4.43 h later keeps 98.4% of the
  primary labels (488 of 496 evaluation positives still listed), all of the churn came from URLhaus, and
  no derived negative became listed (0 of 330). That interval is hourly-resolution only; no second
  retrieval has been measured against the `feed_v3` label set, and `labels.csv` is never rewritten by
  this check. One attempt was made, on 2026-11-01: PhishTank answered HTTP 429 on all five backoff
  attempts of `scripts/feed_v3_churn.py`, and that script aborts rather than recording a partial fetch —
  a truncated feed would otherwise be read as mass delisting. `feed_v3` label durability is therefore
  unmeasured, not assumed to be high.

---

## 5. Dataset schema

### 5.1 `dataset.jsonl`

Each line is one sample:

| Field | Type | Description |
| --- | --- | --- |
| `assessment_id` | string | Assessment identifier. |
| `url` | string | Original submitted URL. |
| `normalized_url` | string | Canonical URL used by the crawler. |
| `final_url` | string | URL after redirects. |
| `domain` | string | Registrable domain used for grouping. |
| `action` | string | `browse`, `signup`, or `purchase`. |
| `assessed_at` | ISO-8601 string | Assessment timestamp. |
| `label` | string | `benign` or `malicious` in the primary dataset (optionally `suspicious`). |
| `target` | 0/1 | 0 for benign, 1 for malicious. |
| `label_confidence` | float | Consensus confidence. |
| `label_source` | string | `double_agreement`, `adjudicated`, or `single_annotator`. |
| `leakage` | list[string] | Leakage reasons detected before exclusion; empty in the main dataset. |
| `features` | object | Named numeric features from the versioned schema. |
| `split` | string | `train`, `val`, or `test`. |

### 5.2 `dataset.csv`

A flattened view with metadata columns followed by all 116 hybrid features. It is convenient for
inspection and external tools; `dataset.jsonl` is authoritative.

### 5.3 `manifest.json`

Includes:

- dataset and feature schema versions;
- creation time, split seed, ratios, action filter, per-domain limit;
- include-suspicious and allow-leakage flags;
- sample/domain counts and per-split label counts;
- exclusion counts and up to 20 examples per exclusion reason;
- duplicate count;
- warnings (small splits, single-class splits, domain overlap);
- assessment source and label-file metadata (path, SHA-256, conflicts, label counts);
- feature names and group sizes;
- SHA-256 and byte size for `dataset.jsonl` and `dataset.csv`.

`research train` records the dataset JSONL hash in the run and in every model artifact. A changed
dataset without a changed hash is a protocol violation.

---

## 6. Splits and leakage prevention

- **Grouped by domain.** All assessments and actions for a domain go to exactly one split. The training
  code refuses to run if it detects domain overlap between splits.
- **Stratified by label.** Domains are allocated per label using the requested ratios, with a
  deterministic seed and a best-effort guarantee that validation and test are non-empty when at least
  three domains exist.
- **Frozen test set.** Model selection, calibration, and threshold selection use only train and
  validation. The test split is evaluated once per final configuration.
- **Temporal leakage is not yet enforced.** A domain's newest assessment is deduplicated, but there is
  no global time cutoff between splits. Because the unit is domain and all actions are grouped, the
  main leakage route is closed; however, a deployed system would face temporal drift, so future
  versions should add a time-based split for a realism check.
- **No random row split.** Splitting rows instead of domains would leak the same site across splits and
  inflate results. The tooling does not support that mode.

### 6.1 Recommended ablation variants

| Variant | Purpose |
| --- | --- |
| `url` only | Establishes how much lexical URL structure alone explains. |
| `signals` (URL + page/domain observations + key flags) | Tests the value of measured page evidence without rule scores. |
| `rule` only | Tests whether a learned model can recalibrate the rule outputs. |
| `hybrid` (all features) | Main model; includes rule outputs, so it is a stacked model, not an independent replacement for the rule engine. |
| Rule engine raw | Deterministic baseline; no training. |
| Hybrid without rule outputs | Optional independence check; the current feature groups do not expose this directly, so it requires a documented custom design matrix. |

The paper must state that `hybrid` contains the rule score. A claim that "learning beats rules" needs
the `signals` or URL-only comparison, not only the hybrid-versus-rule comparison.

---

## 7. Uses

**Permitted:**

- research on website trust, phishing detection, calibration, and selective prediction;
- ablation and reproducibility studies using the published manifest and hashes;
- teaching and local demonstrations with synthetic or public data;
- development of defensive browser warnings, with human oversight.

**Not permitted or not supported:**

- surveillance, profiling, or automated blocking of individuals or small organizations;
- claims of web-wide prevalence or guaranteed safety;
- using model outputs as the sole basis for legal, financial, employment, or access decisions;
- redistributing screenshots or page captures that may contain personal data;
- using the dataset to train offensive tools or to improve phishing evasion.

The dataset contains domain names, which are public, but it may also contain derived features from live
pages. Review the license and privacy posture before any public release.

---

## 8. Distribution and maintenance

- **Current storage:** local project data directories; not a public release.
- **Planned release:** derived features, labels, split assignments, manifest, code version, and label
  provenance, subject to an institutional and privacy review. Raw screenshots and assessments are not
  planned for release by default.
- **License:** to be decided before release. Code is MIT; data may require a separate research license.
- **Versioning:** `DATASET_SCHEMA_VERSION` and `FEATURE_SCHEMA_VERSION` are stored in every manifest.
  Any change to feature definitions, label rules, or sampling requires a new dataset version and new
  runs. Never overwrite a frozen version.
- **Maintenance:** re-scan a sample quarterly to measure drift; re-annotate a stratified sample when the
  codebook changes; archive old versions rather than deleting them.
- **Errata:** report label errors and their effect. Do not silently patch a released dataset.

---

## 9. Known limitations

1. The sample is not random and is enriched for malicious and ambiguous sites.
2. `suspicious` is excluded from the primary binary task, so the model does not learn the middle class.
3. The human labels come from one annotator who is also a system author, so no inter-rater agreement or
   independent adjudication exists and none is claimed. Only 146 domains carry a human label.
4. The primary `malicious` label is abuse-feed membership, which is a proxy: it biases toward reported
   phishing and malware-distribution infrastructure, has no `suspicious` tier, has no per-page
   granularity, and ages between retrieval and crawl.
5. The `benign` class means "absent from both feeds at retrieval time", not "verified trustworthy".
   Unknown-but-clean domains are counted as benign, so measured precision is not real-world precision.
6. Website content changes; the dataset is a snapshot, not a stable property of the domain.
7. Feed candidates and manual browsing can introduce selection bias.
8. Derived features depend on the crawler, Chromium version, OCR availability, and the local knowledge
   files. The manifest and engine version must accompany results.
9. The corpus is a sample of *survivors*: 5,868 selected positive candidates were already unresolvable
   when crawled and only 2,113 of 4,500 selected-and-reserve positives yielded a page. Any accuracy figure
   therefore describes infrastructure that was still live at capture, which over-represents young or
   persistent campaigns relative to the feed as published.
10. The 769-domain test split supports subgroup and tail analysis, but subgroup cells are still small and
    are reported with intervals and counts.
11. Collection ran across several days after a single label retrieval, so the negative class carries drift
    risk (a domain listed after retrieval would sit in the corpus as a silent false negative). This is
    measured, not assumed — see the churn artifact in section 4.2.
12. There is no temporal split in version 1.x; temporal generalisation is future work.
13. Only English-language pages were included in the primary collection; multilingual generalisation is
    not claimed.

---

## 10. Datasheet checklist

- [x] Sampling sources and dates recorded.
- [x] Collection and annotation windows recorded.
- [x] Label file hashed and archived.
- [x] Agreement report included; adjudication not applicable (single annotator, §9).
- [x] Exclusion counts and reasons reported.
- [x] Split counts and class distributions reported.
- [x] Manifest hash matches the dataset used in every reported run.
- [x] Known limitations repeated in the paper.
- [x] No raw personal data or credentials in released artifacts.
