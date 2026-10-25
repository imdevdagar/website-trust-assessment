# Website Trust Assessment System main dataset protocol addendum

Version 2.2 — 2026-10-20

Status: active for the main dataset. This addendum applies only to the main collection. It does not
change the frozen pilot rounds or their archives.

Change log:

- **1.0 (2026-10-20)** — single-annotator continuation of the main collection.
- **2.0 (2026-10-20)** — the primary evaluation ground truth becomes public abuse-feed membership
  (section 2.2). Human labels become a validity subset. Main batch 02 is dropped (section 4.2).
- **2.1 (2026-10-20)** — the benign class is defined by feed absence over the safe main strata
  (section 4.3); main batch 02's assessments re-enter as derived negatives and main batches 03-04 are
  collected for the same purpose. No new human labeling is introduced.
- **2.2 (2026-10-20)** — feed-label transience is a measured result (section 7.2). A second retrieval is
  taken into a separate artifact and compared domain by domain. No label is moved by it.

For the main dataset, this addendum supersedes:

- [annotation-protocol.md](annotation-protocol.md) section 6, which assumes two annotators and 20%
  double annotation;
- [dataset.md](dataset.md) section 2.2, which states the same assumption.

Everything else in the codebook, including the label definitions, decision procedure, evidence rules,
confidence anchors, blinding rules, leakage controls, and grouped-split contract, remains in force.

---

## 1. Reason for the addendum

The protocol was written for a two-person team. Round 1 was double-annotated and frozen. Round 2 was
labelled by annotator A only because annotator B was unavailable; the user explicitly chose
single-annotator continuation on 2026-10-20. A second rater is still not available for the main
collection.

The team will not fabricate, copy, or infer labels for a second annotator. The main dataset is
therefore a **single-annotator dataset**, and the paper must say so. It cannot report inter-rater
agreement, consensus labels, or independent adjudication.

## 2. Label source and reliability

Amendment 2 splits this into two label sources, described in section 2.2. The rules below govern the
human subset; they still apply to any batch a human annotates.

- **Label source:** one human annotator, role A, using the codebook in
  [annotation-protocol.md](annotation-protocol.md).
- **Double annotation:** 0%. No second human sheet exists.
- **Inter-rater reliability:** not computed and not claimed.
- **Label provenance string:** `single_annotator_a`.
- **Pilot labels:** not pooled with the main dataset.
- **Blinding:** the annotator sees only the blinded queue fields and never `key.json` while labelling.
- **Freezing:** each completed batch sheet is validated and frozen read-only with a SHA-256 digest.
  Corrections after freezing are protocol amendments, not silent edits.

### 2.1 Delayed blind intra-rater audit

Because no second rater exists, the main dataset will include a delayed intra-rater audit:

1. After all main label sheets are frozen, select a random 15% of labelled domains (at least 40
   domains when at least 267 domains are available) with a recorded seed.
2. Wait at least seven days.
3. Re-label the audit sample in a fresh blinded sheet that does not show the original labels.
4. Freeze the audit sheet and compute observed agreement and quadratic weighted kappa between the
   original labels and the audit labels.

This measures **intra-rater consistency**, not inter-rater reliability. It must be reported as such.
If observed agreement is below 0.80 or quadratic weighted kappa is below 0.60, the codebook and the
disagreements are reviewed, and any change to frozen labels requires a documented amendment. The audit
does not replace independent human annotation and cannot establish label correctness.

### 2.2 Primary evaluation label source (amendment 2)

Reaching the 400–500 usable-domain target by human annotation is not feasible for this team: one
annotator, full-page inspection, and a 48-hour assessment-to-annotation window do not scale to a
positive class that is mostly unreachable or unsafe to browse. The primary evaluation therefore uses
a machine-readable label source and the human set is demoted to a validity subset.

**Primary ground truth — feed membership.**

- A registrable domain is `malicious` if and only if it appears in the OpenPhish public feed or the
  URLhaus online-payload export at the recorded retrieval time. Everything else in the sample is
  `benign`.
- Labels are produced by `trustlens research feed-labels`, which writes
  `data/labels/feed/labels.csv` plus a provenance manifest containing, per source, the URL, the final
  URL, the SHA-256 of the raw feed body, the retrieval timestamp, the HTTP `Date` header, the accepted
  entry count, and every rejection reason with its count. Raw feed bodies are snapshotted so the label
  set can be rebuilt offline.
- The label means "some reporting community believed this domain was abusive at time T", not "this
  page is untrustworthy". It is a proxy with a known, disclosed bias, not a gold standard.
- Freshness: a feed older than `--max-age-days` (default 7) is refused outright. A local snapshot with
  no retrieval timestamp is accepted with a warning that the crawl window is unverifiable.
- The current label set is **549 domains** retrieved 2026-10-20 (111 accepted OpenPhish entries and
  20,327 accepted URLhaus entries, one domain in both feeds) after dropping IP literals, non-standard
  ports, shared-hosting and CDN hosts, and obvious download paths. Rebuilding offline from the saved raw
  feed snapshots reproduces it exactly. An earlier build of 432 domains is archived in
  `data/labels/feed/superseded/`: it excluded every `main.csv` candidate domain, a rule inherited from
  the human-labelling design that had no place in a feed-labelled primary set and was discarding 117
  valid feed members.

**Validity subset — the frozen human labels.**

- 146 domains remain frozen and untouched: pilot round 1 (36 domains, double-annotated), round 2
  (33 domains, annotator A), and main batch 01 (77 domains, annotator A).
- They are reported separately: metrics on the feed-labeled primary set, then the same metrics on the
  human-labeled subset, then the agreement between feed membership and the human verdict on the
  overlap.
- No human label is rewritten, reinterpreted, or merged into the feed label column. Where a feed and
  an annotator disagree, both records are reported (section 7).

**Why this is not circular.**

1. The feed is never imported into the runtime `domain_labels` store. That store is the only path by
   which a stored verdict reaches scoring, via `known_malicious_label` evidence worth 55 risk points.
   The label CSV must never be passed to `import-labels`.
2. `trustlens research feed-check` runs `assert_no_label_leakage` over the collected assessments and
   fails the build if any assessment carries a leakage reason (`evidence:*`, `floor:known_*`,
   `runtime_domain_label`, `labeled_infrastructure_neighbor`) or if any feed domain appears in the
   runtime store. The last verified run on 184 existing assessments reported
   `runtime_label_store_rows: 0` and `passed: true`.
3. Feed membership is used only at evaluation time, never as a feature, never in candidate ordering,
   and never in a rule branch.

The last verified run covered all 220 collected assessments and reported `runtime_label_store_rows: 0`,
`leaked_assessments: 0`, `passed: true` (`data/labels/feed/leakage_check.json`). This decision and its
evidence are recorded in `data/datasets/label_source_decision.json`.

**Consequences for the claim in the paper.** The contribution is unchanged in kind and narrower in
wording: The system produces evidence-grounded, feature-based trust assessments, and a logistic
regression over page, TLS, and domain-infrastructure signals separates feed-labeled malicious domains
from benign ones better than a URL-only baseline (primary comparison: `signals` versus `url`, on
domain-grouped test AUROC and AUPRC). The paper must state that the positive class is defined by abuse
feeds, that this biases toward phishing and malware-distribution infrastructure, that prevalence in
the wild cannot be inferred from the sample, and that independent human labels cover only 146 domains
from one annotator.

**Limitations this decision introduces, to report verbatim:**

- Feed labels have no `suspicious` tier and no per-page granularity; the unit is the domain.
- Unknown-but-clean domains are counted as benign; feed absence is weak evidence of benignity, so the
  benign class is a convenience class, not a verified one.
- Reporting communities overlap with commercial blocklists, so part of the measured separation may be
  popularity of reporting rather than page quality.
- Labels age: a domain taken down or repaired between retrieval and crawl is mislabeled. The crawl must
  happen inside the recorded window, and the window is reported.

## 3. Sampling design

Target: **400–500 usable registrable domains**.

### 3.1 Strata

| Stratum | Sampling frame | Selected | Reserve | Collection |
| --- | --- | ---: | ---: | --- |
| `established` | Tranco top-1M, rank 1–50,000 | 260 | 80 | Standard safety rules |
| `tail` | Tranco top-1M, rank 50,001–1,000,000 | 100 | 30 | Standard safety rules |
| `scam_feed` | OpenPhish and URLhaus public feeds | 140 | 50 | Gated; fresh explicit approval required |
| **Total** | | **500** | **160** | |

Since amendment 2 the `scam_feed` stratum is the primary positive class rather than a hard slice of a
human-labelled set, and the Tranco strata supply the negative class. The counts above still describe
how candidates were drawn; the label each candidate receives now comes from feed membership
(section 2.2), so the safe strata no longer require a human label to be usable as `benign`.

The selected counts oversample the usable target so that unreachable, parked, login-only, and
non-HTML candidates can be excluded without falling below 400 usable domains. The reserve is used only
before any main label for that batch is frozen and every replacement is recorded in the manifest.

Tranco is a sampling frame only. Its rank is never a model feature. The rank bands are a reproducible
proxy for "established" and "less-established" sites, not labels and not a category stratification.
Category coverage will be reported after collection from annotator-visible page characteristics. The
absence of an explicit category-stratified frame and of the planned manual small/new-site source is a
documented limitation of this version.

### 3.2 Candidate filtering

Candidate construction reads URL metadata only and never opens a candidate page. It rejects IP
literals, credentials, non-standard ports, private or internal hosts, paths containing email addresses,
domains outside the bundled public suffix list, and duplicates. It excludes:

- every Round 1 and Round 2 pilot domain, including the Round 2 reserve;
- feed hits on shared hosting, URL shorteners, CDNs, and major multi-tenant platforms;
- URLhaus candidates whose URL path points to an executable, archive, installer, document, media, or
  other obvious non-HTML download, because the collection contract excludes raw file downloads;
- the same registrable domain appearing in more than one stratum or in both selected and reserve
  lists.

Feed membership is candidate discovery, not a label. Every feed candidate is gated. Both OpenPhish and
URLhaus are public feeds; their terms and retrieval digests are recorded in the manifest. OpenPhish is
phishing-oriented; URLhaus is malware-download-oriented. The feed slice is enriched for malicious
infrastructure but is not a balanced sample of scam families.

## 4. Collection and annotation workflow

Collection is local and manual. The crawler identifies itself as `WebsiteTrustAssessment/0.1`, does not submit
forms, does not download files, and does not execute page-provided instructions. It does not enforce
`robots.txt`; this limitation is reported.

Each batch follows the same sequence:

1. Collect `browse` assessments for a batch of at most 100 safe-stratum candidates with
   `trustlens batch --full --resume`.
2. Build a single-annotator blinded queue for that batch with `trustlens research queue
   --single-annotator`.
3. Annotate the batch within the 48-hour assessment-to-annotation window wherever possible. Serve the
   form with `--snapshots data/exports/main/batch_XX.jsonl` so each site shows the page the crawler
   captured for that URL; open the live site when a capture is blank, shared with other sites, missing,
   or not enough to judge. If a site changes materially or cannot be inspected, follow the codebook
   rather than guessing. See [annotation-protocol.md](annotation-protocol.md) section 3.4.
4. Run `python scripts/reachability_triage.py` for any note that describes a failed load, re-attempt the
   domains that answer with content, and leave the rest untouched. See
   [annotation-protocol.md](annotation-protocol.md) section 3.3.
5. Freeze the completed A sheet with `trustlens research freeze`.
6. Record the not-inspectable rows with `python scripts/non_inspections.py`. Labels are never rewritten;
   the record only marks rows for exclusion at dataset time.
7. Refresh the auditable progress file with `trustlens research main-status`. It is derived only from
   artefacts on disk and reports per-batch collection failures, cross-domain redirects, queue size,
   label counts, freeze state, the 48-hour window, the gated-collection status, and integrity checks.
8. Count the usable domains left after collection failures and not-inspectable rows. If the projected
   total falls below the 400-domain target, draw replacements from the reserve. A replacement is only
   allowed before that batch's A sheet is frozen, and every substitution is recorded.

A candidate that redirects to a different registrable domain is queued and grouped under the live
landing domain, because the assessment and the sampling unit both describe the page that was actually
inspected. `research main-status` lists every such substitution so the replacement is auditable rather
than silent.

Steps 2–6 apply to batches whose labels come from a human: the batch 01-style safe strata and any
future human slice. Batches whose labels come from feeds skip them entirely; their label step is
`research feed-labels` before the crawl plus `research feed-check` after it.

The gated `scam_feed` stratum is collected only after a fresh explicit team approval for the main
collection. The Round 2 approval covered only the 20 pilot candidates and is spent. No main feed page
may be opened by passing `--allow-gated` without that fresh approval.

Under amendment 2 the feed crawl is a machine collection, not an annotation task: no annotator opens
a feed page, and the crawler's own safety rules (no form submission, no file download, no
page-provided instructions executed, isolated browser profile) are the controls. This removes the human
review burden but does **not** remove the gate — the approval required is for touching live malicious
infrastructure from this machine, which is unchanged.

### 4.1 Feed crawl plan of record

`trustlens research feed-candidates --labels data/labels/feed/labels.csv --out-dir
data/candidates --seed 42` turns the label CSV into gated batches. It reads label metadata only and
opens no page. The current plan (`data/candidates/feed_manifest.json`) is:

| Item | Value |
| --- | --- |
| Domains to collect | 549 |
| Batches (contract cap 100 each) | 7 — 5 from `data/candidates/feed_batch_*.csv` (432 domains, seed 42) and 2 from `data/candidates/feed_remaining/` (117 domains, seed 43) |
| Approved | All 7 batches, 2026-10-20: batch 01 collected as a pilot, then the remaining 449 domains approved on its interim yield |
| Feed URLs pointing at a download | 304 of 549 (294 + 10) — crawl target set to the domain root instead |
| Collection gate on every row | `malicious_page_requires_explicit_confirmation` |
| Human verification | none; `verification_required` is `false` for these rows |

A feed entry for a payload is a file download, and the collection contract excludes downloads, so the
target falls back to the domain root where the path is not plausibly HTML. That measures the site's
page, not its malware, and the count is reported.

Batch order is a deterministic function of the seed, so a re-run names the same domains. Collecting any
batch still requires passing `--allow-gated`, which requires the approval in section 6.

### 4.2 Main batch 02: labeling dropped, assessments reused as derived negatives

Batch 02 collected assessments for 74 domains and never received a frozen label sheet. The decision
taken on 2026-10-20 was to **drop the labeling**, not the data: no human inspection of those sites is
owed, and none of them were drawn as feed candidates. Section 4.3 records the follow-on handling —
their assessments now enter the primary dataset through the same feed-absence rule used for every other
collected domain, which requires no label of any kind from an annotator. What remains forbidden is
inferring `benign` from the *absence of a human label*; the label here is the feed query result, exactly
as in section 2.2. Batch 01 remains frozen exactly as validated.

This is a reversal of the narrower reading of the drop decision, it is the user's to confirm, and it is
flagged in the status report rather than presented as settled.

### 4.3 Negative pool (amendment 3)

The feed plan supplies positives only: every one of its 549 domains is a feed member. A classifier needs
negatives, and under amendment 2 the negative rule is *absent from both feeds at retrieval time*. Applying
that rule to assessments of domains that were **not** drawn from a feed gives the benign class without any
manual review.

| Source | Rows | Why eligible |
| --- | --- | --- |
| `data/exports/main/batch_01.jsonl` | 77 | human-labelled, so **excluded** — those domains carry a frozen verdict and get no derived label |
| `data/exports/main/batch_02.jsonl` | 74 | safe main strata, never labelled, never feed candidates |
| `data/candidates/main_batch_03.csv` | 90 | safe main strata, collected 2026-10-20, ungated |
| `data/candidates/main_batch_04.csv` | 90 | safe main strata, collected 2026-10-20, ungated |

Batches 03 and 04 are collected without `--allow-gated`: they contain no gated rows, and their
`scam_feed` counterparts are already covered by the 549-domain feed plan, so nothing is skipped that the
design needs. Selection came from the pre-registered main manifest, not from any judgement about whether
a site looks clean, which is what keeps feed absence usable as a negative label.

Read together with section 2.2, the honest statement of the rule is: **a domain is positive because a
feed listed it, and negative because it was sampled from the safe strata and no feed listed it.** A feed
domain that could not be reached is dropped, never turned into a negative.

## 5. Dataset construction and reporting

- Frozen main A sheets are merged into one label CSV by registrable domain.
- The primary dataset is binary `benign` versus `malicious`; `suspicious` is excluded from the primary
  task and used only in a sensitivity analysis.
- The primary label column is produced by `research feed-eval-labels`, which joins the assessments that
  were actually collected with feed membership: in a feed → `malicious`, absent from both feeds →
  `benign`. The assessment pool it is run over is the union of the feed batches (section 4.1) and the
  safe main strata (section 4.3); running it over the feed exports alone would leave almost no negatives.
  Two rules bind it:
  - a feed domain that produced no assessment is dropped, never labelled `benign`;
  - a domain carrying a frozen human label is given **no** derived label. Feed absence would otherwise
    convert a human-confirmed positive into a silent negative; on the current data that would have
    mislabelled 12 of the 13 human-malicious domains. They remain the validity subset only.
- The primary label column is feed membership from `research feed-labels`; the human label column is
  carried alongside it as a separate field on the 146-domain validity subset and is never overwritten
  by, or merged into, the feed column.
- Splits are grouped by registrable domain, seed 42, approximately 70/15/15.
- Leakage controls in [dataset.md](dataset.md) section 4.1 are mandatory, and
  `research feed-check` must report `passed: true` on the assessments before a build is accepted.
  `research dataset --allow-leakage` remains off by default.
- A feed domain that cannot be assessed is dropped. It is never recorded as `benign`; only domains
  that produced an assessment enter the dataset, and the drop count is reported.
- The dataset manifest records the label source, the feed URLs with retrieval timestamps and SHA-256
  digests, the freshness window, the feed-check result, the human-subset size, batch provenance, the
  candidate manifest digest, the replacement log, and the batch 02 drop.
- The paper reports the single-annotator limitation, the intra-rater audit, the sampling-frame
  limitations, the feed-label bias list in section 2.2, and the absence of prevalence claims.

## 6. Approval record

| Decision | Record |
| --- | --- |
| Single-annotator continuation | User choice, 2026-10-20 |
| Proceed with main dataset work | User instruction "lets move ahead now", 2026-10-20 |
| Feed-labeled primary evaluation, human labels kept as validity subset | User choice, 2026-10-20 |
| Drop main batch 02 rather than label it; batch 01 stays frozen | User choice, 2026-10-20 |
| Main gated feed collection | Approved by the user 2026-10-20: batch 01 first as a pilot, then the remaining 449 domains on the reported interim yield. Evidence: `data/datasets/label_source_decision.json` |
| Collection-scope compliance | Checked, not remembered: `scripts/gate_compliance.py` (run through `scripts/gate_compliance_all.sh`) compares each candidate CSV with its export and reports scored rows per `collection_gate`. Last run `data/research/gate_compliance.json`: 12 pairs passed, every gated assessment came from the approved feed plan, **0 gated rows scored in any ungated run** (so the reserve's 50 `scam_feed` candidates were never opened), and 0 export rows came from outside their candidate file. |
| Feed crawl plan of record (432 domains, 5 gated batches) | Prepared by the assistant, 2026-10-20 |
| Main protocol addendum | Prepared by the assistant under the user's direction, 2026-10-20 |

## 7. Cross-checking feed labels against the human subset

Feed membership and a human verdict are different statements, so their disagreement is the finding, not
an error to fix. The first cross-check was run against the then-current 432-domain feed set; the frozen
`feed_v2` set is larger (496 malicious domains, 497 samples), and its overlap with the 146 human labels
remains 4. On that overlap:

1. Build the confusion between `benign`/`suspicious`/`malicious` and feed membership across all 146
   human-labelled domains, plus observed agreement on the overlap. Cohen kappa is **not reportable**
   here: every overlapping feed domain is `malicious` by construction, so one marginal is constant and
   kappa is pinned at zero regardless of the human labels. Report the confusion table and the agreement,
   and label them as agreement between two label *sources*, not reliability of a rater.
2. Walk through every disagreement against the codebook and say which reading each one supports. The
   20 gated Round 2 candidates are the priority case: the annotator called 12 of them `malicious` from
   the page, and the feeds they came from assert the same thing independently.
3. Never reconcile silently. A disagreement does not move a frozen human label and does not remove a
   domain from the feed label set; if evidence shows a label is wrong, that is a documented amendment
   with the reason recorded.
4. Report the disagreement rate as a limitation of the primary label source. If the human subset
   disagrees with the feed on a large share of positives, the paper must discuss feed precision rather
   than assume it is 1.0.

### 7.1 First run (2026-10-20, `data/labels/feed/human_vs_feed.json`)

`trustlens research feed-agreement` compared the 146 frozen human labels with the 432 feed labels:

| Human verdict | Domains | Still in a feed |
| --- | ---: | ---: |
| benign | 103 | 0 |
| suspicious | 30 | 3 |
| malicious | 13 | 1 |

Overlap is 4 domains. That is not an artefact of excluding candidate domains: rebuilding the label set
without any candidate exclusion (549 instead of 432 domains) left the overlap unchanged at 4, so the two
draws really do describe almost the same small set of sites. The three disagreements are all human
`suspicious` where a feed asserts `malicious`: `roblox.com.pt` and `www-mfacebook.com.vn`
(brand-lookalike hosts the annotator judged as ambiguous rather than confirmed fraud) and
`textfiles.com` (a legacy host reporting a malware payload). No label was moved.

The number that matters for the paper is the coverage row: **only 1 of 13 domains a human called
malicious is still listed in either feed at retrieval time.** Feed membership therefore describes
*currently reported* infrastructure, not a persistent property of a domain. Two consequences must be
stated: the feed-labeled positive class is a different population from the human-labeled one (younger,
still online, mostly never inspected by a human), and a model that scores well against the feeds is
measured on detection of live campaigns rather than on historical fraud. Cohen kappa on the overlap is
0.0 and is **not interpretable**: one marginal is constant, since every overlapping feed domain is
`malicious` by construction. Report observed agreement and the confusion table, never kappa.

### 7.2 Label transience measured against a second retrieval (2026-10-20)

Coverage against one retrieval time is a claim that can be tested, so the feeds were fetched a second
time into `data/labels/feed/churn/` — a separate artifact; `labels.csv` and its manifest were not
touched — and compared domain by domain with `scripts/feed_churn.py`
(`data/labels/feed/churn/churn_report.json`, interval 4.43 h):

| Measure | Result |
| --- | ---: |
| Primary labelled domains | 549 |
| Still listed at the second retrieval | 540 (98.4%) |
| Delisted between retrievals | 9 |
| Newly listed between retrievals | 11 |
| Evaluation positives (496) still listed | 488 (98.4%) |
| Derived negatives (330) now listed | 0 |
| Human-malicious domains (13) still listed | 1 |

The report is re-run whenever the evaluation label file changes, so these last three rows describe the
label set the primary dataset actually uses (after the retry and reserve passes); the retrieval pair, its
timestamp and its 4.43 h interval are unchanged. 

OpenPhish returned byte-identical content (same SHA-256), so all churn came from URLhaus. Two readings
belong in the paper. First, the negative class is stable in this window: not one domain sampled from the
safe strata had become feed-listed after 4.43 h, which is the evidence that "absent from both feeds"
behaves as a weak negative rather than a random label. Second, the positive class decays slowly at this
resolution but fast over human timescales — 12 of 13 human-confirmed positives had already left the feeds
before collection began, so the feed-labeled population and the human-labeled population are not the same
population.

State the interval. This is an hourly stability measurement, not a weekly one; nothing here measures
decay beyond 4.43 h, and a later retrieval would have to be run to say more. No label is moved by this
comparison: the 9 delisted domains keep their primary `malicious` label, because the label asserted
membership at collection time and was true then.
