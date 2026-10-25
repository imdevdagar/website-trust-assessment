# Website Trust Assessment System annotation protocol and codebook

Version 1.0 — applied to the frozen 146-label set. The executed single-annotator deviation is recorded
in §8.1; the two-person workflow below is the design that would apply if a second rater were available.

This document defines how human labels are produced for the system. It is written so that two
annotators working without a third party can still produce a defensible, reproducible label set. It
also states where the two-person design is weaker than a fully independent adjudication panel and how
that weakness is reported.

---

## 1. Unit of annotation

- **Sampling unit:** registrable domain (for example `example.com`, not `login.example.com`).
- **Assessment shown:** the latest `browse` assessment for that domain. If no browse assessment
  exists, the latest assessment for any action is used.
- **Label scope:** the domain as a typical visitor would encounter it on the supplied URL. A label is
  not specific to one sub-page, one campaign, or one action.
- **Dataset reuse:** the domain label is attached to every eligible assessment of that domain, up to
  the dataset's per-domain limit. Splits are grouped by domain, so multiple assessments of one domain
  never cross train/validation/test boundaries.

The annotation queue contains `sample_id`, `url`, `domain`, and `action`. It deliberately omits the
system verdict, risk score, confidence, evidence cards, screenshots, and any reputation label.
`key.json` contains those fields for the coordinator and must not be opened by either annotator before
both annotation sheets are frozen.

---

## 2. Labels

Three ordinal labels are available:

| Label | Definition | Typical basis |
| --- | --- | --- |
| `benign` | A legitimate site with no material sign of fraud, impersonation, or deceptive intent. Ordinary privacy or security weaknesses may exist. | Known organisation on its official domain; consistent identity; transparent ownership; ordinary content. |
| `suspicious` | Some evidence raises doubt, but the evidence is insufficient, conflicting, or too weak to call the site malicious. | Recent domain asking for credentials; brand-like name without clear impersonation; missing ownership or policy information; unexplained payment flow. |
| `malicious` | Credible evidence of fraud, phishing, impersonation, malware delivery, or a deceptive transaction. | Brand impersonation plus credential collection; fake payment or gift-card demand; wallet seed-phrase request; confirmed phishing kit or feed-listed URL corroborated by the page. |

The labels are intentionally coarse. The system does not ask annotators to distinguish phishing,
malware, and scam subtypes in the primary label. Subtype notes are welcome but are not part of the
ground truth.

### 2.1 What "benign" does not mean

`benign` does not mean "secure", "privacy-respecting", or "trustworthy for every action". A site can be
benign and still have poor security headers, aggressive trackers, or manipulative interface patterns.
Those observations belong in the dimension scores, not in the label. The annotation task is about
fraudulent or deceptive intent and identity legitimacy, not about awarding a general quality grade.

### 2.2 What "malicious" requires

At least one of the following must be supported by what the annotator can see, and the reason must be
written in `notes`:

- impersonation of a brand, government body, or known service on a domain the entity does not control;
- a credential, card, OTP, seed-phrase, or remote-access request in a context inconsistent with the
  claimed identity;
- payment instructions that are characteristic of fraud (gift cards, direct crypto transfer, manual
  command execution);
- clear evidence of malware delivery, deceptive downloads, or a fake software update;
- a public phishing/malware feed match that is corroborated by the live page, not used as the sole
  reason.

A feed match alone is not enough for the primary label because feeds can be stale, typo-squatted, or
compromised. If the live page is unreachable or has been cleaned, label `suspicious` and record the
uncertainty, unless the supplied evidence is independently decisive.

---

## 3. Decision procedure

Annotators follow the same order for every site. The order prevents a visually polished site from
overriding a decisive fraud signal.

1. **Stop conditions.** If the page requests credentials, payment, OTPs, seed phrases, remote access,
   or a download, do not interact. Observe only. If the browser or a security tool blocks the page,
   record the block and label from the available evidence.
2. **Identity check.** Identify the claimed organisation or purpose. Compare the registrable domain
   with the claimed identity. Check the footer, contact page, legal name, and policy links when they
   are visible.
3. **Fraud and security check.** Look for brand impersonation, unsafe credential flows, fake payment
   instructions, suspicious downloads, technical-support lures, and wallet requests.
4. **Privacy and manipulation check.** Note trackers, consent behaviour, pre-checked marketing,
   countdowns, fabricated scarcity, difficult cancellation, and similar patterns. These rarely justify
   `malicious` alone; they may support `suspicious`.
5. **Consistency check.** Does the content, domain, certificate, contact information, and claimed
   location agree? Are there unexplained redirects or mixed identities?
6. **Assign the label.** If evidence is decisive for fraud or impersonation, choose `malicious`. If
   the site is coherent and no material adverse evidence appears, choose `benign`. If there is real
   doubt but not enough for a malicious call, choose `suspicious` and explain what would resolve it.

### 3.1 Evidence to record

`notes` is mandatory for every `suspicious` or `malicious` label and for every disagreement. Use short,
specific phrases:

- `"brand token in subdomain; login form posts to different registrable domain"`
- `"seed phrase requested; no company identity; domain 4 days old"`
- `"official bank domain; valid certificate; consistent contact page"`
- `"unreachable; Cloudflare challenge; could not inspect content"`

Do not paste personal data, credentials, or large page excerpts. Do not include the system's verdict,
because the annotator should not see it.

### 3.2 Confidence

Every row must include a confidence from 0.0 to 1.0. Suggested anchors:

| Confidence | Meaning |
| --- | --- |
| 0.90–1.00 | Decisive, directly observed evidence; another trained annotator would almost certainly agree. |
| 0.75–0.89 | Strong evidence with a minor ambiguity (for example, identity unclear but fraud pattern clear). |
| 0.60–0.74 | Probable, but a reasonable annotator could choose the adjacent label. |
| 0.40–0.59 | Genuine uncertainty; use `suspicious` unless a decisive signal exists. |
| below 0.40 | The page could not be inspected or the evidence is too weak to label. Use `suspicious` only with an explanatory note; do not guess `benign`. |

Confidence is not used as a sample weight in the primary analysis, but it is reported and used to
prioritise adjudication.

### 3.3 Notes that record a failed load

A note such as "unable to load", "site not found", "access denied", "403", or "takes too long" reports
that the page was never inspected. It is not evidence about the site. Such rows are ambiguous under this
codebook, because §2.2 asks for `suspicious` when a *suspected* page is unreachable, while a geoblocked
government or regional site is simply unavailable from this machine.

The coordinator therefore runs a mechanical transport triage before a sheet is frozen
(`scripts/reachability_triage.py`). It records only DNS, TCP, TLS and HTTP status facts and reads no
page content, so it cannot express a trust judgement.

- Domains that answer with content are re-attempted by the annotator and labelled from the page.
- Domains whose server refuses the client (HTTP 401/403/423/451) or never respond are written to a
  `non_inspections.csv` record by `scripts/non_inspections.py`.
- The annotator's label and note are never changed by this record. It only marks the row as not
  inspectable so dataset construction can drop it with `research dataset --exclude-uninspected`, from
  the primary task **and** from the `--include-suspicious` sensitivity analysis.
- The paper reports these domains as a reachability limitation with their transport classification, and
  never as trust judgements or as prevalence evidence.

This applies to the main collection. Pilot rounds 1 and 2 predate the rule and are reported as they
were labelled.

### 3.4 Labelling from the captured page

Reviewing several hundred domains one live tab at a time is the workload bottleneck, so the labeling
form can show the page the crawler already captured for that exact URL. This is a protocol amendment
recorded before batch 2 was labelled, not a change made after seeing results.

```bash
wtas research label-ui \
  --sheet data/annotations/main/batch_02/annotator_a.csv \
  --snapshots data/exports/main/batch_02.jsonl
```

The form joins the annotator's own sheet URL column to the assessment export and serves only the
screenshot. Each capture is classified by content-hash and size (a rendered 1365×1000 viewport normally compresses
to a few hundred kilobytes):

| Badge | Meaning | What the annotator does |
| --- | --- | --- |
| Captured page | A unique capture of ordinary size for this URL. | Judge the page from the capture; open it live for anything the viewport cannot show (below the fold, login walls, interactive flows). |
| Capture shared with other sites | Byte-identical to N other captures, but of ordinary size. | Treat as a shared error or parking page and open the live site. |
| Capture looks blank | Under 8 KiB, whether or not it repeats. | Open the live site, or record a failed load and use §3.3. |
| No usable capture | Nothing was captured. | Open the live site. Use the "No usable capture" filter to batch these. |

Rules that keep this honest:

1. The snapshot panel carries no verdict. It exposes availability, state, byte size and the duplicate
   count — never `overall_risk`, `overall_level`, evidence codes, strata or the coordinator key. A test
   asserts that no decision field or file path appears in the sheet payload.
2. A capture is only reachable through a `sample_id` that exists in the annotator's own sheet, and the
   route requires the annotation token, so an annotator cannot browse another annotator's images.
3. The unit of annotation stays the domain as a visitor meets it (§1). A capture is a convenience, not a
   different object: when a label depends on information a 1365×1000 viewport cannot show, open the site.
4. The paper states what fraction of labels were made from captures rather than live browsing, because
   a viewport screenshot understates pages that reveal intent only through forms or deeper paths.
5. Batch 1 was labelled live, before this feature existed, and is reported that way.

---

## 4. Blinding and independence

1. The coordinator builds the queue with a fixed seed. Each round has its own directory.
2. Annotator A and annotator B receive only their own CSV. They do not share labels, notes, browser
   sessions, or impressions until both sheets are frozen.
3. Nobody opens `key.json` before both sheets are frozen. The key contains rule scores and levels; an
   annotator who sees them can anchor on the system being evaluated.
4. Overlap sites are mixed into both sheets without identifying which sites are shared.
5. A sheet is frozen by copying it to a read-only archive with a timestamp and SHA-256 hash. Corrections
   after freezing are recorded as protocol amendments, not silent edits.
6. The same person may act as coordinator and annotator, but the coordinator must not reveal the key to
   the other annotator. With two people, complete blinding of the coordinator from the rule output is
   impossible; this is a documented limitation.

---

## 5. Pilot rounds

The pilot runs in two rounds before the main collection. Round 1 calibrates the benign boundary on
familiar sites. Round 2 adds ambiguous and malicious candidates, because a benign-only pilot cannot
validate the malicious boundary.

**Round 1 — benign calibration.** 36 established sites from `data/candidates/pilot.csv`. Set overlap to
1.0 so every site is labelled by both annotators:

```bash
wtas research queue --out data/annotations/pilot \
  --assessments data/exports/pilot/round1.jsonl --overlap 1.0 --seed 7
```

**Round 2 — mixed calibration.** 36 additional domains from `data/candidates/round2.csv`, with both
annotators labelling every site:

| Stratum | Domains | Purpose |
| --- | ---: | --- |
| `scam_feed` | 20 | Public phishing-feed candidates. Candidate discovery only; every row is gated. |
| `ambiguous` | 8 | Login-only, legacy, placeholder, small-business, and classifieds pages. |
| `benign_control` | 8 | Established organisations selected to exercise the benign boundary. |
| **Total** | **36** | All are new registrable domains, disjoint from Round 1. |

The stratum name is a sampling frame, not a preassigned label. A further 28 domains are held in
`data/candidates/round2_reserve.csv` for documented replacement if selected candidates cannot be used;
the reserve is not shown to either annotator unless a replacement is approved before labels are frozen.

### 5.1 Candidate manifest and provenance

The manifest is built by:

```bash
wtas research candidates --out-dir data/candidates --seed 11
```

The current manifest records:

- an OpenPhish public-feed retrieval on 2026-10-20, its SHA-256 digest, line count, and filters;
- 300 feed rows, of which 105 distinct registrable domains survived safety and sampling filters;
- the selected feed URLs after query strings and fragments were removed;
- the curated source and Round 1 exclusion files with their SHA-256 hashes;
- an explicit safety record that **no candidate page was opened** while building the manifest.

The builder rejects IP literals, non-standard ports, credentials, local/internal hosts, paths that
look like they contain an email address, and Round 1 domains. It also excludes feed hits on free
hosts, URL shorteners, CDNs, and major multi-tenant platforms (`weebly.com`, `wixsite.com`,
`blogspot.com`, `github.io`, `pages.dev`, `google.com`, and similar). The sampling unit is the
registrable domain; a feed hit on a shared platform would otherwise assign the platform's domain a
label that belongs to a customer page. This is a conservative exclusion and is reported as a
limitation.

Scam-family coverage is assessed after collection. Candidate rows use `candidate_family` only as a
planning hint; feed rows are `unclassified_feed` until a page is inspected. Expected families include
credential phishing, tech-support/remote-access lures, gift-card/crypto/UPI payment fraud, investment
return lures, advance-fee fraud, fake shops, and off-platform contact. Family notes are welcome, but the
primary label remains the coarse codebook label. OpenPhish is phishing-oriented and does not guarantee
balanced coverage of every family; Round 2 is a boundary-calibration slice, not a family benchmark.

### 5.2 Collection gate

`wtas batch` skips every row whose `collection_gate` is
`malicious_page_requires_explicit_confirmation` unless `--allow-gated` is passed. The default command
therefore collects only the 16 ambiguous and benign-control domains:

```bash
wtas batch data/candidates/round2.csv \
  --out data/exports/pilot/round2.jsonl --full --resume
```

The 20 feed candidates are collected only after the team explicitly confirms, using the dedicated
browser profile and safety rules in sections 3 and 10:

```bash
wtas batch data/candidates/round2.csv \
  --out data/exports/pilot/round2.jsonl --full --resume --allow-gated
```

Do not pass `--allow-gated` merely to finish a batch. It is an acknowledgement that the gated stratum
may expose the collector to hostile content. If a gated page is unreachable, cloaked, or cannot be
inspected safely, record that outcome and label it according to this codebook rather than assuming the
feed is correct. If more than 25% of the feed stratum is unusable, replace those candidates from the
reserve before either annotator sees any labels, and record a protocol amendment. Do not use the
reserve after labels have been compared.

The queue for Round 2 is built from the resulting assessments:

```bash
wtas research queue --out data/annotations/round2 \
  --assessments data/exports/pilot/round2.jsonl --overlap 1.0 --seed 11
```

For both rounds:

1. Both annotators label every pilot site independently.
2. Compute observed agreement and quadratic weighted kappa.
3. Review every disagreement against this codebook. Add examples and decision rules where the codebook
   was ambiguous. Do not inspect the rule engine's scores during this review.
4. Freeze codebook version 1.0 and the annotation form. Record each round's agreement separately; do not
   pool pilot labels with the main dataset unless the protocol explicitly says so.

Suggested gates before scaling:

- observed agreement at least 0.80 in each pilot round;
- quadratic weighted kappa at least 0.70 in each pilot round;
- no unresolved definitional ambiguity on `benign` versus `suspicious`;
- both annotators agree on how to handle unreachable, parked, and login-only pages.

If the gate is missed, revise the codebook and repeat the pilot. Do not proceed by simply relabelling
until agreement looks good.

---

## 6. Main collection workload

Target: **400–500 domains**, with **20% double annotation**.

| Quantity | 400 domains | 500 domains |
| --- | ---: | ---: |
| Overlap sites | 80 | 100 |
| A-only + B-only split | 320 | 400 |
| Annotator A rows | 240 | 300 |
| Annotator B rows | 240 | 300 |
| Total labels | 480 | 600 |

At 12–15 sites per hour, each annotator needs roughly 20–25 hours for 300 labels. Spread this over
three to four weeks and stop after 60–75 minutes of continuous labelling; fatigue degrades consistency.

The queue builder uses `round(total * overlap)` for the shared portion and alternates the remaining
sites between annotators. The exact counts are reported in `key.json`.

---

## 7. Agreement analysis

The coordinator runs:

```bash
wtas research agreement \
  --a data/annotations/round1/annotator_a.csv \
  --b data/annotations/round1/annotator_b.csv \
  --key data/annotations/round1/key.json \
  --out data/annotations/round1/agreement.json \
  --markdown data/annotations/round1/agreement.md
```

The report includes:

- number of double-annotated sites;
- observed and expected agreement;
- Cohen's kappa for the nominal three-class label;
- linearly and quadratically weighted kappa, which respect the ordering benign < suspicious < malicious;
- the full 3×3 confusion matrix;
- every disagreement with both labels, confidences, and notes;
- a Landis–Koch style interpretation label.

### 7.1 Interpretation policy

| Quadratic weighted kappa | Action |
| --- | --- |
| >= 0.80 | Strong agreement. Freeze labels after normal adjudication. |
| 0.61–0.79 | Substantial agreement. Adjudicate disagreements; report category-specific confusion. |
| 0.41–0.60 | Moderate agreement. Revisit codebook examples; consider a second calibration round. |
| < 0.41 | Do not freeze. Redefine labels or sampling; the task is not yet reliable enough for supervised evaluation. |

Report both unweighted and weighted kappa. A high observed agreement with a low kappa can occur when one
class dominates; explain the class distribution instead of hiding the paradox. Do not use kappa as the
only quality metric.

---

## 8. Consensus and adjudication

Initial merge:

```bash
wtas research merge \
  --a data/annotations/round1/annotator_a.csv \
  --b data/annotations/round1/annotator_b.csv \
  --key data/annotations/round1/key.json \
  --out data/annotations/consensus.csv
```

Outputs:

- `consensus.csv` — double agreement, resolved adjudications, and single-annotator labels;
- `consensus_disagreements.csv` — unresolved and resolved disagreements, with columns for
  `adjudicated_label`, `resolved`, and both annotators' notes;
- `consensus_summary.json` — counts by source and label, unresolved count, timestamp.

Adjudication procedure for the two-person team:

1. Both annotators jointly revisit each disagreement in a fresh browser session.
2. Re-read the codebook definition and identify which observation is decisive.
3. Record one `adjudicated_label`, a confidence, and a short note in the disagreement sheet.
4. If the two annotators still disagree, leave `adjudicated_label` blank. The sample is excluded from
   consensus by default and counted in the unresolved rate.
5. Do not change the original `annotator_a.csv` or `annotator_b.csv`. Adjudication is a separate layer.

Rerun merge with the completed adjudication sheet:

```bash
wtas research merge \
  --a data/annotations/round1/annotator_a.csv \
  --b data/annotations/round1/annotator_b.csv \
  --key data/annotations/round1/key.json \
  --adjudication data/annotations/consensus_disagreements.csv \
  --out data/annotations/consensus.csv
```

The second run overwrites the consensus files and reports the adjudicated labels as
`source=adjudicated`. Unresolved samples remain excluded. Report the unresolved rate and the label
distribution of excluded samples; do not silently drop a class.

### 8.1 Two-person limitation

> **Superseded for the main dataset.** The executed main collection has one annotator (role A), no
> adjudication, and no inter-rater reliability claim; see
> [main-dataset-protocol.md](main-dataset-protocol.md) v2.2 sections 1–2. This section describes the
> planned two-person design and would apply only if a second rater were available. Do not cite it as a
> description of the executed label set.

The two annotators are also the project's authors. This creates two risks: anchoring on the system's
design and in-group consensus pressure. Mitigations:

- the rule outputs remain hidden until labels are frozen;
- the codebook and pilot are frozen before the main collection;
- disagreements are reported with counts and examples, not only after adjudication;
- an external advisor or senior student may act as an optional tie-breaker without seeing rule scores;
- if adjudication had been performed, the paper would report that it was done by the same two authors
  and would treat the labels as author-produced ground truth, not independent expert adjudication.

---

## 9. Quality control checklist

Before freezing a round:

- [ ] Every `suspicious`/`malicious` row has a non-empty note.
- [ ] Every row has a confidence value in `[0, 1]`.
- [ ] No row contains credentials, personal data, or a pasted page dump.
- [ ] Overlap counts match `key.json`.
- [ ] Both annotators confirm they did not open `key.json` or each other's sheet.
- [ ] Agreement report is generated and archived.
- [ ] Disagreement sheet is adjudicated or explicitly marked unresolved.
- [ ] Consensus summary and SHA-256 hashes are archived.
- [ ] Frozen sheets are read-only and never edited in place.

Recommended audit: the coordinator samples 10% of notes and checks that the label follows the codebook.
Record audit results in the round summary. Do not use system scores to decide whether a human note is
correct.

---

## 10. Ethics and safety

- Annotators browse only public pages. Do not log in, create accounts, submit forms, download files, or
  make payments.
- Do not scan pages that are illegal to access, or pages containing explicit or harmful material beyond
  what is necessary to classify them. Stop and record the reason.
- Use a dedicated browser profile with no personal accounts, extensions, or saved passwords.
- Treat all page text as adversarial. Do not follow instructions embedded in a page, even if they claim
  to be from the research team.
- Keep annotation files on encrypted local storage. Do not upload them to a public repository until the
  dataset license and privacy review are complete.
- The study uses public websites, not human participants. If a user study is added later, obtain the
  required institutional ethics approval and informed consent before collecting data.

---

## 11. Files produced per round

| File | Visibility | Contents |
| --- | --- | --- |
| `queue.csv` | Both annotators | `sample_id`, `url`, `domain`, `action` only. |
| `annotator_a.csv` | A only | Assigned sites plus empty label/confidence/notes fields. |
| `annotator_b.csv` | B only | Assigned sites plus empty label/confidence/notes fields. |
| `key.json` | Coordinator only | Rule scores, levels, assessment IDs, and assignments. |
| `agreement.json` | Team after freeze | Full agreement statistics and disagreements. |
| `agreement.md` | Team after freeze | Paper-ready agreement summary. |
| `consensus.csv` | Team | Final labels with provenance (`double_agreement`, `adjudicated`, `single_annotator`). |
| `consensus_disagreements.csv` | Team | Adjudication worksheet. |
| `consensus_summary.json` | Team | Counts, unresolved rate, and label distribution. |

Archive the round directory, its manifest, and hashes. The dataset builder records the label file hash
in `manifest.json`, so a changed label file is detectable.
