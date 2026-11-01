# Paper outline

Working title: **Website Trust Assessment System: Evidence-Grounded, Action-Aware Assessment of Web Trust**

Alternative titles:

- *Beyond the Padlock: Multi-Dimensional, Evidence-Grounded Website Trust Assessment*
- *Website Trust Assessment System: Auditable Assessment of Web Trust with Calibrated Abstention*

This outline is a writing plan, not a results claim. Every number in the manuscript must be traceable to
a frozen dataset manifest and a run artifact. Placeholders use angle brackets.

---

## 1. Abstract skeleton (200–250 words)

> Web users decide whether to browse, sign up, or pay on a site with little more than a padlock and an
> opaque reputation verdict. We present the **Website Trust Assessment System**, a local-first tool that assesses a website
> along four dimensions — security and fraud, identity and legitimacy, privacy and data, and
> manipulation and deception — and returns auditable evidence rather than a single unexplained score.
> It combines bounded page collection, transport and domain intelligence, form and content analysis,
> tracker and dark-pattern signals, OCR, and injection detection. Dimension scores are weighted by the
> user's intended action; confidence and source coverage determine when the system abstains. We evaluate
> 5,129 samples over 5,129 domains whose primary labels are PhishTank or OpenPhish feed membership at a
> recorded retrieval time, and report 146 frozen human labels from a blinded single-annotator protocol
> as a separate validity subset. All splits are grouped by registrable domain, and reputation-label
> leakage is asserted absent before every build. On the untouched test split (n = 769), a hybrid logistic
> model reaches AUROC 0.987 (95% CI 0.979–0.994) and AUPRC 0.986 (0.974–0.994), against 0.857 for a
> URL-only model and 0.475 for the shipped rule engine across all 5,129 labelled rows. We report
> calibration, risk–coverage, the padlock paradox (87.2% of feed-listed positives serve HTTPS, but only
> 46.3% present a trusted chain), and a controlled 42-pair injection study in which all 40
> hidden-channel pairs reproduce their clean baseline exactly once injection evidence is removed.
> The system is a CPU-only, no-paid-API prototype for advisory use, not a guarantee of safety.

The numbers above are artifact-backed: dataset `feed_v3` (SHA-256 `a1628d24…`), runs in
`data/research/runs/feed_v3`, H4 in `data/research/injection_h4.json`. If any artifact is rebuilt, rerun
`scripts/paper_artifacts.py` and update the abstract from the regenerated table, never by hand. The
earlier `feed_v2` build (830 samples) is a predecessor and is cited only as such.

Do not add a claim for a hypothesis that was not supported. Label-source wording is fixed by
[main-dataset-protocol.md](main-dataset-protocol.md) section 2.2. The positive class is *feed membership*,
not a human judgement, so the primary evaluation must never be described as human-labelled. Never claim
inter-rater agreement (there is one annotator), never describe the benign class as verified clean (it
means "absent from both feeds at retrieval time"), and never report prevalence in the wild.

---

## 2. Contributions

Frame the paper around four defensible contributions:

1. **An evidence-grounded, four-dimensional assessment framework** with action-aware weights, confidence,
   source coverage, abstention, and provenance. The contribution is the integration and auditability, not
   the invention of any single signal.
2. **A leakage-controlled evaluation protocol** for website trust: domain-grouped splits, label-evidence
   exclusion, validation-only calibration/threshold selection, an untouched test set, and grouped
   bootstrap intervals.
3. **An empirical study** on 5,129 labelled domains comparing rule, URL-only, signal, and hybrid models,
   including calibration, risk–coverage, and the padlock paradox.
4. **A safety analysis** of crawling hostile pages, plus hidden-instruction detection and an isolation
   design; optionally, a small user study of evidence cards versus a single score.

Explicitly state what is *not* claimed: web-wide prevalence, guaranteed safety, state-of-the-art
phishing detection, or independent expert ground truth.

---

## 3. Section plan

### 1. Introduction (≈1.5 pages)

- Open with a concrete decision: a user is about to sign up or pay and sees a padlock plus a vague
  reputation signal.
- Explain why a single binary verdict is insufficient: different dimensions, different actions, missing
  evidence, hostile page content.
- State the research questions and contributions.
- Preview the findings with placeholders; do not overclaim.
- One paragraph on the local-first, CPU-only constraint and why it matters for reproducibility and
  privacy.

### 2. Related work and gaps (≈1.5–2 pages)

Organise by gap, not by a chronological list:

1. Phishing detection: URL lexical, content, visual, blacklist, and hybrid methods. Cite CANTINA,
   PhishZoo, PhishNet, and representative surveys.
2. Security indicators and user trust: padlock misconceptions and warning effectiveness. Cite
   Schechter et al., Egelman et al., Felt et al., Fogg et al.
3. Privacy and manipulation measurement: trackers, consent, dark patterns. Cite OpenWPM/Englehardt &
   Narayanan, Mathur et al.
4. Explainability, calibration, and selective prediction: cite Rudin, Guo et al., Geifman & El-Yaniv,
   Platt.
5. Leakage and reproducibility: cite Kaufman et al., Kapoor & Narayanan.
6. Prompt injection and LLM-integrated tools: cite Greshake et al., Perez & Ribeiro.
7. Position the system: an integrated, action-aware, auditable framework with a leakage-controlled
   evaluation. Avoid claiming "first".

End with a short gap table:

| Gap | Existing practice | System response |
| --- | --- | --- |
| Binary verdicts | One phishing score | Four dimensions with separate evidence. |
| Action-blind | Same threshold for browse/pay | Action-specific weights. |
| Forced answers | No abstention | Confidence, coverage, `unknown`. |
| Opaque explanations | Post-hoc attributions | Evidence cards with provenance. |
| Leaky evaluation | Feed labels, random rows | Label exclusion, domain grouping, frozen test. |
| Trusting page text | Raw HTML to an LLM | Data-only extraction, injection detection. |

### 3. Threat model and requirements (≈0.75 page)

- Assets: user context, local data, verdict integrity, host, research artifacts.
- Adversaries: malicious site, cloaking service, prompt injector, third-party script, local attacker.
- Requirements: SSRF resistance, no credential entry, bounded resources, data/instruction separation,
  local-only storage, auditability.
- Summarise the full threat model in an appendix or supplementary artifact; keep the paper section
  focused on requirements that shaped the design.

### 4. System design (≈2.5 pages)

#### 4.1 Architecture

- URL validation → cache → safe crawler → evidence extractors → aggregation → explanation → storage →
  API/extension.
- Include a figure.
- Describe the static fallback and why coverage matters.

#### 4.2 Evidence model

- Typed `Evidence`: dimension, code, title, detail, severity, risk/trust points, confidence, source,
  provenance, tags.
- Merge by `(dimension, code)` to prevent repetition inflation.
- Table of evidence families and representative codes. Do not list all 70+ codes in the body; put the
  full list in an appendix or artifact.

#### 4.3 Dimensions and action weights

- Define each dimension and what it does *not* mean.
- Table of action weights.
- Explain why privacy and manipulation matter more for signup and less for a quick browse; acknowledge
  that these weights are expert-set and should be validated.

#### 4.4 Aggregation, confidence, coverage, and abstention

- Dimension risk formula (weighted risk minus capped trust).
- Severity floors and imported-label floors, with the caveat that label floors are excluded from
  research features.
- Confidence and coverage definitions.
- Abstention conditions and the `unknown` level.
- Overall active-dimension weighting.
- State clearly: the rule score is not a probability.

#### 4.5 Calibration and explanations

- Optional runtime calibration; research Platt calibration on validation only.
- Evidence cards and deterministic headlines/rationales.
- Missing-evidence notes.
- No LLM in the scoring path; prompt-injection controls.

#### 4.6 Safety controls

- SSRF checks per request/redirect, public-IP validation, blocks.
- No form submission, downloads, service workers, media; dialogs dismissed.
- Timeouts, byte limits, concurrency, cache.
- Localhost-only API and extension.
- Point to the threat-model artifact.

### 5. Data and annotation (≈1.5 pages)

- Sampling frame and sources; enrichment for malicious/ambiguous sites.
- Unit of annotation (registrable domain), representative assessment, action profiles.
- Codebook: benign/suspicious/malicious, decision order, confidence anchors.
- **Primary label source: public abuse-feed membership** (PhishTank `online-valid` + OpenPhish; URLhaus
  retired from the pipeline after HTTP 410) at a recorded retrieval time, with feed URLs, SHA-256 digests,
  a 7-day freshness window, and per-source rejection counts. Benign comparisons are drawn from the Tranco
  top-1M pool and are *feed-absent*, never verified clean.
- Human subset: single-annotator blinded workflow, pilot double annotation, delayed intra-rater audit.
  No inter-rater agreement exists and none may be claimed.
- Agreement between the two label sources on their overlap, and what disagreement says about feed
  precision.
- Two-person limitation: the annotators are the project's authors; no independent adjudicator.
- Inclusion/exclusion and timing window; feed domains that could not be crawled are dropped, never
  recorded as benign.
- Dataset table: domains, assessments, label counts, split counts, exclusions.
- Leakage controls: known-label evidence, floors, infrastructure neighbours, suspicious exclusion, plus
  the feed-check assertion that the evaluation feed never entered the runtime label store.
- Dataset and code availability statement; what cannot be released (raw screenshots).

### 6. Evaluation methodology (≈2 pages)

- Research questions and hypotheses (H1–H4).
- Splits: 70/15/15, domain-grouped, label-stratified, fixed seed.
- Models: rule baseline, logistic regression, HistGradientBoosting; feature groups.
- Protocol: fit on train, CV on train, calibrate/threshold on validation, evaluate once on test.
- Metrics: AUROC, AUPRC, Brier, ECE/MCE, thresholded metrics, risk–coverage.
- Bootstrap: 1,000 domain-grouped resamples; percentile 95% intervals; planned paired bootstrap for
  model differences.
- Baselines: HTTPS-only for H1; URL-only for H2.
- Ablations: features, calibration, floors, and optionally evidence families.
- Implementation details: CPU, RAM, Python/Chromium versions, runtime.
- Any deviations from this plan and their reasons.

### 7. Results (≈2 pages)

Order results by hypothesis, not by table order.

#### 7.1 Dataset and agreement

Primary artifact: `data/datasets/feed_v3` (`manifest.json`), labels `data/labels/feed_v3/eval_labels.csv`,
provenance `data/labels/feed_v3/provenance.json`, leakage gate
`data/labels/feed_v3/leakage_check.json` (`passed: true`, 5,511 assessments checked, 0 leaked, runtime
store empty), composition profile `data/research/profile_feed_v3.json`. Every number quoted below is
snapshotted in `data/datasets/feed_v3/artifacts_snapshot/` by `scripts/feed_v3_freeze.py` so a later
crawl cannot silently move it. The predecessor builds `data/datasets/feed_v2` (830 samples / 826 domains)
and `data/datasets/feed_v1` (743 / 742) are retained as lower-scale stages and are cited only as such.

- Primary labels are feed membership at retrieval time (2026-10-25, PhishTank `online-valid` plus
  OpenPhish; URLhaus was retired from the pipeline after returning HTTP 410), not human verdicts.
- **Attrition is a headline fact, not a footnote.** 11,402 crawl rows were read. 5,891 never produced an
  assessment (5,868 unresolvable hostname, 23 hostname resolving to a non-public address) and 382 landed
  on a different registrable domain than their candidate; all were excluded, never relabelled benign.
  5,129 same-domain assessments were kept, one per domain. Of the feed-listed domains, 7,231 yielded no
  usable assessment. The corpus is therefore the *survivors* of the labelled pool, and the paper must say
  so (`data/exports/feed_v3/analysis/exclusions.json`, `paper/tables/table3_dataset_summary.md`).
- 5,129 samples over 5,129 domains: 2,533 malicious, 2,596 benign, one assessment per domain, so samples
  and domains coincide exactly. Domain-grouped 70/15/15 with seed 42 gives train 3,590 (1,773/1,817), val
  770 (380/390), test 769 (380/389). `feed_v3` candidates were drawn disjoint from the 146 frozen human
  labels by construction, so the human-label exclusion rule had nothing to exclude in this build.
- Positives came from 1,389 selected plus 724 reserve and 420 fixed-ranking top-up candidates, and 111 of
  them were recovered by the pre-registered root-URL retry. Gate compliance was re-checked over all 141
  candidate/export pairs (`data/research/gate_compliance_feed_v3.json`, `passed: true`): every scored
  positive maps to a gated candidate, and no reserve row was scored in an ungated run.
- Class balance is near 1:1 (2,533 / 2,596), and `benign` means *absent from both feeds at retrieval
  time*, never *verified clean*; state both.
- Agreement is between two label **sources**, not two raters: on the 4-domain overlap of the frozen human
  labels with the predecessor `feed_v2` feed labels, observed agreement is 0.25 and Cohen kappa 0.0, which
  is not interpretable because the feed marginal is constant. Report the confusion table
  (`data/labels/feed/human_vs_feed_final.json`) and the transience finding instead: only 1 of the 13
  human-malicious domains is still listed in either feed.
- The delayed 15% intra-rater audit on the human subset, if run, is reported separately and never
  described as inter-rater reliability.
- **Label transience is measured only on the predecessor.** A second retrieval 4.43 h after the primary
  one (`data/labels/feed/churn/churn_report.json`, labels `data/labels/feed/churn/labels_t2.csv`) still
  listed 540 of the 549 `feed_v2` labelled domains (98.4% retained; 9 delisted, 11 newly listed). Of the
  496 domains that evaluation scored positive, 488 (98.4%) remained listed, and none of its 330 derived
  negatives became listed in that window. OpenPhish bytes were unchanged between retrievals (identical
  SHA-256), so all churn came from URLhaus. That artifact measures `feed_v2`, not the primary set.
- **`feed_v3` label durability is unmeasured, not assumed high.** One second retrieval was attempted on
  2026-11-01 with `scripts/feed_v3_churn.py`; PhishTank answered HTTP 429 on all five backoff attempts and
  the script aborts rather than recording a partial fetch, because a truncated feed would otherwise be
  read as mass delisting. Report the predecessor figure as a stability property of the *label source at
  hourly, not weekly, resolution* and state that the primary set has one retrieval timestamp.

#### 7.2 H1: Padlock paradox

- **87.2% of the 2,533 feed-labelled malicious samples were served over HTTPS**
  (`data/research/profile_feed_v3.json`, `malicious.https_share`;
  `paper/tables/table6_https_prevalence.md`). The padlock is present on most live phishing and
  malware-distribution infrastructure, so transport security alone is not a usable trust signal. The
  trusted-chain rate is far lower (46.3% of the same positives) than for the feed-absent class (85.7%),
  which separates "has a certificate" from "the certificate verifies" — do not conflate them. Note the
  direction: malicious sites present HTTPS *more* often than the benign comparison class (87.2% vs 74.0%),
  which is exactly why the padlock misleads.
- **Padlock-only baseline (test, n = 769):** a rule that flags a site when HTTPS is absent reaches
  AUROC **0.416 [0.389, 0.445]**, precision 0.271, recall 0.103, F1 0.149 — worse than chance.
  Requiring a trusted chain lifts the same rule to AUROC **0.635 [0.604, 0.668]**, precision 0.656,
  recall 0.553, still far below page signals (0.979). The HTTPS-only rule is the pre-registered padlock
  baseline; the trusted-chain rule is descriptive and was not pre-registered. Intervals: 1000
  domain-grouped bootstrap resamples; `data/research/profile_feed_v3.json` →
  `transport_rule_baselines`.
- The `url_https` coefficient in the URL-only logistic model is *positive* toward malicious in this set
  (+0.371, standardised), consistent with the padlock-paradox direction above: on feed membership,
  "uses HTTPS" is not a protective feature.
- Do not claim causation about user behaviour without the user study.

#### 7.3 H2: URL-only vs signals vs hybrid

Artifact: `data/research/runs/feed_v3/report.md` (test split, 1000 bootstrap resamples,
domain-grouped; snapshotted in `data/datasets/feed_v3/artifacts_snapshot/runs/`).

| Feature group | Rule engine AUROC | Logistic AUROC [95% CI] | HistGB AUROC | Logistic AUPRC |
| --- | ---: | ---: | ---: | ---: |
| `url` (21) | 0.455 | 0.857 [0.829, 0.883] | 0.881 | 0.840 |
| `signals` (80) | 0.455 | 0.979 [0.967, 0.989] | 0.991 | 0.977 |
| `rule` (36) | 0.455 | 0.964 [0.950, 0.977] | 0.983 | 0.956 |
| `hybrid` (116) | 0.455 | **0.987** [0.979, 0.994] | **0.993** [0.988, 0.997] | 0.986 |

- The headline is the baseline: the shipped rule engine does not separate the classes at all. Across the
  2,533 labelled positives it placed 1,321 in low, 1,183 in medium, 29 in high and 0 in critical
  (**1.1% recall at high-or-critical**, 47.9% at medium-or-above, mean risk 0.218 on the stored 0-1
  scale) while raising 27 of 2,596 benign domains (1.0%). Its AUROC is **0.475 over all 5,129 labelled
  rows** and 0.455 [0.410, 0.494] on the test split — an interval that excludes chance. A learned model
  on the same features reaches 0.987/0.993 AUROC. Report recall, precision and F1 at the calibrated
  threshold, not AUROC alone: hybrid logistic F1 0.966 (P 0.973, R 0.958), HistGB F1 0.967
  (P 0.976, R 0.958).
- **The engine's own threshold degenerates.** Validation selects raw threshold 0.0 for the engine, i.e.
  "escalate almost everything" (test recall 1.000 at precision 0.494, which is exactly the class prior,
  accuracy 0.494) — the F1-optimal operating point for a score that cannot rank. Say this explicitly: it
  is a statement about the shipped policy, not a misconfiguration in the experiment.
- Calibration: hybrid logistic test ECE 0.018 (Platt slope 1.027 — the raw probability was already close
  to calibrated), HistGB 0.014 (slope 0.748). For the engine the pipeline **refuses to calibrate**: Platt
  is skipped and recorded on *both* seeds (`fitted: false`, "validation scores were not positively
  associated with labels"), so its raw and calibrated test ECE are both 0.319. Report this as the
  mechanism-level statement of "calibration cannot rescue a ranking that does not separate the classes":
  the code enforces it instead of merely asserting it.
- Risk–coverage: at 50% coverage hybrid logistic accuracy is 0.995 and HistGB 1.000, versus the rule
  engine at **0.471** — below the 0.494 class prior, i.e. the engine's most confident half of predictions
  is its worst half. Its accuracy never leaves the 0.471–0.546 band at any coverage level. That is a
  stronger and more concrete version of the AUROC claim; lead with it.
- **Robustness (pre-registered sensitivity run).** Re-drawing the domain-grouped split with seed 43
  (`data/research/runs/feed_v3_s43`) leaves the conclusion intact: hybrid logistic AUROC 0.988 and HistGB
  0.993, while the engine stays at 0.475 over all labelled rows and 0.473 on that run's test split — still
  below chance. The predecessor `feed_v2` build additionally ablated its negative stratum (dropping the
  main batch 02 assessments reused as negatives, 73 derived negatives,
  `data/research/runs/feed_v2_no_batch_02`); that ablation has **no `feed_v3` counterpart**, because this
  build's benign class is drawn from the Tranco top-1M pool under the recorded protocol rather than from a
  reused stratum. Quote the all-labelled engine figure as the stable one and report the test-split figure
  alongside it; do not present whichever number suits the argument.
- **Data sufficiency (train-only learning curve).** Answer the reviewer's first question with evidence:
  `data/research/learning_curve_feed_v3.json` (rebuilt by `scripts/learning_curve.py`) re-draws five-fold
  domain-grouped CV inside the training split, subsamples whole domains per class, and pools out-of-fold
  predictions; the validation and test splits are never scored. Logistic AUROC is 0.975 at 287 training
  domains per fold, 0.985 at 1,436 and **0.987 at 2,872**; HistGB is 0.985, 0.991 and **0.993**. Doubling
  from 50% to 100% buys +0.002 for both, and the full-size pooled logistic estimate reproduces the run's
  grouped-CV 0.987 within 0.00013. Quote this as saturation: at this scale data volume is no longer the
  binding constraint on these models, so the remaining gap is a property of the label population, not of
  sample size.
- Ablation reads url → signals → hybrid; state clearly that hybrid includes rule outputs as features, so
  it is a superset comparison, not an independent model family.
- Circularity control: the feed verdict never enters these features (`research feed-check` passes on the
  5,511 readable assessments, runtime label store empty, `--allow-leakage` never used). The models are
  scored on page and URL evidence only.


#### 7.4 H3: Evidence cards (if the study was run)

- Participant counts and demographics (aggregate, no identifying data).
- Appropriate reliance, calibration, time, perceived usefulness.
- Effect sizes and intervals; acknowledge limitations.
- If the study was not run, omit the causal claim and report the heuristic evaluation separately.

#### 7.5 H4: Injection isolation

Artifact: `data/research/injection_h4.json` (`research injection-build`, then `research injection-eval`;
the corpus itself is `data/injection_fixtures/`). It is 42 locally authored page pairs — 26 carrying a
hidden instruction aimed at an automated reviewer, 16 carrying none — produced by rendering one of six
realistic page bodies twice, once with an empty slot and once with that slot filled, so "only the hidden
instruction text was added" is a property of the generator and is asserted in
`tests/test_injection_isolation.py` rather than assumed. Ground truth is content, not model output, and
five of the negatives are deliberately *adversarial*: ordinary text that a keyword detector is expected
to mistake for an instruction. They stay in the precision denominator. Pages are scored through the
production static parse path with the page-derived extractors only (no network enrichment), so absolute
levels sit below a live assessment and every claim below is a within-pair comparison.

**Detection.** 23 of 26 hidden instructions are recorded as `hidden_prompt_injection` or
`encoded_instruction_blob` (recall 0.885). Precision is 0.958 overall and 1.0 on the 11 straightforward
negatives. The single false positive is an AI-tooling vendor's own SEO keyword list ("prompt system
templates, system message library") matching `system_prompt_reference`; it adds an evidence item and
still leaves that page `low` and allowed. Counting the obfuscation codes as detections takes recall to
26/26 with precision 0.963, because every keyword miss leaves a trace.

**The misses are the designed evasions.** Two zero-width-split instructions and one bidi-reversed
instruction fire `zero_width_obfuscation` / `bidi_control_spoofing` while the literal keyword patterns
fail. Normalising those characters out of the hidden channels before matching recovers 2 of 3; the bidi
case stays missed because its words are reversed, not merely interleaved. This is the honest ceiling of
keyword matching, reported as a gap.

**Score isolation.** For all 40 hidden-channel pairs, re-scoring the injected page after dropping the
four injection-related evidence codes reproduces the baseline exactly: identical overall risk (maximum
residual delta 0.0), identical per-dimension scores, identical guard verdict, and no other evidence code
appears or disappears. Whatever the instruction changed, it changed only the evidence recorded about it.
The visible-text control behaves the same way in the other direction: a documentation page quoting the
same attack phrases visibly is not flagged, because the detector reads hidden channels only.

**No obedience, bounded escalation.** Across all 42 pairs no fixture gained a trust point, no overall
risk fell, and no verdict was relaxed toward `allow`. The evidence moves assessments in the conservative
direction only: 17 of 42 go from `low`/`allow` to `medium`/`warn` (median +37.6, maximum +40.5 overall
risk points, of which at most 27 come from the evidence item itself — the remainder is the
HIGH-severity floor the scoring rules apply), and none reaches `high`, `critical` or `block`. Six
detected instructions do not change the verdict at all (+2.1 overall): a single non-strong pattern is
capped at 12 risk points at confidence 0.7, so detection and escalation are separate, bounded decisions.
Every baseline is `low`/`allow` (mean overall risk 3.7/100), so these deltas are not measured against
already-warned pages. `research injection-eval` exits non-zero if any of the eight gate conditions in
`gate` fails.

**Not covered.** Version 1.0 has no LLM in the scoring path, so H4's raw-HTML-versus-structured-evidence
attack-success comparison is not run and stays future work. What is measured is the weaker, defensible
claim: instruction-like content is detected, attributed to the manipulation dimension, and cannot
otherwise influence the score or the verdict.

#### 7.6 Error analysis

Artifact: `data/research/error_analysis_feed_v3.json` (`scripts/error_analysis.py`, snapshotted in
`data/datasets/feed_v3/artifacts_snapshot/`). The script re-derives per-sample probabilities from the
stored logistic artifacts and reproduces the reported test confusion exactly for all four feature groups
(`tp/fp/fn/tn` matched, `reproduction_ok: true`) before extracting errors, so the examples below are the
same predictions the metrics were computed from; the script exits non-zero if they ever diverge.
Categories are computed from recorded evidence codes and feature values, never assigned by hand. Domains
carrying the derived `benign` label are hashed to neutral handles (`benign-<10 hex>`); feed-listed
positives are named, because they are already public in the feed and naming a small legitimate site would
add risk without adding evidence. The predecessor builds (`error_analysis_feed_v2.json`,
`error_analysis_feed_v1.json`) produced the same reading at lower scale.

Test split: 769 samples (380 malicious / 389 benign).

| Model, at its selected threshold | Errors | FP | FN | What the errors are made of |
| --- | ---: | ---: | ---: | --- |
| shipped rule engine, escalation at high-or-critical | 381 | 5 | 376 | recall at escalation 0.011 on this split (1.1% over all 2,533 positives, §7.3) |
| logistic, `url` only | 161 | 79 | 82 | FN `unsafe_delivery_mechanics` 55, `no_email_configuration` 50, `established_host_appearance` 46; FP `unsafe_delivery_mechanics` 67, `established_host_appearance` 57, `hidden_iframe_present` 35 |
| logistic, `signals` | 36 | 20 | 16 | FN `established_host_appearance` 13, `feed_reported_url_on_established_host` 13, `unsafe_delivery_mechanics` 10 |
| logistic, `rule` features | 71 | 42 | 29 | FN `established_host_appearance` 24, `feed_reported_url_on_established_host` 24, `tls_absent_or_invalid` 15 |
| logistic, `hybrid` | 26 | 10 | 16 | FN `established_host_appearance` 13, `feed_reported_url_on_established_host` 13, `unsafe_delivery_mechanics` 13 |

- **The hybrid misses are dominated by one mechanism: label granularity, not perception failure.** 13 of
  the 16 missed positives carry `feed_reported_url_on_established_host`. `pinterest.com` is the starkest
  case — engine risk 0.009, band `low`, model probability 0.421 just under the selected 0.554 threshold,
  and its only two recorded categories are `established_host_appearance` and
  `feed_reported_url_on_established_host`. The feeds report a *URL*; the sampling unit is the registrable
  *domain*; a domain that hosts a reported payload can look entirely ordinary at its root. Other misses
  show the same shape on quieter hosts (`bondevision.com` probability 0.324, `rbfcu.org` 0.317,
  `tunnelsnakes.com` 0.021), and a few are near-misses the model scored above 0.4 but below the threshold
  (`angelnidoresort.com` 0.524). Report the granularity limit as a property of the *label source*, and
  note that a URL-level evaluation would change these specific counts.
- **The false positives are label noise by construction, and there are only ten of them.** The negative
  class was sampled from the safe strata before any verdict existed, and `benign` means *not reported*.
  `benign-ca2fe1f6e2` (probability 1.000) is a shared/free host with a brand claim, no email
  authentication, an invalid chain and a payload path — and it already escalates to `high` in the shipped
  engine. `benign-6e71583950` (1.000) and `benign-bee90ccbfe` (0.993) are credential-form and
  unsafe-delivery profiles with almost nothing else recorded, the shape of a campaign host that has
  already been taken down. `benign-fda59dd4b2` (0.650) also already escalates to `medium`. Two of the ten
  are escalated by the engine itself, so this is not a learned-model quirk. The protocol's rule that an
  unreachable *feed* domain is dropped rather than called benign is the correct handling of the same
  ambiguity from the other side; say so, and report these errors as a property of feed-absence negatives
  rather than purely as model failure.
- **What the engine sees but does not escalate.** Across the 376 missed positives the mechanisms it
  recorded are `unsafe_delivery_mechanics` 268, `no_email_configuration` 245, `unreachable_at_capture`
  193, `established_host_appearance` 185, `feed_reported_url_on_established_host` 185,
  `tls_absent_or_invalid` 166, `thin_capture_low_evidence` 135, `brand_claim_mismatch` 106,
  `domain_age_unknown` 73, `email_authentication_missing` 63. The engine is not blind to these pages; its
  scoring policy does not convert them into a warning. That is the gap the learned models close on
  identical features, and it is a statement about the shipped policy.
- **Injection surface in the wild set.** Across all 5,129 dataset-scope assessments `hidden_prompt_injection`
  appears on 20 domains, of which 1 is a feed-labelled positive — **0.04% of the positives** — while
  `hidden_iframe` appears on 1,192 domains (232 positives, 9.2% of them) and is among the categories of 27
  of the engine's missed positives (`data/research/profile_feed_v3.json`, `injection_surface`). Report the
  injection detection results from the controlled set in §7.5 and use these counts only to state the
  natural prevalence of the surface — do not infer attack success from them.
- Limitations to state with this section: the taxonomy is derived from the engine's own evidence codes, so
  a mechanism the engine cannot observe is invisible to the analysis; errors are per registrable domain, so
  a host that serves both legitimate and reported payloads is counted once; and the benign-side examples
  cannot be verified as actually benign, only as unreported.

### 8. Discussion (≈1.25 pages)

- What the results mean for multi-dimensional trust assessment.
- The cost of abstention and missing coverage.
- The padlock's limited role.
- The value and limits of evidence cards.
- Why action-aware weighting is a design hypothesis, not a validated truth.
- Deployment cautions: false positives, small sites, warning fatigue, local security.
- What would be needed for a production system: larger representative data, temporal validation,
  multi-vantage crawling, independent adjudication, authentication and sandboxing.

#### 8.1 Why the shipped policy is the rule engine, not the 0.987 model

A reviewer will ask this first, so answer it with artifacts rather than preference. Five reasons, in
descending order of force:

1. **The learned model is measured on a proxy label, and the proxy has a known unit error.** The label is
   feed membership at one retrieval time. PhishTank and OpenPhish report a URL; the evaluation unit is the
   registrable domain. 185 of the 376 positives the engine missed on the test split carry
   `feed_reported_url_on_established_host`, and 13 of the 16 hybrid false negatives carry it — a reported
   payload on a domain whose root looks ordinary (`pinterest.com` is the extreme case, §7.6). A
   classifier trained on this label learns that error as signal. The rule engine does not claim to resolve
   it either; that is why its verdicts are advisory and expose evidence.
2. **The label decays faster than a model can be validated.** Only 1 of the 13 human-malicious domains was
   still listed at retrieval time, and in the predecessor's measured window 8 of its 496 evaluation
   positives were delisted 4.43 h later (`data/labels/feed/churn/churn_report.json`). No second retrieval
   has been measured against `feed_v3`: the one attempt aborted when PhishTank returned HTTP 429, so its
   durability is unmeasured, not assumed high. A frozen classifier cannot express "this label may be
   stale"; an evidence card can show the observation date of every signal and abstain when coverage is thin.
3. **The headline AUROC rests on two splits of one retrieval.** Test n = 769, no temporal split, no
   external validation, no independent label source. The seed-43 re-split moves the hybrid logistic AUROC
   from 0.987 to 0.988 and the engine's test AUROC from 0.455 to 0.473, while its all-labelled figure
   stays at 0.475 over all 5,129 rows — so the ordering is robust and the engine's failure is not a split
   artifact. What is *not* robust is the construct: the train-only learning curve is saturated (+0.002
   from 50% to 100% of the training domains), which means more data of this kind will not close the
   remaining gap. A 0.987 test estimate under a proxy label is a promising result, not a deployment case.
   The paper reports it as the former.
4. **Auditability is a product requirement here, not a preference.** The runtime emits typed evidence with
   provenance, merges by `(dimension, code)`, and can point to the observation behind every risk point.
   The API does not load the research artifacts as its decision policy (model card §1). Shipping a
   learned score would replace an auditable chain with a coefficient vector whose largest standardised
   weights are dimension aggregates the engine itself produced (`security_confidence` −2.689,
   `risk_medium_count` −2.126, `security_coverage` +1.655, `overall_rule_risk` −1.466) and in which
   `url_https` enters *positively* toward malicious (+1.127) — a real pattern in this label population,
   but one the interface would have to explain rather than assert. That does not make the model wrong; it
   makes it a different claim than the one the interface makes.
5. **The engine's chance-level ranking is reported, not hidden.** Its AUROC is 0.475 over all 5,129
   labelled rows (0.455 on the test split, interval excluding chance), its recall at high-or-critical is
   1.1%, and at 50% coverage its accuracy is 0.471 — below the 0.494 prior. That is the empirical
   case for a second-stage learned model, and the paper says so. The defensible next step is an optional,
   calibrated second opinion shown behind the evidence and evaluated with a URL-level, temporally split
   protocol, not a silent replacement of the verdict.

State the scope: nothing above argues that the learned model is invalid; it argues that the evaluation
does not yet license shipping it as the sole decision policy.

### 9. Limitations and threats to validity (≈1 page)

- Construct, internal, external, statistical, and conclusion validity from the research plan.
- **Survivorship, not size.** The corpus is 5,129 domains, but it is the survivors of 11,402 crawl rows:
  5,891 never produced an assessment and 382 redirected off-domain, and 7,231 feed-listed domains yielded
  nothing usable. Whatever is unassessable is systematically absent from the evaluation.
- Convenience sampling from two feeds plus the Tranco top-1M; no claim of population prevalence.
- One label source and one retrieval timestamp; `feed_v3` durability unmeasured (the retry aborted on
  HTTP 429). 146 human labels from a single annotator are a validity subset, not an independent label.
- Snapshot and cloaking; a single crawl vantage point.
- No temporal split and no external validation set.
- Synthetic smoke tests are not results.

### 10. Ethics statement (≈0.4 page)

- Public pages only; no credential entry; no downloads.
- Local data storage; no telemetry.
- Human-subject approval and consent if H3 was run.
- No naming and shaming; aggregate reporting.
- Responsible disclosure and dual-use considerations.

### 11. Conclusion (≈0.4 page)

- Restate the problem and the design.
- Summarise supported findings only.
- State the open problems: independent labels, representative sampling, temporal drift, multi-vantage
  crawling, and robust isolation for LLM-assisted explanations.

### Appendix

- Full evidence-code table.
- Feature definitions and schema version.
- Annotation codebook summary.
- Hyperparameters and software versions.
- Additional calibration/risk–coverage tables.
- Prompt-injection construction details.
- Reproducibility commands and artifact hashes.
- Ethics materials (if applicable).

---

## 4. Figures and tables

Data figures and empirical tables are generated by `scripts/paper_artifacts.py`, which asserts the
dataset hash, split counts, error-analysis reproduction, H4 gate and learning-curve anchor before
writing anything. Captions are
in `paper/figure-captions.md`; every empirical caption states the split, sample size, and interval method.

| ID | Item | Source |
| --- | --- | --- |
| Fig. 1 | System architecture and trust boundaries | `paper/figures/fig1_architecture.pdf` from `docs/threat-model.md` (diagram, no data). |
| Fig. 2 | Dashboard verdict and evidence card | `paper/figures/fig2_dashboard.png` (3x local demo capture of example.com; no participant data). |
| Fig. 3 | Dataset composition and split counts | `paper/figures/fig3_dataset_composition.pdf` from `manifest.json`. |
| Fig. 4 | Human-label/feed overlap and feed-label retention, **both measured on the predecessor `feed_v2` label set** | `paper/figures/fig4_label_sources.pdf` from `human_vs_feed_final.json`, `churn_report.json`. |
| Fig. 5 | Reliability diagram (raw engine vs calibrated hybrid) | `paper/figures/fig5_reliability.pdf` from `run.json`. |
| Fig. 6 | Risk–coverage curves | `paper/figures/fig6_risk_coverage.pdf` from `run.json`. |
| Fig. 7 | Ablation AUROC/AUPRC with intervals | `paper/figures/fig7_ablation.pdf` from `run.json`. |
| Fig. 8 | H4 paired risk and bounded escalation | `paper/figures/fig8_injection.pdf` from `injection_h4.json`. |
| Fig. 9 | Train-only learning curve (hybrid logistic and HistGB) | `paper/figures/fig9_learning_curve.pdf` from `learning_curve_feed_v3.json`. |
| Table 1 | Dimensions and representative evidence | Code/knowledge files; author table, not auto-generated. |
| Table 2 | Action weights | `paper/tables/table2_action_weights.md` from `scoring/rules.py`. |
| Table 3 | Dataset and collection summary | `paper/tables/table3_dataset_summary.md` from the manifest. |
| Table 4 | Main test results with 95% CIs | `paper/tables/table4_main_results.md`. |
| Table 5 | Ablations | `paper/tables/table5_ablation.md`. |
| Table 6 | H1 HTTPS and trusted-chain prevalence, plus padlock-only test baselines | `paper/tables/table6_https_prevalence.md`. |
| Table 7 | Error categories and reproduction check | `paper/tables/table7_errors.md`. |
| Table 8 | Runtime and resource use | `paper/tables/table8_runtime.md` + `.json`. |
| Table 9 | Pre-registered sensitivity runs | `paper/tables/table9_sensitivity.md`. |
| Table 10 | Learning curve points, train-only grouped CV | `paper/tables/table10_learning_curve.md` from `learning_curve_feed_v3.json`. |

Regenerate with `PYTHONPATH=. python scripts/paper_artifacts.py`. Do not paste a number from a notebook
into the manuscript; add it to an artifact and let the script render it. The script refuses to run if
`data/datasets/feed_v3/dataset.jsonl` no longer hashes to the value recorded in the run, if any split
count disagrees with the manifest, if the error analysis no longer reproduces the confusion, if any H4
gate check fails, or if the learning curve no longer reproduces the run's grouped-CV estimate.

Every empirical figure must have a caption that states the split, sample size, and interval method. Do
not use a screenshot that reveals a participant's browsing data.

---

## 5. Claims–evidence map

Use this table as a submission checklist. If a claim has no artifact, remove it.

| Claim | Evidence | Status |
| --- | --- | --- |
| Four dimensions with separate evidence | Schema, extractors, UI | Implemented; describe. |
| Action-aware aggregation | Weight table, code | Implemented; weights are expert-set. |
| Confidence and abstention | Scoring code, risk–coverage | Implemented; evaluate. |
| Evidence provenance | Evidence cards, UI | Implemented; optional user study. |
| No label leakage | Leakage exclusion, manifest | Implemented; audit in paper. |
| Domain-grouped evaluation | Dataset manifest, training checks | Implemented. |
| CPU-only, no paid API | Runtime log, dependency list | Implemented; report. |
| Padlock paradox | H1 analysis (§7.2) | Measured: 87.2% of 2,533 feed positives serve HTTPS, only 46.3% with a trusted chain; HTTPS-only rule AUROC 0.416 [0.389, 0.445]. |
| Signals beat URL-only | H2 test (§7.3) | Measured: url-only 0.857 vs page signals 0.979 vs hybrid 0.987 test AUROC. |
| Shipped engine ranks the classes | §7.3, Table 4 | Measured, and it does not: AUROC 0.455 [0.410, 0.494] on test, 0.475 over all labelled rows, 1.1% recall at escalation. |
| Training set is large enough | Learning curve (§7.3, Table 10) | Measured: 50%→100% of training domains buys only +0.002 for both hybrids; curve saturated. |
| Evidence cards help users | H3 study | Optional; do not claim without data. |
| Injection isolation | H4 detection/invariance (§7.5) | Measured on a controlled 42-pair corpus; isolation gate enforced in code. |
| Safe crawling | Threat model, tests | Implemented; report residual risk. |

---

## 6. Venue strategy

Choose a venue that matches the evidence, not the ambition. A 5,129-domain convenience sample with
feed-derived labels, heavy collection attrition, and a single-annotator validity subset is not a
USENIX Security-scale evaluation.
Realistic options:

- **Primary journal:** *Computers & Security* (Elsevier) or *Journal of Cybersecurity* (Oxford).
  Confirm whether the chosen route has a mandatory article-processing charge; do not commit to a fee
  without institutional support.
- **Primary conference/workshop:** a peer-reviewed security or web conference workshop (for example,
  an APWG eCrime or ARES workshop) where a system-and-evaluation paper with a modest dataset fits.
- **Stretch:** *IEEE TIFS*, *ACM TOPS*, *NDSS*, or *USENIX Security* only if the dataset, user study, and
  external validity are substantially stronger than the plan above.
- **Avoid:** venues that promise rapid acceptance, hide fees, or lack credible peer review. Check
  indexing and the venue's ethics/policy pages.

Before submission, confirm:

- page limit and formatting;
- anonymity requirements and artifact appendix rules;
- ethics/human-subjects statement;
- data availability policy;
- conflict-of-interest and funding statements;
- whether a preprint is allowed.

---

## 7. Writing schedule

| Draft | Target date | Contents |
| --- | --- | --- |
| Outline + claims map | End of month 3 | This document updated with actual dataset features. |
| Method + data draft | End of month 4 | Sections 3–6, dataset tables, figures 1–4. |
| Full draft v0.5 | Week 18 | All sections with placeholder results. |
| Results-complete draft | Week 19 | Final numbers, intervals, ablations, error analysis. |
| Internal review v0.8 | Week 19–20 | Advisor/peer review, consistency check. |
| Submission candidate | Week 21–22 | Formatting, citations, artifact appendix, ethics. |
| Camera-ready/revision | After decision | Address reviewers; archive release. |

Writing rules:

- One claim per paragraph; no suspense.

---

## 8. Reviewer questions and prebuttals

1. **"Isn't this just a rule engine?"**
   - The contribution is the integrated evidence model, action-aware aggregation, abstention, auditability,
     and the leakage-controlled evaluation. Learned models are compared as well. The paper does not claim
     that rules are state of the art.
2. **"Why only 400–500 domains?"**
   - It is a final-year project with one annotator and no funding; full-page human inspection does not
     scale to a positive class that is mostly hostile or unreachable. Report intervals, avoid subgroup
     claims, and provide the full protocol so the study can be scaled. Do not claim prevalence.
3. **"Aren't the labels biased?"**
   - Yes, in two distinct ways, and both are measured. The human subset is single-annotator and the
     annotator is a system author, so it supports no independence claim. The primary labels are feed
     membership, which biases toward reported phishing and malware-distribution infrastructure, has no
     suspicious tier, treats feed absence as benign, and ages between retrieval and crawl. The paper
     reports the feed/human disagreement rate as the observable proxy for feed precision.
4. **"Isn't using the same feeds that a reputation feature also uses circular?"**
   - The verdict path is closed and asserted, not assumed: the feeds are never imported into the local
     `domain_labels` store, which is the only route by which a stored verdict becomes scored
     `known_malicious_label` evidence worth 55 risk points. `research feed-check` reruns the leakage
     audit on every build and the dataset builder refuses leakage by default.
5. **"Why not annotate the malicious sites yourselves?"**
   - Because a label produced by inspecting a hostile page is exactly the step this project cannot do
     honestly at scale, and guessing labels to fill a column would invalidate the dataset. Feed
     membership is a disclosed, reproducible proxy instead.
6. **"How do you know features don't leak labels?"**
   - Known-label evidence, floors, and infrastructure neighbours are excluded; the manifest records the
     leakage audit. Reputation labels are not in the feature schema.
7. **"Is the evaluation reproducible?"**
   - Domain-grouped splits, fixed seeds, dataset/manifest hashes, run artifacts, and a clean-machine
     reproduction gate. The release includes commands and versions.
8. **"Does the system actually help users?"**
   - Only claim this if H3 was run with ethics approval. Otherwise present the interface as a design
     contribution and call for a user study.
9. **"What about cloaking and false positives?"**
   - Both are discussed as limitations. The system reports observations and uncertainty, not ground
     truth. Error analysis is included.
10. **"Is crawling malicious pages ethical/safe?"**
   - Public pages only, no form submission, no credential entry, no downloads, bounded browser, and a
     documented threat model. Human annotators follow stop conditions.
11. **"Why four dimensions?"**
   - They map to distinct user questions and evidence sources; the ontology is a design choice, not a
     validated psychological model. Ablations and future factor analysis can test it.
12. **"Why not use a large language model?"**
    - The current path is deterministic and CPU-only for reproducibility and prompt-injection
      isolation. An LLM narration experiment is future work with a separate threat model.
13. **"If the learned model reaches 0.987, why ship the 0.475 rule engine?"**
    - See §8.1. The label is a decaying proxy with a URL-to-domain unit error, the headline is one
      retrieval split into two seeds, and the runtime's contract is an auditable evidence chain. The
      learned model is an evaluation artifact; the path to shipping it is a URL-level, temporally split
      evaluation and a calibrated second opinion behind the evidence, not a silent replacement.
14. **"Then the dataset is 6× bigger and your engine still ranks at chance — is the engine broken?"**
    - Yes, against this label, and the report says so rather than hiding it: 0.455 [0.410, 0.494] on the
      test split, an interval that excludes chance, and 0.475 over all 5,129 labelled rows on both seeds.
      Growing the set sharpened the negative result instead of rescuing the engine. The engine's own
      F1-optimal validation threshold is 0.0 — "escalate everything" — which is the signature of a score
      that cannot rank. What the engine *does* provide is the evidence chain the learned model consumes:
      on identical features the learned model reaches 0.987, so the information was observed and the
      policy did not act on it (§7.3, §7.6).

---

## 9. Final submission checklist

- [ ] Every number traces to a run artifact and dataset hash.
- [ ] Test set was evaluated once for the final configuration.
- [ ] Kappa and agreement report included.
- [ ] Dataset composition and exclusions table included.
- [ ] Leakage controls described and audited.
- [ ] Calibration and risk–coverage reported.
- [ ] H1/H2/H4 results reported whether supportive or not.
- [ ] H3 claim removed if no study was run.
- [ ] Limitations and ethics sections complete.
- [ ] All references verified against publisher metadata.
- [ ] Artifact appendix and reproduction commands included.
- [ ] No personal data, credentials, or unredacted screenshots.
- [ ] Advisor/internal review completed.
- [ ] Venue formatting, anonymity, and fee policy confirmed.
- [ ] Paper and artifacts archived with a DOI or persistent link if available.
