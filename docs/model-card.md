# Website Trust Assessment System model card

Version 1.2 — 2026-10-21. Covers the deterministic runtime engine and the research model artifacts
evaluated on dataset `feed_v2`.

This card follows the Model Cards for Model Reporting structure (Mitchell et al., 2019). It separates
three things that are easy to confuse:

1. **The runtime rule engine** (`ENGINE_VERSION = 0.1.1-rules`) that serves the API and extension.
2. **The optional runtime calibration file** (`models/calibration.json`) that maps the overall rule
   score to a probability if one has been fitted.
3. **The research artifacts** produced by `wtas research train` (logistic regression,
   HistGradientBoosting, and a calibrated rule baseline). These are evaluation outputs; the API does not
   automatically load them as its decision policy.

The results below come from the frozen `feed_v2` dataset (SHA-256 `ca677752…`) and one evaluation of
the untouched test split. Evaluation numbers match `data/research/runs/feed_v2/run.json`; dataset
composition, label churn, and H4 figures come from the manifest, the churn report, and
`data/research/injection_h4.json`, respectively, and `scripts/paper_artifacts.py` asserts each mapping.
The primary labels are abuse-feed membership, not
human judgement, and the 146 human labels are a separate validity subset. The shipped decision policy
remains the rule engine; the learned models are evaluation artifacts (section 4.3).

---

## 1. Model details

| Item | Value |
| --- | --- |
| Name | Website Trust Assessment System |
| Runtime version | `0.1.1-rules` |
| Runtime decision logic | Deterministic evidence aggregation with action weights, confidence, coverage, abstention, and severity/label floors |
| Research candidates | Rule engine baseline; L2 logistic regression; HistGradientBoosting classifier |
| Feature schema | Version 3 |
| Feature groups | `url` (21), `signals` (80), `rule` (36), `hybrid` (116) |
| Evaluation dataset | `feed_v2`: 830 samples / 826 domains; 497 malicious / 333 benign samples; domain-grouped 70/15/15, seed 42 |
| Calibration | Platt scaling on validation for research models; the primary rule-engine fit was refused (section 5); runtime calibration is optional and separate |
| Threshold | Validation-only max-F1 selection for research runs; runtime risk bands for the rule engine |
| Training hardware | CPU only; 16 GB RAM target; no GPU |
| External services | None required; no paid APIs |

### 1.1 Runtime rule engine

The runtime engine is not a learned classifier. It:

- merges evidence by `(dimension, code)`, keeping the strongest observation;
- computes a dimension score from confidence-weighted risk and trust points;
- applies critical/high-severity floors and optional imported-label floors;
- estimates dimension confidence from evidence reliability and source coverage;
- abstains when confidence and coverage are too low and no strong evidence exists;
- combines active dimensions using action-specific weights;
- emits deterministic evidence cards and an overall recommendation.

This design is intentionally interpretable and reproducible. Its weakness is that the weights and
floors are hand-authored; they are not optimised against a labelled dataset.

### 1.2 Research models

- **Rule engine baseline.** Overall rule risk divided by 100, optionally Platt-calibrated on validation.
- **Logistic regression.** StandardScaler + L2 logistic regression (`C=1.0`, class-balanced,
  lbfgs, max 3000 iterations). Coefficients are converted back to raw feature scale for the JSON
  artifact.
- **HistGradientBoosting.** Class-balanced sample weights, shallow trees, early stopping disabled,
  small-data settings when the training split is under 100 samples.

The `hybrid` feature group includes the rule outputs, so a hybrid model is a stacked model. A claim that
learning improves on the rule engine must use the `signals` or `url` group as the independent
comparison. See [dataset.md](dataset.md) for the ablation plan.

### 1.3 Version history

- `0.1.1-rules` (2026-10-21): fixed payment-processor knowledge parsing, which raised
  `KeyError: 'domain'` and made the content extractor skip its remaining evidence. The error affected
  11 of 1,249 stored assessments; 10 of them belong to `feed_v2`. The frozen `feed_v2` engine metrics
  were measured on `0.1.0-rules` records and were not re-scored after this fix.
- `0.1.0-rules`: evaluation version for the reported dataset results.

---

## 2. Intended use

### 2.1 Primary intended use

- local, advisory assessment of public websites for research and demonstration;
- helping a user inspect why a site looks risky or trustworthy before browsing, signing up, or paying;
- studying calibration, abstention, evidence presentation, and multi-dimensional trust signals;
- generating reproducible features, labels, and evaluation artifacts for a paper.

### 2.2 Intended users

- the project authors and faculty reviewers;
- security and privacy researchers working with public web data;
- consenting study participants using a local prototype;
- developers who read the evidence schema and adapt the engine for defensive research.

### 2.3 Out-of-scope use

- malware detection, sandboxing, or incident response;
- enterprise secure web gateways or parental-control filtering;
- legal, financial, employment, insurance, or access decisions;
- population-level claims about how much of the web is malicious;
- blocking a site without human review;
- scanning authenticated, private, or regulated data;
- offensive use, phishing evasion, or generating deceptive pages.

---

## 3. Features and labels

### 3.1 Features

- **URL:** 21 lexical and structural features (HTTPS, lengths, labels, entropy, digits, punycode, IP
  literal, risky tokens, encoded redirects).
- **Signals:** 80 features combining URL features, page/domain observations (forms, trackers,
  certificate, DNS, policy links, OCR, injection), and 28 key evidence flags.
- **Rule:** 36 summary features from the rule engine (overall risk/confidence, per-dimension scores,
  coverage, abstention, evidence counts, and severity counts).
- **Hybrid:** all 116 features.

No feature is a known reputation label, a `known_*` floor, or an infrastructure-overlap flag. Those
signals are removed before training. External brand, TLD, tracker, payment-processor, and dark-pattern
lists influence the evidence and therefore the features; they are static, human-curated resources and
must be versioned with the results.

### 3.2 Labels

- Primary task: `benign` (0) vs `malicious` (1).
- Primary label source: membership of the OpenPhish or URLhaus public abuse feed at the recorded
  retrieval time (2026-10-20), reduced to registrable domains. A feed label is a proxy, not a human
  judgement; `benign` means "absent from both feeds at retrieval time", never "verified clean".
- The feed CSV is never imported into the runtime `domain_labels` store. `known_malicious_label` is
  worth 55 risk points, so that import would put the target into the scored evidence; `research
  feed-check` asserts the store holds no feed labels before every build.
- 146 frozen human labels (103 benign, 30 suspicious, 13 malicious) were produced by one annotator who
  is also a system author. No inter-rater agreement, adjudication, or independence is claimed. They
  are a validity subset, never training labels; 82 of those domains were collected in the `feed_v2`
  build without a feed label and were therefore excluded from the 830 samples.
- Four of the 146 human-labelled domains overlap the feeds (1 human-malicious, 3 human-suspicious).
  That is too few for kappa, so source agreement is reported as a confusion table, not as a
  reliability statistic.
- `suspicious` is collected but excluded from the primary binary task.
- Sensitivity variant: `suspicious` is mapped to 1 and the task is clearly reported as
  benign-vs-{suspicious or malicious}, not as the primary task.
- Label transience is measured, not assumed: a second feed retrieval 4.43 h after the first retains
  540 of 549 labels (98.4%), 488 of 496 evaluation positives, and adds none of the 330 derived
  negatives. This is hourly-resolution stability, not a durable property.
- Protocol: [annotation-protocol.md](annotation-protocol.md); label-source decision and provenance
  rules: [main-dataset-protocol.md](main-dataset-protocol.md) section 2.2.

---

## 4. Evaluation protocol

The evaluation protocol, including the feed-labelled primary decision, is in
[main-dataset-protocol.md](main-dataset-protocol.md) section 2.2 and [dataset.md](dataset.md);
[research-plan.md](research-plan.md) is the original pre-registration with its dated amendment. In
summary:

1. Group all samples by registrable domain.
2. Split domains by label into train/validation/test (70/15/15, fixed seed).
3. Fit candidate models on train only.
4. Run StratifiedGroupKFold cross-validation on train to estimate variability.
5. Fit Platt calibration on validation only.
6. Select the decision threshold on validation only (maximum F1, tie-break toward 0.5).
7. Evaluate the frozen configuration once on test.
8. Report grouped bootstrap confidence intervals, with domain as the resampling unit.
9. Report risk-coverage at fixed coverage levels for selective prediction.

### 4.1 Metrics

| Family | Metrics |
| --- | --- |
| Ranking | AUROC, average precision (AUPRC) |
| Calibration | Brier score, expected calibration error (ECE), maximum calibration error (MCE), reliability table |
| Thresholded | Accuracy, balanced accuracy, precision, recall, specificity, F1, MCC |
| Selective prediction | Accuracy/error rate at configured coverage levels (default 100%, 80%, 50%) |
| Uncertainty | Grouped bootstrap 95% intervals for AUROC, AUPRC, Brier, and ECE |
| Importance | Standardised logistic coefficients; permutation importance on validation for HGB |

AUPRC is emphasised because malicious sites are the minority in most realistic samples. Accuracy alone
is not an acceptable headline metric.

### 4.2 Reported results

| Model | Feature group | AUROC [95% CI] | AUPRC [95% CI] | Brier | ECE | F1 | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Rule engine (raw) | n/a | 0.519 [0.410, 0.621] | 0.701 [0.562, 0.787] | 0.398 | 0.402 | 0.745 | Shipped policy. Platt fit refused, so raw and calibrated scores are identical. |
| Logistic | url | 0.805 [0.723, 0.878] | 0.867 [0.788, 0.927] | 0.181 | 0.088 | 0.812 | Lexical-only reference. |
| Logistic | signals | 0.972 [0.940, 0.995] | 0.984 [0.965, 0.997] | 0.062 | 0.058 | 0.945 | Independent of rule outputs. |
| Logistic | hybrid | 0.986 [0.961, 0.999] | 0.993 [0.979, 0.999] | 0.035 | 0.026 | 0.959 | Stacked; includes rule outputs. |
| HGB | signals | 0.981 [0.960, 0.996] | 0.989 [0.976, 0.998] | 0.051 | 0.048 | 0.928 | Non-linear comparison. |
| HGB | hybrid | 0.991 [0.975, 0.999] | 0.995 [0.986, 1.000] | 0.044 | 0.052 | 0.950 | Main non-linear model. |

Test split: 123 samples / 123 domains (74 malicious, 49 benign). Calibration and thresholds were fit on
validation only; the test set was evaluated once. Intervals are percentile 95% bounds from 1000
domain-grouped bootstrap resamples. The rule-engine F1 is measured at the validation-selected threshold
of 0.001 rather than at an escalation band: 122 of 123 test rows exceed it, so this F1 describes a
near-all-positive prediction. The escalation policy is reported separately, where 5 of 497 feed
positives (1.0%) reach high or critical risk. Pre-registered sensitivity runs move hybrid logistic
AUROC to 0.982 (re-split, seed 43) and 0.978 (without batch-02 negatives); the engine's all-labelled
AUROC stays within 0.513–0.517 across the three runs.

### 4.3 Deployment decision

The runtime ships the rule engine, not the hybrid model. The reasons are recorded in the paper's §8.1:

- the label is feed membership with a URL-to-domain unit error and measurable decay (section 3.2), so
  0.986 is agreement with a decaying proxy, not with a verified verdict;
- the headline comes from one 123-sample split. Hybrid AUROC spans 0.978–0.986 across sensitivity
  runs, and the engine's test AUROC moves between 0.519 and 0.676 at n = 123;
- the runtime contract is an auditable evidence chain. In the fitted hybrid model the single largest
  standardised coefficient is `risk_medium_count` (a rule output, −2.65), and `url_https` enters
  positively toward malicious (+1.27), which is a finding about the label rather than a policy to ship.

The path to shipping a learned score is a URL-level, temporally split evaluation and an optional
calibrated second opinion displayed behind the evidence, not a silent replacement of the engine.

---

## 5. Calibration and uncertainty

- The overall rule score is **not** a probability. It is a bounded risk score.
- Runtime `calibrated_probability` is `null` until a compatible `models/calibration.json` is supplied.
- Research runs fit Platt scaling on validation log-odds and record `method=platt_logit`,
  `input_transform=logit`, slope, intercept, and a warning if fitting was skipped.
- Calibration is skipped when validation has one class, constant scores, or a non-positive slope. The
  artifact records the skipped state rather than silently mapping scores.
- On the primary `feed_v2` split the rule engine's validation scores were not positively associated
  with labels, so the Platt fit was refused (`fitted: false`). Its raw and "calibrated" test ECE are
  both 0.402; the refusal is the recorded result, not a missing number.
- The test set is never used to fit calibration or choose a threshold.
- Confidence and coverage are not probabilities. They describe evidence sufficiency, not P(benign).

A user interface must show uncertainty and missing evidence. A low-confidence or `unknown` assessment
is a request for caution, not a clean bill of health.

---

## 6. Performance requirements and operational behaviour

| Requirement | Current behaviour |
| --- | --- |
| No GPU | All models and extractors are CPU-only. |
| No paid API | Local static knowledge; optional OCR; no cloud calls. |
| Latency | Offline parse + score: 22.07 ms/page median, 25.95 ms p95, 44.4 pages/s over 210 fixture scorings; live latency is dominated by page load; timeout 75 s; cache TTL 1 hour. |
| Memory | Peak traced Python allocation 0.9 MB for offline parse + score; Chromium is the largest consumer in a live crawl; concurrency limited to 2 by default. |
| Failure mode | Timeout returns an `unknown` assessment with missing-evidence notes rather than a fabricated verdict. |
| Crawler fallback | If Chromium is unavailable, a static HTTP render is used with reduced coverage. |
| Persistence | SQLite; a persistence failure is recorded in `meta.persistence_error` but does not discard the result. |

---

## 7. Limitations and risks

1. **Hand-authored rules.** The runtime weights and floors are expert choices, not learned parameters.
   They may encode the authors' biases.
2. **Proxy labels.** The headline numbers are agreement with feed membership, not with verified
   truth. Fifty feed-listed domains could not be collected and were dropped, never called benign, and
   the human validity subset overlaps the feeds on only four domains.
3. **Single vantage point.** Client-side cloaking can hide malicious content from the crawler.
4. **Content drift.** A label is a snapshot; sites change and domains change ownership.
5. **Coverage gaps.** OCR may be unavailable; Playwright may be blocked; policy pages may be
   unreachable. Abstention is preferred to guessing.
6. **Static knowledge.** Brand lists and TLD risk lists can be incomplete or culturally biased.
7. **Small evaluation set.** The test split is 123 samples (74 malicious, 49 benign); intervals are
   correspondingly wide and subgroup conclusions are exploratory. Hybrid AUROC spans 0.978–0.986
   across pre-registered sensitivity runs, while the engine's test AUROC spans 0.519–0.676.
8. **Label bias.** Feed membership is biased toward reported phishing and malware-distribution
   infrastructure, has no suspicious tier, and ages between retrieval and crawl (1 of 13
   human-malicious domains was still listed). The 146 human labels come from one annotator who is also
   an author, so they support no independence claim.
9. **False positives.** Small businesses, artists, and non-Western sites may be penalised by missing
   transparency signals. The interface must show the evidence and avoid categorical accusations.
10. **Prompt injection.** No LLM is in the current scoring path; hidden instruction-like content is
    detected. Any future LLM integration needs a new threat review.
11. **No malware execution.** The system observes page behaviour and downloads indicators; it does not
    execute payloads or scan files.
12. **No guarantee of safety.** A low risk score means the collected evidence did not show a material
    adverse signal; it is not proof.
13. **Label transience.** A second retrieval 4.43 h after the primary one retained 540 of 549 labels
    (98.4%) and 488 of 496 evaluation positives, and added none of the 330 derived negatives. This
    supports hourly stability only, not durability.

---

## 8. Ethical considerations

- **Do not automate accusations.** Present evidence and uncertainty; keep a human in the loop.
- **Protect small sites.** A missing privacy policy or a cheap certificate is not fraud. The system
  should not label a site malicious from weak signals.
- **Respect privacy.** Do not scan authenticated pages, collect form values, or publish screenshots
  containing personal data.
- **Consent for user studies.** Any study with participants requires ethics approval, informed consent,
  and a data-management plan.
- **Report limitations.** Do not claim web-wide prevalence from a convenience sample.
- **Dual use.** The same features could help a phishing kit evade detection. The project publishes
  defensive methods and does not provide evasion tooling.
- **Open artifacts.** Publish code, protocols, feature definitions, labels, manifests, and hashes so
  reviewers can audit the claims.

---

## 9. Maintenance

- Retrain and re-calibrate after any change to feature definitions, label codebook, or data source.
- Record `ENGINE_VERSION`, `FEATURE_SCHEMA_VERSION`, `DATASET_SCHEMA_VERSION`, dataset hash, seed, and
  dependency versions in every run.
- Re-scan a stratified sample quarterly to measure drift. If drift is material, rebuild the dataset
  rather than patching a frozen version.
- Review knowledge files and update them with a dated version.
- Keep the browser and Python dependencies patched; test the suite after upgrades.
- Archive model artifacts and reports; never overwrite a published run.
- Add a regression test for every fixed false positive or safety bug, using synthetic assessments
  rather than live malicious pages.

---

## 10. Citation and contact

If you use this prototype, cite the repository and the accompanying paper when available. Replace the
placeholder in [README.md](../README.md) with the final citation. Security reports should be sent
privately to the maintainers before public disclosure.
