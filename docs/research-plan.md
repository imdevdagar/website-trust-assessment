# Website Trust Assessment System research plan

Version 1.0 — pre-registration-style plan for the major project and paper.

This document defines the research problem, the gap The system addresses, the hypotheses, the study
design, the analysis, and the threats to validity. It is written before the human-labelled dataset is
frozen so that the evaluation is not redesigned around observed results. Any change after the freeze
must be recorded as a dated amendment with a reason.

> **Amendment, 2026-10-20 — feed-labelled primary task.** The human-label track stopped at 146 frozen
> labels (one annotator, no adjudication) and could not support the G1/G2 gates below. With the team's
> recorded decision (`data/datasets/label_source_decision.json`), the primary task became benign vs
> malicious by membership of the OpenPhish or URLhaus feed at the recorded retrieval time, and the 146
> human labels became a validity subset. The operative protocol is
> [main-dataset-protocol.md](main-dataset-protocol.md) section 2.2 and [dataset.md](dataset.md). G1 and
> G2 below are retained as the history of the human-label track; their "do not pad with feed labels"
> clause barred mixing feed labels into a human-labelled set, not the later decision to evaluate against
> feeds as the primary source. The H3 user study, the temporal split, and the multi-annotator reliability
> analysis were not run, and no claim depends on them. The H1 HTTPS-only baseline was evaluated as the
> fixed rule "flag when HTTPS is absent" rather than as a fitted classifier, because a fitted model
> would add capacity the hypothesis does not need; the trusted-chain variant is descriptive and was not
> pre-registered.

---

## 1. Problem statement

A browser user who is about to sign in, create an account, or pay must decide whether a website is
trustworthy. Existing defences give either a binary phishing verdict or a padlock, but the decision
depends on several different questions:

- Is the site technically safe to interact with?
- Is it who it claims to be?
- What will it do with the user's data?
- Is it trying to manipulate the user?

A single score hides these distinctions. It also hides uncertainty: a site with little observable
evidence can look "safe" simply because the crawler could not collect enough information.

The system asks a narrower, testable question:

> Can a local, CPU-only system produce a multi-dimensional, action-aware trust assessment whose
> evidence and confidence are auditable, and can it distinguish benign from malicious sites without
> relying on reputation-label leakage or domain overlap?

The system is a research vehicle, not a claim that a four-dimensional score is the correct ontology of
trust.

---

## 2. Research gaps

The related-work landscape suggests six gaps that motivate the design.

### G1. Binary phishing detection dominates

Phishing detection research has a strong tradition of URL lexical models, content models, visual
similarity, and blacklist prediction. These methods are useful, but they usually optimise a binary
"phishing vs legitimate" label. They do not expose separate security, identity, privacy, and
manipulation evidence, and they do not vary the decision by the action the user is about to take.

**System response:** four dimensions, action-specific weights, and evidence-level provenance rather
than a single opaque classifier.

### G2. The padlock is treated as a trust signal

HTTPS protects transit, not identity or intent. Prior work on browser security indicators shows that
users often read a lock or "secure" label as a broader trust judgment. Phishing sites frequently obtain
certificates. The literature often measures certificate features as one classifier input but rarely
reports how much of a user's trust decision is explained by the padlock alone.

**System response:** HTTPS is one evidence item; the padlock paradox is measured descriptively in the
collected sample, and an HTTPS-only baseline is reported so its limits are visible.

### G3. Privacy and manipulation are measured separately

Web privacy measurement and dark-pattern research produce rich findings, but they are usually separate
from phishing detection. A user-facing trust tool should connect "this page may be fraudulent" with
"this page tracks you aggressively" and "this page pressures you", without collapsing them into one
undifferentiated risk number.

**System response:** privacy and manipulation are first-class dimensions with their own evidence,
coverage, and confidence, while the overall score remains action-aware.

### G4. Explanations are often post-hoc, not evidence-grounded

Post-hoc feature attributions can be useful, but they are not the same as showing an auditable
observation with provenance. A phishing warning that says "the model gave 0.93" is hard to contest,
learn from, or audit. Calibration and selective prediction are also rarely reported together in
phishing detection, even though both matter for a warning that is allowed to say "unknown".

**System response:** every score decomposes into typed evidence cards, confidence, coverage, and
missing-evidence notes; calibration and risk-coverage are part of the evaluation protocol.

### G5. Leakage and split design inflate reported performance

Phishing datasets often combine reputation feeds, URL lists, and random row splits. A model can learn a
reputation shortcut or memorise a domain that appears in both train and test. This is a known
reproducibility problem in machine learning for science, and it is especially acute for web security,
where labels and features can come from the same blocklist.

**System response:** label evidence and its derivatives are excluded; splits are grouped by
registrable domain; the test set is frozen; dataset and run hashes are recorded.

### G6. Hostile page content and LLM-assisted explanations

Indirect prompt injection shows that untrusted text can redirect an LLM that processes it. A trust tool
that sends raw page HTML to an LLM creates a new attack surface: the page can try to talk its way into a
favourable verdict. Explainability must be isolated from instruction-following.

**System response:** the current scoring path has no LLM. Hidden instruction-like content is detected
and surfaced. A future LLM narration experiment must pass structured evidence, not raw HTML, and must be
evaluated separately.

### 2.1 Positioning

The contribution is not "the first phishing detector". It is an integrated, auditable assessment
framework plus a protocol for evaluating multi-dimensional website trust without label leakage. The
paper should present the design and the evaluation as a package, and should be explicit about which
parts are novel and which are engineering integration.

---

## 3. Hypotheses

Each hypothesis has an operationalisation and a result that would count against it.

### H1 — The padlock paradox

**Statement.** A meaningful fraction of malicious sites in the sample use HTTPS, so an HTTPS-only policy
will have poor specificity and cannot serve as a trust judgment.

**Operationalisation.**

- Report the proportion of `malicious` domains with a final HTTPS URL and a valid certificate chain.
- Train/evaluate an HTTPS-only baseline (predict malicious if no HTTPS) and report AUROC, precision,
  recall, and F1.
- Compare user-facing interpretations in the optional user study (does a padlock change trust ratings
  for malicious pages?).

**Evidence against.** If nearly all malicious sites lack HTTPS and the HTTPS-only baseline achieves
strong precision/recall, the "paradox" is not present in this sample. Report that result; do not force
the narrative.

### H2 — Multi-signal assessment transfers better than URL-only models

**Statement.** A model using page, domain, transport, privacy, and manipulation signals will rank
held-out domains better than a URL-only lexical model, and the gain will remain after calibration.

**Operationalisation.**

- Primary comparison: `signals` vs `url` logistic regression on test AUROC and AUPRC.
- Secondary: `signals` vs `url` HistGradientBoosting.
- Report grouped bootstrap intervals and a paired domain-level bootstrap of the metric difference.
- Report calibration (Brier, ECE) and risk-coverage, not only ranking.

**Evidence against.** If the signals model's test intervals overlap the URL-only model's intervals and
the paired difference is centred near zero, the hypothesis is not supported. A hybrid model containing
rule outputs cannot be used alone to support H2; it is a stacked comparison.

**Status of the paired bootstrap.** The current `metrics.py` provides individual grouped bootstrap
intervals. A paired domain-level bootstrap of model differences is a planned addition before the final
analysis; until it exists, the paper must describe the comparison as interval-based and exploratory.

### H3 — Evidence cards improve appropriate reliance

**Statement.** Showing evidence cards with provenance and uncertainty leads to better-calibrated user
judgments than showing a single risk score.

**Operationalisation (optional user study).**

- Within-subject design; each participant sees both interface conditions on matched site sets.
- Counterbalance order and site assignment; use benign and malicious cases with known labels.
- Primary outcome: appropriate reliance, defined as agreeing with the correct label while not
  over-trusting a wrong system verdict.
- Secondary: confidence calibration, decision time, perceived usefulness, and intention to investigate.
- Analysis: paired/mixed-effects models with participant as a random effect; report effect sizes and
  intervals.

**Evidence against.** If the evidence-card condition does not improve appropriate reliance or
calibration, report that. A more detailed interface is not automatically a better one.

**Feasibility.** A user study requires ethics approval, consent, and at least 20–30 participants. If it
is not feasible within the project, replace H3 with an expert heuristic evaluation and remove the causal
claim. Do not present a convenience demo as a user study.

### H4 — Instruction-like content can be isolated from the verdict

**Statement.** Hidden instruction-like content in a page can be detected and kept out of the scoring
path, so it does not change the assessment in the way it would change an LLM that reads raw HTML.

**Operationalisation.**

- Build a controlled set of benign pages with and without hidden prompt-injection patterns (visible
  text, comments, metadata, alt text, zero-width/bidi obfuscation).
- Measure detection recall/precision for the injection evidence codes.
- Verify that the rule score and final label are unchanged when only hidden instruction text is added,
  apart from the explicit injection evidence.
- If an optional local LLM narration is added, compare attack success rate under (a) raw HTML and
  (b) structured evidence isolation.

**Evidence against.** If hidden instructions change the score or if detection misses most patterns, the
isolation claim fails. The current system has no LLM, so H4 is primarily an injection-detection and
score-invariance study in version 1.0.

**As executed.** The corpus is 26 injection and 16 negative fixtures rendered from 6 shared body templates
(5 of them adversarial negatives that stay in the precision denominator), scored offline through the
production static parser by `wtas research injection-build` / `injection-eval`. Results — precision
0.958, recall 0.885, and 40/40 paired cases reproducing the clean baseline exactly once injection and trace
evidence is dropped — are in `data/research/injection_h4.json`, reproduced by `tests/test_injection_isolation.py`.
The LLM attack-success comparison below was not run: v1.0 has no LLM.

---

## 4. Study design

### 4.1 Data

- 400–500 public domains, convenience sample enriched for malicious and ambiguous sites.
- 20% double annotation, three-class labels, binary primary task.
- Up to five assessments per domain by default; one `browse` assessment is the annotation
  representative.
- Assessment and annotation within 48 hours where possible.
- Full protocol in [annotation-protocol.md](annotation-protocol.md) and [dataset.md](dataset.md).

### 4.2 Splits

- Domain-grouped, label-stratified 70/15/15 train/validation/test.
- Fixed seed; no domain overlap; the training code rejects overlap.
- Test set touched once per final configuration.
- If the test set is accidentally inspected during development, create a new untouched test set from
  additional domains and report the incident.

### 4.3 Models and ablations

| Model | Group | Role |
| --- | --- | --- |
| Rule engine | n/a | Deterministic baseline; raw and Platt-calibrated. |
| Logistic | `url` | Lexical reference. |
| Logistic | `signals` | Independent page/domain evidence model. |
| Logistic | `rule` | Learned recalibration of rule outputs. |
| Logistic | `hybrid` | Stacked model; includes rule outputs. |
| HGB | `signals` | Non-linear evidence model. |
| HGB | `hybrid` | Non-linear stacked model. |
| Rule engine | n/a | Ablation: disable one evidence family at a time, if time permits. |
| HTTPS-only | n/a | Padlock baseline for H1. |

Hyperparameters are fixed in advance (see `research/training.py`). Any tuning uses training and
validation only. The test split does not participate in feature selection, calibration, thresholding, or
early stopping.

### 4.4 Measurements

For each model and split:

- sample/domain counts, class balance, exclusions;
- AUROC, AUPRC, Brier, log loss, ECE, MCE;
- thresholded accuracy, balanced accuracy, precision, recall, specificity, F1, MCC;
- confusion matrix;
- risk-coverage table;
- grouped bootstrap 95% intervals;
- calibration reliability bins;
- logistic coefficients and HGB permutation importance;
- training and inference runtime on the target laptop.

For the dataset:

- annotation agreement (observed, kappa linear/quadratic);
- unresolved disagreement rate;
- label and exclusion counts;
- HTTPS/certificate prevalence among malicious sites (H1);
- missing-evidence and coverage distributions;
- assessment duration and failure modes.

### 4.5 Statistical analysis

- Descriptive statistics with counts and percentages; no bare averages without denominators.
- Kappa with the interpretation policy in the annotation protocol.
- AUROC/AUPRC/Brier/ECE with domain-grouped percentile bootstrap intervals (1,000 resamples).
- Paired domain-level bootstrap for model differences (planned; prerequisite for a formal H2 claim).
- Calibration plots with bin counts; do not over-interpret sparse bins.
- Risk-coverage curves/tables for selective prediction.
- Multiple comparisons: define a primary family (H2 signal-vs-URL comparisons) and apply Holm–Bonferroni
  or report that the analysis is exploratory. Secondary and subgroup tests are labelled exploratory.
- Report exact sample sizes and interval widths; avoid "near significance" language.
- If the test set has fewer than 20 samples per class, downgrade claims and report the warning.

### 4.6 Missing data and exclusions

- Missing evidence is a feature and a reason to abstain; it is not silently imputed.
- Excluded assessments are counted by reason in the manifest.
- Unresolved labels are excluded from consensus and reported.
- If a site is unreachable, do not label it benign; use `suspicious` only if the available evidence
  supports it, otherwise mark unresolved.
- Report the effect of exclusions on class balance and domain counts.

---

## 5. Expected contributions

1. **Design contribution.** An evidence-grounded, four-dimensional, action-aware assessment framework
   with abstention, coverage, provenance, and deterministic explanations.
2. **Evaluation contribution.** A leakage-controlled, domain-grouped protocol and a reproducible
   CPU-only pipeline for comparing rule, URL-only, signal, and hybrid models.
3. **Empirical contribution.** Evidence on the padlock paradox, the value of page/domain signals,
   calibration/risk-coverage, and the cost of relying on URL-only features.
4. **Safety contribution.** A threat model and injection-isolation design for assessing hostile pages,
   plus an optional LLM-narration experiment with a clear trust boundary.
5. **Artifact contribution.** Code, protocol, model card, dataset datasheet, manifests, and run reports
   that another pair of students can reproduce.

The paper should not claim that The system is a deployed security product or that its labels are
ground truth.

---

## 6. Threats to validity

### 6.1 Construct validity

- **Coarse labels.** `benign` / `suspicious` / `malicious` collapse different phenomena.
- **Dimension scores are not labels.** A site can be benign but privacy-invasive; the evaluation must
  not treat a high privacy score as a misclassification.
- **Padlock measurement.** "Valid HTTPS" depends on the certificate validation policy; document whether
  the crawler ignored TLS errors and how the evidence was derived.
- **Injection dataset.** Synthetic injections may not resemble real attacks. Report the construction and
  avoid overgeneralising.

### 6.2 Internal validity

- **Label leakage.** Removed by feature exclusion and dataset checks; verify with a leakage-only
  diagnostic.
- **Domain leakage.** Prevented by grouped splits; the training code rejects overlap.
- **Test reuse.** Frozen test; evaluation once per final configuration.
- **Annotation bias.** Authors label their own system's evaluation data; blinded to scores, but not to
  the project. Report it.
- **Hyperparameter tuning.** Fixed in advance; no test-driven selection.
- **Implementation bugs.** Unit tests and synthetic smoke tests; review feature extraction paths.

### 6.3 External validity

- **Convenience sample.** Not representative of the web or of phishing prevalence.
- **Language.** English-primary collection; no multilingual claim.
- **Time.** Websites and certificates change; results are a snapshot.
- **Vantage point.** Headless Chromium in one network location can be cloaked or blocked.
- **Platform.** Windows 11, Python 3.14, specific Chromium/Tesseract versions; record them.
- **Action profiles.** `signup` and `purchase` assessments may be sparse relative to `browse`.

### 6.4 Statistical validity

- Small test set; wide intervals; subgroup analyses underpowered.
- Class imbalance; AUPRC and per-class recall are essential.
- Multiple comparisons; predefine the primary family.
- Bootstrap resampling by domain is appropriate for grouped data but still assumes exchangeability of
  domains; report limitations.
- Calibration bins can be unstable with small counts; include bin counts.

### 6.5 Conclusion validity

- A higher AUROC does not prove a better user decision.
- A low false-positive rate on a convenience sample does not prove safety for small businesses.
- The system is advisory; causal claims about user behaviour require the user study.

---

## 7. Reproducibility plan

Archive and publish:

- source commit and dependency versions (`pip freeze` or a lockfile);
- Python, OS, Chromium, Playwright, Tesseract, and knowledge-file versions;
- assessment JSONL or a derived-feature release with a manifest;
- annotation sheets, codebook version, agreement report, and adjudication summary;
- dataset JSONL/CSV, manifest, and SHA-256 hashes;
- every run's `run.json`, `report.md`, model artifacts, and test evaluation;
- exact commands and seeds;
- a README that reproduces the headline table from the released artifacts.

Do not publish raw screenshots or assessment records containing personal data. If a dataset must be
withheld, provide a synthetic example and the feature schema so reviewers can inspect the pipeline.

### 7.1 Environment capture

`research train` records the dataset hash, seed, feature schema, and run ID. Before the final run, add a
small environment manifest (Python, platform, package versions, browser version) to the release. The
paper's artifact appendix should state the hardware and runtime.

---

## 8. Ethics and responsible research

- Public websites only; no authentication, form submission, payment, or download.
- No human-subject data without ethics approval and informed consent.
- No publication of personal data, credentials, or sensitive screenshots.
- Do not name and shame small sites from a false positive. Report aggregate results and use the system
  as advisory.
- Do not release an evasion toolkit. Publish defensive detection logic and features responsibly.
- Security vulnerabilities in the system follow private disclosure before publication.
- The optional user study must include a debrief, a clear explanation that the system can be wrong, and
  a way to withdraw.

---

## 9. Milestones and decision gates

The detailed two-person schedule is in [team-plan.md](team-plan.md). Research gates:

| Gate | Criterion | Decision |
| --- | --- | --- |
| G0 — Protocol freeze | Codebook, sampling frame, and analysis plan reviewed. | Start pilot. |
| G1 — Pilot agreement | Quadratic kappa >= 0.70 and no unresolved definitional ambiguity. | Scale collection. |
| G2 — Dataset freeze | 400–500 domains labelled; consensus and manifest hashed. | Train final models. |
| G3 — Test evaluation | One frozen configuration evaluated once. | Analyse and write results. |
| G4 — Artifact review | A second person reruns the headline command from the release. | Submit paper. |

If G1 fails, revise the codebook and repeat the pilot. If G2 cannot reach 400 domains, report the actual
number and reduce claims; do not pad the dataset with feed labels.

---

## 10. References

These are the works that most directly shape the gaps and protocol. Verify bibliographic details against
the publisher before submission.

1. Gebru, T., Morgenstern, J., Vecchione, B., et al. "Datasheets for Datasets." *Communications of the
   ACM*, 2021.
2. Mitchell, M., Wu, S., Zaldivar, A., et al. "Model Cards for Model Reporting." *FAT\**, 2019.
3. Kapoor, S., and Narayanan, A. "Leakage and the Reproducibility Crisis in Machine-Learning-Based
   Science." *Patterns*, 4(9), 100804, 2023.
4. Kaufman, S., Rosset, S., Perlich, C., and Stitelman, O. "Leakage in Data Mining: Formulation,
   Detection, and Avoidance." *ACM TKDD*, 2012.
5. Guo, C., Pleiss, G., Sun, Y., and Weinberger, K. Q. "On Calibration of Modern Neural Networks."
   *ICML*, 2017.
6. Platt, J. "Probabilistic Outputs for Support Vector Machines and Comparisons to Regularized
   Likelihood Methods." In *Advances in Large Margin Classifiers*, 1999.
7. Geifman, Y., and El-Yaniv, R. "Selective Classification for Deep Neural Networks." *NeurIPS*, 2017.
8. Cohen, J. "A Coefficient of Agreement for Nominal Scales." *Educational and Psychological
   Measurement*, 1960.
9. Landis, J. R., and Koch, G. G. "The Measurement of Observer Agreement for Categorical Data."
   *Biometrics*, 1977.
10. Efron, B., and Tibshirani, R. J. *An Introduction to the Bootstrap*. Chapman & Hall, 1993.
11. Rudin, C. "Stop Explaining Black Box Machine Learning Models for High Stakes Decisions and Use
    Interpretable Models Instead." *Nature Machine Intelligence*, 2019.
12. Fogg, B. J., Marshall, J., Laraki, O., et al. "What Makes Web Sites Credible? A Report on a Large
    Quantitative Study." *CHI*, 2001.
13. Schechter, S. E., Dhamija, R., Ozment, A., and Fischer, I. "The Emperor's New Security Indicators."
    *IEEE Symposium on Security and Privacy*, 2007.
14. Egelman, S., Cranor, L. F., and Hong, J. "You've Been Warned: An Empirical Study of the
    Effectiveness of Web Browser Phishing Warnings." *CHI*, 2008.
15. Felt, A. P., Reeder, R. W., Ainslie, A., et al. "Rethinking Connection Security Indicators." *SOUPS*,
    2016.
16. Xiang, G., Hong, J., Rose, C. P., and Cranor, L. F. "CANTINA+: A Feature-Rich Machine Learning
    Framework for Detecting Phishing Web Sites." *ACM TISSEC*, 14(2), 1–28, 2011.
17. Afroz, S., and Greenstadt, R. "PhishZoo: Detecting Phishing Websites by Looking at Them." *IEEE
    ICSC*, 2011.
18. Prakash, P., Kumar, M., Kompella, R. R., and Gupta, M. "PhishNet: Predictive Blacklisting to Detect
    Phishing Attacks." *INFOCOM*, 2010.
19. Mathur, A., Acar, G., Friedman, M. J., et al. "Dark Patterns at Scale: Findings from a Crawl of 11K
    Shopping Websites." *CSCW*, 2019.
20. Englehardt, S., and Narayanan, A. "Online Tracking: A 1-million-site Measurement and Analysis."
    *CCS*, 2016.
21. Le Pochat, V., Van Goethem, T., Tajalizadehkhoob, S., et al. "Tranco: A Research-Oriented Top Sites
    Ranking Hardened Against Manipulation." *NDSS*, 2019.
22. Greshake, K., Abdelnabi, S., Mishra, S., et al. "Not What You've Signed Up For: Compromising
    Real-World LLM-Integrated Applications with Indirect Prompt Injection." *ACM AISec*, 2023.
23. Perez, F., and Ribeiro, I. "Ignore Previous Prompt: Attack Techniques for Language Models."
    arXiv:2211.09527, 2022.
24. OpenPhish and URLhaus. Public phishing and malware URL feeds used, after the 2026-10-20 amendment,
    as the primary label source by membership at the recorded retrieval time; access dates and raw-body
    hashes are recorded in the feed provenance manifest.
25. Zhang, Y., Hong, J. I., and Cranor, L. F. "CANTINA: A Content-Based Approach to Detecting Phishing
    Web Sites." *WWW*, 639–648, 2007.
