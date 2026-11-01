# Website Trust Assessment System documentation

This directory contains the research and engineering documentation for the system. The README in the
repository root explains installation and day-to-day use; the documents here define the study protocol
and the claims the project is allowed to make.

| Document | Audience | Purpose |
| --- | --- | --- |
| [annotation-protocol.md](annotation-protocol.md) | Annotators, coordinators | Blinded labelling rules, codebook, agreement, adjudication, and quality control. |
| [dataset.md](dataset.md) | Researchers, reviewers | Dataset datasheet, sampling frame, schema, leakage controls, splits, and versioning. |
| [threat-model.md](threat-model.md) | Developers, reviewers | Assets, adversaries, trust boundaries, controls, residual risks, and responsible use. |
| [model-card.md](model-card.md) | Researchers, users | Intended use, features, models, metrics, calibration, limitations, and ethics. |
| [research-plan.md](research-plan.md) | Authors, supervisors | Research gaps, hypotheses, study design, experiments, statistics, validity, references. |
| [paper-outline.md](paper-outline.md) | Authors | Section-by-section manuscript plan, contributions, figures, venues, and review criteria. |
| [team-plan.md](team-plan.md) | Project team | Six-month two-person schedule, ownership, gates, workload, and risk register. |
| [demo.md](demo.md) | Operators, presenters | Pre-demo verification, fresh-install checks, five-minute walkthrough, claims to avoid, and troubleshooting. |

## Documentation rules

1. **Do not report uncollected results.** Placeholders such as `<N>` or "to be populated by the final
   run" are intentional. Synthetic smoke-test scores validate software plumbing, not the method.
2. **Separate rule evidence from human labels.** Known-label evidence and its derivatives are excluded
   from research features. Do not silently re-enable them in a headline experiment.
3. **Keep the test split frozen.** The test set is evaluated once for the final model configuration.
   Any change that uses test feedback requires a new, untouched test set and a documented protocol
   amendment.
4. **Record protocol amendments.** Date, reason, and affected runs belong in the run manifest or an
   appendix. Do not rewrite the protocol after results are known.
5. **Protect people and data.** Annotators must not enter credentials, make payments, or scan
   authenticated pages. Screenshots and assessment databases stay on controlled local machines.

## Status

- Engine, API, dashboard, extension, research tooling: implemented.
- Runtime engine `0.1.1-rules` fixes payment-processor parsing that caused the content extractor to
  skip evidence on 11 of 1,249 stored assessments. Every `feed_v3` assessment was collected under
  `0.1.1-rules`; the retained `feed_v2` and `feed_v1` metrics were measured on `0.1.0-rules` and were
  not re-scored, see [model-card.md](model-card.md).
- `wtas doctor` verifies a fresh install, and [demo.md](demo.md) is the operator runbook.
- Synthetic pipeline smoke test: passing.
- `feed_v3` dataset: frozen at 5,129 samples / 5,129 domains (2,533 malicious, 2,596 benign),
  domain-grouped 70/15/15 split (3,590 / 770 / 769), seed 42. The SHA-256 is recorded in
  `data/datasets/feed_v3/manifest.json`, and `scripts/feed_v3_freeze.py` snapshots the 21 cited artifacts
  beside it (11 more are recorded by digest only). The earlier `feed_v2` build (830 samples / 826 domains) and `feed_v1` build are retained as
  lower-scale predecessors.
- Human labels: 146 frozen labels from one annotator, used only as a validity subset; no inter-rater
  reliability is claimed. `feed_v3` candidates are disjoint from them by construction.
- Model comparison and results: run once on the untouched test split; artifacts are in
  `data/research/runs/feed_v3/` and `paper/tables/`. The H3 user study was not run.
- Train-only learning curve: `data/research/learning_curve_feed_v3.json`, rebuilt by
  `scripts/learning_curve.py` (`--dataset data/datasets/feed_v3/dataset.jsonl --anchor-run
  data/research/runs/feed_v3/run.json`). Re-drawing domain-grouped CV inside the 3,590-row training split,
  the hybrid logistic goes 0.975 (287 domains) → 0.985 (1,436) → 0.987 (2,872) and HistGB
  0.985 → 0.991 → 0.993, so doubling the training domains again buys only **+0.002 logistic / +0.002
  HistGB AUROC**: the curve is flat at 6.2× the predecessor's size, and the predecessor's 462 training
  domains already sat on that flat part (its 50%→100% gain was +0.009 / +0.005). The full-data point
  reproduces the run's grouped-CV estimate to within 0.00013 AUROC. The validation and test splits are
  never scored.

The manuscript must not claim population-level phishing prevalence or generalisation beyond the
sampling frame described in [dataset.md](dataset.md).
