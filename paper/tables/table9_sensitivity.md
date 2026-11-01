# Table 9. Pre-registered sensitivity runs

| Run | Hybrid logistic AUROC | Hybrid HistGB AUROC | Engine AUROC (all labelled) | Engine AUROC (test) |
| --- | ---: | ---: | ---: | ---: |
| Primary, seed 42 | 0.987 | 0.993 | 0.475 | 0.455 |
| Re-split, seed 43 | 0.988 | 0.993 | 0.475 | 0.473 |

The engine's all-labelled AUROC is the stable comparison: it is computed over every labelled assessment and so does not move with the split at all, while its test-split AUROC (769 samples) shifts slightly. The predecessor `feed_v2` build also carried a negative-stratum ablation (dropping the main batch-02 assessments reused as negatives); that ablation has no `feed_v3` counterpart because this build's benign class is drawn from the Tranco top-1M pool under the recorded protocol, not from a reused stratum.
