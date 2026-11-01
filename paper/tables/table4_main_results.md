# Table 4. Test-split results

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier | ECE | F1 | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.455 [0.410, 0.494] | 0.511 [0.464, 0.570] | 0.357 | 0.319 | 0.661 | 0.494 | 1.000 |
| Logistic (hybrid) | 0.987 [0.979, 0.994] | 0.986 [0.974, 0.994] | 0.028 | 0.018 | 0.966 | 0.973 | 0.958 |
| HistGB (hybrid) | 0.993 [0.988, 0.997] | 0.994 [0.991, 0.997] | 0.026 | 0.014 | 0.967 | 0.976 | 0.958 |

Test split: 769 samples / 769 domains (380 malicious / 389 benign). Thresholds and Platt calibration were selected on validation only; the test set was evaluated once. Intervals are percentile 95% bounds from 1000 domain-grouped bootstrap resamples. The rule engine's Platt fit was refused (non-positive association), so raw and calibrated scores are identical. Dataset SHA-256 `a1628d24887d9a329b7c7b2ea142cf35566e99e8db7d4468b611d2dd6c3bfd64`.
