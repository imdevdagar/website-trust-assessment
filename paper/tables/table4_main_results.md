# Table 4. Test-split results

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier | ECE | F1 | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.519 [0.410, 0.621] | 0.701 [0.562, 0.787] | 0.398 | 0.402 | 0.745 | 0.598 | 0.986 |
| Logistic (hybrid) | 0.986 [0.961, 0.999] | 0.993 [0.979, 0.999] | 0.035 | 0.026 | 0.959 | 0.959 | 0.959 |
| HistGB (hybrid) | 0.991 [0.975, 0.999] | 0.995 [0.986, 1.000] | 0.044 | 0.052 | 0.950 | 1.000 | 0.905 |

Test split: 123 samples / 123 domains (74 malicious / 49 benign). Thresholds and Platt calibration were selected on validation only; the test set was evaluated once. Intervals are percentile 95% bounds from 1000 domain-grouped bootstrap resamples. The rule engine's Platt fit was refused (non-positive association), so raw and calibrated scores are identical. Dataset SHA-256 `ca6777520f435271b756079308b7526638c339f3571881f4574cb29928ff1ae2`.
