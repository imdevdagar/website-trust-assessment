# Table 5. Feature-group ablation

| Feature group | Features | Model | AUROC [95% CI] | AUPRC [95% CI] | Brier | ECE | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `url` | 21 | Logistic | 0.857 [0.829, 0.883] | 0.840 [0.795, 0.882] | 0.150 | 0.048 | 0.787 |
| `url` | 21 | HistGB | 0.881 [0.855, 0.903] | 0.886 [0.855, 0.912] | 0.139 | 0.041 | 0.802 |
| `signals` | 80 | Logistic | 0.979 [0.967, 0.989] | 0.977 [0.957, 0.990] | 0.038 | 0.023 | 0.953 |
| `signals` | 80 | HistGB | 0.991 [0.985, 0.995] | 0.992 [0.988, 0.996] | 0.034 | 0.020 | 0.957 |
| `rule` | 36 | Logistic | 0.964 [0.950, 0.977] | 0.956 [0.927, 0.978] | 0.065 | 0.038 | 0.908 |
| `rule` | 36 | HistGB | 0.983 [0.973, 0.991] | 0.987 [0.980, 0.993] | 0.039 | 0.015 | 0.950 |
| `hybrid` | 116 | Logistic | 0.987 [0.979, 0.994] | 0.986 [0.974, 0.994] | 0.028 | 0.018 | 0.966 |
| `hybrid` | 116 | HistGB | 0.993 [0.988, 0.997] | 0.994 [0.991, 0.997] | 0.026 | 0.014 | 0.967 |
| `none` | 0 | Rule engine | 0.455 [0.410, 0.494] | 0.511 [0.464, 0.570] | 0.357 | 0.319 | 0.661 |

All rows use the same domain-grouped test split (769 samples, 380 positive) and the same bootstrap resamples (1000, domain-grouped). `hybrid` includes the rule outputs, so it is a superset comparison, not an independent model family; `signals` is the independent page-evidence comparison.
