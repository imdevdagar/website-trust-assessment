# Table 5. Feature-group ablation

| Feature group | Features | Model | AUROC [95% CI] | AUPRC [95% CI] | Brier | ECE | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `url` | 21 | Logistic | 0.805 [0.723, 0.878] | 0.867 [0.788, 0.927] | 0.181 | 0.088 | 0.812 |
| `url` | 21 | HistGB | 0.819 [0.743, 0.890] | 0.877 [0.803, 0.934] | 0.172 | 0.083 | 0.814 |
| `signals` | 80 | Logistic | 0.972 [0.940, 0.995] | 0.984 [0.965, 0.997] | 0.062 | 0.058 | 0.945 |
| `signals` | 80 | HistGB | 0.981 [0.960, 0.996] | 0.989 [0.976, 0.998] | 0.051 | 0.048 | 0.928 |
| `rule` | 36 | Logistic | 0.959 [0.924, 0.986] | 0.977 [0.953, 0.992] | 0.074 | 0.045 | 0.925 |
| `rule` | 36 | HistGB | 0.971 [0.944, 0.991] | 0.982 [0.963, 0.995] | 0.074 | 0.050 | 0.915 |
| `hybrid` | 116 | Logistic | 0.986 [0.961, 0.999] | 0.993 [0.979, 0.999] | 0.035 | 0.026 | 0.959 |
| `hybrid` | 116 | HistGB | 0.991 [0.975, 0.999] | 0.995 [0.986, 1.000] | 0.044 | 0.052 | 0.950 |
| `none` | 0 | Rule engine | 0.519 [0.410, 0.621] | 0.701 [0.562, 0.787] | 0.398 | 0.402 | 0.745 |

All rows use the same domain-grouped test split (123 samples, 74 positive) and the same bootstrap resamples (1000, domain-grouped). `hybrid` includes the rule outputs, so it is a superset comparison, not an independent model family; `signals` is the independent page-evidence comparison.
