# Table 10. Learning curve (train-only grouped CV)

| Model | Training domains | Share | AUROC [95% interval] | AUPRC [95% interval] |
| --- | ---: | ---: | ---: | ---: |
| Logistic (hybrid) | 287 | 10% | 0.975 [0.972, 0.978] | 0.975 [0.965, 0.980] |
| Logistic (hybrid) | 718 | 25% | 0.981 [0.979, 0.983] | 0.982 [0.977, 0.986] |
| Logistic (hybrid) | 1436 | 50% | 0.985 [0.983, 0.987] | 0.986 [0.982, 0.989] |
| Logistic (hybrid) | 2154 | 75% | 0.986 [0.984, 0.988] | 0.987 [0.981, 0.991] |
| Logistic (hybrid) | 2872 | 100% | 0.987 [0.985, 0.989] | 0.989 [0.984, 0.991] |
| HistGB (hybrid) | 287 | 10% | 0.985 [0.982, 0.986] | 0.988 [0.986, 0.989] |
| HistGB (hybrid) | 718 | 25% | 0.990 [0.989, 0.991] | 0.992 [0.991, 0.993] |
| HistGB (hybrid) | 1436 | 50% | 0.991 [0.990, 0.992] | 0.993 [0.993, 0.994] |
| HistGB (hybrid) | 2154 | 75% | 0.993 [0.992, 0.993] | 0.994 [0.994, 0.995] |
| HistGB (hybrid) | 2872 | 100% | 0.993 [0.992, 0.994] | 0.995 [0.994, 0.995] |

Train-only: five-fold domain-grouped cross-validation inside the training split, re-drawn 20 times for logistic and 10 times for HistGB. Whole domains are subsampled per class, so a fraction never splits a domain. Intervals are the 2.5-97.5 percentile range across repeats. The validation and test splits are never scored. At full size the pooled logistic estimate (0.987) reproduces the run's grouped-CV estimate (0.987) within 0.000.
