# Table 10. Learning curve (train-only grouped CV)

| Model | Training domains | Share | AUROC [95% interval] | AUPRC [95% interval] |
| --- | ---: | ---: | ---: | ---: |
| Logistic (hybrid) | 46 | 10% | 0.907 [0.882, 0.934] | 0.929 [0.895, 0.953] |
| Logistic (hybrid) | 116 | 25% | 0.948 [0.935, 0.960] | 0.960 [0.940, 0.976] |
| Logistic (hybrid) | 231 | 50% | 0.964 [0.956, 0.976] | 0.974 [0.962, 0.985] |
| Logistic (hybrid) | 347 | 75% | 0.969 [0.962, 0.977] | 0.977 [0.966, 0.986] |
| Logistic (hybrid) | 462 | 100% | 0.973 [0.965, 0.980] | 0.979 [0.969, 0.985] |
| HistGB (hybrid) | 46 | 10% | 0.922 [0.910, 0.938] | 0.945 [0.922, 0.959] |
| HistGB (hybrid) | 116 | 25% | 0.969 [0.961, 0.980] | 0.982 [0.976, 0.988] |
| HistGB (hybrid) | 231 | 50% | 0.985 [0.981, 0.991] | 0.992 [0.989, 0.995] |
| HistGB (hybrid) | 347 | 75% | 0.989 [0.986, 0.991] | 0.994 [0.992, 0.994] |
| HistGB (hybrid) | 462 | 100% | 0.990 [0.988, 0.992] | 0.995 [0.994, 0.996] |

Train-only: five-fold domain-grouped cross-validation inside the training split, re-drawn 20 times for logistic and 10 times for HistGB. Whole domains are subsampled per class, so a fraction never splits a domain. Intervals are the 2.5-97.5 percentile range across repeats. The validation and test splits are never scored. At full size the pooled logistic estimate (0.973) reproduces the run's grouped-CV estimate (0.965) within 0.007.
