# Table 9. Pre-registered sensitivity runs

| Run | Hybrid logistic AUROC | Hybrid HistGB AUROC | Engine AUROC (all labelled) |
| --- | ---: | ---: | ---: |
| Primary, seed 42 | 0.986 | 0.991 | 0.513 |
| Re-split, seed 43 | 0.982 | 0.997 | 0.513 |
| Without batch-02 negatives | 0.978 | 0.978 | 0.517 |

The engine's all-labelled AUROC is the stable comparison; its test-split AUROC moves with the split at n=123 and is not a capability estimate.
