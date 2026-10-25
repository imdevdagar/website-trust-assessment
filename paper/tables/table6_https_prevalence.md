# Table 6. Transport security by class (H1), and padlock-only test baselines

| Class | n | HTTPS | Trusted chain | Mean rule risk | Low / medium / high / critical | High+ count | High+ share |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Malicious (in feed) | 497 | 84.9% | 48.3% | 0.229 | 244 / 248 / 5 / 0 | 5 | 1.0% |
| Benign (feed-absent) | 333 | 79.9% | 88.0% | 0.143 | 258 / 73 / 2 / 0 | 2 | 0.6% |
| All labelled | 830 | 82.9% | 64.2% | 0.195 | 502 / 321 / 7 / 0 | 7 | 0.8% |

HTTPS presence and certificate verification are separate measurements; a certificate existing is not a certificate verifying. `Benign` means absent from both feeds at retrieval time, never verified clean. Escalation is the shipped policy: high or critical risk. For the malicious class the high+ share is recall at escalation; for the benign class it is the false-alarm rate, not a recall.

**Test rule baselines (n = 123, 74 malicious).** Each rule predicts malicious when the condition in its label holds; scores are binary, so AUC ties count as half.

| Rule | AUROC [95% CI] | Precision | Recall | F1 [95% CI] |
| --- | ---: | ---: | ---: | ---: |
| HTTPS absent (padlock-only) | 0.432 [0.357, 0.503] | 0.400 | 0.108 | 0.170 [0.071, 0.280] |
| HTTPS absent or untrusted chain | 0.668 [0.586, 0.750] | 0.782 | 0.581 | 0.667 [0.561, 0.758] |

Intervals are percentile 95% bounds from 1000 domain-grouped bootstrap resamples. The HTTPS-only rule is the pre-registered padlock baseline, implemented as a fixed rule rather than a fitted classifier; the trusted-chain rule is descriptive and was not pre-registered.
