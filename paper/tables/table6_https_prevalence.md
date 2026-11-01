# Table 6. Transport security by class (H1), and padlock-only test baselines

| Class | n | HTTPS | Trusted chain | Mean rule risk | Low / medium / high / critical | High+ count | High+ share |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Malicious (in feed) | 2533 | 87.2% | 46.3% | 0.218 | 1321 / 1183 / 29 / 0 | 29 | 1.1% |
| Benign (feed-absent) | 2596 | 74.0% | 85.7% | 0.162 | 1879 / 690 / 27 / 0 | 27 | 1.0% |
| All labelled | 5129 | 80.5% | 66.2% | 0.190 | 3200 / 1873 / 56 / 0 | 56 | 1.1% |

HTTPS presence and certificate verification are separate measurements; a certificate existing is not a certificate verifying. `Benign` means absent from both feeds at retrieval time, never verified clean. Escalation is the shipped policy: high or critical risk. For the malicious class the high+ share is recall at escalation; for the benign class it is the false-alarm rate, not a recall.

**Test rule baselines (n = 769, 380 malicious).** Each rule predicts malicious when the condition in its label holds; scores are binary, so AUC ties count as half.

| Rule | AUROC [95% CI] | Precision | Recall | F1 [95% CI] |
| --- | ---: | ---: | ---: | ---: |
| HTTPS absent (padlock-only) | 0.416 [0.389, 0.445] | 0.271 | 0.103 | 0.149 [0.107, 0.194] |
| HTTPS absent or untrusted chain | 0.635 [0.604, 0.668] | 0.656 | 0.553 | 0.600 [0.557, 0.642] |

Intervals are percentile 95% bounds from 1000 domain-grouped bootstrap resamples. The HTTPS-only rule is the pre-registered padlock baseline, implemented as a fixed rule rather than a fitted classifier; the trusted-chain rule is descriptive and was not pre-registered.
