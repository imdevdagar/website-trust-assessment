# Website trust assessment research run feed_v2_no_batch_02

Generated: 2026-10-20T20:00:16.522532+00:00

## Protocol

- Models are fitted on the training split only.
- The decision threshold and Platt calibration are selected on validation.
- The test split is evaluated once and never used for fitting or selection.
- All splits are grouped by registrable domain.
- The rule engine is reported both as-is and after Platt calibration.
- Metrics below are computed by `trustlens.research.metrics`.

## Dataset

- Dataset: `data\datasets\feed_v2_no_batch_02\dataset.jsonl`
- SHA-256: `445a911f2fbe17182ffa3536e2b9bfa1d567a27340dc0bd6e4a0a49299cb0b41`
- Feature schema: v3
- Dataset split seed: 42
- Training seed: 42

| Split | Samples | Domains | Benign | Malicious |
| --- | ---: | ---: | ---: | ---: |
| train | 530 | 527 | 183 | 347 |
| val | 114 | 114 | 39 | 75 |
| test | 113 | 112 | 38 | 75 |

Dataset warnings:
- 91 assessment row(s) could not be parsed and were skipped

## Feature group: `url` (21 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 530 | 527 | 347 |
| val | 114 | 114 | 75 |
| test | 113 | 112 | 75 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.676 | 0.821 | 0.358 | 0.414 | 0.798 | 0.664 | 1.000 | 0.000 |
| Rule engine + Platt | 0.676 | 0.821 | 0.358 | 0.414 | 0.798 | 0.664 | 1.000 | 0.000 |
| Logistic regression + Platt | 0.725 | 0.832 | 0.204 | 0.092 | 0.776 | 0.766 | 0.787 | 0.556 |
| HistGradientBoosting + Platt | 0.762 | 0.864 | 0.181 | 0.078 | 0.792 | 0.772 | 0.813 | 0.500 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.676 [0.572, 0.773] | 0.821 [0.705, 0.900] | 0.358 [0.301, 0.421] |
| Logistic regression | 0.725 [0.618, 0.824] | 0.832 [0.738, 0.912] | 0.204 [0.155, 0.254] |
| HistGradientBoosting | 0.762 [0.669, 0.848] | 0.864 [0.783, 0.927] | 0.181 [0.142, 0.226] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.358 | 0.358 | 0.414 | 0.414 |
| Logistic regression | 0.219 | 0.204 | 0.160 | 0.092 |
| HistGradientBoosting | 0.204 | 0.181 | 0.149 | 0.078 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.518 | 0.482 |
| Rule engine | 80% | 0.378 | 0.622 |
| Rule engine | 100% | 0.336 | 0.664 |
| Logistic regression | 50% | 0.821 | 0.179 |
| Logistic regression | 80% | 0.756 | 0.244 |
| Logistic regression | 100% | 0.708 | 0.292 |
| HistGradientBoosting | 50% | 0.839 | 0.161 |
| HistGradientBoosting | 80% | 0.767 | 0.233 |
| HistGradientBoosting | 100% | 0.717 | 0.283 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `url_digits_log` | +1.275 |
| `url_digit_ratio` | -0.762 |
| `url_path_length_log` | +0.746 |
| `url_query_params` | -0.718 |
| `url_query_length_log` | -0.686 |
| `url_length_log` | +0.652 |
| `url_risky_tokens` | +0.482 |
| `url_https` | +0.476 |
| `url_path_depth` | -0.348 |
| `url_dots` | -0.319 |
| `url_host_labels` | -0.319 |
| `url_special_log` | +0.257 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `url_path_length_log` | 0.2057 | 0.0499 |
| `url_https` | 0.0825 | 0.0254 |
| `url_host_entropy` | 0.0360 | 0.0194 |
| `url_length_log` | 0.0359 | 0.0152 |
| `url_host_labels` | 0.0302 | 0.0146 |
| `url_host_length_log` | 0.0236 | 0.0035 |
| `url_digit_ratio` | 0.0110 | 0.0123 |
| `url_special_log` | 0.0107 | 0.0044 |
| `url_digits_log` | 0.0100 | 0.0057 |
| `url_host_digit_ratio` | 0.0071 | 0.0056 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.772 ± 0.030 | 0.869 ± 0.009 | 0.198 ± 0.009 | 0.155 ± 0.029 |
| HistGradientBoosting | 5 | 0.729 ± 0.047 | 0.833 ± 0.025 | 0.221 ± 0.027 | 0.189 ± 0.039 |

## Feature group: `signals` (80 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 530 | 527 | 347 |
| val | 114 | 114 | 75 |
| test | 113 | 112 | 75 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.676 | 0.821 | 0.358 | 0.414 | 0.798 | 0.664 | 1.000 | 0.000 |
| Rule engine + Platt | 0.676 | 0.821 | 0.358 | 0.414 | 0.798 | 0.664 | 1.000 | 0.000 |
| Logistic regression + Platt | 0.972 | 0.988 | 0.057 | 0.065 | 0.940 | 0.946 | 0.933 | 0.460 |
| HistGradientBoosting + Platt | 0.982 | 0.992 | 0.043 | 0.042 | 0.959 | 0.986 | 0.933 | 0.506 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.676 [0.572, 0.773] | 0.821 [0.705, 0.900] | 0.358 [0.301, 0.421] |
| Logistic regression | 0.972 [0.941, 0.994] | 0.988 [0.974, 0.998] | 0.057 [0.033, 0.085] |
| HistGradientBoosting | 0.982 [0.960, 0.999] | 0.992 [0.982, 0.999] | 0.043 [0.019, 0.073] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.358 | 0.358 | 0.414 | 0.414 |
| Logistic regression | 0.054 | 0.057 | 0.072 | 0.065 |
| HistGradientBoosting | 0.050 | 0.043 | 0.054 | 0.042 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.518 | 0.482 |
| Rule engine | 80% | 0.378 | 0.622 |
| Rule engine | 100% | 0.336 | 0.664 |
| Logistic regression | 50% | 1.000 | 0.000 |
| Logistic regression | 80% | 0.967 | 0.033 |
| Logistic regression | 100% | 0.920 | 0.080 |
| HistGradientBoosting | 50% | 1.000 | 0.000 |
| HistGradientBoosting | 80% | 0.978 | 0.022 |
| HistGradientBoosting | 100% | 0.947 | 0.053 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `redirected` | -3.334 |
| `flag_cross_domain_redirect` | -1.738 |
| `url_path_length_log` | +1.716 |
| `url_https` | +1.321 |
| `url_risky_tokens` | +1.071 |
| `domain_age_unknown` | -1.013 |
| `flag_unencrypted_http` | -0.725 |
| `domain_age_log` | -0.685 |
| `url_digits_log` | +0.622 |
| `page_cookies_log` | +0.609 |
| `trust_link_privacy` | -0.596 |
| `tracker_total_log` | -0.571 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `redirected` | 0.2079 | 0.0383 |
| `url_https` | 0.0905 | 0.0220 |
| `url_path_length_log` | 0.0456 | 0.0132 |
| `url_length_log` | 0.0064 | 0.0049 |
| `domain_age_log` | 0.0042 | 0.0004 |
| `url_host_labels` | 0.0017 | 0.0033 |
| `flag_cross_domain_redirect` | 0.0017 | 0.0005 |
| `page_images_log` | 0.0012 | 0.0019 |
| `page_network_log` | 0.0010 | 0.0027 |
| `url_host_length_log` | 0.0007 | 0.0003 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.962 ± 0.026 | 0.981 ± 0.014 | 0.062 ± 0.024 | 0.062 ± 0.012 |
| HistGradientBoosting | 5 | 0.980 ± 0.008 | 0.991 ± 0.004 | 0.049 ± 0.015 | 0.053 ± 0.014 |

## Feature group: `rule` (36 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 530 | 527 | 347 |
| val | 114 | 114 | 75 |
| test | 113 | 112 | 75 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.676 | 0.821 | 0.358 | 0.414 | 0.798 | 0.664 | 1.000 | 0.000 |
| Rule engine + Platt | 0.676 | 0.821 | 0.358 | 0.414 | 0.798 | 0.664 | 1.000 | 0.000 |
| Logistic regression + Platt | 0.913 | 0.938 | 0.103 | 0.117 | 0.904 | 0.930 | 0.880 | 0.580 |
| HistGradientBoosting + Platt | 0.959 | 0.981 | 0.078 | 0.053 | 0.894 | 0.837 | 0.960 | 0.147 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.676 [0.572, 0.773] | 0.821 [0.705, 0.900] | 0.358 [0.301, 0.421] |
| Logistic regression | 0.913 [0.844, 0.970] | 0.938 [0.867, 0.986] | 0.103 [0.063, 0.148] |
| HistGradientBoosting | 0.959 [0.922, 0.987] | 0.981 [0.961, 0.994] | 0.078 [0.045, 0.119] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.358 | 0.358 | 0.414 | 0.414 |
| Logistic regression | 0.105 | 0.103 | 0.115 | 0.117 |
| HistGradientBoosting | 0.082 | 0.078 | 0.072 | 0.053 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.518 | 0.482 |
| Rule engine | 80% | 0.378 | 0.622 |
| Rule engine | 100% | 0.336 | 0.664 |
| Logistic regression | 50% | 0.964 | 0.036 |
| Logistic regression | 80% | 0.922 | 0.078 |
| Logistic regression | 100% | 0.850 | 0.150 |
| HistGradientBoosting | 50% | 1.000 | 0.000 |
| HistGradientBoosting | 80% | 0.944 | 0.056 |
| HistGradientBoosting | 100% | 0.894 | 0.106 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `risk_medium_count` | -3.359 |
| `security_risk_points` | +2.701 |
| `identity_risk_points` | +1.687 |
| `privacy_risk_points` | +1.639 |
| `risk_low_count` | -1.572 |
| `security_confidence` | -1.566 |
| `privacy_score` | +1.541 |
| `overall_confidence` | -1.445 |
| `manipulation_confidence` | +1.355 |
| `privacy_confidence` | -1.136 |
| `manipulation_coverage` | +1.110 |
| `security_evidence_count` | -0.988 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `risk_medium_count` | 0.0380 | 0.0160 |
| `security_confidence` | 0.0291 | 0.0080 |
| `security_risk_points` | 0.0196 | 0.0054 |
| `missing_evidence_count` | 0.0175 | 0.0048 |
| `identity_score` | 0.0135 | 0.0024 |
| `identity_evidence_count` | 0.0110 | 0.0033 |
| `overall_confidence` | 0.0092 | 0.0046 |
| `identity_risk_points` | 0.0084 | 0.0117 |
| `privacy_risk_points` | 0.0055 | 0.0023 |
| `privacy_coverage` | 0.0052 | 0.0042 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.938 ± 0.023 | 0.950 ± 0.026 | 0.086 ± 0.013 | 0.089 ± 0.014 |
| HistGradientBoosting | 5 | 0.957 ± 0.009 | 0.979 ± 0.005 | 0.087 ± 0.011 | 0.083 ± 0.012 |

## Feature group: `hybrid` (116 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 530 | 527 | 347 |
| val | 114 | 114 | 75 |
| test | 113 | 112 | 75 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.676 | 0.821 | 0.358 | 0.414 | 0.798 | 0.664 | 1.000 | 0.000 |
| Rule engine + Platt | 0.676 | 0.821 | 0.358 | 0.414 | 0.798 | 0.664 | 1.000 | 0.000 |
| Logistic regression + Platt | 0.978 | 0.991 | 0.044 | 0.083 | 0.954 | 0.947 | 0.960 | 0.356 |
| HistGradientBoosting + Platt | 0.978 | 0.992 | 0.028 | 0.035 | 0.973 | 0.986 | 0.960 | 0.500 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.676 [0.572, 0.773] | 0.821 [0.705, 0.900] | 0.358 [0.301, 0.421] |
| Logistic regression | 0.978 [0.942, 1.000] | 0.991 [0.978, 1.000] | 0.044 [0.022, 0.073] |
| HistGradientBoosting | 0.978 [0.941, 1.000] | 0.992 [0.978, 1.000] | 0.028 [0.007, 0.056] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.358 | 0.358 | 0.414 | 0.414 |
| Logistic regression | 0.037 | 0.044 | 0.048 | 0.083 |
| HistGradientBoosting | 0.027 | 0.028 | 0.037 | 0.035 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.518 | 0.482 |
| Rule engine | 80% | 0.378 | 0.622 |
| Rule engine | 100% | 0.336 | 0.664 |
| Logistic regression | 50% | 0.964 | 0.036 |
| Logistic regression | 80% | 0.978 | 0.022 |
| Logistic regression | 100% | 0.965 | 0.035 |
| HistGradientBoosting | 50% | 0.982 | 0.018 |
| HistGradientBoosting | 80% | 0.978 | 0.022 |
| HistGradientBoosting | 100% | 0.965 | 0.035 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `risk_medium_count` | -2.587 |
| `redirected` | -2.260 |
| `flag_cross_domain_redirect` | -1.765 |
| `url_path_length_log` | +1.313 |
| `security_evidence_count` | -1.310 |
| `url_https` | +1.170 |
| `flag_suspicious_tld` | -0.935 |
| `identity_risk_points` | +0.920 |
| `identity_score` | +0.913 |
| `flag_tls_certificate_invalid` | +0.899 |
| `identity_evidence_count` | +0.787 |
| `dmarc_record` | -0.758 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `redirected` | 0.0643 | 0.0198 |
| `url_https` | 0.0439 | 0.0119 |
| `url_path_length_log` | 0.0255 | 0.0069 |
| `url_length_log` | 0.0055 | 0.0014 |
| `risk_medium_count` | 0.0049 | 0.0043 |
| `security_risk_points` | 0.0043 | 0.0020 |
| `security_score` | 0.0027 | 0.0018 |
| `security_confidence` | 0.0023 | 0.0037 |
| `page_network_log` | 0.0017 | 0.0016 |
| `flag_cross_domain_redirect` | 0.0012 | 0.0007 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.978 ± 0.012 | 0.988 ± 0.006 | 0.044 ± 0.020 | 0.056 ± 0.012 |
| HistGradientBoosting | 5 | 0.995 ± 0.002 | 0.998 ± 0.001 | 0.026 ± 0.005 | 0.034 ± 0.008 |

## Limitations

- The dataset is a convenience sample of live sites, not a random sample of the web.
- Labels are human judgments and may contain errors; reported agreement is in the run metadata.
- Suspicious sites are excluded from the main binary task unless a sensitivity run is requested.
- Site content and infrastructure change; results describe the collection window.
- Automated assessment is advisory and cannot guarantee that a site is safe.
