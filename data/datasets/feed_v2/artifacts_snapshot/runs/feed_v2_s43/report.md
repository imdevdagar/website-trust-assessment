# Website trust assessment research run feed_v2_s43

Generated: 2026-10-20T19:57:16.152715+00:00

## Protocol

- Models are fitted on the training split only.
- The decision threshold and Platt calibration are selected on validation.
- The test split is evaluated once and never used for fitting or selection.
- All splits are grouped by registrable domain.
- The rule engine is reported both as-is and after Platt calibration.
- Metrics below are computed by `trustlens.research.metrics`.

## Dataset

- Dataset: `data\datasets\feed_v2_s43\dataset.jsonl`
- SHA-256: `5363bbf72856ae728d70e43115dceedd39e3db1c657cb3d7e203b03648629eeb`
- Feature schema: v3
- Dataset split seed: 43
- Training seed: 43

| Split | Samples | Domains | Benign | Malicious |
| --- | ---: | ---: | ---: | ---: |
| train | 581 | 578 | 233 | 348 |
| val | 126 | 125 | 51 | 75 |
| test | 123 | 123 | 49 | 74 |

Dataset warnings:
- 107 assessment row(s) could not be parsed and were skipped

## Feature group: `url` (21 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 581 | 578 | 348 |
| val | 126 | 125 | 75 |
| test | 123 | 123 | 74 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.575 | 0.760 | 0.378 | 0.408 | 0.751 | 0.602 | 1.000 | 0.000 |
| Rule engine + Platt | 0.575 | 0.760 | 0.236 | 0.116 | 0.751 | 0.602 | 1.000 | 0.408 |
| Logistic regression + Platt | 0.777 | 0.848 | 0.185 | 0.065 | 0.793 | 0.705 | 0.905 | 0.509 |
| HistGradientBoosting + Platt | 0.732 | 0.807 | 0.201 | 0.065 | 0.785 | 0.664 | 0.959 | 0.324 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.575 [0.479, 0.675] | 0.760 [0.632, 0.831] | 0.236 [0.218, 0.253] |
| Logistic regression | 0.777 [0.689, 0.854] | 0.848 [0.771, 0.910] | 0.185 [0.155, 0.213] |
| HistGradientBoosting | 0.732 [0.642, 0.820] | 0.807 [0.708, 0.888] | 0.201 [0.165, 0.238] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.378 | 0.236 | 0.408 | 0.116 |
| Logistic regression | 0.186 | 0.185 | 0.106 | 0.065 |
| HistGradientBoosting | 0.220 | 0.201 | 0.155 | 0.065 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.677 | 0.323 |
| Rule engine | 80% | 0.551 | 0.449 |
| Rule engine | 100% | 0.602 | 0.398 |
| Logistic regression | 50% | 0.806 | 0.194 |
| Logistic regression | 80% | 0.755 | 0.245 |
| Logistic regression | 100% | 0.699 | 0.301 |
| HistGradientBoosting | 50% | 0.806 | 0.194 |
| HistGradientBoosting | 80% | 0.724 | 0.276 |
| HistGradientBoosting | 100% | 0.675 | 0.325 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `url_length_log` | +0.950 |
| `url_digits_log` | +0.879 |
| `url_path_length_log` | +0.850 |
| `url_query_params` | -0.538 |
| `url_query_length_log` | -0.531 |
| `url_path_depth` | -0.523 |
| `url_https` | +0.497 |
| `url_risky_tokens` | +0.431 |
| `url_digit_ratio` | -0.355 |
| `url_dots` | -0.306 |
| `url_host_labels` | -0.306 |
| `url_hyphens` | +0.221 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `url_path_length_log` | 0.0916 | 0.0260 |
| `url_https` | 0.0694 | 0.0114 |
| `url_host_labels` | 0.0448 | 0.0078 |
| `url_host_entropy` | 0.0370 | 0.0270 |
| `url_digit_ratio` | 0.0347 | 0.0094 |
| `url_special_log` | 0.0250 | 0.0084 |
| `url_digits_log` | 0.0128 | 0.0037 |
| `url_length_log` | 0.0106 | 0.0074 |
| `url_hyphens` | 0.0011 | 0.0018 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.772 ± 0.025 | 0.842 ± 0.026 | 0.196 ± 0.015 | 0.122 ± 0.029 |
| HistGradientBoosting | 5 | 0.763 ± 0.031 | 0.834 ± 0.025 | 0.219 ± 0.020 | 0.182 ± 0.041 |

## Feature group: `signals` (80 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 581 | 578 | 348 |
| val | 126 | 125 | 75 |
| test | 123 | 123 | 74 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.575 | 0.760 | 0.378 | 0.408 | 0.751 | 0.602 | 1.000 | 0.000 |
| Rule engine + Platt | 0.575 | 0.760 | 0.236 | 0.116 | 0.751 | 0.602 | 1.000 | 0.408 |
| Logistic regression + Platt | 0.948 | 0.966 | 0.066 | 0.062 | 0.923 | 0.957 | 0.892 | 0.781 |
| HistGradientBoosting + Platt | 0.984 | 0.992 | 0.034 | 0.032 | 0.966 | 0.986 | 0.946 | 0.500 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.575 [0.479, 0.675] | 0.760 [0.632, 0.831] | 0.236 [0.218, 0.253] |
| Logistic regression | 0.948 [0.904, 0.984] | 0.966 [0.934, 0.992] | 0.066 [0.030, 0.106] |
| HistGradientBoosting | 0.984 [0.963, 0.999] | 0.992 [0.980, 0.999] | 0.034 [0.013, 0.061] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.378 | 0.236 | 0.408 | 0.116 |
| Logistic regression | 0.065 | 0.066 | 0.068 | 0.062 |
| HistGradientBoosting | 0.038 | 0.034 | 0.045 | 0.032 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.677 | 0.323 |
| Rule engine | 80% | 0.551 | 0.449 |
| Rule engine | 100% | 0.602 | 0.398 |
| Logistic regression | 50% | 0.968 | 0.032 |
| Logistic regression | 80% | 0.939 | 0.061 |
| Logistic regression | 100% | 0.935 | 0.065 |
| HistGradientBoosting | 50% | 1.000 | 0.000 |
| HistGradientBoosting | 80% | 0.990 | 0.010 |
| HistGradientBoosting | 100% | 0.959 | 0.041 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `redirected` | -3.150 |
| `flag_cross_domain_redirect` | -1.870 |
| `url_path_length_log` | +1.473 |
| `url_https` | +1.382 |
| `domain_age_unknown` | -1.141 |
| `domain_age_log` | -0.972 |
| `url_risky_tokens` | +0.889 |
| `url_length_log` | +0.820 |
| `flag_unencrypted_http` | -0.751 |
| `flag_tls_certificate_invalid` | +0.651 |
| `url_digits_log` | +0.582 |
| `spf_record` | -0.557 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `redirected` | 0.2671 | 0.0283 |
| `url_https` | 0.0724 | 0.0083 |
| `url_path_length_log` | 0.0180 | 0.0066 |
| `tls_days_remaining_log` | 0.0113 | 0.0048 |
| `url_host_labels` | 0.0099 | 0.0043 |
| `tracker_total_log` | 0.0075 | 0.0029 |
| `flag_cross_domain_redirect` | 0.0048 | 0.0029 |
| `dmarc_record` | 0.0044 | 0.0027 |
| `page_hidden_elements_log` | 0.0036 | 0.0006 |
| `trust_link_contact` | 0.0035 | 0.0011 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.957 ± 0.013 | 0.975 ± 0.010 | 0.065 ± 0.012 | 0.054 ± 0.006 |
| HistGradientBoosting | 5 | 0.971 ± 0.007 | 0.985 ± 0.004 | 0.060 ± 0.018 | 0.061 ± 0.017 |

## Feature group: `rule` (36 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 581 | 578 | 348 |
| val | 126 | 125 | 75 |
| test | 123 | 123 | 74 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.575 | 0.760 | 0.378 | 0.408 | 0.751 | 0.602 | 1.000 | 0.000 |
| Rule engine + Platt | 0.575 | 0.760 | 0.236 | 0.116 | 0.751 | 0.602 | 1.000 | 0.408 |
| Logistic regression + Platt | 0.950 | 0.970 | 0.084 | 0.056 | 0.919 | 0.919 | 0.919 | 0.426 |
| HistGradientBoosting + Platt | 0.977 | 0.985 | 0.063 | 0.058 | 0.874 | 0.967 | 0.797 | 0.781 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.575 [0.479, 0.675] | 0.760 [0.632, 0.831] | 0.236 [0.218, 0.253] |
| Logistic regression | 0.950 [0.914, 0.982] | 0.970 [0.944, 0.989] | 0.084 [0.052, 0.119] |
| HistGradientBoosting | 0.977 [0.953, 0.994] | 0.985 [0.966, 0.996] | 0.063 [0.037, 0.096] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.378 | 0.236 | 0.408 | 0.116 |
| Logistic regression | 0.086 | 0.084 | 0.072 | 0.056 |
| HistGradientBoosting | 0.063 | 0.063 | 0.052 | 0.058 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.677 | 0.323 |
| Rule engine | 80% | 0.551 | 0.449 |
| Rule engine | 100% | 0.602 | 0.398 |
| Logistic regression | 50% | 0.984 | 0.016 |
| Logistic regression | 80% | 0.929 | 0.071 |
| Logistic regression | 100% | 0.894 | 0.106 |
| HistGradientBoosting | 50% | 1.000 | 0.000 |
| HistGradientBoosting | 80% | 0.969 | 0.031 |
| HistGradientBoosting | 100% | 0.911 | 0.089 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `risk_medium_count` | -3.052 |
| `security_risk_points` | +2.856 |
| `privacy_risk_points` | +1.749 |
| `identity_risk_points` | +1.638 |
| `overall_confidence` | -1.467 |
| `security_confidence` | -1.123 |
| `identity_confidence` | +1.079 |
| `privacy_confidence` | -1.056 |
| `security_evidence_count` | -1.035 |
| `risk_low_count` | -0.937 |
| `privacy_abstained` | -0.934 |
| `manipulation_confidence` | +0.864 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `risk_medium_count` | 0.1266 | 0.0367 |
| `security_risk_points` | 0.0357 | 0.0036 |
| `identity_risk_points` | 0.0164 | 0.0026 |
| `identity_evidence_count` | 0.0134 | 0.0047 |
| `security_confidence` | 0.0109 | 0.0038 |
| `overall_confidence` | 0.0086 | 0.0020 |
| `missing_evidence_count` | 0.0061 | 0.0034 |
| `evidence_count_log` | 0.0045 | 0.0014 |
| `security_score` | 0.0044 | 0.0037 |
| `identity_score` | 0.0033 | 0.0025 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.928 ± 0.032 | 0.931 ± 0.046 | 0.095 ± 0.020 | 0.088 ± 0.020 |
| HistGradientBoosting | 5 | 0.958 ± 0.021 | 0.971 ± 0.017 | 0.086 ± 0.028 | 0.083 ± 0.025 |

## Feature group: `hybrid` (116 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 581 | 578 | 348 |
| val | 126 | 125 | 75 |
| test | 123 | 123 | 74 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.575 | 0.760 | 0.378 | 0.408 | 0.751 | 0.602 | 1.000 | 0.000 |
| Rule engine + Platt | 0.575 | 0.760 | 0.236 | 0.116 | 0.751 | 0.602 | 1.000 | 0.408 |
| Logistic regression + Platt | 0.982 | 0.987 | 0.055 | 0.059 | 0.939 | 0.945 | 0.932 | 0.470 |
| HistGradientBoosting + Platt | 0.997 | 0.998 | 0.025 | 0.025 | 0.973 | 0.986 | 0.959 | 0.500 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.575 [0.479, 0.675] | 0.760 [0.632, 0.831] | 0.236 [0.218, 0.253] |
| Logistic regression | 0.982 [0.960, 0.997] | 0.987 [0.970, 0.998] | 0.055 [0.024, 0.095] |
| HistGradientBoosting | 0.997 [0.992, 1.000] | 0.998 [0.994, 1.000] | 0.025 [0.003, 0.050] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.378 | 0.236 | 0.408 | 0.116 |
| Logistic regression | 0.051 | 0.055 | 0.057 | 0.059 |
| HistGradientBoosting | 0.023 | 0.025 | 0.025 | 0.025 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.677 | 0.323 |
| Rule engine | 80% | 0.551 | 0.449 |
| Rule engine | 100% | 0.602 | 0.398 |
| Logistic regression | 50% | 1.000 | 0.000 |
| Logistic regression | 80% | 0.980 | 0.020 |
| Logistic regression | 100% | 0.927 | 0.073 |
| HistGradientBoosting | 50% | 1.000 | 0.000 |
| HistGradientBoosting | 80% | 1.000 | 0.000 |
| HistGradientBoosting | 100% | 0.967 | 0.033 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `risk_medium_count` | -2.654 |
| `redirected` | -2.149 |
| `flag_cross_domain_redirect` | -1.958 |
| `url_https` | +1.231 |
| `security_evidence_count` | -1.229 |
| `url_path_length_log` | +1.178 |
| `flag_tls_certificate_invalid` | +0.967 |
| `identity_risk_points` | +0.895 |
| `risk_low_count` | +0.866 |
| `url_length_log` | +0.807 |
| `url_risky_tokens` | +0.767 |
| `spf_record` | -0.764 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `redirected` | 0.0820 | 0.0108 |
| `url_https` | 0.0236 | 0.0035 |
| `risk_medium_count` | 0.0223 | 0.0031 |
| `url_path_length_log` | 0.0106 | 0.0020 |
| `flag_cross_domain_redirect` | 0.0017 | 0.0008 |
| `page_network_log` | 0.0004 | 0.0004 |
| `page_links_log` | 0.0002 | 0.0002 |
| `domain_age_log` | 0.0001 | 0.0001 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.967 ± 0.015 | 0.973 ± 0.020 | 0.048 ± 0.011 | 0.051 ± 0.009 |
| HistGradientBoosting | 5 | 0.986 ± 0.006 | 0.993 ± 0.003 | 0.031 ± 0.013 | 0.037 ± 0.015 |

## Limitations

- The dataset is a convenience sample of live sites, not a random sample of the web.
- Labels are human judgments and may contain errors; reported agreement is in the run metadata.
- Suspicious sites are excluded from the main binary task unless a sensitivity run is requested.
- Site content and infrastructure change; results describe the collection window.
- Automated assessment is advisory and cannot guarantee that a site is safe.
