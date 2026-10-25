# Website trust assessment research run feed_v2

Generated: 2026-10-20T19:54:19.537229+00:00

## Protocol

- Models are fitted on the training split only.
- The decision threshold and Platt calibration are selected on validation.
- The test split is evaluated once and never used for fitting or selection.
- All splits are grouped by registrable domain.
- The rule engine is reported both as-is and after Platt calibration.
- Metrics below are computed by `trustlens.research.metrics`.

## Dataset

- Dataset: `data\datasets\feed_v2\dataset.jsonl`
- SHA-256: `ca6777520f435271b756079308b7526638c339f3571881f4574cb29928ff1ae2`
- Feature schema: v3
- Dataset split seed: 42
- Training seed: 42

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
| Rule engine (raw) | 0.519 | 0.701 | 0.398 | 0.402 | 0.745 | 0.598 | 0.986 | 0.001 |
| Rule engine + Platt | 0.519 | 0.701 | 0.398 | 0.402 | 0.745 | 0.598 | 0.986 | 0.001 |
| Logistic regression + Platt | 0.805 | 0.867 | 0.181 | 0.088 | 0.812 | 0.719 | 0.932 | 0.445 |
| HistGradientBoosting + Platt | 0.819 | 0.877 | 0.172 | 0.083 | 0.814 | 0.699 | 0.973 | 0.402 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.519 [0.410, 0.621] | 0.701 [0.562, 0.787] | 0.398 [0.329, 0.463] |
| Logistic regression | 0.805 [0.723, 0.878] | 0.867 [0.788, 0.927] | 0.181 [0.159, 0.206] |
| HistGradientBoosting | 0.819 [0.743, 0.890] | 0.877 [0.803, 0.934] | 0.172 [0.146, 0.197] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.398 | 0.398 | 0.402 | 0.402 |
| Logistic regression | 0.186 | 0.181 | 0.115 | 0.088 |
| HistGradientBoosting | 0.171 | 0.172 | 0.115 | 0.083 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.452 | 0.548 |
| Rule engine | 80% | 0.449 | 0.551 |
| Rule engine | 100% | 0.398 | 0.602 |
| Logistic regression | 50% | 0.823 | 0.177 |
| Logistic regression | 80% | 0.776 | 0.224 |
| Logistic regression | 100% | 0.740 | 0.260 |
| HistGradientBoosting | 50% | 0.871 | 0.129 |
| HistGradientBoosting | 80% | 0.806 | 0.194 |
| HistGradientBoosting | 100% | 0.715 | 0.285 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `url_digits_log` | +0.843 |
| `url_length_log` | +0.758 |
| `url_query_length_log` | -0.653 |
| `url_query_params` | -0.554 |
| `url_path_length_log` | +0.529 |
| `url_risky_tokens` | +0.501 |
| `url_https` | +0.333 |
| `url_dots` | -0.311 |
| `url_host_labels` | -0.311 |
| `url_host_digit_ratio` | +0.268 |
| `url_digit_ratio` | -0.259 |
| `url_path_depth` | -0.168 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `url_path_length_log` | 0.0959 | 0.0166 |
| `url_length_log` | 0.0714 | 0.0266 |
| `url_https` | 0.0592 | 0.0171 |
| `url_host_labels` | 0.0205 | 0.0036 |
| `url_digit_ratio` | 0.0133 | 0.0129 |
| `url_host_entropy` | 0.0117 | 0.0379 |
| `url_host_digit_ratio` | 0.0014 | 0.0055 |
| `url_digits_log` | 0.0010 | 0.0078 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.774 ± 0.044 | 0.847 ± 0.030 | 0.197 ± 0.013 | 0.135 ± 0.018 |
| HistGradientBoosting | 5 | 0.758 ± 0.059 | 0.831 ± 0.039 | 0.215 ± 0.035 | 0.156 ± 0.042 |

## Feature group: `signals` (80 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 581 | 578 | 348 |
| val | 126 | 125 | 75 |
| test | 123 | 123 | 74 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.519 | 0.701 | 0.398 | 0.402 | 0.745 | 0.598 | 0.986 | 0.001 |
| Rule engine + Platt | 0.519 | 0.701 | 0.398 | 0.402 | 0.745 | 0.598 | 0.986 | 0.001 |
| Logistic regression + Platt | 0.972 | 0.984 | 0.062 | 0.058 | 0.945 | 0.958 | 0.932 | 0.747 |
| HistGradientBoosting + Platt | 0.981 | 0.989 | 0.051 | 0.048 | 0.928 | 1.000 | 0.865 | 0.870 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.519 [0.410, 0.621] | 0.701 [0.562, 0.787] | 0.398 [0.329, 0.463] |
| Logistic regression | 0.972 [0.940, 0.995] | 0.984 [0.965, 0.997] | 0.062 [0.033, 0.096] |
| HistGradientBoosting | 0.981 [0.960, 0.996] | 0.989 [0.976, 0.998] | 0.051 [0.023, 0.081] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.398 | 0.398 | 0.402 | 0.402 |
| Logistic regression | 0.063 | 0.062 | 0.061 | 0.058 |
| HistGradientBoosting | 0.051 | 0.051 | 0.051 | 0.048 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.452 | 0.548 |
| Rule engine | 80% | 0.449 | 0.551 |
| Rule engine | 100% | 0.398 | 0.602 |
| Logistic regression | 50% | 0.984 | 0.016 |
| Logistic regression | 80% | 0.969 | 0.031 |
| Logistic regression | 100% | 0.911 | 0.089 |
| HistGradientBoosting | 50% | 1.000 | 0.000 |
| HistGradientBoosting | 80% | 0.990 | 0.010 |
| HistGradientBoosting | 100% | 0.919 | 0.081 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `redirected` | -3.263 |
| `flag_cross_domain_redirect` | -1.673 |
| `url_https` | +1.386 |
| `url_path_length_log` | +1.198 |
| `domain_age_unknown` | -1.169 |
| `url_risky_tokens` | +1.022 |
| `domain_age_log` | -0.827 |
| `url_length_log` | +0.817 |
| `trust_link_privacy` | -0.676 |
| `flag_unencrypted_http` | -0.609 |
| `page_cookies_log` | +0.604 |
| `url_host_length_log` | +0.604 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `redirected` | 0.3122 | 0.0263 |
| `url_https` | 0.0803 | 0.0143 |
| `url_length_log` | 0.0063 | 0.0024 |
| `tracker_total_log` | 0.0058 | 0.0055 |
| `page_network_log` | 0.0042 | 0.0010 |
| `url_host_labels` | 0.0041 | 0.0017 |
| `url_path_length_log` | 0.0035 | 0.0025 |
| `tls_days_remaining_log` | 0.0027 | 0.0017 |
| `url_host_entropy` | 0.0025 | 0.0007 |
| `page_images_log` | 0.0013 | 0.0005 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.953 ± 0.027 | 0.971 ± 0.017 | 0.075 ± 0.029 | 0.075 ± 0.022 |
| HistGradientBoosting | 5 | 0.978 ± 0.008 | 0.988 ± 0.005 | 0.059 ± 0.012 | 0.055 ± 0.013 |

## Feature group: `rule` (36 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 581 | 578 | 348 |
| val | 126 | 125 | 75 |
| test | 123 | 123 | 74 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.519 | 0.701 | 0.398 | 0.402 | 0.745 | 0.598 | 0.986 | 0.001 |
| Rule engine + Platt | 0.519 | 0.701 | 0.398 | 0.402 | 0.745 | 0.598 | 0.986 | 0.001 |
| Logistic regression + Platt | 0.959 | 0.977 | 0.074 | 0.045 | 0.925 | 0.932 | 0.919 | 0.477 |
| HistGradientBoosting + Platt | 0.971 | 0.982 | 0.074 | 0.050 | 0.915 | 0.886 | 0.946 | 0.311 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.519 [0.410, 0.621] | 0.701 [0.562, 0.787] | 0.398 [0.329, 0.463] |
| Logistic regression | 0.959 [0.924, 0.986] | 0.977 [0.953, 0.992] | 0.074 [0.042, 0.109] |
| HistGradientBoosting | 0.971 [0.944, 0.991] | 0.982 [0.963, 0.995] | 0.074 [0.040, 0.114] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.398 | 0.398 | 0.402 | 0.402 |
| Logistic regression | 0.077 | 0.074 | 0.065 | 0.045 |
| HistGradientBoosting | 0.075 | 0.074 | 0.083 | 0.050 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.452 | 0.548 |
| Rule engine | 80% | 0.449 | 0.551 |
| Rule engine | 100% | 0.398 | 0.602 |
| Logistic regression | 50% | 0.984 | 0.016 |
| Logistic regression | 80% | 0.939 | 0.061 |
| Logistic regression | 100% | 0.911 | 0.089 |
| HistGradientBoosting | 50% | 1.000 | 0.000 |
| HistGradientBoosting | 80% | 0.959 | 0.041 |
| HistGradientBoosting | 100% | 0.902 | 0.098 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `risk_medium_count` | -3.059 |
| `security_risk_points` | +2.948 |
| `privacy_risk_points` | +1.693 |
| `identity_risk_points` | +1.597 |
| `manipulation_confidence` | +1.326 |
| `security_confidence` | -1.268 |
| `identity_confidence` | +1.156 |
| `overall_confidence` | -1.124 |
| `privacy_confidence` | -1.104 |
| `risk_low_count` | -1.085 |
| `manipulation_coverage` | +0.975 |
| `security_evidence_count` | -0.971 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `risk_medium_count` | 0.0844 | 0.0180 |
| `security_risk_points` | 0.0424 | 0.0080 |
| `security_confidence` | 0.0380 | 0.0108 |
| `identity_evidence_count` | 0.0146 | 0.0030 |
| `identity_score` | 0.0141 | 0.0020 |
| `overall_confidence` | 0.0087 | 0.0042 |
| `missing_evidence_count` | 0.0052 | 0.0028 |
| `security_evidence_count` | 0.0037 | 0.0027 |
| `overall_rule_risk` | 0.0036 | 0.0018 |
| `evidence_count_log` | 0.0023 | 0.0030 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.915 ± 0.007 | 0.906 ± 0.029 | 0.102 ± 0.010 | 0.075 ± 0.014 |
| HistGradientBoosting | 5 | 0.953 ± 0.012 | 0.963 ± 0.022 | 0.085 ± 0.011 | 0.075 ± 0.012 |

## Feature group: `hybrid` (116 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 581 | 578 | 348 |
| val | 126 | 125 | 75 |
| test | 123 | 123 | 74 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.519 | 0.701 | 0.398 | 0.402 | 0.745 | 0.598 | 0.986 | 0.001 |
| Rule engine + Platt | 0.519 | 0.701 | 0.398 | 0.402 | 0.745 | 0.598 | 0.986 | 0.001 |
| Logistic regression + Platt | 0.986 | 0.993 | 0.035 | 0.026 | 0.959 | 0.959 | 0.959 | 0.421 |
| HistGradientBoosting + Platt | 0.991 | 0.995 | 0.044 | 0.052 | 0.950 | 1.000 | 0.905 | 0.812 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.519 [0.410, 0.621] | 0.701 [0.562, 0.787] | 0.398 [0.329, 0.463] |
| Logistic regression | 0.986 [0.961, 0.999] | 0.993 [0.979, 0.999] | 0.035 [0.012, 0.066] |
| HistGradientBoosting | 0.991 [0.975, 0.999] | 0.995 [0.986, 1.000] | 0.044 [0.014, 0.080] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.398 | 0.398 | 0.402 | 0.402 |
| Logistic regression | 0.035 | 0.035 | 0.036 | 0.026 |
| HistGradientBoosting | 0.034 | 0.044 | 0.039 | 0.052 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.452 | 0.548 |
| Rule engine | 80% | 0.449 | 0.551 |
| Rule engine | 100% | 0.398 | 0.602 |
| Logistic regression | 50% | 0.984 | 0.016 |
| Logistic regression | 80% | 0.990 | 0.010 |
| Logistic regression | 100% | 0.959 | 0.041 |
| HistGradientBoosting | 50% | 0.984 | 0.016 |
| HistGradientBoosting | 80% | 0.990 | 0.010 |
| HistGradientBoosting | 100% | 0.943 | 0.057 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `risk_medium_count` | -2.645 |
| `redirected` | -2.099 |
| `flag_cross_domain_redirect` | -1.972 |
| `security_evidence_count` | -1.267 |
| `url_https` | +1.266 |
| `flag_tls_certificate_invalid` | +1.053 |
| `url_path_length_log` | +0.988 |
| `identity_risk_points` | +0.984 |
| `url_length_log` | +0.956 |
| `privacy_confidence` | -0.896 |
| `risk_low_count` | +0.796 |
| `identity_score` | +0.793 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `redirected` | 0.1585 | 0.0242 |
| `url_https` | 0.0307 | 0.0062 |
| `risk_medium_count` | 0.0067 | 0.0041 |
| `url_path_length_log` | 0.0030 | 0.0009 |
| `url_length_log` | 0.0026 | 0.0013 |
| `url_host_entropy` | 0.0011 | 0.0002 |
| `security_confidence` | 0.0006 | 0.0003 |
| `page_scripts_log` | 0.0003 | 0.0000 |
| `url_host_length_log` | 0.0003 | 0.0000 |
| `url_host_labels` | 0.0003 | 0.0002 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.965 ± 0.019 | 0.973 ± 0.017 | 0.053 ± 0.017 | 0.046 ± 0.017 |
| HistGradientBoosting | 5 | 0.991 ± 0.002 | 0.996 ± 0.001 | 0.025 ± 0.004 | 0.026 ± 0.004 |

## Limitations

- The dataset is a convenience sample of live sites, not a random sample of the web.
- Labels are human judgments and may contain errors; reported agreement is in the run metadata.
- Suspicious sites are excluded from the main binary task unless a sensitivity run is requested.
- Site content and infrastructure change; results describe the collection window.
- Automated assessment is advisory and cannot guarantee that a site is safe.
