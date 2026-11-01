# Website trust assessment research run feed_v3

Generated: 2026-11-01T08:15:20.219756+00:00

## Protocol

- Models are fitted on the training split only.
- The decision threshold and Platt calibration are selected on validation.
- The test split is evaluated once and never used for fitting or selection.
- All splits are grouped by registrable domain.
- The rule engine is reported both as-is and after Platt calibration.
- Metrics below are computed by `website_trust_assessment.research.metrics`.

## Dataset

- Dataset: `data\datasets\feed_v3\dataset.jsonl`
- SHA-256: `a1628d24887d9a329b7c7b2ea142cf35566e99e8db7d4468b611d2dd6c3bfd64`
- Feature schema: v3
- Dataset split seed: 42
- Training seed: 42

| Split | Samples | Domains | Benign | Malicious |
| --- | ---: | ---: | ---: | ---: |
| train | 3590 | 3590 | 1817 | 1773 |
| val | 770 | 770 | 390 | 380 |
| test | 769 | 769 | 389 | 380 |

## Feature group: `url` (21 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 3590 | 3590 | 1773 |
| val | 770 | 770 | 380 |
| test | 769 | 769 | 380 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.455 | 0.511 | 0.357 | 0.319 | 0.661 | 0.494 | 1.000 | 0.000 |
| Rule engine + Platt | 0.455 | 0.511 | 0.357 | 0.319 | 0.661 | 0.494 | 1.000 | 0.000 |
| Logistic regression + Platt | 0.857 | 0.840 | 0.150 | 0.048 | 0.787 | 0.790 | 0.784 | 0.427 |
| HistGradientBoosting + Platt | 0.881 | 0.886 | 0.139 | 0.041 | 0.802 | 0.806 | 0.797 | 0.417 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.455 [0.410, 0.494] | 0.511 [0.464, 0.570] | 0.357 [0.332, 0.384] |
| Logistic regression | 0.857 [0.829, 0.883] | 0.840 [0.795, 0.882] | 0.150 [0.134, 0.167] |
| HistGradientBoosting | 0.881 [0.855, 0.903] | 0.886 [0.855, 0.912] | 0.139 [0.124, 0.155] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.357 | 0.357 | 0.319 | 0.319 |
| Logistic regression | 0.150 | 0.150 | 0.053 | 0.048 |
| HistGradientBoosting | 0.139 | 0.139 | 0.043 | 0.041 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.471 | 0.529 |
| Rule engine | 80% | 0.546 | 0.454 |
| Rule engine | 100% | 0.505 | 0.495 |
| Logistic regression | 50% | 0.891 | 0.109 |
| Logistic regression | 80% | 0.846 | 0.154 |
| Logistic regression | 100% | 0.789 | 0.211 |
| HistGradientBoosting | 50% | 0.922 | 0.078 |
| HistGradientBoosting | 80% | 0.859 | 0.141 |
| HistGradientBoosting | 100% | 0.796 | 0.204 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `url_length_log` | +1.499 |
| `url_path_length_log` | +1.333 |
| `url_digits_log` | +0.710 |
| `url_hyphens` | +0.541 |
| `url_special_log` | -0.457 |
| `url_path_depth` | -0.384 |
| `url_query_params` | -0.189 |
| `url_host_labels` | -0.154 |
| `url_dots` | -0.154 |
| `url_https` | +0.148 |
| `url_digit_ratio` | -0.130 |
| `url_host_digit_ratio` | +0.092 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `url_path_length_log` | 0.1039 | 0.0030 |
| `url_length_log` | 0.0633 | 0.0033 |
| `url_host_labels` | 0.0208 | 0.0034 |
| `url_hyphens` | 0.0156 | 0.0037 |
| `url_host_entropy` | 0.0105 | 0.0049 |
| `url_https` | 0.0099 | 0.0023 |
| `url_digit_ratio` | 0.0082 | 0.0032 |
| `url_host_digit_ratio` | 0.0043 | 0.0008 |
| `url_digits_log` | 0.0032 | 0.0021 |
| `url_host_length_log` | 0.0021 | 0.0067 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.876 ± 0.014 | 0.888 ± 0.015 | 0.138 ± 0.010 | 0.042 ± 0.007 |
| HistGradientBoosting | 5 | 0.883 ± 0.012 | 0.898 ± 0.012 | 0.134 ± 0.009 | 0.041 ± 0.007 |

## Feature group: `signals` (80 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 3590 | 3590 | 1773 |
| val | 770 | 770 | 380 |
| test | 769 | 769 | 380 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.455 | 0.511 | 0.357 | 0.319 | 0.661 | 0.494 | 1.000 | 0.000 |
| Rule engine + Platt | 0.455 | 0.511 | 0.357 | 0.319 | 0.661 | 0.494 | 1.000 | 0.000 |
| Logistic regression + Platt | 0.979 | 0.977 | 0.038 | 0.023 | 0.953 | 0.948 | 0.958 | 0.455 |
| HistGradientBoosting + Platt | 0.991 | 0.992 | 0.034 | 0.020 | 0.957 | 0.944 | 0.971 | 0.385 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.455 [0.410, 0.494] | 0.511 [0.464, 0.570] | 0.357 [0.332, 0.384] |
| Logistic regression | 0.979 [0.967, 0.989] | 0.977 [0.957, 0.990] | 0.038 [0.028, 0.050] |
| HistGradientBoosting | 0.991 [0.985, 0.995] | 0.992 [0.988, 0.996] | 0.034 [0.024, 0.044] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.357 | 0.357 | 0.319 | 0.319 |
| Logistic regression | 0.037 | 0.038 | 0.017 | 0.023 |
| HistGradientBoosting | 0.032 | 0.034 | 0.018 | 0.020 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.471 | 0.529 |
| Rule engine | 80% | 0.546 | 0.454 |
| Rule engine | 100% | 0.505 | 0.495 |
| Logistic regression | 50% | 0.984 | 0.016 |
| Logistic regression | 80% | 0.977 | 0.023 |
| Logistic regression | 100% | 0.954 | 0.046 |
| HistGradientBoosting | 50% | 0.997 | 0.003 |
| HistGradientBoosting | 80% | 0.989 | 0.011 |
| HistGradientBoosting | 100% | 0.958 | 0.042 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `redirected` | -3.173 |
| `url_length_log` | +1.519 |
| `url_https` | +1.440 |
| `url_path_length_log` | +1.278 |
| `domain_age_log` | -1.055 |
| `domain_age_unknown` | -0.910 |
| `http_ok` | +0.757 |
| `flag_unencrypted_http` | -0.753 |
| `tls_trusted` | -0.740 |
| `page_scripts_log` | +0.702 |
| `page_links_log` | -0.665 |
| `page_images_log` | -0.523 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `redirected` | 0.1458 | 0.0110 |
| `url_https` | 0.0384 | 0.0031 |
| `url_path_length_log` | 0.0120 | 0.0015 |
| `url_length_log` | 0.0077 | 0.0007 |
| `url_host_labels` | 0.0035 | 0.0008 |
| `page_cookies_log` | 0.0027 | 0.0007 |
| `page_links_log` | 0.0021 | 0.0014 |
| `http_ok` | 0.0021 | 0.0004 |
| `page_iframes` | 0.0014 | 0.0002 |
| `domain_age_log` | 0.0013 | 0.0006 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.981 ± 0.004 | 0.983 ± 0.006 | 0.039 ± 0.004 | 0.020 ± 0.003 |
| HistGradientBoosting | 5 | 0.985 ± 0.002 | 0.989 ± 0.001 | 0.032 ± 0.002 | 0.021 ± 0.004 |

## Feature group: `rule` (36 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 3590 | 3590 | 1773 |
| val | 770 | 770 | 380 |
| test | 769 | 769 | 380 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.455 | 0.511 | 0.357 | 0.319 | 0.661 | 0.494 | 1.000 | 0.000 |
| Rule engine + Platt | 0.455 | 0.511 | 0.357 | 0.319 | 0.661 | 0.494 | 1.000 | 0.000 |
| Logistic regression + Platt | 0.964 | 0.956 | 0.065 | 0.038 | 0.908 | 0.893 | 0.924 | 0.366 |
| HistGradientBoosting + Platt | 0.983 | 0.987 | 0.039 | 0.015 | 0.950 | 0.975 | 0.926 | 0.545 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.455 [0.410, 0.494] | 0.511 [0.464, 0.570] | 0.357 [0.332, 0.384] |
| Logistic regression | 0.964 [0.950, 0.977] | 0.956 [0.927, 0.978] | 0.065 [0.054, 0.076] |
| HistGradientBoosting | 0.983 [0.973, 0.991] | 0.987 [0.980, 0.993] | 0.039 [0.029, 0.049] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.357 | 0.357 | 0.319 | 0.319 |
| Logistic regression | 0.065 | 0.065 | 0.039 | 0.038 |
| HistGradientBoosting | 0.038 | 0.039 | 0.012 | 0.015 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.471 | 0.529 |
| Rule engine | 80% | 0.546 | 0.454 |
| Rule engine | 100% | 0.505 | 0.495 |
| Logistic regression | 50% | 0.984 | 0.016 |
| Logistic regression | 80% | 0.966 | 0.034 |
| Logistic regression | 100% | 0.919 | 0.081 |
| HistGradientBoosting | 50% | 0.995 | 0.005 |
| HistGradientBoosting | 80% | 0.984 | 0.016 |
| HistGradientBoosting | 100% | 0.951 | 0.049 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `risk_medium_count` | -5.058 |
| `privacy_risk_points` | +4.648 |
| `security_risk_points` | +3.748 |
| `security_confidence` | -3.558 |
| `identity_risk_points` | +3.266 |
| `risk_high_count` | -2.912 |
| `security_coverage` | +2.437 |
| `manipulation_abstained` | +2.296 |
| `risk_low_count` | -2.059 |
| `security_evidence_count` | -1.969 |
| `manipulation_coverage` | +1.905 |
| `privacy_confidence` | -1.447 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `security_risk_points` | 0.0466 | 0.0037 |
| `security_confidence` | 0.0268 | 0.0014 |
| `risk_medium_count` | 0.0173 | 0.0034 |
| `identity_evidence_count` | 0.0066 | 0.0010 |
| `missing_evidence_count` | 0.0057 | 0.0023 |
| `security_coverage` | 0.0033 | 0.0002 |
| `identity_risk_points` | 0.0022 | 0.0007 |
| `identity_score` | 0.0021 | 0.0013 |
| `privacy_risk_points` | 0.0019 | 0.0006 |
| `security_score` | 0.0017 | 0.0008 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.965 ± 0.004 | 0.970 ± 0.005 | 0.063 ± 0.005 | 0.042 ± 0.010 |
| HistGradientBoosting | 5 | 0.982 ± 0.002 | 0.986 ± 0.001 | 0.040 ± 0.004 | 0.025 ± 0.004 |

## Feature group: `hybrid` (116 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 3590 | 3590 | 1773 |
| val | 770 | 770 | 380 |
| test | 769 | 769 | 380 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.455 | 0.511 | 0.357 | 0.319 | 0.661 | 0.494 | 1.000 | 0.000 |
| Rule engine + Platt | 0.455 | 0.511 | 0.357 | 0.319 | 0.661 | 0.494 | 1.000 | 0.000 |
| Logistic regression + Platt | 0.987 | 0.986 | 0.028 | 0.018 | 0.966 | 0.973 | 0.958 | 0.554 |
| HistGradientBoosting + Platt | 0.993 | 0.994 | 0.026 | 0.014 | 0.967 | 0.976 | 0.958 | 0.662 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.455 [0.410, 0.494] | 0.511 [0.464, 0.570] | 0.357 [0.332, 0.384] |
| Logistic regression | 0.987 [0.979, 0.994] | 0.986 [0.974, 0.994] | 0.028 [0.020, 0.038] |
| HistGradientBoosting | 0.993 [0.988, 0.997] | 0.994 [0.991, 0.997] | 0.026 [0.018, 0.036] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.357 | 0.357 | 0.319 | 0.319 |
| Logistic regression | 0.028 | 0.028 | 0.018 | 0.018 |
| HistGradientBoosting | 0.027 | 0.026 | 0.021 | 0.014 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.471 | 0.529 |
| Rule engine | 80% | 0.546 | 0.454 |
| Rule engine | 100% | 0.505 | 0.495 |
| Logistic regression | 50% | 0.995 | 0.005 |
| Logistic regression | 80% | 0.985 | 0.015 |
| Logistic regression | 100% | 0.966 | 0.034 |
| HistGradientBoosting | 50% | 1.000 | 0.000 |
| HistGradientBoosting | 80% | 0.997 | 0.003 |
| HistGradientBoosting | 100% | 0.965 | 0.035 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `security_confidence` | -2.689 |
| `redirected` | -2.406 |
| `risk_medium_count` | -2.126 |
| `security_evidence_count` | -1.791 |
| `security_coverage` | +1.655 |
| `overall_rule_risk` | -1.466 |
| `privacy_risk_points` | +1.368 |
| `url_length_log` | +1.299 |
| `flag_tls_certificate_invalid` | +1.150 |
| `url_https` | +1.127 |
| `identity_risk_points` | +1.059 |
| `url_path_length_log` | +0.989 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `redirected` | 0.0653 | 0.0081 |
| `url_https` | 0.0150 | 0.0007 |
| `risk_medium_count` | 0.0031 | 0.0011 |
| `url_path_length_log` | 0.0029 | 0.0004 |
| `security_confidence` | 0.0024 | 0.0011 |
| `http_ok` | 0.0018 | 0.0003 |
| `url_length_log` | 0.0014 | 0.0010 |
| `security_risk_points` | 0.0014 | 0.0013 |
| `url_path_depth` | 0.0011 | 0.0005 |
| `page_cookies_log` | 0.0009 | 0.0000 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.987 ± 0.004 | 0.989 ± 0.004 | 0.031 ± 0.003 | 0.015 ± 0.003 |
| HistGradientBoosting | 5 | 0.994 ± 0.002 | 0.995 ± 0.001 | 0.023 ± 0.001 | 0.020 ± 0.002 |

## Limitations

- The dataset is a convenience sample of live sites, not a random sample of the web.
- Labels are human judgments and may contain errors; reported agreement is in the run metadata.
- Suspicious sites are excluded from the main binary task unless a sensitivity run is requested.
- Site content and infrastructure change; results describe the collection window.
- Automated assessment is advisory and cannot guarantee that a site is safe.
