# Website trust assessment research run feed_v3_s43

Generated: 2026-11-01T08:16:52.033659+00:00

## Protocol

- Models are fitted on the training split only.
- The decision threshold and Platt calibration are selected on validation.
- The test split is evaluated once and never used for fitting or selection.
- All splits are grouped by registrable domain.
- The rule engine is reported both as-is and after Platt calibration.
- Metrics below are computed by `website_trust_assessment.research.metrics`.

## Dataset

- Dataset: `data\datasets\feed_v3_s43\dataset.jsonl`
- SHA-256: `b8a8fd84adc69ae23ed45ac45400a5e26be34d1d9b021d178c034f8625b42c2a`
- Feature schema: v3
- Dataset split seed: 43
- Training seed: 43

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
| Rule engine (raw) | 0.473 | 0.542 | 0.350 | 0.305 | 0.661 | 0.494 | 1.000 | 0.000 |
| Rule engine + Platt | 0.473 | 0.542 | 0.350 | 0.305 | 0.661 | 0.494 | 1.000 | 0.000 |
| Logistic regression + Platt | 0.885 | 0.898 | 0.137 | 0.028 | 0.805 | 0.795 | 0.816 | 0.357 |
| HistGradientBoosting + Platt | 0.890 | 0.904 | 0.132 | 0.026 | 0.802 | 0.815 | 0.789 | 0.395 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.473 [0.433, 0.515] | 0.542 [0.478, 0.583] | 0.350 [0.326, 0.375] |
| Logistic regression | 0.885 [0.859, 0.907] | 0.898 [0.872, 0.921] | 0.137 [0.124, 0.152] |
| HistGradientBoosting | 0.890 [0.866, 0.911] | 0.904 [0.878, 0.924] | 0.132 [0.118, 0.147] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.350 | 0.350 | 0.305 | 0.305 |
| Logistic regression | 0.136 | 0.137 | 0.038 | 0.028 |
| HistGradientBoosting | 0.132 | 0.132 | 0.025 | 0.026 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.500 | 0.500 |
| Rule engine | 80% | 0.527 | 0.473 |
| Rule engine | 100% | 0.507 | 0.493 |
| Logistic regression | 50% | 0.930 | 0.070 |
| Logistic regression | 80% | 0.857 | 0.143 |
| Logistic regression | 100% | 0.800 | 0.200 |
| HistGradientBoosting | 50% | 0.940 | 0.060 |
| HistGradientBoosting | 80% | 0.865 | 0.135 |
| HistGradientBoosting | 100% | 0.806 | 0.194 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `url_path_length_log` | +1.880 |
| `url_hyphens` | +0.540 |
| `url_length_log` | +0.539 |
| `url_path_depth` | -0.452 |
| `url_host_length_log` | +0.416 |
| `url_digits_log` | +0.381 |
| `url_special_log` | -0.315 |
| `url_has_punycode` | -0.228 |
| `url_digit_ratio` | +0.204 |
| `url_https` | +0.190 |
| `url_dots` | -0.143 |
| `url_host_labels` | -0.143 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `url_path_length_log` | 0.1069 | 0.0064 |
| `url_length_log` | 0.0648 | 0.0117 |
| `url_host_labels` | 0.0183 | 0.0080 |
| `url_hyphens` | 0.0144 | 0.0019 |
| `url_https` | 0.0135 | 0.0025 |
| `url_host_entropy` | 0.0074 | 0.0075 |
| `url_digit_ratio` | 0.0072 | 0.0019 |
| `url_digits_log` | 0.0067 | 0.0030 |
| `url_host_digit_ratio` | 0.0040 | 0.0020 |
| `url_special_log` | 0.0024 | 0.0008 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.870 ± 0.008 | 0.882 ± 0.017 | 0.141 ± 0.004 | 0.046 ± 0.017 |
| HistGradientBoosting | 5 | 0.882 ± 0.006 | 0.897 ± 0.008 | 0.135 ± 0.003 | 0.036 ± 0.006 |

## Feature group: `signals` (80 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 3590 | 3590 | 1773 |
| val | 770 | 770 | 380 |
| test | 769 | 769 | 380 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.473 | 0.542 | 0.350 | 0.305 | 0.661 | 0.494 | 1.000 | 0.000 |
| Rule engine + Platt | 0.473 | 0.542 | 0.350 | 0.305 | 0.661 | 0.494 | 1.000 | 0.000 |
| Logistic regression + Platt | 0.979 | 0.985 | 0.041 | 0.020 | 0.945 | 0.959 | 0.932 | 0.446 |
| HistGradientBoosting + Platt | 0.985 | 0.990 | 0.028 | 0.016 | 0.963 | 0.978 | 0.947 | 0.390 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.473 [0.433, 0.515] | 0.542 [0.478, 0.583] | 0.350 [0.326, 0.375] |
| Logistic regression | 0.979 [0.967, 0.989] | 0.985 [0.978, 0.992] | 0.041 [0.031, 0.052] |
| HistGradientBoosting | 0.985 [0.974, 0.994] | 0.990 [0.983, 0.996] | 0.028 [0.020, 0.038] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.350 | 0.350 | 0.305 | 0.305 |
| Logistic regression | 0.041 | 0.041 | 0.024 | 0.020 |
| HistGradientBoosting | 0.028 | 0.028 | 0.020 | 0.016 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.500 | 0.500 |
| Rule engine | 80% | 0.527 | 0.473 |
| Rule engine | 100% | 0.507 | 0.493 |
| Logistic regression | 50% | 0.992 | 0.008 |
| Logistic regression | 80% | 0.982 | 0.018 |
| Logistic regression | 100% | 0.945 | 0.055 |
| HistGradientBoosting | 50% | 0.995 | 0.005 |
| HistGradientBoosting | 80% | 0.985 | 0.015 |
| HistGradientBoosting | 100% | 0.962 | 0.038 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `redirected` | -3.400 |
| `url_path_length_log` | +2.083 |
| `url_https` | +1.274 |
| `flag_unencrypted_http` | -1.032 |
| `domain_age_log` | -0.855 |
| `http_ok` | +0.774 |
| `domain_age_unknown` | -0.774 |
| `tls_trusted` | -0.768 |
| `page_links_log` | -0.562 |
| `page_images_log` | -0.534 |
| `url_path_depth` | -0.470 |
| `page_iframes` | -0.470 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `redirected` | 0.2006 | 0.0157 |
| `url_https` | 0.0533 | 0.0048 |
| `url_path_length_log` | 0.0109 | 0.0019 |
| `url_length_log` | 0.0069 | 0.0019 |
| `url_host_labels` | 0.0032 | 0.0010 |
| `page_cookies_log` | 0.0023 | 0.0006 |
| `page_links_log` | 0.0017 | 0.0009 |
| `page_forms_log` | 0.0014 | 0.0005 |
| `page_images_log` | 0.0011 | 0.0006 |
| `domain_age_log` | 0.0009 | 0.0005 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.982 ± 0.008 | 0.985 ± 0.006 | 0.039 ± 0.009 | 0.023 ± 0.008 |
| HistGradientBoosting | 5 | 0.986 ± 0.006 | 0.990 ± 0.003 | 0.031 ± 0.005 | 0.021 ± 0.004 |

## Feature group: `rule` (36 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 3590 | 3590 | 1773 |
| val | 770 | 770 | 380 |
| test | 769 | 769 | 380 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.473 | 0.542 | 0.350 | 0.305 | 0.661 | 0.494 | 1.000 | 0.000 |
| Rule engine + Platt | 0.473 | 0.542 | 0.350 | 0.305 | 0.661 | 0.494 | 1.000 | 0.000 |
| Logistic regression + Platt | 0.964 | 0.969 | 0.062 | 0.034 | 0.922 | 0.958 | 0.889 | 0.523 |
| HistGradientBoosting + Platt | 0.982 | 0.987 | 0.036 | 0.013 | 0.956 | 0.968 | 0.945 | 0.418 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.473 [0.433, 0.515] | 0.542 [0.478, 0.583] | 0.350 [0.326, 0.375] |
| Logistic regression | 0.964 [0.950, 0.976] | 0.969 [0.955, 0.982] | 0.062 [0.050, 0.075] |
| HistGradientBoosting | 0.982 [0.972, 0.991] | 0.987 [0.981, 0.993] | 0.036 [0.027, 0.047] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.350 | 0.350 | 0.305 | 0.305 |
| Logistic regression | 0.064 | 0.062 | 0.040 | 0.034 |
| HistGradientBoosting | 0.037 | 0.036 | 0.016 | 0.013 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.500 | 0.500 |
| Rule engine | 80% | 0.527 | 0.473 |
| Rule engine | 100% | 0.507 | 0.493 |
| Logistic regression | 50% | 0.982 | 0.018 |
| Logistic regression | 80% | 0.961 | 0.039 |
| Logistic regression | 100% | 0.923 | 0.077 |
| HistGradientBoosting | 50% | 0.995 | 0.005 |
| HistGradientBoosting | 80% | 0.982 | 0.018 |
| HistGradientBoosting | 100% | 0.953 | 0.047 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `risk_medium_count` | -5.002 |
| `privacy_risk_points` | +4.250 |
| `security_risk_points` | +3.907 |
| `identity_risk_points` | +3.878 |
| `security_confidence` | -3.468 |
| `risk_high_count` | -2.942 |
| `security_coverage` | +2.442 |
| `risk_low_count` | -2.130 |
| `manipulation_coverage` | +2.067 |
| `manipulation_abstained` | +2.006 |
| `security_evidence_count` | -1.921 |
| `identity_score` | -1.722 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `security_risk_points` | 0.0744 | 0.0108 |
| `security_confidence` | 0.0279 | 0.0050 |
| `risk_medium_count` | 0.0165 | 0.0033 |
| `identity_evidence_count` | 0.0123 | 0.0021 |
| `missing_evidence_count` | 0.0089 | 0.0012 |
| `identity_score` | 0.0042 | 0.0012 |
| `identity_risk_points` | 0.0034 | 0.0008 |
| `security_coverage` | 0.0027 | 0.0003 |
| `overall_confidence` | 0.0020 | 0.0003 |
| `privacy_confidence` | 0.0015 | 0.0003 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.963 ± 0.004 | 0.966 ± 0.007 | 0.066 ± 0.003 | 0.048 ± 0.006 |
| HistGradientBoosting | 5 | 0.981 ± 0.003 | 0.985 ± 0.002 | 0.042 ± 0.005 | 0.020 ± 0.003 |

## Feature group: `hybrid` (116 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 3590 | 3590 | 1773 |
| val | 770 | 770 | 380 |
| test | 769 | 769 | 380 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.473 | 0.542 | 0.350 | 0.305 | 0.661 | 0.494 | 1.000 | 0.000 |
| Rule engine + Platt | 0.473 | 0.542 | 0.350 | 0.305 | 0.661 | 0.494 | 1.000 | 0.000 |
| Logistic regression + Platt | 0.988 | 0.992 | 0.027 | 0.020 | 0.964 | 0.971 | 0.958 | 0.314 |
| HistGradientBoosting + Platt | 0.993 | 0.995 | 0.020 | 0.011 | 0.976 | 0.997 | 0.955 | 0.719 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.473 [0.433, 0.515] | 0.542 [0.478, 0.583] | 0.350 [0.326, 0.375] |
| Logistic regression | 0.988 [0.978, 0.995] | 0.992 [0.986, 0.996] | 0.027 [0.018, 0.036] |
| HistGradientBoosting | 0.993 [0.986, 0.998] | 0.995 [0.991, 0.998] | 0.020 [0.012, 0.028] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.350 | 0.350 | 0.305 | 0.305 |
| Logistic regression | 0.026 | 0.027 | 0.019 | 0.020 |
| HistGradientBoosting | 0.020 | 0.020 | 0.016 | 0.011 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.500 | 0.500 |
| Rule engine | 80% | 0.527 | 0.473 |
| Rule engine | 100% | 0.507 | 0.493 |
| Logistic regression | 50% | 0.995 | 0.005 |
| Logistic regression | 80% | 0.990 | 0.010 |
| Logistic regression | 100% | 0.969 | 0.031 |
| HistGradientBoosting | 50% | 0.997 | 0.003 |
| HistGradientBoosting | 80% | 0.995 | 0.005 |
| HistGradientBoosting | 100% | 0.975 | 0.025 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `redirected` | -2.714 |
| `security_confidence` | -2.447 |
| `risk_medium_count` | -2.107 |
| `security_coverage` | +1.894 |
| `flag_tls_certificate_invalid` | +1.873 |
| `security_evidence_count` | -1.759 |
| `url_path_length_log` | +1.616 |
| `identity_risk_points` | +1.270 |
| `overall_rule_risk` | -1.261 |
| `privacy_evidence_count` | -1.204 |
| `overall_confidence` | +1.063 |
| `privacy_risk_points` | +1.062 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `redirected` | 0.0972 | 0.0117 |
| `url_https` | 0.0229 | 0.0018 |
| `url_path_length_log` | 0.0070 | 0.0013 |
| `risk_medium_count` | 0.0049 | 0.0012 |
| `url_length_log` | 0.0033 | 0.0006 |
| `security_confidence` | 0.0016 | 0.0007 |
| `page_images_log` | 0.0014 | 0.0007 |
| `identity_score` | 0.0014 | 0.0005 |
| `security_risk_points` | 0.0011 | 0.0012 |
| `url_host_labels` | 0.0009 | 0.0006 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.989 ± 0.005 | 0.991 ± 0.004 | 0.031 ± 0.005 | 0.021 ± 0.007 |
| HistGradientBoosting | 5 | 0.993 ± 0.002 | 0.995 ± 0.002 | 0.023 ± 0.003 | 0.018 ± 0.005 |

## Limitations

- The dataset is a convenience sample of live sites, not a random sample of the web.
- Labels are human judgments and may contain errors; reported agreement is in the run metadata.
- Suspicious sites are excluded from the main binary task unless a sensitivity run is requested.
- Site content and infrastructure change; results describe the collection window.
- Automated assessment is advisory and cannot guarantee that a site is safe.
