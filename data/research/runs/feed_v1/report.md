# Website trust assessment research run feed_v1

Generated: 2026-10-20T18:43:57.831180+00:00

## Protocol

- Models are fitted on the training split only.
- The decision threshold and Platt calibration are selected on validation.
- The test split is evaluated once and never used for fitting or selection.
- All splits are grouped by registrable domain.
- The rule engine is reported both as-is and after Platt calibration.
- Metrics below are computed by `trustlens.research.metrics`.

## Dataset

- Dataset: `data\datasets\feed_v1\dataset.jsonl`
- SHA-256: `ef275433e2903354840ba462b6e7c44026a774e0c1d595963316dbab54d3bc28`
- Feature schema: v3
- Dataset split seed: 42
- Training seed: 42

| Split | Samples | Domains | Benign | Malicious |
| --- | ---: | ---: | ---: | ---: |
| train | 520 | 520 | 173 | 347 |
| val | 112 | 111 | 38 | 74 |
| test | 111 | 111 | 37 | 74 |

Dataset warnings:
- 84 assessment row(s) could not be parsed and were skipped

## Feature group: `url` (21 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 520 | 520 | 347 |
| val | 112 | 111 | 74 |
| test | 111 | 111 | 74 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.501 | 0.725 | 0.446 | 0.476 | 0.800 | 0.667 | 1.000 | 0.000 |
| Rule engine + Platt | 0.501 | 0.725 | 0.223 | 0.008 | 0.800 | 0.667 | 1.000 | 0.500 |
| Logistic regression + Platt | 0.752 | 0.860 | 0.181 | 0.070 | 0.798 | 0.713 | 0.905 | 0.500 |
| HistGradientBoosting + Platt | 0.698 | 0.813 | 0.192 | 0.075 | 0.807 | 0.728 | 0.905 | 0.515 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.501 [0.390, 0.604] | 0.725 [0.593, 0.822] | 0.223 [0.197, 0.253] |
| Logistic regression | 0.752 [0.655, 0.839] | 0.860 [0.767, 0.931] | 0.181 [0.152, 0.214] |
| HistGradientBoosting | 0.698 [0.593, 0.788] | 0.813 [0.709, 0.899] | 0.192 [0.163, 0.223] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.446 | 0.223 | 0.476 | 0.008 |
| Logistic regression | 0.207 | 0.181 | 0.137 | 0.070 |
| HistGradientBoosting | 0.235 | 0.192 | 0.180 | 0.075 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.696 | 0.304 |
| Rule engine | 80% | 0.629 | 0.371 |
| Rule engine | 100% | 0.667 | 0.333 |
| Logistic regression | 50% | 0.875 | 0.125 |
| Logistic regression | 80% | 0.742 | 0.258 |
| Logistic regression | 100% | 0.694 | 0.306 |
| HistGradientBoosting | 50% | 0.786 | 0.214 |
| HistGradientBoosting | 80% | 0.730 | 0.270 |
| HistGradientBoosting | 100% | 0.712 | 0.288 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `url_digits_log` | +0.932 |
| `url_path_length_log` | +0.793 |
| `url_query_length_log` | -0.770 |
| `url_digit_ratio` | +0.754 |
| `url_query_params` | -0.571 |
| `url_risky_tokens` | +0.490 |
| `url_https` | +0.460 |
| `url_host_entropy` | +0.380 |
| `url_length_log` | +0.310 |
| `url_host_labels` | -0.280 |
| `url_dots` | -0.280 |
| `url_host_digit_ratio` | -0.231 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `url_path_length_log` | 0.1038 | 0.0276 |
| `url_host_labels` | 0.0535 | 0.0273 |
| `url_https` | 0.0274 | 0.0080 |
| `url_digit_ratio` | 0.0251 | 0.0112 |
| `url_special_log` | 0.0031 | 0.0018 |
| `url_host_digit_ratio` | 0.0025 | 0.0018 |
| `url_host_entropy` | 0.0022 | 0.0222 |
| `url_digits_log` | 0.0011 | 0.0035 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.796 ± 0.026 | 0.894 ± 0.015 | 0.187 ± 0.011 | 0.137 ± 0.017 |
| HistGradientBoosting | 5 | 0.771 ± 0.054 | 0.878 ± 0.022 | 0.207 ± 0.039 | 0.183 ± 0.043 |

## Feature group: `signals` (80 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 520 | 520 | 347 |
| val | 112 | 111 | 74 |
| test | 111 | 111 | 74 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.501 | 0.725 | 0.446 | 0.476 | 0.800 | 0.667 | 1.000 | 0.000 |
| Rule engine + Platt | 0.501 | 0.725 | 0.223 | 0.008 | 0.800 | 0.667 | 1.000 | 0.500 |
| Logistic regression + Platt | 0.961 | 0.983 | 0.076 | 0.087 | 0.946 | 0.946 | 0.946 | 0.683 |
| HistGradientBoosting + Platt | 0.969 | 0.988 | 0.065 | 0.086 | 0.947 | 0.934 | 0.959 | 0.591 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.501 [0.390, 0.604] | 0.725 [0.593, 0.822] | 0.223 [0.197, 0.253] |
| Logistic regression | 0.961 [0.918, 0.993] | 0.983 [0.962, 0.997] | 0.076 [0.044, 0.113] |
| HistGradientBoosting | 0.969 [0.929, 0.997] | 0.988 [0.972, 0.999] | 0.065 [0.032, 0.101] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.446 | 0.223 | 0.476 | 0.008 |
| Logistic regression | 0.060 | 0.076 | 0.044 | 0.087 |
| HistGradientBoosting | 0.052 | 0.065 | 0.055 | 0.086 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.696 | 0.304 |
| Rule engine | 80% | 0.629 | 0.371 |
| Rule engine | 100% | 0.667 | 0.333 |
| Logistic regression | 50% | 0.982 | 0.018 |
| Logistic regression | 80% | 0.966 | 0.034 |
| Logistic regression | 100% | 0.883 | 0.117 |
| HistGradientBoosting | 50% | 1.000 | 0.000 |
| HistGradientBoosting | 80% | 0.955 | 0.045 |
| HistGradientBoosting | 100% | 0.928 | 0.072 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `redirected` | -3.122 |
| `domain_age_unknown` | -1.338 |
| `url_https` | +1.220 |
| `url_path_length_log` | +1.177 |
| `flag_cross_domain_redirect` | -1.164 |
| `flag_tls_certificate_invalid` | +0.975 |
| `domain_age_log` | -0.913 |
| `flag_unencrypted_http` | -0.911 |
| `url_risky_tokens` | +0.908 |
| `tracker_total_log` | -0.676 |
| `has_login_form` | +0.673 |
| `url_length_log` | +0.611 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `redirected` | 0.2664 | 0.0256 |
| `url_https` | 0.0186 | 0.0051 |
| `url_path_length_log` | 0.0100 | 0.0025 |
| `flag_cross_domain_redirect` | 0.0076 | 0.0031 |
| `url_host_entropy` | 0.0070 | 0.0024 |
| `url_host_labels` | 0.0049 | 0.0019 |
| `url_length_log` | 0.0032 | 0.0025 |
| `dmarc_record` | 0.0017 | 0.0020 |
| `page_images_log` | 0.0014 | 0.0017 |
| `page_iframes` | 0.0012 | 0.0008 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.970 ± 0.020 | 0.986 ± 0.010 | 0.058 ± 0.023 | 0.061 ± 0.020 |
| HistGradientBoosting | 5 | 0.985 ± 0.009 | 0.993 ± 0.004 | 0.048 ± 0.023 | 0.059 ± 0.019 |

## Feature group: `rule` (36 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 520 | 520 | 347 |
| val | 112 | 111 | 74 |
| test | 111 | 111 | 74 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.501 | 0.725 | 0.446 | 0.476 | 0.800 | 0.667 | 1.000 | 0.000 |
| Rule engine + Platt | 0.501 | 0.725 | 0.223 | 0.008 | 0.800 | 0.667 | 1.000 | 0.500 |
| Logistic regression + Platt | 0.936 | 0.971 | 0.098 | 0.090 | 0.898 | 0.904 | 0.892 | 0.596 |
| HistGradientBoosting + Platt | 0.938 | 0.966 | 0.096 | 0.083 | 0.905 | 0.905 | 0.905 | 0.478 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.501 [0.390, 0.604] | 0.725 [0.593, 0.822] | 0.223 [0.197, 0.253] |
| Logistic regression | 0.936 [0.886, 0.974] | 0.971 [0.944, 0.989] | 0.098 [0.060, 0.145] |
| HistGradientBoosting | 0.938 [0.882, 0.976] | 0.966 [0.926, 0.990] | 0.096 [0.058, 0.142] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.446 | 0.223 | 0.476 | 0.008 |
| Logistic regression | 0.098 | 0.098 | 0.077 | 0.090 |
| HistGradientBoosting | 0.104 | 0.096 | 0.103 | 0.083 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.696 | 0.304 |
| Rule engine | 80% | 0.629 | 0.371 |
| Rule engine | 100% | 0.667 | 0.333 |
| Logistic regression | 50% | 0.982 | 0.018 |
| Logistic regression | 80% | 0.921 | 0.079 |
| Logistic regression | 100% | 0.883 | 0.117 |
| HistGradientBoosting | 50% | 0.982 | 0.018 |
| HistGradientBoosting | 80% | 0.933 | 0.067 |
| HistGradientBoosting | 100% | 0.874 | 0.126 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `risk_medium_count` | -3.007 |
| `security_risk_points` | +2.910 |
| `privacy_risk_points` | +1.499 |
| `overall_confidence` | -1.439 |
| `risk_high_count` | -1.340 |
| `identity_risk_points` | +1.324 |
| `identity_confidence` | +0.953 |
| `manipulation_confidence` | +0.907 |
| `manipulation_coverage` | +0.832 |
| `privacy_confidence` | -0.821 |
| `privacy_abstained` | -0.785 |
| `security_evidence_count` | -0.778 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `security_risk_points` | 0.0457 | 0.0133 |
| `security_confidence` | 0.0415 | 0.0098 |
| `risk_medium_count` | 0.0410 | 0.0079 |
| `identity_score` | 0.0259 | 0.0044 |
| `identity_risk_points` | 0.0169 | 0.0041 |
| `missing_evidence_count` | 0.0145 | 0.0059 |
| `identity_confidence` | 0.0117 | 0.0020 |
| `security_score` | 0.0046 | 0.0041 |
| `overall_rule_risk` | 0.0023 | 0.0039 |
| `privacy_risk_points` | 0.0020 | 0.0045 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.918 ± 0.021 | 0.947 ± 0.025 | 0.099 ± 0.007 | 0.087 ± 0.008 |
| HistGradientBoosting | 5 | 0.963 ± 0.013 | 0.981 ± 0.007 | 0.070 ± 0.015 | 0.067 ± 0.016 |

## Feature group: `hybrid` (116 features)

| Split | Samples | Domains | Positives |
| --- | ---: | ---: | ---: |
| train | 520 | 520 | 347 |
| val | 112 | 111 | 74 |
| test | 111 | 111 | 74 |

### Test results

| Model | AUROC | AUPRC | Brier | ECE | F1 | Precision | Recall | Threshold |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Rule engine (raw) | 0.501 | 0.725 | 0.446 | 0.476 | 0.800 | 0.667 | 1.000 | 0.000 |
| Rule engine + Platt | 0.501 | 0.725 | 0.223 | 0.008 | 0.800 | 0.667 | 1.000 | 0.500 |
| Logistic regression + Platt | 0.972 | 0.989 | 0.062 | 0.062 | 0.922 | 0.887 | 0.959 | 0.447 |
| HistGradientBoosting + Platt | 0.988 | 0.995 | 0.031 | 0.029 | 0.966 | 0.986 | 0.946 | 0.500 |

Grouped bootstrap 95% CIs (calibrated test scores):

| Model | AUROC [95% CI] | AUPRC [95% CI] | Brier [95% CI] |
| --- | --- | --- | --- |
| Rule engine | 0.501 [0.390, 0.604] | 0.725 [0.593, 0.822] | 0.223 [0.197, 0.253] |
| Logistic regression | 0.972 [0.935, 0.998] | 0.989 [0.973, 0.999] | 0.062 [0.029, 0.103] |
| HistGradientBoosting | 0.988 [0.967, 1.000] | 0.995 [0.986, 1.000] | 0.031 [0.010, 0.059] |

### Calibration effect on test

| Model | Brier raw | Brier calibrated | ECE raw | ECE calibrated |
| --- | ---: | ---: | ---: | ---: |
| Rule engine | 0.446 | 0.223 | 0.476 | 0.008 |
| Logistic regression | 0.051 | 0.062 | 0.044 | 0.062 |
| HistGradientBoosting | 0.034 | 0.031 | 0.034 | 0.029 |

### Selective prediction (calibrated scores)

| Model | Coverage | Accuracy | Error rate |
| --- | ---: | ---: | ---: |
| Rule engine | 50% | 0.696 | 0.304 |
| Rule engine | 80% | 0.629 | 0.371 |
| Rule engine | 100% | 0.667 | 0.333 |
| Logistic regression | 50% | 0.982 | 0.018 |
| Logistic regression | 80% | 0.966 | 0.034 |
| Logistic regression | 100% | 0.919 | 0.081 |
| HistGradientBoosting | 50% | 1.000 | 0.000 |
| HistGradientBoosting | 80% | 0.989 | 0.011 |
| HistGradientBoosting | 100% | 0.955 | 0.045 |

### Logistic coefficients (standardized, largest magnitude)

| Feature | Coefficient |
| --- | ---: |
| `risk_medium_count` | -2.436 |
| `redirected` | -2.116 |
| `flag_cross_domain_redirect` | -1.457 |
| `security_evidence_count` | -1.285 |
| `flag_tls_certificate_invalid` | +1.144 |
| `url_https` | +1.083 |
| `url_path_length_log` | +0.950 |
| `risk_low_count` | +0.830 |
| `identity_score` | +0.818 |
| `flag_unencrypted_http` | -0.806 |
| `identity_risk_points` | +0.803 |
| `flag_suspicious_tld` | -0.686 |

### HistGradientBoosting permutation importance (validation)

| Feature | Mean AUROC drop | Std |
| --- | ---: | ---: |
| `redirected` | 0.1540 | 0.0123 |
| `url_path_length_log` | 0.0144 | 0.0051 |
| `flag_cross_domain_redirect` | 0.0138 | 0.0031 |
| `url_https` | 0.0095 | 0.0031 |
| `risk_medium_count` | 0.0081 | 0.0039 |
| `security_confidence` | 0.0062 | 0.0036 |
| `security_risk_points` | 0.0040 | 0.0025 |
| `identity_score` | 0.0009 | 0.0003 |
| `url_length_log` | 0.0008 | 0.0013 |
| `identity_confidence` | 0.0003 | 0.0004 |

### Grouped cross-validation (training split)

| Model | Folds | AUROC | AUPRC | Brier | ECE |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic regression | 5 | 0.984 ± 0.011 | 0.992 ± 0.005 | 0.038 ± 0.016 | 0.048 ± 0.007 |
| HistGradientBoosting | 5 | 0.998 ± 0.003 | 0.999 ± 0.001 | 0.016 ± 0.010 | 0.026 ± 0.009 |

## Limitations

- The dataset is a convenience sample of live sites, not a random sample of the web.
- Labels are human judgments and may contain errors; reported agreement is in the run metadata.
- Suspicious sites are excluded from the main binary task unless a sensitivity run is requested.
- Site content and infrastructure change; results describe the collection window.
- Automated assessment is advisory and cannot guarantee that a site is safe.
