# Table 7. Test-split errors

| Feature group | Test errors | False positives | False negatives | Threshold |
| --- | ---: | ---: | ---: | ---: |
| `url` | 161 | 79 | 82 | 0.427 |
| `signals` | 36 | 20 | 16 | 0.455 |
| `rule` | 71 | 42 | 29 | 0.366 |
| `hybrid` | 26 | 10 | 16 | 0.554 |

All four reproductions match the confusion recorded by the run (`reproduction_ok: true`).

Hybrid logistic error categories (a page can carry more than one code):

| Direction | Evidence category | Pages |
| --- | ---: | ---: |
| False negative | `established_host_appearance` | 13 |
| False negative | `feed_reported_url_on_established_host` | 13 |
| False negative | `unsafe_delivery_mechanics` | 13 |
| False negative | `email_authentication_missing` | 6 |
| False negative | `no_email_configuration` | 6 |
| False negative | `third_party_or_tracker_surface` | 5 |
| False negative | `thin_capture_low_evidence` | 4 |
| False negative | `tls_absent_or_invalid` | 4 |
| False negative | `domain_age_unknown` | 3 |
| False negative | `brand_claim_mismatch` | 2 |
| False negative | `unreachable_at_capture` | 2 |
| False negative | `file_host_or_payload_path` | 1 |
| False negative | `media_only_page` | 1 |
| False positive | `unsafe_delivery_mechanics` | 9 |
| False positive | `domain_age_unknown` | 4 |
| False positive | `third_party_or_tracker_surface` | 4 |
| False positive | `established_host_appearance` | 3 |
| False positive | `hidden_iframe_present` | 3 |
| False positive | `no_email_configuration` | 3 |
| False positive | `brand_claim_mismatch` | 2 |
| False positive | `credential_form_present` | 2 |
| False positive | `email_authentication_missing` | 2 |
| False positive | `file_host_or_payload_path` | 2 |
| False positive | `shared_or_free_hosting` | 1 |
| False positive | `thin_capture_low_evidence` | 1 |
| False positive | `tls_absent_or_invalid` | 1 |
| False positive | `unreachable_at_capture` | 1 |
