# Table 7. Test-split errors

| Feature group | Test errors | False positives | False negatives | Threshold |
| --- | ---: | ---: | ---: | ---: |
| `url` | 32 | 27 | 5 | 0.445 |
| `signals` | 8 | 3 | 5 | 0.747 |
| `rule` | 11 | 5 | 6 | 0.477 |
| `hybrid` | 6 | 3 | 3 | 0.421 |

All four reproductions match the confusion recorded by the run (`reproduction_ok: true`).

Hybrid logistic error categories (a page can carry more than one code):

| Direction | Evidence category | Pages |
| --- | ---: | ---: |
| False negative | `domain_age_unknown` | 2 |
| False negative | `third_party_or_tracker_surface` | 2 |
| False negative | `unsafe_delivery_mechanics` | 2 |
| False negative | `established_host_appearance` | 1 |
| False negative | `feed_reported_url_on_established_host` | 1 |
| False negative | `file_host_or_payload_path` | 1 |
| False negative | `hidden_iframe_present` | 1 |
| False negative | `no_email_configuration` | 1 |
| False negative | `thin_capture_low_evidence` | 1 |
| False negative | `tls_absent_or_invalid` | 1 |
| False negative | `unreachable_at_capture` | 1 |
| False positive | `established_host_appearance` | 2 |
| False positive | `no_email_configuration` | 2 |
| False positive | `tls_absent_or_invalid` | 2 |
| False positive | `email_authentication_missing` | 1 |
| False positive | `shared_or_free_hosting` | 1 |
| False positive | `thin_capture_low_evidence` | 1 |
| False positive | `third_party_or_tracker_surface` | 1 |
| False positive | `unreachable_at_capture` | 1 |
| False positive | `unsafe_delivery_mechanics` | 1 |
