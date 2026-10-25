# Table 3. Dataset composition

| Split | Samples | Domains | Malicious | Benign |
| --- | ---: | ---: | ---: | ---: |
| Train | 581 | 578 | 348 | 233 |
| Val | 126 | 125 | 75 | 51 |
| Test | 123 | 123 | 74 | 49 |
| **Total** | **830** | **826** | **497** | **333** |

Collection and exclusion facts (primary build `feed_v2`):

- 549 feed-listed domains were planned; 50 could not be collected and were dropped, never called benign.
- 912 scored assessments passed the leakage check (`leaked_assessments: 0`, runtime label store empty).
- 107 crawl rows carry only `{url, error}` and were skipped as assessments that never existed.
- 82 collected domains carry a frozen human label and no feed label, so they were excluded from the 830; the 146 frozen human labels form the separate validity subset.
- 496 distinct malicious and 330 distinct benign domains; four domains contribute two assessments each.
- Dataset SHA-256 `ca6777520f435271b756079308b7526638c339f3571881f4574cb29928ff1ae2`; seed 42; domain-grouped split ratios 70% / 15% / 15%.
