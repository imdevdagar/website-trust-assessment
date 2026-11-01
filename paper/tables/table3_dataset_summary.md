# Table 3. Dataset composition

| Split | Samples | Domains | Malicious | Benign |
| --- | ---: | ---: | ---: | ---: |
| Train | 3,590 | 3,590 | 1,773 | 1,817 |
| Val | 770 | 770 | 380 | 390 |
| Test | 769 | 769 | 380 | 389 |
| **Total** | **5,129** | **5,129** | **2,533** | **2,596** |

Collection and exclusion facts (primary build `feed_v3`):

- 11,402 crawl rows were read. 5,891 never produced an assessment (5,868 unresolvable hostname, 23 hostname resolving to a non-public address) and 382 landed on a different registrable domain than their candidate; all were excluded, never relabelled benign.
- 5,129 same-domain assessments were kept, one per domain: 2,533 malicious and 2,596 benign.
- Positives came from 1,389 selected + 724 reserve + 420 fixed-ranking top-up candidates, and 111 of them were recovered by the pre-registered root-URL retry.
- 7,231 feed-listed domains yielded no usable assessment and were dropped; a domain that cannot be assessed is not evidence of anything.
- 5,511 readable assessments passed the leakage check (`leaked_assessments: 0`, runtime label store empty). The feed CSV is never imported into the runtime store.
- No candidate carried a frozen human label, so the exclusion rule had nothing to exclude (`excluded_human_labelled_domains: 0`): the 146-label validity subset is disjoint from this build by construction, verified before any crawl started.
- Dataset SHA-256 `a1628d24887d9a329b7c7b2ea142cf35566e99e8db7d4468b611d2dd6c3bfd64`; seed 42; domain-grouped split ratios 70% / 15% / 15%.
