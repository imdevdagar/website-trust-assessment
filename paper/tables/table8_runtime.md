# Table 8. Runtime and resource use

| Measurement | Value |
| --- | ---: |
| Environment | Python 3.14.0; Intel64 Family 6 Model 154 Stepping 3, GenuineIntel |
| Offline parse + score, median | 32.4 ms/page |
| Offline parse + score, p95 | 38.57 ms/page |
| Throughput | 32.0 pages/s |
| Peak traced memory | 0.9 MB |
| Dataset size | 19.86 MB (5129 samples) |
| Model artifact `logistic_hybrid.json` | 10.9 KB |
| Model artifact `logistic_rule.json` | 4.4 KB |
| Model artifact `logistic_signals.json` | 7.9 KB |
| Model artifact `logistic_url.json` | 2.8 KB |

Measured on 210 offline page scorings (42 fixtures x 5 repeats) after one warm-up page. This isolates the scoring core; live collection latency is dominated by page load and lies outside this measurement. Peak memory is Python allocations tracked by `tracemalloc`, so it excludes the interpreter baseline and any native allocations; Chromium, when used for a live crawl, is the largest runtime consumer and is not part of this number. The suite and all runs are CPU-only with no paid API or GPU.
