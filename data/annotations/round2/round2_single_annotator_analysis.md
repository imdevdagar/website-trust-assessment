# Round 2 single-annotator analysis

- Generated: 2026-10-20T11:09:16.620362+00:00
- Annotation status: single annotator (A only)
- Sites: 33
- Source sheet SHA-256: `92ad8e40e2cb54528f58bebb12e65bb27d157c69ac2b6fd893ff4b6aeafbba3f`

## Inter-annotator agreement

**Not computable.** Annotator B is blank and unavailable. This round has no kappa, no agreement confusion matrix, and no adjudication.

## Label distribution

| Label | Overall | Scam feed | Ambiguous | Benign control |
| --- | ---: | ---: | ---: | ---: |
| benign | 14 | 1 | 5 | 8 |
| suspicious | 6 | 3 | 3 | 0 |
| malicious | 13 | 13 | 0 | 0 |

## Confidence and notes

- Confidence mean 0.9879, median 1.0, range 0.85-1.0.
- Notes present on 20/33 rows; 10 mention a browser or warning, 3 mention an unreachable or broken page.

## Rule-engine alignment

### Rule level by human label

| Rule level | benign | suspicious | malicious |
| --- | ---: | ---: | ---: |
| low | 14 | 2 | 7 |
| medium | 0 | 3 | 6 |
| high | 0 | 1 | 0 |
| critical | 0 | 0 | 0 |

### Primary binary task (suspicious excluded)

- n = 27 (13 malicious, 14 benign)
- AUC using rule risk: 0.7665
- At high/critical: TP 0, FP 0, TN 14, FN 13; recall 0.0
- At medium or higher: TP 6, FP 0, TN 14, FN 7; precision 1.0, recall 0.4615, F1 0.6316

No site scored high or critical. The engine ranks malicious above benign moderately well, but its absolute threshold never reaches the high-risk band for any human-malicious site.

## Annotation-quality flags

- `s_286bde0a8b` (ambiguous): labeled `benign` at confidence 1.0, note "it doesnt open but seems legit". The note says the page did not open. Codebook section 2.2 and 3.2 require suspicious or an explicit inability to inspect, not a confident benign guess, when the live page is unreachable.
- `s_e61c4b0421` (scam_feed): labeled `malicious` at confidence 1.0, note "site not found". Feed membership alone is not sufficient for malicious, and the note records only that the site was not found. Codebook section 2.2 requires suspicious when an unreachable feed match lacks independently decisive evidence.

## Limitations

- Single annotator for Round 2; no inter-annotator agreement or adjudication is possible.
- The pilot calibration gate (observed agreement >= 0.80 and QWK >= 0.70 in each round) is not met.
- All 13 malicious labels are scam-feed candidates whose notes are short; most cite a browser warning, so the labels lean on an external security tool rather than independently observed page evidence.
- No high or critical rule-level predictions occur in this pilot, so threshold calibration cannot be validated at the high/critical boundary.
- Frozen labels were not modified; the two flagged rows require a documented amendment if they are to be corrected.
