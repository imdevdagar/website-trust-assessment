# Round 2 single-annotator analysis (v2, after amendment)

- Generated: 2026-10-20T11:21:12.306066+00:00
- Annotation status: single annotator (A only), post-amendment
- Sites: 33
- Source sheet SHA-256: `e446f453c89ca678b989dfc377af0fe11fc8743b97a17ac349f0330157ca17b2`
- Amendment: `round2_a_amendment_01` (not independent adjudication)

## Inter-annotator agreement

**Not computable.** Annotator B is blank and unavailable. This round has no kappa, no agreement confusion matrix, and no independent adjudication.

## Amendment

Two unreachable-page labels were corrected to `suspicious` under codebook sections 2.2 and 3.2. Original labels and notes are preserved in the amendment record:
- `s_286bde0a8b`: benign -> suspicious, confidence 1.00 -> 0.40, note "it doesnt open but seems legit".
- `s_e61c4b0421`: malicious -> suspicious, confidence 1.00 -> 0.40, note "site not found".

## Label distribution

| Label | Overall | Scam feed | Ambiguous | Benign control |
| --- | ---: | ---: | ---: | ---: |
| benign | 13 | 1 | 4 | 8 |
| suspicious | 8 | 4 | 4 | 0 |
| malicious | 12 | 12 | 0 | 0 |

## Confidence and notes

- Confidence mean 0.9515, median 1.0, range 0.4-1.0.
- Notes present on 20/33 rows; 10 mention a browser or warning, 3 mention an unreachable or broken page.

## Rule-engine alignment

### Rule level by human label

| Rule level | benign | suspicious | malicious |
| --- | ---: | ---: | ---: |
| low | 13 | 3 | 7 |
| medium | 0 | 4 | 5 |
| high | 0 | 1 | 0 |
| critical | 0 | 0 | 0 |

### Primary binary task (suspicious excluded)

- n = 25 (12 malicious, 13 benign)
- AUC using rule risk: 0.7276
- At high/critical: TP 0, FP 0, TN 13, FN 12; recall 0.0
- At medium or higher: TP 5, FP 0, TN 13, FN 7; precision 1.0, recall 0.4167, F1 0.5882

No site scored high or critical. The engine ranks malicious above benign moderately well, but its absolute threshold never reaches the high-risk band for any human-malicious site.

## Pre-amendment comparison

- Before amendment: {'benign': 14, 'malicious': 13, 'suspicious': 6}, primary n=27, AUC=0.7665, medium+ recall=0.4615.
- After amendment: {'benign': 13, 'suspicious': 8, 'malicious': 12}, primary n=25, AUC=0.7276, medium+ recall=0.4167.

## Limitations

- Single annotator for Round 2; no inter-annotator agreement or independent adjudication is possible.
- The pilot calibration gate (observed agreement >= 0.80 and QWK >= 0.70 in each round) is not met.
- The two corrections were a codebook-compliance amendment, not an independent second-rater decision.
- All 12 malicious labels are scam-feed candidates whose notes are short; most cite a browser warning, so the labels lean on an external security tool rather than independently observed page evidence.
- No high or critical rule-level predictions occur in this pilot, so threshold calibration cannot be validated at the high/critical boundary.
