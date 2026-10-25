# Two-person project plan

Six-month plan for a final-year Computer Science major project, with one laptop class machine
(Intel i5-12500H, 16 GB RAM, no dedicated GPU), no paid APIs, and a two-person team. The plan is
deliberately conservative: the paper must remain honest and submittable even if the optional user study
does not happen.

> **Status, 2026-10-21.** The human-label gates (G1, G2) and the "never reuse feed labels" rule below
> describe the original human-labelled track, which stopped at 146 frozen labels. The primary task is
> now feed membership, per the dated amendment in [research-plan.md](research-plan.md) and
> [main-dataset-protocol.md](main-dataset-protocol.md) section 2.2. The schedule, roles, and workload
> estimates remain the plan of record.

---

## 1. Team roles

Names are placeholders; assign them at the first meeting.

| Role | Owner | Responsibilities |
| --- | --- | --- |
| **Data and interface lead** | Person A | Sampling frame, collection schedule, annotation coordination, consensus files, dataset freeze, dashboard/extension, optional user study. |
| **ML and backend lead** | Person B | Crawler and evidence extractors, scoring, training/evaluation scripts, calibration, reproducibility, API reliability, artifact packaging. |
| **Annotation** | Both | Each labels an independent sheet; 20% overlap; joint adjudication. |
| **Paper** | Both | A leads related work, dataset, and interface sections; B leads method, scoring, and results. Both edit every section. |
| **Review** | Both | Every code change gets a second pair of eyes; every reported number gets a manifest/hash check. |

Do not let one person own both the labels and the test evaluation. The annotation key remains with the
coordinator, and the person who runs the final test evaluation must verify that the dataset hash matches
the frozen manifest.

### 1.1 Decision rights

- **Scope changes:** unanimous.
- **Codebook changes after pilot:** unanimous, with a dated amendment.
- **Test-set access:** only after the final configuration is frozen; both must be present.
- **Paper claims:** both must be able to point to an artifact for every number.
- **Data deletion:** both must agree; archive before deleting.

---

## 2. Working agreement

- **Repository:** one Git repository, `main` protected, feature branches, pull requests, no direct pushes
  to `main` after the initial scaffold.
- **Issues:** every task has an issue with an acceptance criterion. Use labels: `safety`, `crawler`,
  `scoring`, `research`, `docs`, `paper`, `bug`.
- **Weekly rhythm:** 30-minute Monday planning, 15-minute Wednesday data/annotation check, 45-minute
  Friday demo and triage.
- **Sprints:** two weeks. At the end of each sprint, tag a reproducible snapshot and update the risk
  register.
- **No secrets in Git:** no `.env`, API keys, personal URLs, or annotation notes with personal data.
- **Definition of done:** tests pass, docs updated, no lint errors, a second person has reviewed the
  change, and the artifact is reproducible from a clean command.
- **Time budget:** 12–15 hours per person per week during teaching weeks; 25–30 hours during breaks.
  Protect at least one no-meeting evening per week to avoid burnout.

---

## 3. Six-month schedule

### Month 1 — Protocol and pilot

**Goals:** freeze the study protocol, validate the assessment pipeline, collect the first 50 domains.

| Week | Person A | Person B | Shared gate |
| --- | --- | --- | --- |
| 1 | Finalise sampling frame and annotation form; prepare ethics checklist; review dashboard/extension. | Audit crawler safety, scoring floors, and feature extraction; run the full test suite. | Scope freeze; no new dimensions after this point. |
| 2 | Write codebook v0.9; recruit 30 pilot domains across categories. | Build/verify the research CLI; run a synthetic end-to-end dataset/train smoke test. | Pilot queue generated. |
| 3 | Label 30 pilot domains; second annotator also labels all 30. | Independently label the same 30; inspect safety failures. | Agreement report generated. |
| 4 | Revise codebook to v1.0; archive pilot results; start main collection. | Fix pilot issues; record environment versions; draft method section. | G1: quadratic kappa >= 0.70; otherwise repeat pilot. |

**Deliverables:** codebook v1.0, pilot agreement report, 50 assessments, baseline report, safety audit
notes.

### Month 2 — Main collection and annotation

**Goals:** 200–250 domains collected and annotated; crawler reliability improved; related-work draft.

| Week | Person A | Person B | Shared gate |
| --- | --- | --- | --- |
| 5 | Collect 60–80 domains; annotate 10–12/day. | Collect malicious candidates; fix crawler failures; monitor coverage. | No rule changes after week 6 unless a safety bug. |
| 6 | Continue annotation; audit 10% of notes. | Improve domain intelligence and evidence coverage; keep tests green. | Mid-pilot agreement check. |
| 7 | Collect and annotate another 60–80 domains. | Prepare the analysis scripts for H1 and ablations. | Dataset size >= 150. |
| 8 | Adjudicate disagreements; archive round 1. | Run interim dataset build; check leakage exclusions and split counts. | Round 1 frozen with hashes. |

**Deliverables:** 200–250 labelled domains, agreement report, interim dataset, related-work draft
(2–3 pages), safety/limitations notes.

### Month 3 — Dataset freeze and final experiments

**Goals:** 400–500 labelled domains, frozen dataset, final training and ablations, no test reuse.

| Week | Person A | Person B | Shared gate |
| --- | --- | --- | --- |
| 9 | Collect/annotate remaining domains. | Freeze candidate model configurations and hyperparameters. | Model configuration frozen before test access. |
| 10 | Finish annotation; adjudicate all disagreements. | Build dataset v1 with fixed seed; verify manifest and hashes. | G2: dataset freeze. |
| 11 | Verify labels, exclusions, and class balance; prepare data tables. | Run final train/evaluate once; archive run artifacts; run ablations. | Test evaluated once. |
| 12 | Analyse H1 (HTTPS prevalence); prepare figures. | Verify reproducibility from a clean command; write results. | Results review; no changes to test. |

**Deliverables:** dataset v1.0 with manifest, final run directory, ablation table, calibration and
risk-coverage figures, results section draft.

### Month 4 — User study or heuristic evaluation, interface, error analysis

**Goals:** complete the optional H3 study if approved; otherwise run a structured expert review; finish
the extension/dashboard polish.

| Week | Person A | Person B | Shared gate |
| --- | --- | --- | --- |
| 13 | Submit ethics/consent materials; prepare study protocol. | Improve error analysis; aggregate false positives/negatives by category. | Ethics decision. |
| 14 | Run pilot study (3–5 participants) or expert review. | Fix high-severity interface and scoring issues that do not touch the frozen test. | No test-driven tuning. |
| 15 | Run main study (if approved) or complete expert review. | Finalise extension/dashboard; record demo screenshots. | H3 data or heuristic report. |
| 16 | Analyse study data; write discussion. | Reproducibility package; cleanup; dependency audit. | Artifact review gate. |

**Deliverables:** user-study report or expert evaluation, interface fixes, error-analysis appendix,
reproducibility package v0.9.

If ethics approval or recruitment is delayed, do not invent a user study. Replace H3 with a heuristic
evaluation by 3–5 peers using a written rubric, label it as such, and remove causal language.

### Month 5 — Paper draft

**Goals:** complete a full draft, all figures/tables, and an internal review.

| Week | Person A | Person B | Shared gate |
| --- | --- | --- | --- |
| 17 | Draft introduction, related work, dataset, ethics. | Draft method, scoring, evaluation protocol. | Complete outline with claims-evidence map. |
| 18 | Draft results narrative and figures; check every number. | Draft results tables, calibration, ablations, threats. | Full draft v0.5. |
| 19 | Internal review with advisor/peer; revise. | Reproduce headline table from released artifacts; fix inconsistencies. | Draft v0.8. |
| 20 | Edit for clarity, length, and venue formatting. | Artifact appendix, model card, datasheet, citations. | Submission candidate v0.9. |

**Deliverables:** 10–12 page manuscript draft, all figures, artifact appendix, citation check,
plagiarism check, advisor feedback addressed.

### Month 6 — Revision, submission, and demo

**Goals:** submit the paper, finish the thesis/demo, and archive the project.

| Week | Person A | Person B | Shared gate |
| --- | --- | --- | --- |
| 21 | Final language edit; check abstract and claims. | Final artifact smoke test on a clean machine; tag release. | Release candidate. |
| 22 | Submit to the target venue; record submission ID. | Prepare demo script; verify extension from a fresh install. | Submission. |
| 23 | Write thesis chapters and presentation. | Final test suite, safety review, dependency audit. | Demo dry run. |
| 24 | Final presentation; archive data and code; update docs. | Restore/verify from archive; write maintenance notes. | Project closeout. |

**Deliverables:** submitted paper, thesis, demo, tagged release, archived dataset/model artifacts,
maintenance notes for future students.

---

## 4. Workload estimate

| Activity | Person A | Person B |
| --- | ---: | ---: |
| Literature and protocol | 25 h | 20 h |
| Crawler/evidence/scoring implementation | 15 h | 70 h |
| Dashboard/extension | 45 h | 10 h |
| Data collection and annotation | 55 h | 55 h |
| Dataset/training/evaluation | 15 h | 60 h |
| User study or expert evaluation | 30 h | 10 h |
| Paper and thesis | 60 h | 60 h |
| Review, demo, archive | 15 h | 15 h |
| **Approximate total** | **260 h** | **300 h** |

The ML/backend load is heavier. Person A should take more annotation coordination and writing in the
later months; Person B should not also carry the entire paper. Rebalance at the end of each month.

---

## 5. Gates and contingency

| Gate | Date | Criterion | If missed |
| --- | --- | --- | --- |
| G0 Protocol freeze | End of week 2 | Codebook, sampling frame, analysis plan reviewed. | Delay collection; do not label without a codebook. |
| G1 Pilot agreement | End of week 4 | Quadratic kappa >= 0.70. | Revise codebook, repeat 30-site pilot. |
| G2 Dataset freeze | End of week 10 | 400–500 domains, consensus complete, manifest hashed. | Freeze at >= 300 and reduce claims; do not pad with feed labels. |
| G3 Test evaluation | Week 11 | Configuration frozen before access. | If test is seen early, create a new untouched test set from additional domains; document. |
| G4 Artifact review | Week 16 | Second person reproduces headline table from release. | Delay submission; fix reproducibility. |

### Contingency scenarios

1. **Annotation is slower than planned.** Freeze at 300 domains. Keep the 20% overlap. Report wider
   intervals and fewer subgroup claims. Do not reduce the overlap below 15%.
2. **Malicious candidates are scarce.** Increase candidate sourcing from public feeds, but keep human
   verification. Never reuse feed labels as ground truth. Report the enrichment strategy.
3. **Kappa remains below 0.60.** The task may be too ambiguous for a three-class label. Merge
   `suspicious` into a two-stage decision (benign vs not-benign) and report the change as a protocol
   amendment, or restrict the primary task to clear benign vs clear malicious.
4. **Browser blocking is high.** Use the static fallback, add a `bot_challenge` missing-evidence note,
   and report coverage. Do not label a blocked page benign.
5. **HGB training is slow.** Run logistic first; HGB is secondary. The main comparison does not require
   a GPU.
6. **User study approval is delayed.** Use the heuristic evaluation fallback and label H3 as exploratory.
7. **A safety bug appears after the test freeze.** Fix it, then create a new untouched test set and
   rerun the final evaluation. Do not reuse the old test result.
8. **Paper rejection.** Use reviewer comments to revise; submit to the backup venue. The artifact release
   remains valid.
9. **Team member illness.** The other person can keep the artifact and writing moving; the plan has no
   single-person dependency for submission.

---

## 6. Risk register

| Risk | Likelihood | Impact | Mitigation | Owner |
| --- | --- | --- | --- | --- |
| Label leakage inflates results | Medium | High | Feature exclusion, dataset manifest, leakage diagnostic, review. | B |
| Domain overlap / test reuse | Medium | High | Grouped splits, frozen test, gate G3. | B |
| Low annotation agreement | Medium | High | Pilot, codebook, adjudication, fallback task definition. | A |
| Dataset too small | Medium | Medium | Start collection early; freeze at 300 with reduced claims. | A |
| Crawler blocked or slow | High | Medium | Static fallback, timeouts, coverage reporting, sampling buffer. | B |
| False positives on small sites | Medium | Medium | Evidence-first UI, error analysis, conservative floors. | Both |
| Interface work expands | Medium | Medium | Freeze UI scope after month 4; move extras to future work. | A |
| User study delay | High | Medium | Heuristic evaluation fallback. | A |
| Reproducibility failure | Low | High | Hashes, clean-machine test, artifact review gate. | B |
| Dependency or browser vulnerability | Low | High | Patch, lockfile, vulnerability scan before release. | Both |
| Burnout | Medium | High | Weekly hours cap, no-meeting evening, rotate tasks. | Both |
| Scope creep | High | High | Scope freeze in week 1; maintain a "future work" list. | Both |

---

## 7. Data and artifact management

- **Raw assessments:** `data/exports/` (not committed). Keep a backup on an encrypted drive.
- **Annotations:** `data/annotations/round*/` with frozen sheets, key, agreement, and adjudication.
- **Datasets:** `data/datasets/v1/` with JSONL, CSV, and manifest. Never overwrite a frozen version.
- **Models:** `models/research/` with run ID, calibration, threshold, and metrics.
- **Runs:** `data/research/runs/<run-id>/` with `run.json`, `report.md`, and artifacts.
- **Release:** a tagged Git commit plus an archive containing the derived dataset, manifests, run
  artifacts, model cards, and the exact command list.
- **Backups:** 3-2-1 rule; at least one offline copy before the test freeze.
- **Retention:** keep the thesis artifacts for at least one year after submission; remove personal data
  and screenshots that are not needed.

---

## 8. Weekly checklist

- [ ] Pull latest `main`; run the test suite.
- [ ] Check annotation throughput and remaining domain count.
- [ ] Check agreement on any new overlap batch.
- [ ] Check that no runtime label or test result leaked into training.
- [ ] Update the risk register and issue board.
- [ ] Back up the current dataset and run artifacts.
- [ ] Write a two-line progress note for the supervisor.

---

## 9. Final deliverables

1. Submitted research paper.
2. Final-year thesis/report.
3. Tagged source release and reproducibility commands.
4. Frozen dataset manifest (and a derived-feature release if approved).
5. Model card, datasheet, annotation protocol, threat model.
6. Working local demo: dashboard and browser extension.
7. Presentation and demo script.
8. Maintenance notes for the next student.
