#!/usr/bin/env bash
# Builds feed_v2 (the enlarged primary dataset) plus the two sensitivity runs the paper needs,
# then re-runs the error analysis on the new test split.
#
# Nothing here opens a page: it consumes the exports that scripts/feed_grow.sh produced.
# Each run writes its own models directory so the reported feed_v1 artifacts stay intact.
set -uo pipefail
cd "$(dirname "$0")/.."

LOCK=.feed_v2_build.lock
if ! mkdir "$LOCK" 2>/dev/null; then
  printf 'another build holds %s; refusing to start\n' "$LOCK" >&2
  exit 1
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

say() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
run() { say "run: $*"; python .tmp-ptest/run_cli.py "$@"; }

ASSESSMENTS=()
for f in data/exports/feed/batch_0*.jsonl data/exports/main/batch_0*.jsonl data/exports/main/reserve.jsonl; do
  [ -s "$f" ] && ASSESSMENTS+=("$f")
done
NEG_NO_BATCH02=()
for f in "${ASSESSMENTS[@]}"; do
  case "$f" in
    data/exports/main/batch_02.jsonl) say "sensitivity run excludes derived negatives from $f" ;;
    *) NEG_NO_BATCH02+=("$f") ;;
  esac
done
say "assessment files: primary=${#ASSESSMENTS[@]} without_batch_02=${#NEG_NO_BATCH02[@]}"

HUMAN=(
  data/annotations/pilot/frozen/annotator_a_20261020T101448Z.csv
  data/annotations/pilot/frozen/annotator_b_20261020T102324Z.csv
  data/annotations/round2/frozen/annotator_a_v2_20261020T111826Z.csv
  data/annotations/main/batch_01/frozen/annotator_a_20261020T133255Z.csv
)

# --- primary: feed_v2 ---------------------------------------------------------
run research dataset \
  --out data/datasets/feed_v2 \
  --assessments "${ASSESSMENTS[@]}" \
  --labels data/labels/feed/eval_labels.csv \
  --seed 42 || exit 1

run research train \
  --dataset data/datasets/feed_v2/dataset.jsonl \
  --run-name feed_v2 \
  --models-dir models/research/feed_v2 \
  --seed 42 || exit 1

# --- sensitivity 1: split/model seed -----------------------------------------
run research dataset \
  --out data/datasets/feed_v2_s43 \
  --assessments "${ASSESSMENTS[@]}" \
  --labels data/labels/feed/eval_labels.csv \
  --seed 43 || exit 1

run research train \
  --dataset data/datasets/feed_v2_s43/dataset.jsonl \
  --run-name feed_v2_s43 \
  --models-dir models/research/feed_v2_s43 \
  --seed 43 || exit 1

# --- sensitivity 2: negative pool without the reused batch-02 assessments ----
run research feed-eval-labels \
  --labels data/labels/feed/labels.csv \
  --assessments "${NEG_NO_BATCH02[@]}" \
  --human-labels "${HUMAN[@]}" \
  --out data/labels/feed/eval_labels_no_batch_02.csv || exit 1

run research dataset \
  --out data/datasets/feed_v2_no_batch_02 \
  --assessments "${NEG_NO_BATCH02[@]}" \
  --labels data/labels/feed/eval_labels_no_batch_02.csv \
  --seed 42 || exit 1

run research train \
  --dataset data/datasets/feed_v2_no_batch_02/dataset.jsonl \
  --run-name feed_v2_no_batch_02 \
  --models-dir models/research/feed_v2_no_batch_02 \
  --seed 42 || exit 1

# --- integrity: which gate did each crawl honour? ----------------------------
bash scripts/gate_compliance_all.sh || exit 1

# --- error analysis on the new test split ------------------------------------
PYTHONPATH=. python scripts/error_analysis.py \
  --dataset data/datasets/feed_v2/dataset.jsonl \
  --models models/research/feed_v2 \
  --exports "data/exports/feed/batch_0*.jsonl" "data/exports/main/batch_0*.jsonl" \
    data/exports/main/reserve.jsonl \
  --out data/research/error_analysis_feed_v2.json || exit 1

# --- dataset profile: class split, HTTPS prevalence, engine escalation -------
for d in feed_v2 feed_v2_s43 feed_v2_no_batch_02; do
  PYTHONPATH=. python scripts/dataset_profile.py \
    --dataset "data/datasets/$d/dataset.jsonl" \
    --assessments "${ASSESSMENTS[@]}" \
    --out "data/research/profile_$d.json" || exit 1
done

say "feed_v2 build complete"
