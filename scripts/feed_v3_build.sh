#!/usr/bin/env bash
# Build the feed_v3 evaluation dataset from the completed exports.
#
# Nothing here opens a page. It checks label leakage, derives domain-level labels from feed
# membership, builds a domain-grouped dataset, trains and calibrates every feature group, and
# profiles the result. feed_v2 artifacts are left untouched.
set -uo pipefail
cd "$(dirname "$0")/.."

LOCK=.feed_v3_build.lock
if ! mkdir "$LOCK" 2>/dev/null; then
  printf 'another feed_v3 build holds %s; refusing to start\n' "$LOCK" >&2
  exit 1
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

say() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
run() { say "run: $*"; python -m website_trust_assessment.cli "$@"; }

ASSESSMENTS=()
while IFS= read -r file; do ASSESSMENTS+=("$file"); done < <(
  ls data/exports/feed_v3/feed_batch_*.jsonl \
     data/exports/feed_v3/feed_reserve_*.jsonl \
     data/exports/feed_v3/feed_topup_*.jsonl \
     data/exports/feed_v3/neg_*.jsonl \
     data/exports/feed_v3/retry/feed_*.jsonl 2>/dev/null
)
if [ "${#ASSESSMENTS[@]}" -eq 0 ]; then
  say "no feed_v3 exports found; run the collection first"
  exit 1
fi
say "assessment files: ${#ASSESSMENTS[@]}"

# --- same-domain analysis files: cross-domain redirects are excluded -----------
python scripts/feed_v3_filter_exports.py || exit 1
ANALYSIS=(
  data/exports/feed_v3/analysis/positive.jsonl
  data/exports/feed_v3/analysis/negative.jsonl
)

HUMAN=(
  data/annotations/pilot/frozen/annotator_a_20261020T101448Z.csv
  data/annotations/pilot/frozen/annotator_b_20261020T102324Z.csv
  data/annotations/round2/frozen/annotator_a_v2_20261020T111826Z.csv
  data/annotations/main/batch_01/frozen/annotator_a_20261020T133255Z.csv
)

# --- integrity: gates honoured and collection accounted for --------------------
python scripts/feed_v3_outcome.py || exit 1
python scripts/feed_v3_gate_compliance.py || exit 1

# --- integrity: no feed verdict reached the scored assessments -----------------
run research feed-check \
  --labels data/labels/feed_v3/labels.csv \
  --assessments "${ASSESSMENTS[@]}" \
  --out data/labels/feed_v3/leakage_check.json || exit 1

# --- primary labels: feed membership, human-labelled domains excluded ----------
run research feed-eval-labels \
  --labels data/labels/feed_v3/labels.csv \
  --assessments "${ANALYSIS[@]}" \
  --human-labels "${HUMAN[@]}" \
  --out data/labels/feed_v3/eval_labels.csv || exit 1

# --- primary: feed_v3 ----------------------------------------------------------
run research dataset \
  --out data/datasets/feed_v3 \
  --assessments "${ANALYSIS[@]}" \
  --labels data/labels/feed_v3/eval_labels.csv \
  --seed 42 --force || exit 1

run research train \
  --dataset data/datasets/feed_v3/dataset.jsonl \
  --run-name feed_v3 \
  --models-dir models/research/feed_v3 \
  --seed 42 || exit 1

# --- sensitivity: split/model seed --------------------------------------------
run research dataset \
  --out data/datasets/feed_v3_s43 \
  --assessments "${ANALYSIS[@]}" \
  --labels data/labels/feed_v3/eval_labels.csv \
  --seed 43 --force || exit 1

run research train \
  --dataset data/datasets/feed_v3_s43/dataset.jsonl \
  --run-name feed_v3_s43 \
  --models-dir models/research/feed_v3_s43 \
  --seed 43 || exit 1

# --- primary comparison against the frozen feed_v2 artifact --------------------
python scripts/feed_v3_metrics.py || exit 1

# --- dataset profile -----------------------------------------------------------
PYTHONPATH=. python scripts/dataset_profile.py \
  --dataset data/datasets/feed_v3/dataset.jsonl \
  --assessments "${ANALYSIS[@]}" \
  --out data/research/profile_feed_v3.json || exit 1

# --- error analysis on the feed_v3 test split ----------------------------------
PYTHONPATH=. python scripts/error_analysis.py \
  --dataset data/datasets/feed_v3/dataset.jsonl \
  --models models/research/feed_v3 \
  --exports "${ANALYSIS[@]}" \
  --out data/research/error_analysis_feed_v3.json || exit 1

say "feed_v3 build complete"
