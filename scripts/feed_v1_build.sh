#!/usr/bin/env bash
# Builds the primary feed-labeled dataset and runs the model comparison.
# Run after scripts/feed_crawl_remaining.sh finishes; it reuses the derived label file that
# runner writes, so nothing here opens a page or touches a frozen sheet.
set -uo pipefail
cd "$(dirname "$0")/.."

ASSESSMENTS=()
for f in data/exports/feed/batch_0*.jsonl data/exports/main/batch_0*.jsonl; do
  [ -s "$f" ] && ASSESSMENTS+=("$f")
done
say() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }
say "assessment files: ${#ASSESSMENTS[@]}"

python .tmp-ptest/run_cli.py research dataset \
  --out data/datasets/feed_v1 \
  --assessments "${ASSESSMENTS[@]}" \
  --labels data/labels/feed/eval_labels.csv \
  --seed 42 || exit 1

python .tmp-ptest/run_cli.py research train \
  --dataset data/datasets/feed_v1/dataset.jsonl \
  --run-name feed_v1 || exit 1

# Same two label sources re-compared now that the crawl is complete (protocol S7).
python .tmp-ptest/run_cli.py research feed-agreement \
  --labels data/labels/feed/labels.csv \
  --human-labels \
    data/annotations/pilot/frozen/annotator_a_20261020T101448Z.csv \
    data/annotations/pilot/frozen/annotator_b_20261020T102324Z.csv \
    data/annotations/round2/frozen/annotator_a_v2_20261020T111826Z.csv \
    data/annotations/main/batch_01/frozen/annotator_a_20261020T133255Z.csv \
  --out data/labels/feed/human_vs_feed_final.json

say "feed_v1 build complete"
