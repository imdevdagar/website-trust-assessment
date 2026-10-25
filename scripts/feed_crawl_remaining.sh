#!/usr/bin/env bash
# Runs the approved feed crawl batches back-to-back, once the pilot batch has finished.
# Label source is public-feed membership (docs/main-dataset-protocol.md S4.1); no annotator
# inspects these pages, which is why every row carries the gated collection flag.
set -uo pipefail
cd "$(dirname "$0")/.."

LOG=data/exports/feed/run_remaining.log
mkdir -p data/exports/feed

# Three concurrent runners once appended the same domains three times over; a second copy of
# this script does nothing useful, so it refuses to start instead.
LOCK=.feed_crawl.lock
if ! mkdir "$LOCK" 2>/dev/null; then
  printf 'another runner holds %s; refusing to start\n' "$LOCK" >&2
  exit 1
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

say() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }

say "chained runner started; waiting for feed_batch_01 to finish"
running_feed_01() {
  powershell -NoProfile -Command \
    "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { \$_.CommandLine -match 'feed_batch_01' } | Select-Object -ExpandProperty CommandLine" \
    2>/dev/null | grep -q feed_batch_01
}
while running_feed_01; do
  sleep 60
done
say "feed_batch_01 no longer running"

run_batch() {
  local src="$1" dst="$2"
  shift 2
  say "crawl $src -> $dst $*"
  if [ "$#" -gt 0 ]; then
    python .tmp-ptest/run_cli.py batch "$src" --out "$dst" --full --resume "$@" >>"$LOG" 2>&1
  else
    python .tmp-ptest/run_cli.py batch "$src" --out "$dst" --full --resume >>"$LOG" 2>&1
  fi
  local code=$?
  say "crawl $src exit=$code rows=$(wc -l < "$dst")"
}

run_batch data/candidates/feed_batch_01.csv data/exports/feed/batch_01.jsonl --allow-gated
run_batch data/candidates/feed_batch_02.csv          data/exports/feed/batch_02.jsonl --allow-gated
run_batch data/candidates/feed_batch_03.csv          data/exports/feed/batch_03.jsonl --allow-gated
run_batch data/candidates/feed_batch_04.csv          data/exports/feed/batch_04.jsonl --allow-gated
run_batch data/candidates/feed_batch_05.csv          data/exports/feed/batch_05.jsonl --allow-gated
run_batch data/candidates/feed_remaining/feed_batch_01.csv data/exports/feed/batch_06.jsonl --allow-gated
run_batch data/candidates/feed_remaining/feed_batch_02.csv data/exports/feed/batch_07.jsonl --allow-gated

# Safe main strata: these carry no gated rows and need no human labels under the feed-label
# regime, so they are the benign-negative pool (label = absent from both feeds).
run_batch data/candidates/main_batch_03.csv data/exports/main/batch_03.jsonl
run_batch data/candidates/main_batch_04.csv data/exports/main/batch_04.jsonl

# Expanded at run time; an unquoted glob inside an array literal stays literal in bash.
ALL_ASSESSMENTS=()
for f in data/exports/feed/batch_0*.jsonl data/exports/main/batch_0*.jsonl; do
  [ -s "$f" ] && ALL_ASSESSMENTS+=("$f")
done
say "collapsing any duplicate crawl rows"
python scripts/dedupe_exports.py "${ALL_ASSESSMENTS[@]}" >>"$LOG" 2>&1
say "dedupe exit=$?"

ALL_ASSESSMENTS=()
for f in data/exports/feed/batch_0*.jsonl data/exports/main/batch_0*.jsonl; do
  [ -s "$f" ] && ALL_ASSESSMENTS+=("$f")
done
say "assessment files for the label join: ${#ALL_ASSESSMENTS[@]}"

say "leakage check"
python .tmp-ptest/run_cli.py research feed-check \
  --labels data/labels/feed/labels.csv \
  --assessments "${ALL_ASSESSMENTS[@]}" \
  --out data/labels/feed/leakage_check.json >>"$LOG" 2>&1
say "feed-check exit=$?"

say "derived evaluation labels"
# round2 uses the amended v2 sheet; the superseded original must not contribute labels.
python .tmp-ptest/run_cli.py research feed-eval-labels \
  --labels data/labels/feed/labels.csv \
  --assessments "${ALL_ASSESSMENTS[@]}" \
  --human-labels \
    data/annotations/pilot/frozen/annotator_a_20261020T101448Z.csv \
    data/annotations/pilot/frozen/annotator_b_20261020T102324Z.csv \
    data/annotations/round2/frozen/annotator_a_v2_20261020T111826Z.csv \
    data/annotations/main/batch_01/frozen/annotator_a_20261020T133255Z.csv \
  --out data/labels/feed/eval_labels.csv >>"$LOG" 2>&1
say "feed-eval-labels exit=$?"

say "all approved feed batches complete"
