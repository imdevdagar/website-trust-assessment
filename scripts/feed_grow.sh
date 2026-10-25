#!/usr/bin/env bash
# Grows the dataset without any new approval scope: it re-attempts domains that failed as
# unreachable, and collects the pre-registered main reserve under the standard safe rules.
# No gated row is opened that the 2026-10-20 approval does not already cover — the feed retries
# are inside the approved 549-domain plan, and the reserve is crawled WITHOUT --allow-gated so
# its 50 scam_feed rows are skipped by the collection gate.
set -uo pipefail
cd "$(dirname "$0")/.."

LOG=data/exports/feed/run_growth.log
mkdir -p data/exports/feed

LOCK=.feed_growth.lock
if ! mkdir "$LOCK" 2>/dev/null; then
  printf 'another growth run holds %s; refusing to start\n' "$LOCK" >&2
  exit 1
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

say() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }

crawl() {
  local src="$1" dst="$2"
  shift 2
  say "crawl $src -> $dst $*"
  python .tmp-ptest/run_cli.py batch "$src" --out "$dst" --full --resume "$@" >>"$LOG" 2>&1
  local code=$?
  say "crawl $src exit=$code rows=$(wc -l < "$dst")"
}

say "growth run started"

for n in 01 02 03 04 05 06 07; do
  case "$n" in
    06) src=data/candidates/feed_remaining/feed_batch_01.csv ;;
    07) src=data/candidates/feed_remaining/feed_batch_02.csv ;;
    *) src=data/candidates/feed_batch_$n.csv ;;
  esac
  crawl "$src" "data/exports/feed/batch_$n.jsonl" --allow-gated
done

for n in 01 02 03 04; do
  crawl "data/candidates/main_batch_$n.csv" "data/exports/main/batch_$n.jsonl"
done

# Pre-registered reserve: 80 established + 30 tail collected, 50 gated scam_feed rows skipped.
say "reserve pool is ungated here; the gate must skip its scam_feed rows"
crawl data/candidates/main_reserve.csv data/exports/main/reserve.jsonl

FILES=(data/exports/feed/batch_0*.jsonl data/exports/main/batch_0*.jsonl data/exports/main/reserve.jsonl)
say "collapsing duplicate crawl rows"
python scripts/dedupe_exports.py "${FILES[@]}" >>"$LOG" 2>&1

say "leakage check"
python .tmp-ptest/run_cli.py research feed-check \
  --labels data/labels/feed/labels.csv \
  --assessments "${FILES[@]}" \
  --out data/labels/feed/leakage_check.json >>"$LOG" 2>&1
code=$?
say "feed-check exit=$code"
if [ "$code" -ne 0 ]; then
  say "growth run stopped: leakage check failed, no labels derived"
  exit "$code"
fi

say "derived evaluation labels"
python .tmp-ptest/run_cli.py research feed-eval-labels \
  --labels data/labels/feed/labels.csv \
  --assessments "${FILES[@]}" \
  --human-labels \
    data/annotations/pilot/frozen/annotator_a_20261020T101448Z.csv \
    data/annotations/pilot/frozen/annotator_b_20261020T102324Z.csv \
    data/annotations/round2/frozen/annotator_a_v2_20261020T111826Z.csv \
    data/annotations/main/batch_01/frozen/annotator_a_20261020T133255Z.csv \
  --out data/labels/feed/eval_labels.csv >>"$LOG" 2>&1
say "feed-eval-labels exit=$?"

say "growth run complete"
