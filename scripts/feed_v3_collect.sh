#!/usr/bin/env bash
# Collect the approved feed_v3 candidate set in bounded batches.
#
# Usage: FEED_V3_WORKERS=3 scripts/feed_v3_collect.sh [positive|negative|all]
#
# Positive batches are gated and pass --allow-gated under the recorded 2026-10-26 approval.
# After each positive batch, a root-URL retry batch recovers domains whose recorded URL did
# not resolve but whose registrable root may. If the selected set and registered reserves do
# not reach 2,500 usable positives, the fixed-ranking top-up (amendment 01) supplies more
# candidates from the same pool. The negative runner can run at the same time as the positive
# runner; they write separate exports and WAL mode handles the shared database.
#
# Batches are still at most 100 candidates and every gated page still needs --allow-gated.
# FEED_V3_WORKERS only controls how many independent batches are in flight at once; each worker
# writes its own export file and its own log, and progress is counted from completed rows.
set -uo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-all}"
case "$MODE" in
  positive|negative|all) ;;
  *) printf 'usage: %s [positive|negative|all]\n' "$0" >&2; exit 2 ;;
esac

WORKERS="${FEED_V3_WORKERS:-1}"
case "$WORKERS" in
  ''|*[!0-9]*|0) printf 'FEED_V3_WORKERS must be a positive integer\n' >&2; exit 2 ;;
esac
[ "$WORKERS" -gt 4 ] && WORKERS=4

LOG=data/exports/feed_v3/collection_${MODE}.log
BATCH_LOGS=data/exports/feed_v3/logs
RETRY_DIR=data/exports/feed_v3/retry
mkdir -p "$RETRY_DIR" "$BATCH_LOGS"
LOCK=".feed_v3_${MODE}.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  printf 'another feed_v3 %s run holds %s; refusing to start\n' "$MODE" "$LOCK" >&2
  exit 1
fi
trap 'rmdir "$LOCK" 2>/dev/null' EXIT

say() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }
status_json() { python scripts/feed_v3_status.py; }

class_count() {
  python - "$1" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, "scripts")
from feed_v3_status import count

print(count(Path("data/exports/feed_v3"))[sys.argv[1]])
PY
}

# One batch: crawl, then one root-URL retry for a positive batch. Each batch keeps its own log so
# concurrent workers never interleave output.
run_batch() {
  local src="$1" dst="$2" name="$3"
  shift 3
  local log="$BATCH_LOGS/${name}.log"
  {
    printf '%s crawl %s -> %s %s\n' "$(date -u +%FT%TZ)" "$src" "$dst" "$*"
    python -m website_trust_assessment.cli batch "$src" --out "$dst" --full --resume "$@"
    printf '%s crawl exit=%s rows=%s\n' "$(date -u +%FT%TZ)" "$?" \
      "$( [ -f "$dst" ] && wc -l < "$dst" || echo 0 )"
  } >>"$log" 2>&1

  if [ "$name" != "${name#neg_}" ]; then
    return 0
  fi
  local csv="$RETRY_DIR/${name}_retry.csv"
  local jsonl="$RETRY_DIR/${name}_retry.jsonl"
  python scripts/feed_v3_root_retry.py --batch "$src" --export "$dst" --out "$csv" \
    >>"$log" 2>&1
  if [ -f "$csv" ] && [ "$(wc -l < "$csv")" -gt 1 ]; then
    {
      printf '%s retry %s -> %s\n' "$(date -u +%FT%TZ)" "$csv" "$jsonl"
      python -m website_trust_assessment.cli batch "$csv" --out "$jsonl" --full --resume \
        --allow-gated
      printf '%s retry exit=%s rows=%s\n' "$(date -u +%FT%TZ)" "$?" \
        "$( [ -f "$jsonl" ] && wc -l < "$jsonl" || echo 0 )"
    } >>"$log" 2>&1
  fi
}

# Run a list of "src dst name [extra args]" entries in waves of $WORKERS, stopping once the
# counter named by $4 reaches $5. Entries are newline-delimited so spaces in arguments stay safe.
run_wave_list() {
  local list="$1" counter="$2" target="$3"
  local pids=() src dst name extra count
  while IFS='|' read -r src dst name extra; do
    [ -z "$src" ] && continue
    count="$(class_count "$counter")"
    if [ "$count" -ge "$target" ]; then
      say "$counter=$count reached target $target; skipping remaining batches"
      return 0
    fi
    run_batch "$src" "$dst" "$name" $extra &
    pids+=("$!")
    if [ "${#pids[@]}" -ge "$WORKERS" ]; then
      for pid in "${pids[@]}"; do wait "$pid"; done
      pids=()
      say "wave finished; $counter=$(class_count "$counter")"
    fi
  done <<<"$list"
  for pid in "${pids[@]}"; do wait "$pid"; done
  say "wave finished; $counter=$(class_count "$counter")"
}

positive_list() {
  local n src dst
  for n in $(seq -w 1 30); do
    src="data/candidates/feed_v3/feed_batch_$n.csv"
    dst="data/exports/feed_v3/feed_batch_$n.jsonl"
    printf '%s|%s|%s|--allow-gated\n' "$src" "$dst" "feed_batch_$n"
  done
}

positive_reserve_list() {
  local n
  for n in $(seq -w 1 15); do
    printf 'data/candidates/feed_v3/reserve/feed_reserve_%s.csv|data/exports/feed_v3/feed_reserve_%s.jsonl|feed_reserve_%s|--allow-gated\n' \
      "$n" "$n" "$n"
  done
}

positive_topup_list() {
  local n
  for n in $(seq -w 1 40); do
    printf 'data/candidates/feed_v3/topup/feed_topup_%s.csv|data/exports/feed_v3/feed_topup_%s.jsonl|feed_topup_%s|--allow-gated\n' \
      "$n" "$n" "$n"
  done
}

negative_list() {
  local n
  for n in $(seq -w 1 30); do
    printf 'data/candidates/feed_v3/negatives/neg_%s.csv|data/exports/feed_v3/neg_%s.jsonl|neg_%s|\n' \
      "$n" "$n" "$n"
  done
}

negative_reserve_list() {
  local n
  for n in $(seq -w 1 10); do
    printf 'data/candidates/feed_v3/negatives/neg_reserve_%s.csv|data/exports/feed_v3/neg_reserve_%s.jsonl|neg_reserve_%s|\n' \
      "$n" "$n" "$n"
  done
}

run_positive() {
  say "positive collection started with $WORKERS worker(s); $(status_json | tr -d '\n ')"
  run_wave_list "$(positive_list)" positive_domains 2500
  run_wave_list "$(positive_reserve_list)" positive_domains 2500

  if [ "$(class_count positive_domains)" -lt 2500 ]; then
    say "positive target not met by the registered set; generating the fixed-ranking top-up"
    python scripts/feed_v3_topup.py >>"$LOG" 2>&1
    say "top-up generated; crawling from the fixed ranking"
    run_wave_list "$(positive_topup_list)" positive_domains 2500
  fi
  say "positive collection finished; $(status_json | tr -d '\n ')"
}

run_negative() {
  say "negative collection started with $WORKERS worker(s); $(status_json | tr -d '\n ')"
  run_wave_list "$(negative_list)" negative_domains 2500
  run_wave_list "$(negative_reserve_list)" negative_domains 2500
  say "negative collection finished; $(status_json | tr -d '\n ')"
}

case "$MODE" in
  positive) run_positive ;;
  negative) run_negative ;;
  all) run_positive; run_negative ;;
esac
