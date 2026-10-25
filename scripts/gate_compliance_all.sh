#!/usr/bin/env bash
# Reports, for every crawl in the feed-labeled evaluation, which collection gate it honoured.
# Reads candidate CSVs and export JSONL only; opens no pages.
set -uo pipefail
cd "$(dirname "$0")/.."

PAIRS=()
UNGATED=()
GATED=()

for n in 01 02 03 04; do
  pair="data/candidates/main_batch_$n.csv=data/exports/main/batch_$n.jsonl"
  PAIRS+=(--pair "$pair")
  # main batch 01 was collected before the feed pivot, still without --allow-gated.
  UNGATED+=(--ungated "$pair")
done

pair="data/candidates/main_reserve.csv=data/exports/main/reserve.jsonl"
PAIRS+=(--pair "$pair")
UNGATED+=(--ungated "$pair")

for n in 01 02 03 04 05; do
  pair="data/candidates/feed_batch_$n.csv=data/exports/feed/batch_$n.jsonl"
  PAIRS+=(--pair "$pair")
  GATED+=(--allow-gated "$pair")
done
PAIRS+=(--pair "data/candidates/feed_remaining/feed_batch_01.csv=data/exports/feed/batch_06.jsonl")
GATED+=(--allow-gated "data/candidates/feed_remaining/feed_batch_01.csv=data/exports/feed/batch_06.jsonl")
PAIRS+=(--pair "data/candidates/feed_remaining/feed_batch_02.csv=data/exports/feed/batch_07.jsonl")
GATED+=(--allow-gated "data/candidates/feed_remaining/feed_batch_02.csv=data/exports/feed/batch_07.jsonl")

PYTHONPATH=. python scripts/gate_compliance.py \
  "${PAIRS[@]}" "${UNGATED[@]}" "${GATED[@]}" \
  --out data/research/gate_compliance.json
