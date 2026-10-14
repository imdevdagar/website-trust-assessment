"""
fetch_aa419_scam.py  (v2 - corrected)
=======================================
AA419 API returns HTTP 201 as success (not 200).
The scamtype parameter does NOT filter server-side — we fetch all pages
and filter locally by ScamType field.

All 17 confirmed scam types:
  fakeshop, courier, pet, escrow, nondelivery, rental, loan, bank,
  govt, job, lotto, romance, vehicle, lawyer, drug, blackmoney, other
"""

import sys
import time
import requests
import pandas as pd
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from src.features.url_features import extract_url_features

# ── Configuration ─────────────────────────────────────────────────────────
API_KEYS = [
    "af20bd4c1ef24e45b7ecb8b0baa9f53a",
    "3fd6dad907804c109516618c0256f1d8",
]

# All confirmed scam types from AA419 database
ALL_SCAM_TYPES = {
    "fakeshop", "courier", "pet", "escrow", "nondelivery", "rental",
    "loan", "bank", "govt", "job", "lotto", "romance", "vehicle",
    "lawyer", "drug", "blackmoney", "other"
}

API_URL    = "https://api.aa419.org/fakesites"
PAGE_SIZE  = 500
SLEEP_OK   = 1.2   # polite delay between pages
SLEEP_429  = 45    # wait on rate-limit
MAX_RETRY  = 3

BASE         = Path(__file__).resolve().parent
EXISTING_CSV = BASE / "data" / "processed" / "unified_multiclass_dataset.csv"
OUTPUT_CSV   = BASE / "data" / "processed" / "unified_multiclass_dataset.csv"
RAW_OUT      = BASE / "data" / "raw" / "aa419_all_scam_raw.csv"


def fetch_page(api_key: str, page_no: int) -> list:
    """Fetch one page. Returns list of dicts (empty list on failure)."""
    params  = {"pgsize": PAGE_SIZE, "pgno": page_no, "order": "ASC"}
    headers = {"Auth-API-Id": api_key}
    for attempt in range(MAX_RETRY):
        try:
            r = requests.get(API_URL, params=params, headers=headers, timeout=20)
            # AA419 uses 201 as success code
            if r.status_code in (200, 201):
                data = r.json() if r.text.strip() else []
                return data if isinstance(data, list) else []
            elif r.status_code == 429:
                print(f"    [429] Rate limited. Sleeping {SLEEP_429}s ...")
                time.sleep(SLEEP_429)
            else:
                print(f"    [HTTP {r.status_code}] Unexpected — skipping.")
                return []
        except requests.RequestException as e:
            print(f"    Connection error: {e}. Attempt {attempt+1}/{MAX_RETRY}")
            time.sleep(5)
    return []


def extract_url(record: dict) -> str:
    for key in ("Url", "SiteURL", "Domain", "url", "domain"):
        val = record.get(key, "")
        if val and isinstance(val, str) and "." in val:
            val = val.strip()
            if not val.startswith("http"):
                val = "https://" + val
            return val
    return ""


def main():
    print("=" * 60)
    print("AA419 Full Scam Dataset Extractor v2")
    print("=" * 60)

    all_records = []
    key_idx     = 0
    page_no     = 0

    # -- Fetch all pages from the API -----------------------------------------
    while True:
        api_key = API_KEYS[key_idx % len(API_KEYS)]
        print(f"  Page {page_no:>4} | key={key_idx % len(API_KEYS)} | fetching ...", end=" ", flush=True)

        records = fetch_page(api_key, page_no)
        if not records:
            print(f"Empty page. Stopping at page {page_no}.")
            break

        # All AA419 records are scam sites — keep everything
        all_records.extend(records)
        print(f"{len(records)} fetched | total={len(all_records)}")

        if len(records) < PAGE_SIZE:
            print("Last page reached.")
            break

        page_no += 1
        key_idx += 1   # alternate keys each page
        time.sleep(SLEEP_OK)

    if not all_records:
        print("No scam records fetched. Check API keys and network.")
        return

    # -- Save raw pull ---------------------------------------------------------
    raw_df = pd.DataFrame(all_records)
    RAW_OUT.parent.mkdir(parents=True, exist_ok=True)
    raw_df.to_csv(RAW_OUT, index=False)
    print(f"\nRaw records saved: {len(raw_df)} -> {RAW_OUT}")
    print(f"ScamType distribution:\n{raw_df['ScamType'].value_counts().to_string()}\n")

    # -- Extract URL features --------------------------------------------------
    print("Extracting URL features ...")
    feat_rows = []
    skipped   = 0
    for i, rec in enumerate(all_records):
        if i % 1000 == 0:
            print(f"  {i}/{len(all_records)} ...")
        url = extract_url(rec)
        if not url:
            skipped += 1
            continue
        try:
            feats = extract_url_features(url)
            feats["label"]    = 2   # Scam
            feats["source"]   = f"aa419_{rec.get('ScamType','unknown')}"
            feat_rows.append(feats)
        except Exception:
            skipped += 1

    print(f"Feature rows: {len(feat_rows)} | Skipped (no URL): {skipped}")
    feat_df = pd.DataFrame(feat_rows)

    # -- Merge with existing dataset -------------------------------------------
    if EXISTING_CSV.exists():
        print(f"\nLoading existing dataset: {EXISTING_CSV}")
        existing = pd.read_csv(EXISTING_CSV)
        print(f"  Existing: {existing.shape}")
        print(f"  Existing labels:\n{existing['label'].value_counts().to_string()}")

        # Remove any existing aa419 rows to prevent duplicates on re-run
        if "source" in existing.columns:
            existing = existing[~existing["source"].str.startswith("aa419_", na=False)]
            print(f"  After dedup: {existing.shape}")

        feat_aligned = feat_df.reindex(columns=existing.columns, fill_value=0)
        merged = pd.concat([existing, feat_aligned], ignore_index=True)
    else:
        merged = feat_df

    merged.to_csv(OUTPUT_CSV, index=False)
    print(f"\nUpdated dataset saved: {OUTPUT_CSV}")
    print(f"  New shape: {merged.shape}")
    print(f"  New label distribution:")
    print(merged["label"].value_counts().to_string())
    print("\nDone!")


if __name__ == "__main__":
    main()
