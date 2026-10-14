"""
pipeline_step1_clean.py
========================
Step 1: Clean and deduplicate the existing dataset.

Actions:
  - Remove exact duplicate rows
  - Check for near-duplicate features (identical feature vectors, different labels)
  - Report class balance statistics
  - Save cleaned version

Also: inspect the raw AA419 CSV and filter out expired scam domains,
      then rebuild scam rows from scratch.
"""
import sys, json
from pathlib import Path
import pandas as pd
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from src.features.url_features import extract_url_features

BASE         = Path(__file__).resolve().parent
DATA_CSV     = BASE / "data" / "processed" / "unified_multiclass_dataset.csv"
RAW_AA419    = BASE / "data" / "raw" / "aa419_all_scam_raw.csv"
CLEAN_CSV    = BASE / "data" / "processed" / "unified_clean.csv"
FEAT_JSON    = BASE / "models" / "multiclass_features.json"

print("=" * 60)
print("STEP 1: Dataset Cleaning & Deduplication")
print("=" * 60)

df = pd.read_csv(DATA_CSV)
print(f"\nOriginal: {df.shape}")
print(f"Label dist:\n{df['label'].value_counts().to_string()}")

# 1. Remove exact duplicate rows
before = len(df)
df = df.drop_duplicates()
print(f"\nAfter exact dedup: {len(df)} (removed {before - len(df)} rows)")

# 2. Remove rows where all feature columns are identical (same vector, any label)
feat_cols = [c for c in df.columns if c != 'label']
before = len(df)
df = df.drop_duplicates(subset=feat_cols, keep='first')
print(f"After feature-vector dedup: {len(df)} (removed {before - len(df)} rows)")

# 3. Check for conflicting labels (same features, different labels)
dupes_check = df[feat_cols].duplicated(keep=False)
if dupes_check.any():
    print(f"\nWARNING: {dupes_check.sum()} rows share identical features but kept due to label conflict.")
else:
    print("No feature vector conflicts found. OK")

# 4. Remove rows with all-zero feature vectors (bad records)
zero_mask = (df[feat_cols] == 0).all(axis=1)
before = len(df)
df = df[~zero_mask]
print(f"After removing all-zero rows: {len(df)} (removed {before - len(df)} rows)")

print(f"\nCleaned label dist:\n{df['label'].value_counts().to_string()}")

# 5. Rebuild scam rows from raw AA419 with the latest url_features.py
#    We keep ALL records (including expired) — expired domains still have
#    valid URL feature patterns that teach the model about scam structure.
if RAW_AA419.exists():
    print(f"\nLoading raw AA419 CSV to rebuild scam features with latest extractor...")
    raw = pd.read_csv(RAW_AA419)
    print(f"  Total AA419: {len(raw)}")

    # Save ScamType metadata for sub-classifier (keep active only for that)
    active_mask = raw.get('Expired', pd.Series(['0']*len(raw))).astype(str) == '0'
    print(f"  Active: {active_mask.sum()} | Expired: {(~active_mask).sum()}")
    print(f"  Keeping ALL for training (expired domains still have valid URL patterns)")

    # Re-extract features for ALL scam URLs with updated url_features.py
    print(f"\nRe-extracting features for {len(raw)} scam URLs...")
    feat_rows = []
    scam_type_rows = []
    skipped = 0
    for i, row in raw.iterrows():
        if i % 25000 == 0:
            print(f"  {i}/{len(raw)}...")
        url = str(row.get('Url', row.get('Domain', ''))).strip()
        if not url.startswith('http'):
            url = 'https://' + url
        try:
            feats = extract_url_features(url)
            feats['label'] = 2
            feat_rows.append(feats)
            scam_type_rows.append({'ScamType': row.get('ScamType', 'unknown')})
        except Exception:
            skipped += 1

    aa419_df = pd.DataFrame(feat_rows)
    print(f"  Extracted: {len(aa419_df)} | Skipped: {skipped}")

    # Save ScamType metadata for sub-classifier
    scam_meta = pd.DataFrame(scam_type_rows)
    scam_meta.to_csv(BASE / "data" / "processed" / "aa419_scam_types.csv", index=False)
    print("  ScamType metadata saved for sub-classifier.")

    # Replace old scam rows (pre-dedup) with fresh AA419 rows
    # Keep non-scam rows from the deduped df
    non_scam = df[df['label'] != 2].copy()
    scam_new  = aa419_df.reindex(columns=non_scam.columns, fill_value=0)

    # Dedup the new scam rows too
    scam_before = len(scam_new)
    feat_cols_sub = [c for c in scam_new.columns if c != 'label']
    scam_new = scam_new.drop_duplicates(subset=feat_cols_sub, keep='first')
    print(f"  Scam dedup: {scam_before} -> {len(scam_new)} rows")

    df_final = pd.concat([non_scam, scam_new], ignore_index=True)
    print(f"\nFinal dataset after rebuild:")
    print(df_final['label'].value_counts().to_string())
else:
    df_final = df
    print("\nNo raw AA419 CSV found, using cleaned df as-is.")

# Save also the ScamType metadata separately for sub-classifier
if 'ScamType' in df_final.columns:
    scam_type_df = df_final[['ScamType', 'label']].copy()
    scam_type_df.to_csv(BASE / "data" / "processed" / "aa419_scam_types.csv", index=False)
    print("\nScamType metadata saved for sub-classifier.")
    df_final = df_final.drop(columns=['ScamType'])

df_final.to_csv(CLEAN_CSV, index=False)
print(f"\nCleaned dataset saved: {CLEAN_CSV}")
print(f"Final shape: {df_final.shape}")
print(f"\nFinal label distribution:")
print(df_final['label'].value_counts().to_string())
print("\nDone!")
