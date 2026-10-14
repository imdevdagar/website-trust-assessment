"""
pipeline_step4_subcategory.py
==============================
Step 4: Train a Scam Sub-Category Classifier.

The AA419 dataset labels each scam URL with one of 17 sub-categories
(bank, pet, courier, fakeshop, nondelivery, etc.).

This step trains a secondary 17-class XGBoost classifier that,
given a URL already classified as "Scam", predicts what TYPE of scam it is.

This adds massive value for end users (e.g. "This is a BANK SCAM").
"""
import sys, json
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report
from xgboost import XGBClassifier

BASE      = Path(__file__).resolve().parent
RAW_AA419 = BASE / "data" / "raw" / "aa419_all_scam_raw.csv"
FEAT_JSON = BASE / "models" / "multiclass_features.json"
MODEL_OUT = BASE / "models" / "scam_subcategory_model.pkl"
LABEL_OUT = BASE / "models" / "scam_subcategory_labels.json"

print("=" * 60)
print("STEP 4: Scam Sub-Category Classifier (17-class)")
print("=" * 60)

if not RAW_AA419.exists():
    print("ERROR: Raw AA419 CSV not found. Run fetch_aa419_scam.py first.")
    sys.exit(1)

from src.features.url_features import extract_url_features

# ── Load raw AA419 with ScamType labels ───────────────────────────────────
print("\nLoading raw AA419 data...")
raw = pd.read_csv(RAW_AA419)
print(f"Total records: {len(raw)}")

# Filter out expired + unknown types
if 'Expired' in raw.columns:
    raw = raw[raw['Expired'].astype(str) == '0']
    print(f"Active only: {len(raw)}")

# Filter unknown ScamType
raw = raw[raw['ScamType'].notna() & (raw['ScamType'].str.lower() != 'unknown')]
print(f"After removing 'unknown' ScamType: {len(raw)}")
print(f"\nScamType distribution:")
print(raw['ScamType'].value_counts().to_string())

# ── Keep only categories with enough samples ──────────────────────────────
MIN_SAMPLES = 100
type_counts = raw['ScamType'].value_counts()
valid_types = type_counts[type_counts >= MIN_SAMPLES].index.tolist()
raw = raw[raw['ScamType'].isin(valid_types)]
print(f"\nCategories with >= {MIN_SAMPLES} samples: {len(valid_types)}")
print(f"Filtered dataset: {len(raw)} rows")

# ── Extract URL features ──────────────────────────────────────────────────
print("\nExtracting URL features...")
feat_rows = []
labels = []
skipped = 0
for i, row in raw.iterrows():
    if i % 10000 == 0:
        print(f"  {i}/{len(raw)}...")
    url = str(row.get('Url', row.get('Domain', ''))).strip()
    if not url.startswith('http'):
        url = 'https://' + url
    try:
        feats = extract_url_features(url)
        feat_rows.append(feats)
        labels.append(row['ScamType'].lower().strip())
    except Exception:
        skipped += 1

print(f"Extracted: {len(feat_rows)} | Skipped: {skipped}")

feat_df = pd.DataFrame(feat_rows).fillna(0)
feat_cols = json.loads(FEAT_JSON.read_text()) if FEAT_JSON.exists() else list(feat_df.columns)
feat_cols = [c for c in feat_cols if c in feat_df.columns]

X = feat_df[feat_cols]
y_raw = np.array(labels)

# ── Encode labels ─────────────────────────────────────────────────────────
le = LabelEncoder()
y = le.fit_transform(y_raw)
class_names = list(le.classes_)
print(f"\nClasses: {class_names}")
print(f"Feature count: {X.shape[1]}")

# ── Train/Test Split ──────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)
print(f"\nTrain: {X_train.shape}  Test: {X_test.shape}")

# ── Train XGBoost Sub-Category Classifier ────────────────────────────────
print("\nTraining sub-category classifier...")
xgb = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.85,
    colsample_bytree=0.85,
    eval_metric='mlogloss',
    random_state=42,
    n_jobs=-1,
    tree_method='hist',
)

pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('model',  xgb),
])

pipeline.fit(X_train, y_train)
print("Training complete.")

# ── Evaluate ──────────────────────────────────────────────────────────────
y_pred = pipeline.predict(X_test)
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=class_names))

# ── Save ──────────────────────────────────────────────────────────────────
joblib.dump(pipeline, MODEL_OUT)
json.dump(class_names, open(LABEL_OUT, 'w'))
print(f"\nSub-category model saved: {MODEL_OUT}")
print(f"Label mapping saved: {LABEL_OUT}")
print(f"Classes: {class_names}")
print("\nDone!")
