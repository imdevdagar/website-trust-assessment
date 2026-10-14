"""
pipeline_step5_final_retrain.py
=================================
Step 5: Final retrain on the clean + Tranco-expanded dataset.

Uses the best feature set (37 features) with SMOTE balancing,
optimized thresholds from Phase 4.

Input:  data/processed/unified_with_tranco.csv
Output: models/XGBoost_multiclass.pkl  (updated)
        models/multiclass_features.json (updated)
        models/multiclass_thresholds.json (updated)
"""
import sys, json
from pathlib import Path
import pandas as pd
import numpy as np
import joblib

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE

BASE       = Path(__file__).resolve().parent
DATA_CSV   = BASE / "data" / "processed" / "unified_with_tranco.csv"
if not DATA_CSV.exists():
    DATA_CSV = BASE / "data" / "processed" / "unified_clean.csv"
if not DATA_CSV.exists():
    DATA_CSV = BASE / "data" / "processed" / "unified_multiclass_dataset.csv"

FEAT_JSON  = BASE / "models" / "multiclass_features.json"
MODEL_OUT  = BASE / "models" / "XGBoost_multiclass.pkl"
THRESH_OUT = BASE / "models" / "multiclass_thresholds.json"

LABEL_NAMES = ["Legitimate", "Phishing", "Scam"]

print("=" * 65)
print("STEP 5: Final Retrain on Expanded + Cleaned Dataset")
print("=" * 65)

df = pd.read_csv(DATA_CSV)
print(f"\nDataset: {df.shape}")
print(f"Label dist:\n{df['label'].value_counts().to_string()}")

feat_cols = json.loads(FEAT_JSON.read_text()) if FEAT_JSON.exists() else \
            [c for c in df.columns if c != 'label']
feat_cols = [f for f in feat_cols if f in df.columns]
print(f"Features: {len(feat_cols)}")

X = df[feat_cols].fillna(0)
y = df['label'].astype(int)

# ── Split ─────────────────────────────────────────────────────────────────
X_temp, X_test, y_temp, y_test = train_test_split(
    X, y, test_size=0.15, random_state=42, stratify=y
)
X_train, X_val, y_train, y_val = train_test_split(
    X_temp, y_temp, test_size=0.15, random_state=42, stratify=y_temp
)
print(f"\nTrain: {X_train.shape}  Val: {X_val.shape}  Test: {X_test.shape}")

# ── SMOTE ─────────────────────────────────────────────────────────────────
print("\nBalancing with SMOTE...")
target_n = int(y_train.value_counts().max())
smote = SMOTE(sampling_strategy={0: target_n, 1: target_n, 2: target_n},
              random_state=42, k_neighbors=5)
X_res, y_res = smote.fit_resample(X_train, y_train)
print(f"  Balanced shape: {X_res.shape}")

# ── Train ─────────────────────────────────────────────────────────────────
print("\nTraining XGBoost...")
xgb = XGBClassifier(
    n_estimators=400,
    max_depth=7,
    learning_rate=0.07,
    subsample=0.85,
    colsample_bytree=0.85,
    eval_metric='mlogloss',
    random_state=42,
    n_jobs=-1,
    tree_method='hist',
)
pipeline = Pipeline([('scaler', StandardScaler()), ('model', xgb)])
pipeline.fit(X_res, y_res)
print("Training complete.")

# ── Evaluate (default) ────────────────────────────────────────────────────
y_proba_test = pipeline.predict_proba(X_test)
y_pred_def   = np.argmax(y_proba_test, axis=1)
print("\nDefault thresholds:")
print(classification_report(y_test, y_pred_def, target_names=LABEL_NAMES))

# ── Threshold sweep ───────────────────────────────────────────────────────
print("Running threshold sweep on validation set...")
y_proba_val = pipeline.predict_proba(X_val)
best_thresholds = {}
for ci, cn in enumerate(LABEL_NAMES):
    y_bin = (y_val == ci).astype(int)
    best_t, best_f1 = 0.5, 0.0
    for t in np.arange(0.28, 0.82, 0.02):
        preds = (y_proba_val[:, ci] >= t).astype(int)
        if preds.sum() == 0: continue
        f = f1_score(y_bin, preds, zero_division=0)
        if f > best_f1:
            best_f1, best_t = f, t
    best_thresholds[cn] = round(float(best_t), 4)
    print(f"  {cn}: thresh={best_t:.2f}  F1={best_f1:.4f}")

# Apply tuned thresholds
y_pred_tuned = np.zeros(len(y_test), dtype=int)
for i in range(len(y_test)):
    scores = {j: y_proba_test[i,j] / best_thresholds[LABEL_NAMES[j]] for j in range(3)}
    y_pred_tuned[i] = max(scores, key=scores.get)

print("\nTuned thresholds:")
print(classification_report(y_test, y_pred_tuned, target_names=LABEL_NAMES))
print("Confusion matrix:")
print(confusion_matrix(y_test, y_pred_tuned))

# ── Save ──────────────────────────────────────────────────────────────────
joblib.dump(pipeline, MODEL_OUT)
FEAT_JSON.write_text(json.dumps(feat_cols))
THRESH_OUT.write_text(json.dumps(best_thresholds))

print(f"\nModel saved: {MODEL_OUT}")
print(f"Features saved ({len(feat_cols)}): {FEAT_JSON}")
print(f"Thresholds: {best_thresholds}")
print("\nDone! Restart Streamlit to load the updated model.")
