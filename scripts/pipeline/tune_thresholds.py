import sys, json, joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score

BASE = Path(r'd:\WEBSITE ASSESSMENT SYSTEM\website-trust-assessment')
sys.path.insert(0, str(BASE))

df = pd.read_csv(BASE / 'data' / 'processed' / 'unified_multiclass_dataset.csv')
X = df.drop(columns=['label'])
y = df['label']

_, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

model = joblib.load(BASE / 'models' / 'XGBoost_multiclass.pkl')
proba = model.predict_proba(X_test)

# Try different threshold combinations for each class
# Default: predict the class with highest probability
# We tune a minimum confidence threshold per class

print("Tuning per-class thresholds...")
print(f"Base predictions (no threshold):")
base_pred = proba.argmax(axis=1)
print(classification_report(y_test, base_pred, target_names=["Legitimate", "Phishing", "Scam"]))

best_f1 = 0
best_thresh = (0.5, 0.5, 0.4)

# We tune a single scam threshold (most impactful)
for scam_thresh in np.arange(0.30, 0.70, 0.05):
    preds = []
    for p in proba:
        if p[2] >= scam_thresh:
            preds.append(2)
        else:
            preds.append(p[:2].argmax())
    
    macro_f1 = f1_score(y_test, preds, average='macro')
    scam_f1 = f1_score(y_test, preds, average=None)[2]
    if macro_f1 > best_f1:
        best_f1 = macro_f1
        best_thresh = scam_thresh
        print(f"  Scam threshold={scam_thresh:.2f} => Macro F1={macro_f1:.4f}, Scam F1={scam_f1:.4f}")

print(f"\nBest Scam Threshold: {best_thresh:.2f} (Macro F1: {best_f1:.4f})")

# Save thresholds
thresholds = {"Legitimate": 0.0, "Phishing": 0.0, "Scam": float(best_thresh)}
(BASE / 'models' / 'multiclass_thresholds.json').write_text(json.dumps(thresholds, indent=2))
print(f"Saved thresholds: {thresholds}")
