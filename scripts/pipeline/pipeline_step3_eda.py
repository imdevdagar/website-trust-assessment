"""
pipeline_step3_eda.py
======================
Step 3: Exploratory Data Analysis (EDA) & Visualization.

Generates the following plots saved to results/eda/:
  1. Class distribution bar chart
  2. Feature correlation heatmap (top 20 features)
  3. Feature distribution per class (box plots for top 10 features)
  4. AA419 scam sub-category breakdown pie chart
  5. Feature importance from trained model
  6. Confusion matrix heatmap
"""
import sys, json
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')   # non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import joblib

sys.path.insert(0, str(Path(__file__).resolve().parent))

BASE      = Path(__file__).resolve().parent
DATA_CSV  = BASE / "data" / "processed" / "unified_with_tranco.csv"
if not DATA_CSV.exists():
    DATA_CSV = BASE / "data" / "processed" / "unified_clean.csv"
if not DATA_CSV.exists():
    DATA_CSV = BASE / "data" / "processed" / "unified_multiclass_dataset.csv"

MODEL_PKL = BASE / "models" / "XGBoost_multiclass.pkl"
FEAT_JSON = BASE / "models" / "multiclass_features.json"
RAW_AA419 = BASE / "data" / "raw" / "aa419_all_scam_raw.csv"
OUT_DIR   = BASE / "results" / "eda"
OUT_DIR.mkdir(parents=True, exist_ok=True)

COLORS = {0: "#4CAF50", 1: "#FF5722", 2: "#9C27B0"}  # green, red, purple
LABEL_NAMES = {0: "Legitimate", 1: "Phishing", 2: "Scam"}
PALETTE = [COLORS[i] for i in range(3)]

print("=" * 60)
print("STEP 3: EDA & Visualization")
print("=" * 60)

df = pd.read_csv(DATA_CSV)
feat_cols = json.loads(FEAT_JSON.read_text()) if FEAT_JSON.exists() else \
            [c for c in df.columns if c != 'label']
# Keep only features that exist in df
feat_cols = [f for f in feat_cols if f in df.columns]

print(f"Dataset: {df.shape}")
print(f"Features: {len(feat_cols)}")

# ── Plot 1: Class Distribution ──────────────────────────────────────────────
print("\nPlot 1: Class distribution...")
fig, ax = plt.subplots(figsize=(8, 5))
counts = df['label'].value_counts().sort_index()
labels = [LABEL_NAMES[i] for i in counts.index]
bars = ax.bar(labels, counts.values, color=PALETTE, edgecolor='white', linewidth=1.5, width=0.5)
for bar, val in zip(bars, counts.values):
    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 500,
            f'{val:,}', ha='center', va='bottom', fontsize=11, fontweight='bold')
ax.set_title("Class Distribution in Training Dataset", fontsize=14, fontweight='bold', pad=15)
ax.set_ylabel("Number of Samples", fontsize=11)
ax.set_xlabel("Class", fontsize=11)
ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, _: f'{int(x):,}'))
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)
ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig(OUT_DIR / "01_class_distribution.png", dpi=150, bbox_inches='tight')
plt.close()
print(f"  Saved: {OUT_DIR / '01_class_distribution.png'}")

# ── Plot 2: Feature Correlation Heatmap ────────────────────────────────────
print("\nPlot 2: Feature correlation heatmap...")
sample = df[feat_cols].sample(min(50000, len(df)), random_state=42)
corr = sample.corr()
# Pick top 18 most correlated features with each other
upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
top_feats = sorted(feat_cols, key=lambda f: upper[f].abs().max(), reverse=True)[:18]
corr_sub = corr.loc[top_feats, top_feats]

fig, ax = plt.subplots(figsize=(12, 10))
mask = np.triu(np.ones_like(corr_sub, dtype=bool))
sns.heatmap(corr_sub, mask=mask, cmap='coolwarm', center=0,
            annot=True, fmt='.2f', annot_kws={'size': 7},
            linewidths=0.5, ax=ax, vmin=-1, vmax=1)
ax.set_title("Feature Correlation Heatmap (Top 18 Features)", fontsize=13, fontweight='bold', pad=15)
plt.tight_layout()
plt.savefig(OUT_DIR / "02_feature_correlation.png", dpi=150, bbox_inches='tight')
plt.close()
print(f"  Saved: {OUT_DIR / '02_feature_correlation.png'}")

# ── Plot 3: Feature Distribution per Class (top 8 discriminative features) ──
print("\nPlot 3: Feature distribution per class...")
# Find the 8 features with highest variance between class means
class_means = df.groupby('label')[feat_cols].mean()
between_class_var = class_means.var()
top8 = between_class_var.nlargest(8).index.tolist()

fig, axes = plt.subplots(2, 4, figsize=(18, 8))
axes = axes.flatten()
sample_small = df.sample(min(20000, len(df)), random_state=42)

for i, feat in enumerate(top8):
    ax = axes[i]
    for lbl in [0, 1, 2]:
        data = sample_small[sample_small['label'] == lbl][feat].dropna()
        ax.hist(data, bins=30, alpha=0.6, color=COLORS[lbl],
                label=LABEL_NAMES[lbl], density=True, edgecolor='none')
    ax.set_title(feat, fontsize=9, fontweight='bold')
    ax.set_xlabel('Value', fontsize=8)
    ax.set_ylabel('Density', fontsize=8)
    ax.tick_params(labelsize=7)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

# Legend
handles = [mpatches.Patch(color=COLORS[i], label=LABEL_NAMES[i]) for i in range(3)]
fig.legend(handles=handles, loc='lower center', ncol=3, fontsize=10, frameon=False, bbox_to_anchor=(0.5, -0.02))
fig.suptitle("Feature Distributions per Class (Most Discriminative Features)",
             fontsize=13, fontweight='bold', y=1.01)
plt.tight_layout()
plt.savefig(OUT_DIR / "03_feature_distributions.png", dpi=150, bbox_inches='tight')
plt.close()
print(f"  Saved: {OUT_DIR / '03_feature_distributions.png'}")

# ── Plot 4: AA419 ScamType Breakdown ───────────────────────────────────────
print("\nPlot 4: AA419 scam sub-category breakdown...")
if RAW_AA419.exists():
    raw = pd.read_csv(RAW_AA419)
    type_counts = raw['ScamType'].value_counts().head(12)

    fig, ax = plt.subplots(figsize=(9, 6))
    colors = plt.cm.Set3(np.linspace(0, 1, len(type_counts)))
    wedges, texts, autotexts = ax.pie(
        type_counts.values, labels=type_counts.index,
        colors=colors, autopct='%1.1f%%', startangle=140,
        pctdistance=0.82, wedgeprops=dict(width=0.6)
    )
    for t in texts: t.set_fontsize(9)
    for at in autotexts: at.set_fontsize(8)
    ax.set_title(f"AA419 Scam Site Categories\n(177,212 total scam URLs)",
                 fontsize=12, fontweight='bold', pad=10)
    plt.tight_layout()
    plt.savefig(OUT_DIR / "04_aa419_categories.png", dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {OUT_DIR / '04_aa419_categories.png'}")
else:
    print("  Skipped (raw AA419 CSV not found)")

# ── Plot 5: Model Feature Importance ───────────────────────────────────────
print("\nPlot 5: Model feature importance...")
if MODEL_PKL.exists():
    pipeline = joblib.load(MODEL_PKL)
    xgb_model = pipeline.named_steps.get('model') or pipeline.steps[-1][1]
    importances = xgb_model.feature_importances_
    # Use the pipeline's scaler to get the actual feature count
    n_feats = len(importances)
    feat_labels = feat_cols[:n_feats] if len(feat_cols) >= n_feats else \
                  feat_cols + [f'feature_{i}' for i in range(len(feat_cols), n_feats)]
    feat_importance = pd.Series(importances, index=feat_labels).sort_values(ascending=True)
    top20 = feat_importance.tail(20)

    fig, ax = plt.subplots(figsize=(10, 7))
    bars = ax.barh(top20.index, top20.values, color=plt.cm.RdYlGn(top20.values / top20.values.max()))
    ax.set_xlabel("Feature Importance (XGBoost gain)", fontsize=11)
    ax.set_title("Top 20 Most Important Features\n(XGBoost Multi-Class Model)", fontsize=12, fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='x', alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT_DIR / "05_feature_importance.png", dpi=150, bbox_inches='tight')
    plt.close()
    print(f"  Saved: {OUT_DIR / '05_feature_importance.png'}")
else:
    print("  Skipped (model not found)")

# ── Plot 6: Confusion Matrix ────────────────────────────────────────────────
print("\nPlot 6: Confusion matrix...")
if MODEL_PKL.exists():
    try:
        from sklearn.metrics import confusion_matrix as cm
        from sklearn.model_selection import train_test_split

        # Load the exact feature list the model was trained on
        saved_feats = json.loads(FEAT_JSON.read_text()) if FEAT_JSON.exists() else feat_cols
        available   = [f for f in saved_feats if f in df.columns]
        missing     = [f for f in saved_feats if f not in df.columns]

        if missing:
            print(f"  Note: {len(missing)} model features not in current dataset — padding with 0.")
            for f in missing:
                df[f] = 0
            available = saved_feats

        X = df[available].fillna(0)
        y = df['label'].astype(int)
        _, X_test, _, y_test = train_test_split(X, y, test_size=0.1, random_state=42, stratify=y)

        y_pred = pipeline.predict(X_test)
        conf      = cm(y_test, y_pred)
        conf_norm = conf.astype(float) / conf.sum(axis=1, keepdims=True)

        fig, ax = plt.subplots(figsize=(7, 6))
        sns.heatmap(conf_norm, annot=conf, fmt='d', cmap='Blues',
                    xticklabels=list(LABEL_NAMES.values()),
                    yticklabels=list(LABEL_NAMES.values()),
                    linewidths=1, ax=ax, cbar_kws={'label': 'Proportion'})
        ax.set_xlabel("Predicted", fontsize=11, fontweight='bold')
        ax.set_ylabel("Actual",    fontsize=11, fontweight='bold')
        ax.set_title("Confusion Matrix (10% Holdout Test Set)", fontsize=12, fontweight='bold', pad=10)
        plt.tight_layout()
        plt.savefig(OUT_DIR / "06_confusion_matrix.png", dpi=150, bbox_inches='tight')
        plt.close()
        print(f"  Saved: {OUT_DIR / '06_confusion_matrix.png'}")
    except Exception as e:
        print(f"  Skipped (error: {e})")
else:
    print("  Skipped (model not found)")

# ── Summary Stats ───────────────────────────────────────────────────────────
print("\n" + "=" * 60)
print("EDA Summary Statistics")
print("=" * 60)
print(f"\nDataset shape: {df.shape}")
print(f"\nClass distribution:")
for lbl, count in df['label'].value_counts().sort_index().items():
    print(f"  {LABEL_NAMES[lbl]:12s}: {count:>8,} ({count/len(df)*100:.1f}%)")

print(f"\nFeature statistics (sample of key features):")
print(df[top8[:5]].describe().round(3).to_string())

print(f"\nAll EDA plots saved to: {OUT_DIR}")
print("\nDone!")
