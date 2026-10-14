import os, sys
from pathlib import Path
import pandas as pd
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logging import get_logger
logger = get_logger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PHISHING_SRC = _PROJECT_ROOT.parent / "Phishing Dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv"
_SCAM_SRC     = _PROJECT_ROOT.parent / "Scam dataset"


def load_phishing_raw(nrows=None) -> pd.DataFrame:
    """Load the PhiUSIIL Phishing URL Dataset from the adjacent source folder."""
    path = _PHISHING_SRC
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset required: place PhiUSIIL_Phishing_URL_Dataset.csv inside "
            f"the sibling 'Phishing Dataset' folder.\nExpected: {path}"
        )
    logger.info(f"Loading PhiUSIIL dataset from: {path}")
    df = pd.read_csv(path, nrows=nrows, low_memory=False,
                     encoding="utf-8", encoding_errors="replace")
    logger.info(f"Loaded shape: {df.shape}")
    return df


def load_scam_raw() -> pd.DataFrame:
    """
    Load the ScamFerret dataset from the adjacent 'Scam dataset' folder.
    Returns DataFrame with: url, category, split, label  (2=scam, 0=legitimate)
    """
    base = _SCAM_SRC
    if not base.exists():
        raise FileNotFoundError(
            f"ScamFerret dataset not found.\nExpected root: {base}"
        )
    categories = [
        "cryptocurrency", "investment",
        "online_shopping_english", "online_shopping_german",
        "online_shopping_japanese", "technical_support",
    ]
    records = []
    for split_name, lbl in [("scam_websites", 2), ("legitimate_websites", 0)]:
        split_dir = base / split_name
        for cat in categories:
            url_file = split_dir / cat / "groundtruth_url.txt"
            if url_file.exists():
                urls = [
                    line.strip()
                    for line in url_file.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip()
                ]
                for u in urls:
                    records.append({"url": u, "category": cat, "split": split_name, "label": lbl})
    df = pd.DataFrame(records)
    logger.info(f"ScamFerret loaded: {df.shape}")
    logger.info(f"Label distribution:\n{df['label'].value_counts().to_string()}")
    return df


def inspect_dataframe(df: pd.DataFrame, name: str = "DataFrame") -> dict:
    """Run full inspection on a DataFrame; print summary; return summary dict."""
    sep = "=" * 60
    print(f"\n{sep}\nDATASET INSPECTION: {name}\n{sep}")
    print(f"Shape         : {df.shape}")
    print(f"Rows          : {df.shape[0]}")
    print(f"Columns       : {df.shape[1]}")

    print(f"\nColumn names ({len(df.columns)}):")
    for c in df.columns:
        print(f"  - {c}")

    print("\nData types:")
    print(df.dtypes.to_string())

    missing = df.isnull().sum()
    missing_pct = (missing / len(df) * 100).round(2)
    missing_df = pd.DataFrame({"missing_count": missing, "missing_pct": missing_pct})
    print("\nMissing values:")
    shown = missing_df[missing_df["missing_count"] > 0]
    print(shown.to_string() if not shown.empty else "  None")

    dup_rows = int(df.duplicated().sum())
    print(f"\nDuplicate rows: {dup_rows}")
    for ucol in ["URL", "url"]:
        if ucol in df.columns:
            dup_u = int(df[ucol].duplicated().sum())
            print(f"Duplicate {ucol}s: {dup_u}")
    for dcol in ["Domain", "domain"]:
        if dcol in df.columns:
            dup_d = int(df[dcol].duplicated().sum())
            print(f"Duplicate {dcol}s: {dup_d}")

    target_col = next((c for c in ["label", "Label", "target"] if c in df.columns), None)
    if target_col:
        vals = sorted(df[target_col].unique())
        print(f"\nTarget column : '{target_col}'")
        print(f"Unique values : {vals}")
        print(f"Value counts  :")
        print(df[target_col].value_counts().to_string())

    num_cols = df.select_dtypes(include=[np.number]).columns[:5]
    print("\nNumeric summary (first 5 numeric cols):")
    print(df[num_cols].describe().to_string())

    return {
        "name": name,
        "shape": list(df.shape),
        "columns": list(df.columns),
        "missing_total": int(missing.sum()),
        "duplicate_rows": dup_rows,
        "target_column": target_col,
        "label_distribution": df[target_col].value_counts().to_dict() if target_col else {},
    }
