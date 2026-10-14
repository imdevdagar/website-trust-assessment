import sys
from pathlib import Path
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.data.split import standard_split, domain_aware_split
from src.models.registry import get_models
from src.models.train import build_pipeline, train_model
from src.models.evaluate import evaluate_model
from src.utils.logging import get_logger
logger = get_logger(__name__)


def run_domain_split_comparison(
    df_clean: pd.DataFrame,
    feature_cols: list,
    domain_col: pd.Series,
    best_model_name: str = "RandomForest",
    label_names: list = None,
    multiclass: bool = False,
) -> pd.DataFrame:
    """
    Compare standard vs domain-aware split for the same model.
    Returns DataFrame with comparison results.
    """
    if label_names is None:
        label_names = ["Legitimate", "Phishing"]

    results = []
    for split_type in ["standard", "domain_aware"]:
        logger.info(f"\n--- {split_type} split ---")
        if split_type == "standard":
            X_train, X_test, y_train, y_test = standard_split(df_clean, feature_cols)
        else:
            X_train, X_test, y_train, y_test = domain_aware_split(
                df_clean, feature_cols, domain_col
            )

        models   = get_models(multiclass=multiclass)
        model    = models[best_model_name]
        pipeline = build_pipeline(model)
        pipeline, train_time = train_model(pipeline, X_train, y_train)
        metrics  = evaluate_model(
            pipeline, X_test, y_test,
            model_name=f"{best_model_name}_{split_type}",
            label_names=label_names,
            multiclass=multiclass,
        )
        metrics["Split_Type"] = split_type
        metrics["Train_Size"]  = len(y_train)
        metrics["Test_Size"]   = len(y_test)
        metrics["Train_Time"]  = train_time
        results.append(metrics)
        logger.info(f"  Accuracy={metrics['Accuracy']:.4f}  Macro_F1={metrics['Macro_F1']:.4f}")

    df = pd.DataFrame(results)
    logger.info(f"\nDomain split comparison:\n{df[['Split_Type', 'Accuracy', 'Macro_F1', 'ROC_AUC']].to_string()}")
    return df
