import sys
from pathlib import Path
import pandas as pd
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.features.feature_groups import get_ablation_configs
from src.models.registry import get_models
from src.models.train import build_pipeline, train_model
from src.models.evaluate import evaluate_model
from src.data.split import standard_split
from src.utils.logging import get_logger
logger = get_logger(__name__)


def run_ablation(
    df_clean: pd.DataFrame,
    all_feature_cols: list,
    best_model_name: str = "RandomForest",
    label_names: list = None,
    multiclass: bool = False,
) -> pd.DataFrame:
    """
    Run three ablation experiments using the selected model.
    Returns a DataFrame with comparison metrics.
    """
    if label_names is None:
        label_names = ["Legitimate", "Phishing"]

    configs = get_ablation_configs(all_feature_cols)
    logger.info(f"Ablation configs: {list(configs.keys())}")

    results = []
    for config_name, feature_cols in configs.items():
        if len(feature_cols) == 0:
            logger.warning(f"Config {config_name} has no features; skipping.")
            continue
        logger.info(f"\n--- Ablation: {config_name} ({len(feature_cols)} features) ---")

        X_train, X_test, y_train, y_test = standard_split(df_clean, feature_cols)
        models = get_models(multiclass=multiclass)
        model  = models[best_model_name]
        pipeline = build_pipeline(model)
        pipeline, train_time = train_model(pipeline, X_train, y_train)
        metrics = evaluate_model(
            pipeline, X_test, y_test,
            model_name=f"{best_model_name}_{config_name}",
            label_names=label_names,
            multiclass=multiclass,
        )
        metrics["Config"]       = config_name
        metrics["Num_Features"] = len(feature_cols)
        metrics["Features"]     = str(feature_cols)
        metrics["Train_Time"]   = train_time
        results.append(metrics)

    df_results = pd.DataFrame(results)
    logger.info(f"\nAblation results:\n{df_results[['Config', 'Num_Features', 'Accuracy', 'Macro_F1']].to_string()}")
    return df_results
