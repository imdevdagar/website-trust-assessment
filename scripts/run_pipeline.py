"""
scripts/run_pipeline.py
Main execution script for Phase 1: Binary Legitimate vs Phishing.

Runs all phases in order:
  Phase 1:  Dataset inspection
  Phase 2:  Data cleaning + leakage analysis
  Phase 3:  Feature selection
  Phase 4:  Standard split + train 5 models
  Phase 5:  Evaluate + confusion matrices + model comparison
  Phase 6:  Domain-aware split evaluation
  Phase 7:  Probability calibration
  Phase 8:  Confidence / Needs Review analysis
  Phase 9:  SHAP explainability
  Phase 10: Feature ablation
  Phase 11: Save experiment config

All results are saved to the results/ directory.
"""
import sys, json, time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd

from src.utils.logging import get_logger
from src.utils.paths import ensure_dirs, get_results_dir, get_figures_dir, get_metrics_dir
from src.utils.paths import get_confusion_matrices_dir, get_shap_dir, get_ablation_dir, get_models_dir
from src.data.load_data import load_phishing_raw, inspect_dataframe
from src.data.clean import clean_phishing, get_feature_columns
from src.data.split import standard_split, domain_aware_split
from src.features.feature_selection import select_features
from src.models.registry import get_models
from src.models.train import build_pipeline, train_model, save_model
from src.models.evaluate import evaluate_model, save_confusion_matrix, save_model_comparison_plot
from src.models.calibrate import calibrate_model, compute_brier_score, save_calibration_curve
from src.models.confidence import threshold_sweep, confidence_band_analysis, save_confidence_coverage_plot
from src.experiments.leakage import generate_leakage_report
from src.experiments.ablation import run_ablation
from src.experiments.domain_split import run_domain_split_comparison
from src.experiments.confidence_analysis import run_confidence_analysis
from src.explainability.shap_explainer import (
    compute_shap_values, save_shap_summary_plot, save_shap_bar_plot, explain_single_prediction
)

logger = get_logger("pipeline")
RANDOM_STATE = 42
LABEL_NAMES  = ["Legitimate", "Phishing"]
DEFAULT_THRESHOLD = 0.70

np.random.seed(RANDOM_STATE)


def main():
    run_start = time.time()
    ensure_dirs()

    results_dir      = get_results_dir()
    figures_dir      = get_figures_dir()
    metrics_dir      = get_metrics_dir()
    cm_dir           = get_confusion_matrices_dir()
    shap_dir         = get_shap_dir()
    ablation_dir     = get_ablation_dir()
    models_dir       = get_models_dir()

    # ================================================================
    # PHASE 1: Dataset Inspection
    # ================================================================
    logger.info("\n" + "="*60)
    logger.info("PHASE 1: Dataset Inspection")
    logger.info("="*60)
    raw_df = load_phishing_raw()
    summary = inspect_dataframe(raw_df, name="PhiUSIIL Phishing URL Dataset")
    pd.DataFrame([summary]).to_json(metrics_dir / "dataset_summary.json", indent=2)

    # ================================================================
    # PHASE 2: Leakage Analysis + Cleaning
    # ================================================================
    logger.info("\n" + "="*60)
    logger.info("PHASE 2: Leakage Analysis + Cleaning")
    logger.info("="*60)
    generate_leakage_report(out_path=str(results_dir / "leakage_analysis.md"))

    domain_col_raw = raw_df["Domain"].copy() if "Domain" in raw_df.columns else None
    df_clean = clean_phishing(raw_df, keep_flagged=True)
    all_feature_cols = get_feature_columns(df_clean)
    logger.info(f"Raw feature columns after cleaning: {len(all_feature_cols)}")

    # ================================================================
    # PHASE 3: Feature Selection
    # ================================================================
    logger.info("\n" + "="*60)
    logger.info("PHASE 3: Feature Selection (variance + correlation filter)")
    logger.info("="*60)
    feature_cols = select_features(df_clean, all_feature_cols)
    logger.info(f"Selected features ({len(feature_cols)}): {feature_cols}")
    (metrics_dir / "selected_features.json").write_text(
        json.dumps(feature_cols, indent=2), encoding="utf-8"
    )

    # Align domain_col with cleaned df index
    if domain_col_raw is not None:
        domain_col = domain_col_raw.loc[df_clean.index].reset_index(drop=True)
        df_clean_reset = df_clean.reset_index(drop=True)
    else:
        domain_col = None
        df_clean_reset = df_clean.reset_index(drop=True)

    # ================================================================
    # PHASE 4: Standard Split + Train All Models
    # ================================================================
    logger.info("\n" + "="*60)
    logger.info("PHASE 4: Standard Split + Train 5 Models")
    logger.info("="*60)
    X_train, X_test, y_train, y_test = standard_split(df_clean_reset, feature_cols)

    models_dict = get_models(multiclass=False)
    trained = {}
    for name, model in models_dict.items():
        logger.info(f"\nTraining: {name}")
        pipeline = build_pipeline(model)
        pipeline, train_time = train_model(pipeline, X_train, y_train)
        trained[name] = {"pipeline": pipeline, "train_time": train_time}
        save_model(pipeline, str(models_dir / f"{name}_binary.pkl"))

    # ================================================================
    # PHASE 5: Evaluate All Models
    # ================================================================
    logger.info("\n" + "="*60)
    logger.info("PHASE 5: Evaluation")
    logger.info("="*60)
    all_metrics = []
    for name, info in trained.items():
        pipeline   = info["pipeline"]
        train_time = info["train_time"]
        metrics    = evaluate_model(
            pipeline, X_test, y_test,
            model_name=name, label_names=LABEL_NAMES, multiclass=False,
        )
        metrics["Training_Time"] = train_time
        all_metrics.append(metrics)

        y_pred = pipeline.predict(X_test)
        save_confusion_matrix(
            y_test, y_pred, model_name=name,
            label_names=LABEL_NAMES,
            out_path=str(cm_dir / f"cm_{name}_standard.png"),
        )

    comparison_df = pd.DataFrame(all_metrics)
    comparison_df.to_csv(results_dir / "model_comparison.csv", index=False)
    logger.info(f"\nModel Comparison:\n{comparison_df[['Model','Accuracy','Macro_F1','ROC_AUC','Training_Time']].to_string()}")
    save_model_comparison_plot(comparison_df, str(figures_dir / "model_comparison.png"))

    # Identify best model by Macro_F1
    best_model_name = comparison_df.loc[comparison_df["Macro_F1"].idxmax(), "Model"]
    best_pipeline   = trained[best_model_name]["pipeline"]
    logger.info(f"\nBest model (by Macro_F1): {best_model_name}")

    # ================================================================
    # PHASE 6: Domain-Aware Split Evaluation
    # ================================================================
    logger.info("\n" + "="*60)
    logger.info("PHASE 6: Domain-Aware Split Evaluation")
    logger.info("="*60)
    domain_split_df = run_domain_split_comparison(
        df_clean_reset, feature_cols, domain_col,
        best_model_name=best_model_name,
        label_names=LABEL_NAMES,
    )
    domain_split_df.to_csv(results_dir / "domain_split_comparison.csv", index=False)

    # ================================================================
    # PHASE 7: Probability Calibration
    # ================================================================
    logger.info("\n" + "="*60)
    logger.info("PHASE 7: Probability Calibration")
    logger.info("="*60)
    uncal_pipeline = trained[best_model_name]["pipeline"]
    brier_uncal = compute_brier_score(uncal_pipeline, X_test, y_test, binary=True)
    logger.info(f"Uncalibrated Brier score: {brier_uncal:.6f}")

    cal_pipeline = calibrate_model(uncal_pipeline, X_train, y_train, method="isotonic")
    brier_cal    = compute_brier_score(cal_pipeline, X_test, y_test, binary=True)
    logger.info(f"Calibrated   Brier score: {brier_cal:.6f}")

    save_calibration_curve(
        uncal_pipeline, cal_pipeline, X_test, y_test,
        model_name=best_model_name,
        out_path=str(figures_dir / "calibration_curve.png"),
    )
    cal_summary = pd.DataFrame([{
        "Model":          best_model_name,
        "Brier_Uncal":    round(brier_uncal, 6),
        "Brier_Cal":      round(brier_cal, 6),
        "Method":         "isotonic",
    }])
    cal_summary.to_csv(metrics_dir / "calibration.csv", index=False)
    save_model(cal_pipeline, str(models_dir / f"{best_model_name}_binary_calibrated.pkl"))

    # Use calibrated pipeline for downstream analysis
    active_pipeline = cal_pipeline

    # ================================================================
    # PHASE 8: Confidence / Needs Review Analysis
    # ================================================================
    logger.info("\n" + "="*60)
    logger.info("PHASE 8: Confidence / Needs Review Analysis")
    logger.info("="*60)
    threshold_df, band_df = run_confidence_analysis(
        active_pipeline, X_test, y_test, figures_dir=figures_dir
    )
    threshold_df.to_csv(results_dir / "confidence_threshold_analysis.csv", index=False)
    band_df.to_csv(results_dir / "confidence_error_analysis.csv", index=False)

    # ================================================================
    # PHASE 9: SHAP Explainability
    # ================================================================
    logger.info("\n" + "="*60)
    logger.info("PHASE 9: SHAP Explainability")
    logger.info("="*60)
    shap_sample_size = min(1000, len(X_test))
    shap_idx   = np.random.choice(len(X_test), shap_sample_size, replace=False)
    X_shap     = X_test.iloc[shap_idx] if hasattr(X_test, "iloc") else X_test[shap_idx]
    y_shap     = y_test.iloc[shap_idx] if hasattr(y_test, "iloc") else y_test[shap_idx]

    try:
        shap_vals, _ = compute_shap_values(
            best_pipeline, X_train, X_shap, max_samples=500
        )
        save_shap_summary_plot(
            shap_vals, X_shap, feature_names=list(feature_cols),
            out_path=str(shap_dir / "shap_summary.png"),
        )
        save_shap_bar_plot(
            shap_vals, feature_names=list(feature_cols),
            out_path=str(shap_dir / "shap_importance.png"),
        )
        # Individual explanation for a high-confidence phishing example
        phish_mask = y_shap.values == 1 if hasattr(y_shap, "values") else y_shap == 1
        if phish_mask.sum() > 0:
            xi_index = np.where(phish_mask)[0][0]
            xi = X_shap.iloc[xi_index].to_dict() if hasattr(X_shap, "iloc") else {f: X_shap[xi_index, fi] for fi, f in enumerate(feature_cols)}
            indiv_result = explain_single_prediction(
                best_pipeline, X_train, xi,
                feature_names=list(feature_cols),
                label_map={0: "Legitimate", 1: "Phishing"},
                out_path=str(shap_dir / "shap_individual_phishing.png"),
            )
            logger.info(f"\nIndividual SHAP explanation (Phishing example):")
            logger.info(f"  Prediction : {indiv_result.get('prediction')}")
            logger.info(f"  Confidence : {indiv_result.get('confidence')}")
            for feat in indiv_result.get("top_features", [])[:5]:
                logger.info(f"    {feat['feature']}: {feat['shap_value']}")
            with open(shap_dir / "individual_explanation.json", "w") as f:
                json.dump(indiv_result, f, indent=2)
    except Exception as e:
        logger.error(f"SHAP analysis failed: {e}")
        import traceback
        traceback.print_exc()

    # ================================================================
    # PHASE 10: Feature Ablation
    # ================================================================
    logger.info("\n" + "="*60)
    logger.info("PHASE 10: Feature Ablation")
    logger.info("="*60)
    ablation_df = run_ablation(
        df_clean_reset, feature_cols,
        best_model_name=best_model_name,
        label_names=LABEL_NAMES,
        multiclass=False,
    )
    ablation_df.to_csv(ablation_dir / "ablation_comparison.csv", index=False)
    logger.info(f"\nAblation:\n{ablation_df[['Config','Num_Features','Accuracy','Macro_F1','ROC_AUC']].to_string()}")

    # ================================================================
    # PHASE 11: Save Experiment Configuration
    # ================================================================
    logger.info("\n" + "="*60)
    logger.info("PHASE 11: Saving Experiment Configuration")
    logger.info("="*60)
    experiment_config = {
        "dataset":           "PhiUSIIL_Phishing_URL_Dataset.csv",
        "dataset_shape":     list(raw_df.shape),
        "feature_list":      list(feature_cols),
        "num_features":      len(feature_cols),
        "random_state":      RANDOM_STATE,
        "test_size":         0.20,
        "train_size":        len(X_train),
        "test_n":            len(X_test),
        "label_map":         {"0": "Legitimate", "1": "Phishing"},
        "confidence_threshold": DEFAULT_THRESHOLD,
        "calibration_method": "isotonic",
        "best_model":        best_model_name,
        "best_macro_f1":     float(comparison_df.loc[comparison_df["Macro_F1"].idxmax(), "Macro_F1"]),
        "models_trained":    list(trained.keys()),
    }
    (results_dir / "experiment_config.json").write_text(
        json.dumps(experiment_config, indent=2), encoding="utf-8"
    )
    logger.info(f"Experiment config saved.")

    total_time = time.time() - run_start
    logger.info(f"\n{'='*60}")
    logger.info(f"PIPELINE COMPLETE  Total time: {total_time:.1f}s")
    logger.info(f"{'='*60}")
    logger.info(f"\nResults saved to: {results_dir}")
    logger.info(f"Best model: {best_model_name}")
    logger.info(f"  Macro_F1  : {experiment_config['best_macro_f1']:.4f}")
    logger.info(f"\nKey output files:")
    logger.info(f"  results/model_comparison.csv")
    logger.info(f"  results/figures/model_comparison.png")
    logger.info(f"  results/leakage_analysis.md")
    logger.info(f"  results/confidence_threshold_analysis.csv")
    logger.info(f"  results/confidence_error_analysis.csv")
    logger.info(f"  results/ablation/ablation_comparison.csv")
    logger.info(f"  results/shap/shap_summary.png")

    return experiment_config


if __name__ == "__main__":
    main()
