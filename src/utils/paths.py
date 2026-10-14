"""
utils/paths.py — Resolve project-relative paths robustly.
"""
from pathlib import Path


def get_project_root() -> Path:
    """Return the project root directory (parent of src/)."""
    return Path(__file__).resolve().parents[2]


def get_data_raw() -> Path:
    return get_project_root() / "data" / "raw"


def get_data_interim() -> Path:
    return get_project_root() / "data" / "interim"


def get_data_processed() -> Path:
    return get_project_root() / "data" / "processed"


def get_models_dir() -> Path:
    return get_project_root() / "models"


def get_results_dir() -> Path:
    return get_project_root() / "results"


def get_figures_dir() -> Path:
    return get_results_dir() / "figures"


def get_metrics_dir() -> Path:
    return get_results_dir() / "metrics"


def get_confusion_matrices_dir() -> Path:
    return get_results_dir() / "confusion_matrices"


def get_shap_dir() -> Path:
    return get_results_dir() / "shap"


def get_ablation_dir() -> Path:
    return get_results_dir() / "ablation"


def get_multiclass_dir() -> Path:
    return get_results_dir() / "multiclass"


def ensure_dirs():
    """Create all output directories if they do not exist."""
    dirs = [
        get_data_raw(), get_data_interim(), get_data_processed(),
        get_models_dir(), get_results_dir(), get_figures_dir(),
        get_metrics_dir(), get_confusion_matrices_dir(),
        get_shap_dir(), get_ablation_dir(), get_multiclass_dir(),
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
