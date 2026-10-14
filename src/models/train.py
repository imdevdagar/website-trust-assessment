import time
import sys
from pathlib import Path
import joblib
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logging import get_logger
logger = get_logger(__name__)


def build_pipeline(model) -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("model",  model),
    ])


def train_model(pipeline: Pipeline, X_train, y_train) -> tuple:
    start = time.perf_counter()
    pipeline.fit(X_train, y_train)
    elapsed = time.perf_counter() - start
    logger.info(f"Training time: {elapsed:.4f}s")
    return pipeline, elapsed


def train_all_models(models: dict, X_train, y_train) -> dict:
    results = {}
    for name, model in models.items():
        logger.info(f"Training: {name}")
        pipeline = build_pipeline(model)
        fitted, t = train_model(pipeline, X_train, y_train)
        results[name] = {"pipeline": fitted, "train_time": round(t, 4)}
        logger.info(f"  {name}: done in {t:.2f}s")
    return results


def save_model(pipeline: Pipeline, path: str):
    joblib.dump(pipeline, path)
    logger.info(f"Model saved: {path}")


def load_model(path: str) -> Pipeline:
    pipeline = joblib.load(path)
    logger.info(f"Model loaded: {path}")
    return pipeline
