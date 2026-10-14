from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

RANDOM_STATE = 42


def get_models(multiclass: bool = False) -> dict:
    xgb_params = dict(
        n_estimators=200,
        random_state=RANDOM_STATE,
        eval_metric="mlogloss" if multiclass else "logloss",
        verbosity=0,
    )
    if multiclass:
        xgb_params["objective"] = "multi:softprob"
        xgb_params["num_class"] = 3

    lgbm_obj = "multiclass" if multiclass else "binary"

    return {
        "LogisticRegression": LogisticRegression(
            max_iter=1000, random_state=RANDOM_STATE,
            solver="lbfgs", C=1.0,
        ),
        "DecisionTree": DecisionTreeClassifier(
            random_state=RANDOM_STATE, max_depth=20,
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=200, random_state=RANDOM_STATE, n_jobs=-1,
        ),
        "XGBoost": XGBClassifier(**xgb_params),
        "LightGBM": LGBMClassifier(
            n_estimators=200, random_state=RANDOM_STATE,
            verbose=-1, objective=lgbm_obj,
        ),
    }
