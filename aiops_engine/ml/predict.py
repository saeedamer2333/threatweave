"""Load the trained Random Forest and expose P_RF prediction for a Finding.

The model is loaded once (lazily) and reused. If the model file is missing,
`predict_p_rf` returns None so the scorer can fall back to its heuristic --
the engine never hard-fails just because the model has not been trained yet.
"""
from __future__ import annotations

from pathlib import Path
from functools import lru_cache

MODEL_PATH = Path(__file__).resolve().parent / "model" / "rf_model.joblib"


@lru_cache(maxsize=1)
def _load():
    if not MODEL_PATH.exists():
        return None
    try:
        import joblib
        return joblib.load(MODEL_PATH)
    except Exception as e:
        print(f"  [rf] could not load model: {e}")
        return None


def is_available() -> bool:
    return _load() is not None


def predict_p_rf(title: str, description: str = "", cwes: list[str] | None = None) -> float | None:
    """Return the model's probability (0-1) that this finding is severe."""
    model = _load()
    if model is None:
        return None
    import numpy as np
    text = f"{title} {description}".strip()
    cwe_text = " ".join(cwes) if cwes else "none"
    X = np.array([[text, cwe_text]], dtype=object)
    proba = model.predict_proba(X)[0, 1]
    return float(proba)


def explain_p_rf(title: str, description: str = "", cwes: list[str] | None = None, top_n: int = 5) -> list[dict]:
    """Which words in *this specific finding* actually drove its P_RF score.

    The model is a TF-IDF + Random Forest pipeline (see train_rf.py) - two
    numbers combine to tell a real, per-finding story instead of leaving
    "0.82" as a bare, unexplained output: how much weight this finding's own
    text gives a term (TF-IDF, per-finding) times how much the whole trained
    forest relies on that term in general (feature_importances_, global).
    A term absent from this finding contributes nothing no matter how
    important the model considers it elsewhere, so this is genuinely
    specific to the finding being explained, not a generic "what the model
    cares about" dump.

    This is a lightweight, defensible stand-in for a full SHAP explanation -
    proportional to it for a tree ensemble, at a fraction of the
    computational cost, and needs no extra dependency.
    """
    model = _load()
    if model is None:
        return []
    try:
        features = model.named_steps["features"]
        rf = model.named_steps["rf"]
        text = f"{title} {description}".strip()
        cwe_text = " ".join(cwes) if cwes else "none"

        tfidf_row = features.transform([[text, cwe_text]])
        names = features.get_feature_names_out()
        importances = rf.feature_importances_

        row = tfidf_row.toarray()[0] if hasattr(tfidf_row, "toarray") else tfidf_row[0]
        contributions = [
            (names[i], float(row[i] * importances[i]))
            for i in range(len(names)) if row[i] > 0
            # "none" is the CWE field's own placeholder for "no CWE data" (see
            # cwe_text above and train_rf.py's load_dataset) - the model can
            # genuinely learn a weight for it, but showing "none" as a term
            # that "drove the prediction" would mislead a reader into
            # thinking it is real evidence rather than an absence-of-data
            # artifact.
            and names[i].partition("__")[2] != "none"
        ]
        contributions.sort(key=lambda t: t[1], reverse=True)

        results = []
        for name, weight in contributions[:top_n]:
            source, _, term = name.partition("__")
            results.append({
                "term": term or name,
                "source": "description" if source == "desc" else "cwe",
                "weight": round(weight, 4),
            })
        return results
    except Exception:
        # Explanation is a bonus, not core scoring - never let an
        # introspection failure (e.g. an older sklearn without
        # get_feature_names_out) break the actual P_RF prediction above.
        return []
