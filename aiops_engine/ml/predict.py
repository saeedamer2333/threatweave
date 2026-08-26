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
