"""Train the Random Forest severity classifier (produces P_RF).

Design decision (important, defensible in the viva):
  * LABEL  = 1 if CVSS base score >= 7.0 (High/Critical), else 0.
  * FEATURES = CWE weakness ids + description text (TF-IDF).
    The CVSS score itself is NOT a feature. Using it would be circular
    (the label is derived from it) and, more importantly, the model must be
    able to score findings that have NO CVSS at all (e.g. SonarQube code
    issues). So it learns "which kinds of weakness/description tend to be
    severe" from text, which generalises to no-CVE findings.

Outputs ml/model/rf_model.joblib (the pipeline: TF-IDF + one-hot + RF).
Run:  python ml/train_rf.py
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

HERE = Path(__file__).resolve().parent
DATA = HERE / "data" / "cve_dataset.json"
MODEL_OUT = HERE / "model" / "rf_model.joblib"

SEVERE_THRESHOLD = 7.0


def load_dataset():
    rows = json.loads(DATA.read_text(encoding="utf-8"))
    texts, cwe_texts, labels = [], [], []
    for r in rows:
        texts.append(r.get("description", "") or "")
        # join CWE ids into a text field so TF-IDF can treat them as tokens
        cwe_texts.append(" ".join(r.get("cwes", [])) or "none")
        labels.append(1 if r["cvss"] >= SEVERE_THRESHOLD else 0)
    return texts, cwe_texts, labels


def build_pipeline() -> Pipeline:
    # Two text inputs: the description (rich) and the CWE ids (categorical-ish).
    features = ColumnTransformer([
        ("desc", TfidfVectorizer(max_features=800, stop_words="english", ngram_range=(1, 2)), 0),
        ("cwe", TfidfVectorizer(max_features=200, token_pattern=r"[A-Za-z0-9\-]+"), 1),
    ])
    clf = RandomForestClassifier(
        n_estimators=200, max_depth=None, min_samples_leaf=2,
        class_weight="balanced", n_jobs=-1, random_state=42,
    )
    return Pipeline([("features", features), ("rf", clf)])


def main():
    print("Loading dataset ...")
    texts, cwe_texts, labels = load_dataset()
    # X is a 2-column array: [description, cwe_text]
    X = list(zip(texts, cwe_texts))
    import numpy as np
    X = np.array(X, dtype=object)
    y = np.array(labels)
    print(f"  {len(y)} samples | severe={int(y.sum())} not_severe={int((1-y).sum())}")

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    print("Training Random Forest ...")
    pipe = build_pipeline()
    pipe.fit(X_tr, y_tr)

    print("\nEvaluation on held-out test set:")
    pred = pipe.predict(X_te)
    proba = pipe.predict_proba(X_te)[:, 1]
    print(classification_report(y_te, pred, target_names=["not_severe", "severe"]))
    print(f"ROC-AUC: {roc_auc_score(y_te, proba):.3f}")

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, MODEL_OUT)
    print(f"\nSaved model -> {MODEL_OUT}")


if __name__ == "__main__":
    main()
