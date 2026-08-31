"""Unit tests for ml/predict.py.

A real, tiny pipeline is fitted here (same shape as train_rf.py's - TF-IDF
over description + TF-IDF over CWE ids, feeding a RandomForestClassifier) so
these tests exercise the actual sklearn introspection path, not a mock of
it - a fake that only returns a canned number would not catch a real
get_feature_names_out()/feature_importances_ mismatch.
"""
from __future__ import annotations

import numpy as np
import pytest
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline

from ml import predict


def _fit_tiny_pipeline():
    """A small but real fit: 'buffer overflow' texts labelled severe,
    'minor typo' texts labelled not severe, so the forest genuinely learns
    to weight those terms rather than being an untrained/random pipeline."""
    texts = [
        "remote buffer overflow allows code execution",
        "stack buffer overflow in parser",
        "heap buffer overflow via crafted input",
        "minor typo in log message",
        "cosmetic whitespace issue in output",
        "unused variable warning in build",
    ]
    cwe_texts = ["CWE-120", "CWE-120", "CWE-120", "none", "none", "none"]
    labels = [1, 1, 1, 0, 0, 0]

    features = ColumnTransformer([
        ("desc", TfidfVectorizer(stop_words="english"), 0),
        ("cwe", TfidfVectorizer(token_pattern=r"[A-Za-z0-9\-]+"), 1),
    ])
    clf = RandomForestClassifier(n_estimators=20, random_state=42)
    pipe = Pipeline([("features", features), ("rf", clf)])

    X = np.array(list(zip(texts, cwe_texts)), dtype=object)
    pipe.fit(X, labels)
    return pipe


@pytest.fixture(autouse=True)
def _clear_cache():
    # _load() is @lru_cache'd at module level - stale across tests otherwise.
    predict._load.cache_clear()
    yield
    predict._load.cache_clear()


def test_explain_p_rf_surfaces_the_term_that_actually_drove_a_severe_prediction(monkeypatch):
    pipe = _fit_tiny_pipeline()
    monkeypatch.setattr(predict, "_load", lambda: pipe)

    result = predict.explain_p_rf("remote buffer overflow found", cwes=["CWE-120"])

    terms = [r["term"] for r in result]
    assert "overflow" in terms or "buffer" in terms


def test_explain_p_rf_labels_which_field_each_term_came_from(monkeypatch):
    pipe = _fit_tiny_pipeline()
    monkeypatch.setattr(predict, "_load", lambda: pipe)

    result = predict.explain_p_rf("buffer overflow", cwes=["CWE-120"])

    sources = {r["source"] for r in result}
    assert sources <= {"description", "cwe"}


def test_explain_p_rf_respects_top_n(monkeypatch):
    pipe = _fit_tiny_pipeline()
    monkeypatch.setattr(predict, "_load", lambda: pipe)

    result = predict.explain_p_rf("remote buffer overflow allows code execution", cwes=["CWE-120"], top_n=2)

    assert len(result) <= 2


def test_explain_p_rf_returns_results_sorted_by_weight_descending(monkeypatch):
    pipe = _fit_tiny_pipeline()
    monkeypatch.setattr(predict, "_load", lambda: pipe)

    result = predict.explain_p_rf("remote buffer overflow allows code execution", cwes=["CWE-120"])

    weights = [r["weight"] for r in result]
    assert weights == sorted(weights, reverse=True)


def test_explain_p_rf_returns_empty_list_when_no_model_is_available(monkeypatch):
    monkeypatch.setattr(predict, "_load", lambda: None)

    assert predict.explain_p_rf("anything") == []


def test_explain_p_rf_returns_empty_list_rather_than_raising_on_a_broken_pipeline(monkeypatch):
    # Explanation is a bonus on top of the real P_RF number - it must never
    # be the thing that breaks a scan.
    class _BrokenModel:
        named_steps = {}
    monkeypatch.setattr(predict, "_load", lambda: _BrokenModel())

    assert predict.explain_p_rf("anything") == []


def test_the_no_cwe_placeholder_term_never_appears_as_explanatory_evidence(monkeypatch):
    # "none" is the CWE field's own placeholder for "this finding has no CWE
    # data" (see explain_p_rf's own comment) - the model can genuinely learn
    # a weight for it, but it is an absence-of-data artifact, not real
    # evidence, and must never be presented to a reader as if it were.
    pipe = _fit_tiny_pipeline()
    monkeypatch.setattr(predict, "_load", lambda: pipe)

    result = predict.explain_p_rf("remote buffer overflow allows code execution")  # no cwes given -> "none"

    terms = [r["term"] for r in result]
    assert "none" not in terms


def test_a_term_not_present_in_this_finding_never_appears_in_its_explanation(monkeypatch):
    # The whole point of TF-IDF-weighted (not just global) importance: a
    # term the forest cares about in general contributes nothing to a
    # finding whose own text never mentions it.
    pipe = _fit_tiny_pipeline()
    monkeypatch.setattr(predict, "_load", lambda: pipe)

    result = predict.explain_p_rf("cosmetic whitespace issue")

    terms = [r["term"] for r in result]
    assert "overflow" not in terms
