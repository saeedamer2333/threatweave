"""Unit tests for scorer.py.

The three external signals (trained Random Forest, BM25 retrieval, EPSS)
are monkeypatched throughout so this suite is hermetic: it needs no trained
model file, no NVD corpus and no network access, and gives the same result
on any machine, including CI. The deterministic pieces - S_asset,
confidence tiering, and exposure propagation - are tested directly since
they are pure functions with no external dependency at all.
"""
from __future__ import annotations

from schema import Finding
import scorer


def _f(**kwargs) -> Finding:
    defaults = dict(source="trivy", type="VULNERABILITY", severity="HIGH",
                     title="t", affected_resource="r")
    defaults.update(kwargs)
    return Finding(**defaults)


# ---- S_asset: deterministic exposure bands --------------------------------

def test_s_asset_publicly_reachable_scores_1_0():
    assert scorer._s_asset(_f(internet_facing=True)) == 1.0


def test_s_asset_reachable_via_exposure_scores_0_6():
    assert scorer._s_asset(_f(internet_facing=False, reachable_via_exposure=True)) == 0.6


def test_s_asset_no_established_route_scores_0_3():
    assert scorer._s_asset(_f(internet_facing=False, reachable_via_exposure=False)) == 0.3


def test_s_asset_first_hand_evidence_takes_priority_over_inherited():
    """A finding that is itself the exposure must score 1.0 even if it also
    happens to carry reachable_via_exposure=True from a prior propagation."""
    f = _f(internet_facing=True, reachable_via_exposure=True)
    assert scorer._s_asset(f) == 1.0


# ---- Confidence tiering, derived from P_RF alone --------------------------

def test_confidence_tiers_at_their_documented_boundaries():
    assert scorer._confidence(0.85) == "High Confidence"
    assert scorer._confidence(0.90) == "High Confidence"
    assert scorer._confidence(0.84) == "Moderate"
    assert scorer._confidence(0.60) == "Moderate"
    assert scorer._confidence(0.59) == "Needs Analyst Review"
    assert scorer._confidence(0.0) == "Needs Analyst Review"


# ---- Exposure propagation --------------------------------------------------

def test_propagate_exposure_marks_deployed_findings_when_asset_is_exposed():
    exposure = _f(source="aws", internet_facing=True)
    container_finding = _f(source="trivy", internet_facing=False)

    marked = scorer.propagate_exposure([exposure, container_finding])

    assert marked == 1
    assert container_finding.reachable_via_exposure is True
    assert exposure.reachable_via_exposure is False    # the exposure itself is unaffected


def test_propagate_exposure_does_nothing_without_exposure_evidence():
    container_finding = _f(source="trivy", internet_facing=False)
    marked = scorer.propagate_exposure([container_finding])
    assert marked == 0
    assert container_finding.reachable_via_exposure is False


def test_propagate_exposure_does_not_touch_source_code_findings():
    """SonarQube/GitLeaks findings describe the repository, not the deployed
    artifact, and must not inherit reachability from a live host exposure."""
    exposure = _f(source="aws", internet_facing=True)
    code_finding = _f(source="sonarqube", internet_facing=False)

    scorer.propagate_exposure([exposure, code_finding])

    assert code_finding.reachable_via_exposure is False


def test_propagate_exposure_does_not_overwrite_first_hand_exposure():
    already_exposed = _f(source="trivy", internet_facing=True)
    other_exposure = _f(source="checkov", internet_facing=True)

    scorer.propagate_exposure([other_exposure, already_exposed])

    # first-hand evidence is not replaced by an inferred flag
    assert already_exposed.reachable_via_exposure is False


# ---- score(): hermetic end-to-end, external signals monkeypatched --------

def test_score_combines_all_four_weighted_signals(monkeypatch):
    monkeypatch.setattr(scorer.rf_predict, "predict_p_rf", lambda title, desc: 0.9)
    monkeypatch.setattr(scorer.rf_predict, "is_available", lambda: True)
    monkeypatch.setattr(scorer.retrieval, "retrieve_score", lambda q: 0.5)
    monkeypatch.setattr(scorer.retrieval, "is_available", lambda: True)
    monkeypatch.setattr(scorer.epss_api, "scores_for", lambda cve_ids: {})

    finding = _f(internet_facing=True, cve_id=None)   # S_asset = 1.0, S_EPSS = 0.0 (no CVE)
    result = scorer.score([finding])[0]

    # 0.45*0.9 + 0.25*0.5 + 0.20*1.0 + 0.10*0.0 = 0.405 + 0.125 + 0.20 + 0 = 0.73
    assert result.risk_score == 73
    assert result.confidence == "High Confidence"
    assert result.scores["P_RF"] == 0.9
    assert result.scores["S_asset"] == 1.0


def test_score_falls_back_to_cvss_when_rf_model_unavailable(monkeypatch):
    monkeypatch.setattr(scorer.rf_predict, "predict_p_rf", lambda title, desc: None)
    monkeypatch.setattr(scorer.rf_predict, "is_available", lambda: False)
    monkeypatch.setattr(scorer.retrieval, "retrieve_score", lambda q: 0.5)
    monkeypatch.setattr(scorer.retrieval, "is_available", lambda: True)
    monkeypatch.setattr(scorer.epss_api, "scores_for", lambda cve_ids: {})

    finding = _f(cvss_score=8.0)
    result = scorer.score([finding])[0]

    assert result.scores["P_RF"] == 0.8          # 8.0 / 10.0


def test_score_falls_back_to_severity_when_no_cvss_and_no_model(monkeypatch):
    monkeypatch.setattr(scorer.rf_predict, "predict_p_rf", lambda title, desc: None)
    monkeypatch.setattr(scorer.rf_predict, "is_available", lambda: False)
    monkeypatch.setattr(scorer.retrieval, "retrieve_score", lambda q: None)
    monkeypatch.setattr(scorer.retrieval, "is_available", lambda: False)
    monkeypatch.setattr(scorer.epss_api, "scores_for", lambda cve_ids: {})

    finding = _f(severity="CRITICAL", cvss_score=None)
    result = scorer.score([finding])[0]

    assert result.scores["P_RF"] == 0.95          # _SEV_BASE["CRITICAL"]
    assert result.scores["S_retrieval"] == 0.95


def test_score_looks_up_epss_by_uppercased_cve_id(monkeypatch):
    monkeypatch.setattr(scorer.rf_predict, "predict_p_rf", lambda title, desc: 0.5)
    monkeypatch.setattr(scorer.rf_predict, "is_available", lambda: True)
    monkeypatch.setattr(scorer.retrieval, "retrieve_score", lambda q: 0.5)
    monkeypatch.setattr(scorer.retrieval, "is_available", lambda: True)
    monkeypatch.setattr(scorer.epss_api, "scores_for",
                         lambda cve_ids: {"CVE-2021-44228": 0.97})

    finding = _f(cve_id="cve-2021-44228")   # lowercase in the finding
    result = scorer.score([finding])[0]

    assert result.scores["S_EPSS"] == 0.97
