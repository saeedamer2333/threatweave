"""Scorer - computes the composite risk score for every finding.

    FinalRisk = 0.45*P_RF + 0.25*S_retrieval + 0.20*S_asset + 0.10*S_EPSS

Each component comes from a different kind of evidence, so a weakness in one
signal is covered by the others:

    P_RF         trained Random Forest severity probability      (ml/predict.py)
    S_retrieval  BM25 similarity to known-scored CVEs            (retrieval.py)
    S_asset      deterministic exposure rules                    (here)
    S_EPSS       live exploitation probability from FIRST.org    (epss.py)

Every component degrades gracefully: if the model is untrained, the corpus is
missing, or the machine is offline, that component falls back to a heuristic
and the engine still produces a score.
"""
from __future__ import annotations

import sys
from pathlib import Path

from schema import Finding

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ml import predict as rf_predict
import retrieval
import epss as epss_api

WEIGHTS = {"P_RF": 0.45, "S_retrieval": 0.25, "S_asset": 0.20, "S_EPSS": 0.10}

_SEV_BASE = {"CRITICAL": 0.95, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.25, "INFO": 0.1}


def _p_rf(f: Finding) -> float:
    """Random Forest probability that the finding is severe."""
    proba = rf_predict.predict_p_rf(f.title, f.description)
    if proba is not None:
        return proba
    if f.cvss_score is not None:                       # fallback
        return min(f.cvss_score / 10.0, 1.0)
    return _SEV_BASE.get(f.severity, 0.5)


def _s_retrieval(f: Finding) -> float:
    """BM25 similarity to known-scored vulnerabilities."""
    query = f"{f.title} {f.description}".strip()
    score = retrieval.retrieve_score(query)
    if score is not None:
        return score
    return _SEV_BASE.get(f.severity, 0.5)              # fallback


# Findings that describe the deployed artifact rather than the source tree.
# A container package vulnerability runs on whatever host the image runs on,
# so exposure of that host applies to it. Code-side findings (SonarQube,
# GitLeaks) describe the repository and are not made reachable by an open port.
_DEPLOYED_SOURCES = ("trivy",)

# Sources that can provide first-hand evidence that an asset is reachable.
_EXPOSURE_SOURCES = ("aws", "checkov")


def propagate_exposure(findings: list[Finding]) -> int:
    """Carry proven exposure across to the findings it makes reachable.

    Without this, S_asset is a constant for every container finding: Trivy
    never sets internet_facing, so a vulnerable package on a host open to the
    internet scores exactly the same as one on an internal host. That is the
    cross-source link the correlator reports, so it belongs in the score too.

    Deliberately conservative: inherited reachability is recorded in its own
    field rather than by setting internet_facing, so first-hand evidence and
    inferred evidence stay distinguishable and score differently.
    """
    exposed = any(f.internet_facing for f in findings
                  if f.source in _EXPOSURE_SOURCES)
    if not exposed:
        return 0

    marked = 0
    for f in findings:
        if f.source in _DEPLOYED_SOURCES and not f.internet_facing:
            f.reachable_via_exposure = True
            marked += 1
    return marked


def _s_asset(f: Finding) -> float:
    """Asset criticality - deterministic by design, never learned.

    Three bands, as specified in the report: a publicly reachable resource with
    an open port scores 1.0, a resource reachable only behind another asset's
    exposure scores 0.6, and one with no established route scores 0.3.
    """
    if f.internet_facing:
        return 1.0       # first-hand: this finding IS the public exposure
    if f.reachable_via_exposure:
        return 0.6       # inherited: reachable through an exposed asset
    return 0.3           # no established route to this resource


def _confidence(p_rf: float) -> str:
    if p_rf >= 0.85:
        return "High Confidence"
    if p_rf >= 0.60:
        return "Moderate"
    return "Needs Analyst Review"


def score(findings: list[Finding]) -> list[Finding]:
    # EPSS is fetched once for every CVE in this run, not per finding.
    cve_ids = [f.cve_id for f in findings if f.cve_id]
    epss_scores = epss_api.scores_for(cve_ids) if cve_ids else {}

    reachable = propagate_exposure(findings)
    if reachable:
        print(f"  [asset] {reachable} deployed finding(s) inherit exposure "
              "from a reachable asset")

    # Report degraded components loudly. The fallbacks below keep the engine
    # running on an untrained or offline machine, but they are not equivalent:
    # P_RF alone is 45% of the score. Announcing only the healthy path made a
    # missing model invisible, since the evidence was a line that did not print.
    if rf_predict.is_available():
        print("  [rf]   using trained Random Forest for P_RF")
    else:
        print("  [rf]   WARNING: no trained model found - P_RF (45% of the "
              "score) is falling back to a CVSS/severity heuristic.")
        print("         Findings without a CVSS score degrade to their "
              "reported severity, and published accuracy figures do not apply.")
        print(f"         Expected model at: {rf_predict.MODEL_PATH}")
        print("         Train one with: python aiops_engine/ml/train_rf.py")
    if retrieval.is_available():
        print("  [bm25] using NVD corpus for S_retrieval")
    else:
        print("  [bm25] WARNING: no NVD corpus found - S_retrieval (25%) is "
              "falling back to reported severity.")

    for f in findings:
        s = {
            "P_RF": round(_p_rf(f), 2),
            "S_retrieval": round(_s_retrieval(f), 2),
            "S_asset": round(_s_asset(f), 2),
            "S_EPSS": round(epss_scores.get((f.cve_id or "").upper(), 0.0), 2),
        }
        final = sum(WEIGHTS[k] * s[k] for k in WEIGHTS)
        f.scores = s
        f.risk_score = round(final * 100)
        f.confidence = _confidence(s["P_RF"])
    return findings
