"""Unit tests for explainer.py - the deterministic, no-LLM explanation
engine. Every branch is a fixed template selected by finding type and
keyword signal, so these tests assert exact, reproducible output rather
than "looks plausible" fuzzy matching.
"""
from __future__ import annotations

from schema import Finding
import explainer


def _f(**kwargs) -> Finding:
    defaults = dict(source="trivy", type="VULNERABILITY", severity="HIGH",
                     title="t", affected_resource="r")
    defaults.update(kwargs)
    return Finding(**defaults)


# ---- explain_finding: routing by type ------------------------------------

def test_cve_finding_routes_to_cve_template():
    f = _f(cve_id="CVE-2021-44228", cvss_score=10.0, merged_count=1)
    text = explainer.explain_finding(f)
    assert "CVE-2021-44228" in text
    assert "Upgrade the package" in text


def test_cve_finding_with_merged_count_explains_the_grouping():
    f = _f(cve_id="CVE-2019-2", merged_count=3, related_cves=["CVE-2019-1", "CVE-2019-2", "CVE-2019-3"])
    text = explainer.explain_finding(f)
    assert "3 vulnerabilities" in text
    assert "single upgrade" in text


def test_code_vulnerability_without_cve_matches_sql_injection_keyword():
    f = _f(cve_id=None, title="SQL Injection risk", description="user input reaches a query")
    text = explainer.explain_finding(f)
    assert "SQL injection" in text
    assert "parameterised queries" in text


def test_code_vulnerability_without_cve_falls_back_to_generic_template():
    f = _f(cve_id=None, title="Obscure finding with no keyword match", description="")
    text = explainer.explain_finding(f)
    assert "Review and remediate before release" in text


def test_secret_finding_matches_aws_key_hint():
    f = _f(type="SECRET", title="AWS Access Key Detected", description="AKIA... found")
    text = explainer.explain_finding(f)
    assert "AWS account" in text
    assert "Rotate the credential" in text


def test_secret_finding_falls_back_to_generic_impact_when_no_hint_matches():
    f = _f(type="SECRET", title="Generic API Key", description="")
    text = explainer.explain_finding(f)
    assert "reused by anyone with repository access" in text


def test_misconfiguration_internet_facing_uses_exposure_language():
    f = _f(type="MISCONFIGURATION", title="Security group allows 0.0.0.0/0", internet_facing=True)
    text = explainer.explain_finding(f)
    assert "open to the whole" in text


def test_misconfiguration_not_internet_facing_uses_generic_language():
    f = _f(type="MISCONFIGURATION", title="Missing encryption", internet_facing=False)
    text = explainer.explain_finding(f)
    assert "recommended secure configuration" in text


def test_iam_finding_uses_least_privilege_language():
    f = _f(type="IAM", title="AdministratorAccess attached")
    text = explainer.explain_finding(f)
    assert "least-privilege" in text


def test_exposure_finding_uses_public_reachability_language():
    f = _f(type="EXPOSURE", title="Host publicly reachable")
    text = explainer.explain_finding(f)
    assert "reachable from the public" in text


def test_unknown_type_falls_back_to_raw_title():
    f = _f(type="SOMETHING_UNMAPPED", title="Raw title text")
    assert explainer.explain_finding(f) == "Raw title text"


# ---- explain_cluster -------------------------------------------------------

def test_cluster_rule_b_explanation_names_the_exposed_resource_and_count():
    cluster = {
        "internet_exposed": True, "severe_count": 5, "total_cves": 12,
        "exposure_resource": "sg-123", "exposure_source": "aws", "cve_id": "CVE-1",
    }
    result = explainer.explain_cluster(cluster, members=[])

    assert "sg-123" in result["why_it_matters"]
    assert "5 severe vulnerabilities" in result["why_it_matters"]
    assert "12 CVEs in total" in result["why_it_matters"]
    assert "AWS monitor observed" in result["why_it_matters"]
    assert "CVE-1" in result["recommended_action"]


def test_cluster_rule_b_explanation_handles_no_cve_top_member():
    """Regression: when the highest-risk member of a Rule B cluster has no
    CVE (a SonarQube/GitLeaks/Checkov finding), cluster["cve_id"] is None
    rather than absent, so a plain `.get(..., default)` never applied the
    fallback and the recommendation read "starting with None"."""
    cluster = {
        "internet_exposed": True, "severe_count": 3, "total_cves": 3,
        "exposure_resource": "aws_instance.app", "exposure_source": "checkov",
        "cve_id": None,
    }
    result = explainer.explain_cluster(cluster, members=[])
    assert "None" not in result["recommended_action"]


def test_cluster_rule_b_explanation_credits_checkov_when_declared_not_runtime():
    cluster = {
        "internet_exposed": True, "severe_count": 1, "total_cves": 1,
        "exposure_resource": "aws_security_group.web", "exposure_source": "checkov", "cve_id": "CVE-1",
    }
    result = explainer.explain_cluster(cluster, members=[])
    assert "declared in the infrastructure code" in result["why_it_matters"]


def test_cluster_rule_a_explanation_names_the_shared_cve():
    trivy_member = _f(source="trivy", affected_resource="Node.js / log4j-2.14.1")
    cluster = {"internet_exposed": False, "cve_id": "CVE-2021-44228"}

    result = explainer.explain_cluster(cluster, members=[trivy_member])

    assert "CVE-2021-44228" in result["why_it_matters"]
    assert "code scanner and again by the container scanner" in result["why_it_matters"]
    assert "Node.js / log4j-2.14.1" in result["recommended_action"]


# ---- explain_all: wiring ----------------------------------------------------

def test_explain_all_sets_explanation_on_every_finding():
    findings = [_f(cve_id="CVE-1"), _f(type="IAM", title="x")]
    explainer.explain_all(findings, clusters=[])
    assert all(f.explanation for f in findings)


def test_explain_all_attaches_explanation_dict_to_each_cluster():
    trivy_member = _f(source="trivy")
    cluster = {"finding_ids": [trivy_member.id], "internet_exposed": False, "cve_id": "CVE-1"}

    explainer.explain_all([trivy_member], clusters=[cluster])

    assert "why_it_matters" in cluster["explanation"]
    assert "what_is_at_risk" in cluster["explanation"]
    assert "recommended_action" in cluster["explanation"]
