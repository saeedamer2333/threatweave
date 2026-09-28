"""Unit tests for correlator.py - the project's primary novelty: linking
findings from separate tools into one attack-path cluster.

Rule A: the same CVE reported by both a code scanner (SonarQube) and a
container scanner (Trivy).
Rule B: severe vulnerabilities grouped behind a single internet-facing
exposure point, capped at 8 named members.
"""
from __future__ import annotations

from schema import Finding
import correlator


def _f(**kwargs) -> Finding:
    defaults = dict(
        source="trivy", type="VULNERABILITY", severity="HIGH",
        title="t", affected_resource="r", risk_score=50,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---- Rule A: cross-source CVE --------------------------------------------

def test_rule_a_fires_only_when_both_sonarqube_and_trivy_report_the_same_cve():
    sonar = _f(source="sonarqube", reported_by=["sonarqube"], cve_id="CVE-2021-44228", risk_score=70)
    trivy = _f(source="trivy", reported_by=["trivy"], cve_id="CVE-2021-44228", risk_score=90)

    clusters = correlator.correlate([sonar, trivy])

    assert len(clusters) == 1
    c = clusters[0]
    assert c["rule"] == "A: cross-source CVE"
    assert c["cve_id"] == "CVE-2021-44228"
    assert c["risk_score"] == 90               # max of the two members
    assert set(c["finding_ids"]) == {sonar.id, trivy.id}
    assert sonar.cluster_id == c["cluster_id"]
    assert trivy.cluster_id == c["cluster_id"]


def test_rule_a_does_not_fire_for_a_cve_seen_by_only_one_source():
    trivy_only = _f(source="trivy", reported_by=["trivy"], cve_id="CVE-2021-1")
    clusters = correlator.correlate([trivy_only])
    assert clusters == []


def test_rule_a_does_not_fire_for_sonarqube_plus_checkov():
    """Rule A is specifically code-to-container; any other pairing must not
    trigger it, even if both tools happen to cite the same CVE string."""
    sonar = _f(source="sonarqube", reported_by=["sonarqube"], cve_id="CVE-2021-1")
    checkov = _f(source="checkov", reported_by=["checkov"], cve_id="CVE-2021-1")
    clusters = correlator.correlate([sonar, checkov])
    assert clusters == []


# ---- Rule B: exposed vulnerable asset -------------------------------------

def test_rule_b_fires_when_exposure_and_severe_vulnerabilities_coexist():
    exposure = _f(source="aws", type="EXPOSURE", internet_facing=True, risk_score=80,
                   affected_resource="sg-123")
    severe1 = _f(cve_id="CVE-1", severity="CRITICAL", risk_score=95)
    severe2 = _f(cve_id="CVE-2", severity="HIGH", risk_score=85)

    clusters = correlator.correlate([exposure, severe1, severe2])

    assert len(clusters) == 1
    c = clusters[0]
    assert c["rule"] == "B: exposed vulnerable asset"
    assert c["internet_exposed"] is True
    assert c["severe_count"] == 2
    assert exposure.id in c["finding_ids"]


def test_rule_b_steps_show_only_the_tools_actually_in_the_path():
    # No container image scanned: the path must not claim a Trivy step.
    exposure = _f(source="aws", type="EXPOSURE", internet_facing=True, risk_score=51,
                  affected_resource="s3://bucket")
    code = _f(source="sonarqube", severity="CRITICAL", risk_score=56)

    c = correlator.correlate([exposure, code])[0]

    assert c["attack_path"] == "Vulnerable code (SonarQube) -> host publicly exposed (AWS security group)"
    assert c["member_sources"] == ["sonarqube"]


def test_rule_b_names_the_live_aws_resource_type_that_is_exposed():
    code = _f(source="sonarqube", severity="CRITICAL", risk_score=56)
    for check, label in [
        ("s3_public_access_block_disabled", "bucket publicly accessible (AWS S3)"),
        ("ec2_public_ip", "instance has a public IP (AWS EC2)"),
        ("security_group_open_ingress", "host publicly exposed (AWS security group)"),
    ]:
        exposure = _f(source="aws", type="EXPOSURE", internet_facing=True, risk_score=51,
                      affected_resource=f"res-{check}", rule_id=check)
        c = correlator.correlate([exposure, code])[0]
        assert c["attack_path"].endswith(label), check


def test_rule_b_steps_run_code_then_container_then_exposure():
    exposure = _f(source="checkov", type="MISCONFIGURATION", internet_facing=True, risk_score=58,
                  affected_resource="aws_security_group.web")
    container = _f(source="trivy", cve_id="CVE-1", severity="HIGH", risk_score=60)
    code = _f(source="sonarqube", severity="HIGH", risk_score=62)

    c = correlator.correlate([exposure, container, code])[0]

    assert c["attack_path"].split(" -> ") == [
        "Vulnerable code (SonarQube)",
        "Vulnerable dependency in deployed container (Trivy)",
        "exposure declared in infrastructure (Checkov)",
    ]


def test_rule_b_does_not_fire_without_exposure_evidence():
    severe = _f(cve_id="CVE-1", severity="CRITICAL")
    clusters = correlator.correlate([severe])
    assert clusters == []


def test_rule_b_does_not_fire_without_any_severe_vulnerability():
    exposure = _f(source="aws", type="EXPOSURE", internet_facing=True)
    medium = _f(severity="MEDIUM")
    clusters = correlator.correlate([exposure, medium])
    assert clusters == []


def test_rule_b_prefers_runtime_evidence_over_declared_evidence():
    """When AWS (live) and Checkov (declared-in-IaC) evidence describe the
    SAME resource, only one cluster should form for it, and AWS must win as
    the stronger claim - not two clusters double-counting one real asset."""
    aws_exp = _f(source="aws", type="EXPOSURE", internet_facing=True, risk_score=60,
                 affected_resource="sg-web")
    checkov_exp = _f(source="checkov", type="MISCONFIGURATION", internet_facing=True,
                      risk_score=90, affected_resource="sg-web")
    severe = _f(cve_id="CVE-1", severity="CRITICAL")

    clusters = correlator.correlate([aws_exp, checkov_exp, severe])

    assert len(clusters) == 1
    assert clusters[0]["exposure_source"] == "aws"


def test_rule_b_forms_one_cluster_per_distinct_exposed_resource():
    """A security group, an EC2 instance and an S3 bucket being independently
    exposed are three different attack paths, not variations on one - unlike
    the same-resource case above, distinct resource strings must each get
    their own cluster."""
    sg = _f(source="checkov", type="MISCONFIGURATION", internet_facing=True,
            risk_score=70, affected_resource="aws_security_group.web")
    ec2 = _f(source="checkov", type="MISCONFIGURATION", internet_facing=True,
             risk_score=60, affected_resource="aws_instance.app")
    s3 = _f(source="checkov", type="MISCONFIGURATION", internet_facing=True,
            risk_score=50, affected_resource="aws_s3_bucket.uploads")
    # More than 3x the per-cluster cap (8), so the strongest exposure claiming
    # its 8 first still leaves enough unclaimed for the other two to form
    # their own clusters rather than finding nothing left to attach to.
    severes = [_f(cve_id=f"CVE-{i}", severity="CRITICAL", risk_score=90 - i)
               for i in range(20)]

    clusters = correlator.correlate([sg, ec2, s3] + severes)

    rule_b = [c for c in clusters if c["rule"].startswith("B")]
    assert len(rule_b) == 3
    exposed_resources = {c["exposure_resource"] for c in rule_b}
    assert exposed_resources == {"aws_security_group.web", "aws_instance.app", "aws_s3_bucket.uploads"}
    # no severe vulnerability is claimed by more than one exposure cluster
    claimed = [fid for c in rule_b for fid in c["finding_ids"] if fid in {s.id for s in severes}]
    assert len(claimed) == len(set(claimed))


def test_rule_b_caps_named_members_at_eight_but_counts_all_severe():
    exposure = _f(source="aws", type="EXPOSURE", internet_facing=True)
    severes = [_f(cve_id=f"CVE-{i}", severity="CRITICAL", risk_score=100 - i)
               for i in range(12)]

    clusters = correlator.correlate([exposure] + severes)

    c = clusters[0]
    assert c["severe_count"] == 12              # all 12 counted
    assert len(c["finding_ids"]) == 1 + 8        # exposure + 8 named members


def test_rule_b_excludes_findings_already_claimed_by_rule_a():
    """A finding already placed in a Rule A cluster must not also be double
    counted as a fresh Rule B member - clusters should partition, not overlap
    on the same finding twice within the same run's output."""
    sonar = _f(source="sonarqube", reported_by=["sonarqube"], cve_id="CVE-SHARED",
               severity="CRITICAL", risk_score=90)
    trivy = _f(source="trivy", reported_by=["trivy"], cve_id="CVE-SHARED",
               severity="CRITICAL", risk_score=90)
    exposure = _f(source="aws", type="EXPOSURE", internet_facing=True)

    clusters = correlator.correlate([sonar, trivy, exposure])

    rule_a = next(c for c in clusters if c["rule"].startswith("A"))
    rule_b = [c for c in clusters if c["rule"].startswith("B")]
    # trivy already belongs to the Rule A cluster; Rule B must not reclaim it
    if rule_b:
        assert trivy.id not in rule_b[0]["finding_ids"]
    assert trivy.id in rule_a["finding_ids"]


def test_clusters_sort_by_risk_score_descending_then_title():
    exposure = _f(source="aws", type="EXPOSURE", internet_facing=True, risk_score=40)
    low_severe = _f(cve_id="CVE-LOW", severity="HIGH", risk_score=40)

    sonar = _f(source="sonarqube", reported_by=["sonarqube"], cve_id="CVE-HIGH", risk_score=99)
    trivy = _f(source="trivy", reported_by=["trivy"], cve_id="CVE-HIGH", risk_score=99)

    clusters = correlator.correlate([exposure, low_severe, sonar, trivy])

    scores = [c["risk_score"] for c in clusters]
    assert scores == sorted(scores, reverse=True)
