"""Unit tests for normaliser.py.

Each tool's native report shape is fixed to what the real scanners actually
produce (Trivy/SonarQube/GitLeaks/Checkov/AWS JSON), not an idealised shape,
so a schema drift in any tool's real output would be caught here.
"""
from __future__ import annotations

import normaliser


def test_from_trivy_maps_core_fields():
    report = {
        "Results": [{
            "Target": "juice-shop (debian 12.5)",
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2019-10744",
                "PkgName": "lodash",
                "InstalledVersion": "4.17.11",
                "Severity": "critical",
                "Title": "lodash: prototype pollution",
                "Description": "A prototype pollution vulnerability.",
                "CVSS": {"nvd": {"V3Score": 9.1}},
            }],
        }]
    }
    findings = normaliser.from_trivy(report)

    assert len(findings) == 1
    f = findings[0]
    assert f.source == "trivy"
    assert f.type == "VULNERABILITY"
    assert f.severity == "CRITICAL"          # uppercased
    assert f.cve_id == "CVE-2019-10744"
    assert f.cvss_score == 9.1
    assert "lodash-4.17.11" in f.affected_resource


def test_from_trivy_falls_back_to_generated_title_when_missing():
    report = {"Results": [{"Target": "t", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2021-1", "PkgName": "pkg", "InstalledVersion": "1.0",
        "Severity": "high",
    }]}]}
    f = normaliser.from_trivy(report)[0]
    assert f.title == "CVE-2021-1 in pkg"     # built from id + package, not left blank


def test_from_trivy_handles_missing_cvss():
    report = {"Results": [{"Target": "t", "Vulnerabilities": [{
        "VulnerabilityID": "CVE-2021-1", "PkgName": "pkg", "InstalledVersion": "1.0",
        "Severity": "low",
    }]}]}
    f = normaliser.from_trivy(report)[0]
    assert f.cvss_score is None               # not 0.0 - "unknown" and "zero" differ


def test_from_sonarqube_filters_to_vulnerability_type_only():
    report = {"issues": [
        {"type": "VULNERABILITY", "severity": "BLOCKER", "message": "SQL injection",
         "component": "src/api.ts", "line": 42, "rule": "typescript:S2077"},
        {"type": "CODE_SMELL", "severity": "MINOR", "message": "unused variable"},
    ]}
    findings = normaliser.from_sonarqube(report)

    assert len(findings) == 1                 # CODE_SMELL dropped
    f = findings[0]
    assert f.source == "sonarqube"
    assert f.severity == "CRITICAL"            # BLOCKER -> CRITICAL
    assert f.rule_id == "typescript:S2077"
    assert f.affected_resource == "src/api.ts:42"


def test_from_sonarqube_severity_mapping_is_complete():
    for sonar_sev, expected in [
        ("BLOCKER", "CRITICAL"), ("CRITICAL", "HIGH"),
        ("MAJOR", "MEDIUM"), ("MINOR", "LOW"), ("INFO", "INFO"),
    ]:
        report = {"issues": [{"type": "VULNERABILITY", "severity": sonar_sev, "message": "x"}]}
        assert normaliser.from_sonarqube(report)[0].severity == expected


def test_from_gitleaks_maps_secret_location():
    report = [{
        "Description": "AWS Access Key", "RuleID": "aws-access-token",
        "File": "src/config.ts", "StartLine": 12,
    }]
    f = normaliser.from_gitleaks(report)[0]
    assert f.source == "gitleaks"
    assert f.type == "SECRET"
    assert f.severity == "HIGH"
    assert f.rule_id == "aws-access-token"
    assert f.affected_resource == "src/config.ts:12"


def test_from_checkov_derives_severity_when_absent():
    """Open-source Checkov does not populate `severity` - it must be inferred
    from the check name, which is the actual behaviour being protected here."""
    report = {"results": {"failed_checks": [
        {"check_id": "CKV_AWS_23", "check_name": "Ensure Security Group allows 0.0.0.0/0",
         "resource": "aws_security_group.web", "file_path": "/main.tf",
         "file_line_range": [10, 20]},
        {"check_id": "CKV_AWS_41", "check_name": "Ensure no hardcoded KMS key",
         "resource": "aws_kms_key.x", "file_path": "/main.tf"},
        {"check_id": "CKV_AWS_1", "check_name": "Ensure versioning is enabled",
         "resource": "aws_s3_bucket.logs", "file_path": "/main.tf"},
    ]}}
    findings = normaliser.from_checkov(report)
    by_id = {f.rule_id: f for f in findings}

    assert by_id["CKV_AWS_23"].severity == "HIGH"      # "0.0.0.0/0" -> high
    assert by_id["CKV_AWS_23"].internet_facing is True
    assert by_id["CKV_AWS_41"].severity == "MEDIUM"    # "kms" -> medium
    assert by_id["CKV_AWS_1"].severity == "LOW"        # "versioning" -> low


def test_from_checkov_accepts_list_of_frameworks():
    """Checkov emits a list when several frameworks are scanned together
    (terraform + dockerfile), not always a single dict."""
    report = [
        {"results": {"failed_checks": [
            {"check_id": "CKV_TF_1", "check_name": "x", "resource": "r1", "file_path": "/main.tf"}
        ]}},
        {"results": {"failed_checks": [
            {"check_id": "CKV_DOCKER_1", "check_name": "y", "resource": "r2", "file_path": "/Dockerfile"}
        ]}},
    ]
    findings = normaliser.from_checkov(report)
    assert {f.rule_id for f in findings} == {"CKV_TF_1", "CKV_DOCKER_1"}


def test_from_aws_splits_iam_from_exposure_by_check_prefix():
    report = {"findings": [
        {"check": "iam_admin_access", "severity": "CRITICAL", "detail": "AdministratorAccess attached",
         "resource": "arn:aws:iam::123:user/cli", "internet_facing": False},
        {"check": "sg_open_ingress", "severity": "HIGH", "detail": "0.0.0.0/0 on port 22",
         "resource": "sg-abc123", "internet_facing": True},
    ]}
    findings = normaliser.from_aws(report)
    by_check = {f.rule_id: f for f in findings}

    assert by_check["iam_admin_access"].type == "IAM"
    assert by_check["sg_open_ingress"].type == "EXPOSURE"
    assert by_check["sg_open_ingress"].internet_facing is True
