"""Unit tests for aggregator.py - reads every tool report present in a
directory and dispatches each to its matching normaliser function.
"""
from __future__ import annotations

import json

import aggregator


def _write(tmp_path, filename, data):
    (tmp_path / filename).write_text(json.dumps(data), encoding="utf-8")


def test_load_all_reads_every_present_report(tmp_path):
    _write(tmp_path, "trivy-report.json", {"Results": [{"Target": "t", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1.0", "Severity": "high"}
    ]}]})
    _write(tmp_path, "gitleaks-report.json", [
        {"Description": "key", "RuleID": "r1", "File": "a.ts", "StartLine": 1}
    ])

    findings, sources = aggregator.load_all(tmp_path)

    result_sources = {f.source for f in findings}
    assert result_sources == {"trivy", "gitleaks"}
    assert len(findings) == 2


def test_load_all_skips_missing_reports_without_error(tmp_path):
    # No report files written at all.
    findings, sources = aggregator.load_all(tmp_path)
    assert findings == []


def test_load_all_dispatches_each_source_to_its_own_normaliser(tmp_path):
    _write(tmp_path, "sonarqube-report.json", {"issues": [
        {"type": "VULNERABILITY", "severity": "BLOCKER", "message": "x"}
    ]})
    _write(tmp_path, "checkov-report.json", {"results": {"failed_checks": [
        {"check_id": "CKV_1", "check_name": "x", "resource": "r", "file_path": "/main.tf"}
    ]}})
    _write(tmp_path, "aws-findings.json", {"findings": [
        {"check": "sg_open", "severity": "HIGH", "detail": "d", "resource": "sg-1"}
    ]})

    findings, sources = aggregator.load_all(tmp_path)

    assert {f.source for f in findings} == {"sonarqube", "checkov", "aws"}


def test_load_all_accepts_a_string_path_as_well_as_a_path_object(tmp_path):
    _write(tmp_path, "gitleaks-report.json", [
        {"Description": "key", "RuleID": "r1", "File": "a.ts", "StartLine": 1}
    ])
    findings, sources = aggregator.load_all(str(tmp_path))
    assert len(findings) == 1


# ---- source status: what actually reaches the dashboard about each source ---

def test_source_status_reports_ok_with_a_finding_count(tmp_path):
    _write(tmp_path, "trivy-report.json", {"Results": [{"Target": "t", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1.0", "Severity": "high"},
        {"VulnerabilityID": "CVE-2", "PkgName": "p", "InstalledVersion": "1.0", "Severity": "high"},
    ]}]})

    _, sources = aggregator.load_all(tmp_path)

    trivy = next(s for s in sources if s["source"] == "trivy")
    assert trivy == {"source": "trivy", "file": "trivy-report.json", "status": "ok", "findings": 2}


def test_source_status_reports_missing_for_a_report_that_was_never_produced(tmp_path):
    # Nothing written - simulates SonarQube not configured, or a scanner
    # stage that failed before it could write its report.
    _, sources = aggregator.load_all(tmp_path)

    assert len(sources) == 5  # all five known sources are always reported on
    assert all(s["status"] == "missing" and s["findings"] == 0 for s in sources)


def test_source_status_reports_error_for_a_malformed_report_without_crashing_the_run(tmp_path):
    (tmp_path / "checkov-report.json").write_text("{not valid json", encoding="utf-8")

    findings, sources = aggregator.load_all(tmp_path)

    checkov = next(s for s in sources if s["source"] == "checkov")
    assert checkov["status"] == "error"
    assert "detail" in checkov
    # The corrupt source contributes nothing, but does not raise and does
    # not prevent other sources' findings from coming through.
    assert findings == []


def test_source_status_error_on_one_report_does_not_affect_other_sources(tmp_path):
    (tmp_path / "checkov-report.json").write_text("{not valid json", encoding="utf-8")
    _write(tmp_path, "trivy-report.json", {"Results": [{"Target": "t", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1.0", "Severity": "high"}
    ]}]})

    findings, sources = aggregator.load_all(tmp_path)

    assert len(findings) == 1
    by_source = {s["source"]: s["status"] for s in sources}
    assert by_source["checkov"] == "error"
    assert by_source["trivy"] == "ok"


# ---- scan-status.json: why a source is missing, failed or carried over ----

def test_stage_status_marks_a_skipped_scanner_as_not_configured(tmp_path):
    _write(tmp_path, "scan-status.json", {"Container - Trivy": "skipped"})

    _, sources = aggregator.load_all(tmp_path)

    trivy = next(s for s in sources if s["source"] == "trivy")
    assert trivy["status"] == "skipped"
    assert trivy["detail"] == "not configured"


def test_stage_status_keeps_a_skip_reason_that_settings_cannot_fix(tmp_path):
    _write(tmp_path, "scan-status.json", {"SAST - SonarQube": "skipped: SonarQube is turned off"})

    _, sources = aggregator.load_all(tmp_path)

    sonar = next(s for s in sources if s["source"] == "sonarqube")
    assert sonar["status"] == "skipped"
    assert sonar["detail"] == "SonarQube is turned off"


def test_stage_status_carries_the_failure_reason_to_the_dashboard(tmp_path):
    _write(tmp_path, "scan-status.json",
           {"Container - Trivy": "failed: image myapp:latest not found locally or in a registry"})

    _, sources = aggregator.load_all(tmp_path)

    trivy = next(s for s in sources if s["source"] == "trivy")
    assert trivy["status"] == "failed"
    assert "myapp:latest not found" in trivy["detail"]


def test_stage_status_marks_a_carried_over_report_as_stale_but_keeps_its_findings(tmp_path):
    _write(tmp_path, "sonarqube-report.json", {"issues": []})
    _write(tmp_path, "scan-status.json",
           {"SAST - SonarQube": "ok (carried over from an earlier scan)"})

    _, sources = aggregator.load_all(tmp_path)

    sonar = next(s for s in sources if s["source"] == "sonarqube")
    assert sonar["status"] == "stale"
    assert "carried over" in sonar["detail"]


def test_stage_status_file_that_is_unreadable_falls_back_to_report_presence(tmp_path):
    (tmp_path / "scan-status.json").write_text("{broken", encoding="utf-8")

    _, sources = aggregator.load_all(tmp_path)

    assert all(s["status"] == "missing" for s in sources)
