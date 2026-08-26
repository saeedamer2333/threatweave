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

    findings = aggregator.load_all(tmp_path)

    sources = {f.source for f in findings}
    assert sources == {"trivy", "gitleaks"}
    assert len(findings) == 2


def test_load_all_skips_missing_reports_without_error(tmp_path):
    # No report files written at all.
    findings = aggregator.load_all(tmp_path)
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

    findings = aggregator.load_all(tmp_path)

    assert {f.source for f in findings} == {"sonarqube", "checkov", "aws"}


def test_load_all_accepts_a_string_path_as_well_as_a_path_object(tmp_path):
    _write(tmp_path, "gitleaks-report.json", [
        {"Description": "key", "RuleID": "r1", "File": "a.ts", "StartLine": 1}
    ])
    findings = aggregator.load_all(str(tmp_path))
    assert len(findings) == 1
