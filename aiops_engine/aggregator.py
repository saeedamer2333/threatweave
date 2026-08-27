"""Aggregator: read every tool report from a directory and normalise them
into one combined list of Finding objects.
"""
from __future__ import annotations

import json
from pathlib import Path

import normaliser
from schema import Finding


# Which file maps to which normaliser function, and the short name reported
# back to the dashboard (also what the correlator/scorer already call these
# sources, so the two stay consistent).
_SOURCES = {
    "trivy-report.json": ("trivy", normaliser.from_trivy),
    "sonarqube-report.json": ("sonarqube", normaliser.from_sonarqube),
    "gitleaks-report.json": ("gitleaks", normaliser.from_gitleaks),
    "checkov-report.json": ("checkov", normaliser.from_checkov),
    "aws-findings.json": ("aws", normaliser.from_aws),
}


def load_all(input_dir: str | Path) -> tuple[list[Finding], list[dict]]:
    """Returns (findings, source_status).

    source_status records what actually happened with each of the five
    expected reports - not just how many findings came out, but whether the
    report was there at all, and why not when it wasn't. Printing this to
    stdout (as this used to do exclusively) means it only ever reached
    whoever was watching the Jenkins console live; a scanner silently
    missing from a run should be visible on the dashboard itself, since that
    is where anyone actually reads results after the fact.

    A malformed report is recorded as an error for that one source rather
    than raising - one corrupt file should not take down a run that four
    other sources contributed real data to, the same "partial evidence beats
    no evidence" principle the Jenkinsfile already applies to a failed
    scanner stage.
    """
    input_dir = Path(input_dir)
    findings: list[Finding] = []
    status: list[dict] = []

    for filename, (source, normalise) in _SOURCES.items():
        path = input_dir / filename
        if not path.exists():
            print(f"  [skip] {filename} not found")
            status.append({
                "source": source, "file": filename,
                "status": "missing", "findings": 0,
            })
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            new = normalise(data)
        except Exception as e:
            print(f"  [error] {filename}: {e}")
            status.append({
                "source": source, "file": filename,
                "status": "error", "findings": 0, "detail": str(e)[:200],
            })
            continue
        findings.extend(new)
        print(f"  [ok]   {filename}: {len(new)} findings")
        status.append({
            "source": source, "file": filename,
            "status": "ok", "findings": len(new),
        })

    return findings, status
