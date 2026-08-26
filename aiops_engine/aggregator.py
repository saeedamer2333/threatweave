"""Aggregator: read every tool report from a directory and normalise them
into one combined list of Finding objects.
"""
from __future__ import annotations

import json
from pathlib import Path

import normaliser
from schema import Finding


# Which file maps to which normaliser function.
_SOURCES = {
    "trivy-report.json": normaliser.from_trivy,
    "sonarqube-report.json": normaliser.from_sonarqube,
    "gitleaks-report.json": normaliser.from_gitleaks,
    "checkov-report.json": normaliser.from_checkov,
    "aws-findings.json": normaliser.from_aws,
}


def load_all(input_dir: str | Path) -> list[Finding]:
    input_dir = Path(input_dir)
    findings: list[Finding] = []
    for filename, normalise in _SOURCES.items():
        path = input_dir / filename
        if not path.exists():
            print(f"  [skip] {filename} not found")
            continue
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        new = normalise(data)
        findings.extend(new)
        print(f"  [ok]   {filename}: {len(new)} findings")
    return findings
