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

# Stage names the Jenkinsfile writes into scan-status.json, per source.
_STAGE_NAMES = {
    "trivy": "Container - Trivy",
    "sonarqube": "SAST - SonarQube",
    "gitleaks": "Secrets - GitLeaks",
    "checkov": "IaC - Checkov",
    "aws": "Cloud - AWS monitor",
}


def _load_stage_status(input_dir: Path) -> dict:
    """What the pipeline itself recorded for each scanner, if it wrote it.

    Older runs, and the API's on-demand re-scoring of old inputs, have no
    such file - every source then falls back to what the reports alone show.
    """
    try:
        with open(input_dir / "scan-status.json", "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _without_report(stage: str | None) -> tuple[str, str | None]:
    """Status and reason for a source that has no report this run."""
    if not stage:
        return "missing", None
    if stage == "skipped":
        return "skipped", "not configured"
    if stage.startswith("skipped:"):
        return "skipped", stage[len("skipped:"):].strip()[:200]
    if stage.startswith("failed:"):
        return "failed", stage[len("failed:"):].strip()[:200]
    if stage == "no report produced":
        return "failed", "the scanner ran but wrote no report"
    return "missing", None


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
    stages = _load_stage_status(input_dir)

    for filename, (source, normalise) in _SOURCES.items():
        path = input_dir / filename
        stage = stages.get(_STAGE_NAMES[source])
        if not path.exists():
            print(f"  [skip] {filename} not found")
            state, reason = _without_report(stage)
            entry = {
                "source": source, "file": filename,
                "status": state, "findings": 0,
            }
            if reason:
                entry["detail"] = reason
            status.append(entry)
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
        if stage and "carried over" in stage:
            # Reused from an earlier scan of the same project - real
            # findings, but not from this run's code.
            status.append({
                "source": source, "file": filename,
                "status": "stale", "findings": len(new),
                "detail": "carried over from an earlier scan",
            })
            continue
        status.append({
            "source": source, "file": filename,
            "status": "ok", "findings": len(new),
        })

    return findings, status
