"""Normaliser: convert each tool's native report into unified Finding objects.

One function per tool. Each knows that tool's JSON shape and maps it onto the
common Finding schema defined in schema.py.
"""
from __future__ import annotations

from schema import Finding


# SonarQube uses its own severity words; map them to our scale.
_SONAR_SEV = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "HIGH",
    "MAJOR": "MEDIUM",
    "MINOR": "LOW",
    "INFO": "INFO", 
}


def from_trivy(report: dict) -> list[Finding]:
    findings: list[Finding] = []
    for result in report.get("Results", []):
        target = result.get("Target", "")
        for v in result.get("Vulnerabilities", []) or []:
            cvss = (v.get("CVSS", {}).get("nvd", {}) or {}).get("V3Score")
            findings.append(Finding(
                source="trivy",
                type="VULNERABILITY",
                severity=v.get("Severity", "MEDIUM").upper(),
                title=v.get("Title") or f'{v.get("VulnerabilityID")} in {v.get("PkgName")}',
                description=v.get("Description", ""),
                affected_resource=f'{target} / {v.get("PkgName")}-{v.get("InstalledVersion")}',
                cve_id=v.get("VulnerabilityID"),
                cvss_score=float(cvss) if cvss is not None else None,
            ))
    return findings


def from_sonarqube(report: dict) -> list[Finding]:
    findings: list[Finding] = []
    for issue in report.get("issues", []):
        if issue.get("type") != "VULNERABILITY":
            continue
        findings.append(Finding(
            source="sonarqube",
            type="VULNERABILITY",
            severity=_SONAR_SEV.get(issue.get("severity", ""), "MEDIUM"),
            title=issue.get("message", "Code vulnerability"),
            affected_resource=f'{issue.get("component", "")}:{issue.get("line", "")}',
            cve_id=issue.get("cve"),
            internet_facing=False,
            rule_id=issue.get("rule"),
        ))
    return findings


def from_gitleaks(report: list) -> list[Finding]:
    findings: list[Finding] = []
    for leak in report:
        findings.append(Finding(
            source="gitleaks",
            type="SECRET",
            severity="HIGH",
            title=f'{leak.get("Description", "Secret")} committed to source',
            description=f'Rule {leak.get("RuleID")} matched.',
            affected_resource=f'{leak.get("File")}:{leak.get("StartLine")}',
            rule_id=leak.get("RuleID"),
        ))
    return findings


# Open-source Checkov does not populate `severity` (it is a Prisma Cloud
# feature), so it is derived from what the check is actually about.
_CHECKOV_HIGH = (
    "0.0.0.0", "public ip", "public access", "publicly", "privilege escalation",
    "credentials exposure", "admin", "wildcard", "unrestricted", "world",
)
_CHECKOV_MEDIUM = ("encrypt", "kms", "tls", "ssl", "imds", "metadata service", "mfa")
_CHECKOV_LOW = ("description", "logging", "log", "monitoring", "versioning", "tag", "backup")


def _checkov_severity(check_name: str, check_id: str) -> str:
    name = check_name.lower()
    if any(k in name for k in _CHECKOV_HIGH):
        return "HIGH"
    if any(k in name for k in _CHECKOV_MEDIUM):
        return "MEDIUM"
    if any(k in name for k in _CHECKOV_LOW):
        return "LOW"
    return "MEDIUM"


def from_checkov(report) -> list[Finding]:
    # Checkov emits a dict for a single framework, or a list when several
    # frameworks (terraform, dockerfile, ...) are scanned together.
    blocks = report if isinstance(report, list) else [report]
    findings: list[Finding] = []
    for block in blocks:
        for c in block.get("results", {}).get("failed_checks", []) or []:
            name = c.get("check_name", "IaC misconfiguration")
            cid = c.get("check_id", "")
            sev = c.get("severity") or _checkov_severity(name, cid)
            lines = c.get("file_line_range") or []
            loc = f'{c.get("file_path", "")}'
            if lines:
                loc += f":{lines[0]}"
            findings.append(Finding(
                source="checkov",
                type="MISCONFIGURATION",
                severity=str(sev).upper(),
                title=f"{cid}: {name}" if cid else name,
                description=c.get("guideline") or c.get("description") or "",
                affected_resource=f'{c.get("resource")} ({loc})',
                internet_facing=any(k in name.lower() for k in ("0.0.0.0", "public", "world")),
                rule_id=cid,
            ))
    return findings


def from_aws(report: dict) -> list[Finding]:
    findings: list[Finding] = []
    for a in report.get("findings", []):
        ftype = "IAM" if a.get("check", "").startswith("iam") else "EXPOSURE"
        findings.append(Finding(
            source="aws",
            type=ftype,
            severity=a.get("severity", "MEDIUM").upper(),
            title=a.get("detail", "Cloud misconfiguration"),
            affected_resource=f'{a.get("resource")}'
                              + (f' / {a.get("attached_to")}' if a.get("attached_to") else ""),
            internet_facing=bool(a.get("internet_facing", False)),
            rule_id=a.get("check"),
        ))
    return findings
