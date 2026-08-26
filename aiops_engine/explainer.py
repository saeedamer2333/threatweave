"""Explainer - deterministic template engine (no LLM).

Selects a template based on the finding's type and keyword signals, then fills
it with the real values from the finding. Because templates are fixed, output
is reproducible and can never hallucinate. Adding a new template widens
coverage without introducing any non-determinism.
"""
from __future__ import annotations

from schema import Finding


# ---------------------------------------------------------------------------
# Keyword-based sub-type detection for code vulnerabilities (no CVE).
# Each entry: (keywords, why, action)
# ---------------------------------------------------------------------------
_CODE_PATTERNS: list[tuple[tuple[str, ...], str, str]] = [
    (("sql", "injection"),
     "user input reaches a database query without sanitisation, allowing SQL injection",
     "Use parameterised queries or an ORM so input can never alter query structure."),
    (("xss", "cross-site", "cross site"),
     "unescaped user input is rendered in the page, allowing cross-site scripting (XSS)",
     "Escape or encode all user-controlled output and apply a Content-Security-Policy."),
    (("cors", "access-control-allow-origin", "any origin"),
     "the CORS policy trusts any origin, letting untrusted sites call the API with credentials",
     "Restrict Access-Control-Allow-Origin to an explicit allow-list of trusted domains."),
    (("path traversal", "directory traversal", "../"),
     "user input is used in a file path, allowing directory traversal",
     "Canonicalise and validate paths against an allowed base directory."),
    (("command", "os command", "rce", "remote code execution"),
     "user input reaches a system command, allowing command injection",
     "Avoid shelling out; if unavoidable, use argument arrays and strict allow-lists."),
    (("deserial", "insecure deserialization"),
     "untrusted data is deserialised, which can lead to remote code execution",
     "Avoid native deserialisation of untrusted input; use a safe data format such as JSON with a schema."),
    (("hardcoded", "hard-coded"),
     "a credential is embedded directly in source code",
     "Move the value to a secret manager and rotate the exposed credential."),
]

# Secret rule id / description -> what the secret unlocks
_SECRET_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("aws", "akia"), "grant direct access to the AWS account"),
    (("stripe", "sk_live", "payment"), "allow fraudulent charges through the payment provider"),
    (("github", "ghp_", "gitlab"), "grant write access to source repositories"),
    (("private key", "-----begin"), "allow an attacker to impersonate the service"),
]


def _match(text: str, keywords: tuple[str, ...]) -> bool:
    t = text.lower()
    return any(k in t for k in keywords)


def _explain_code_vuln(f: Finding) -> str:
    text = f"{f.title} {f.description}"
    for keywords, why, action in _CODE_PATTERNS:
        if _match(text, keywords):
            return f"At {f.affected_resource}, {why}. {action}"
    return f"{f.title} at {f.affected_resource}. Review and remediate before release."


def _explain_cve(f: Finding) -> str:
    exploited = f.scores.get("S_EPSS", 0) >= 0.9
    tail = " and is on public exploitation feeds, so treat it as urgent" if exploited else ""
    sev = f.severity.title()
    cvss = f" (CVSS {f.cvss_score})" if f.cvss_score is not None else ""

    if f.merged_count > 1:
        return (f"{f.merged_count} vulnerabilities affect {f.affected_resource}; the most "
                f"severe is {f.cve_id}{cvss}, a {sev.lower()} issue{tail}. A single upgrade of "
                f"this package clears all {f.merged_count}, so treat it as one action rather "
                f"than {f.merged_count} separate tickets.")

    return (f"{f.cve_id}{cvss} is a {sev.lower()} vulnerability affecting "
            f"{f.affected_resource}{tail}. Upgrade the package to a fixed version and redeploy.")


def _explain_secret(f: Finding) -> str:
    text = f"{f.title} {f.description}"
    impact = "be reused by anyone with repository access"
    for keywords, effect in _SECRET_HINTS:
        if _match(text, keywords):
            impact = effect
            break
    return (f"A secret was committed at {f.affected_resource}; it could {impact}. "
            f"Rotate the credential immediately and remove it from git history.")


def _explain_misconfig(f: Finding) -> str:
    if f.internet_facing or "0.0.0.0/0" in f.title:
        return (f"{f.title} ({f.affected_resource}) leaves the resource open to the whole "
                f"internet. Restrict ingress to known CIDR ranges.")
    return (f"{f.title} at {f.affected_resource}. Apply the recommended secure configuration "
            f"in the infrastructure code.")


def _explain_exposure(f: Finding) -> str:
    return (f"{f.title} The resource {f.affected_resource} is reachable from the public "
            f"internet, widening the attack surface. Limit access to trusted networks.")


def _explain_iam(f: Finding) -> str:
    return (f"{f.title} on {f.affected_resource}. Over-broad permissions let a compromised "
            f"identity do far more damage. Apply least-privilege and remove wildcard/admin grants.")


def explain_finding(f: Finding) -> str:
    if f.type == "SECRET":
        return _explain_secret(f)
    if f.type == "VULNERABILITY":
        return _explain_cve(f) if f.cve_id else _explain_code_vuln(f)
    if f.type == "MISCONFIGURATION":
        return _explain_misconfig(f)
    if f.type == "IAM":
        return _explain_iam(f)
    if f.type == "EXPOSURE":
        return _explain_exposure(f)
    return f.title


# ---------------------------------------------------------------------------
# Cluster (attack-path) explanations
# ---------------------------------------------------------------------------
def explain_cluster(cluster: dict, members: list[Finding]) -> dict:
    # `.get(..., default)` only falls back when the key is absent, but Rule B
    # always sets "cve_id" - to members[0].cve_id, which is None whenever the
    # top-risk member is a CVE-less finding (SonarQube, GitLeaks, Checkov).
    # That produced literal "starting with None" in the recommended action.
    cve = cluster.get("cve_id") or "the highest-risk one"

    # Rule B - an internet-exposed asset with severe vulnerabilities behind it
    if cluster.get("internet_exposed"):
        n = cluster.get("severe_count", len(members))
        total = cluster.get("total_cves", n)
        resource = cluster.get("exposure_resource", "the affected asset")
        runtime = cluster.get("exposure_source") == "aws"
        evidence = ("The AWS monitor observed this exposure on the live account"
                    if runtime else
                    "The exposure is declared in the infrastructure code, so it will exist "
                    "once this configuration is applied")
        extra = f" covering {total} CVEs in total" if total > n else ""
        return {
            "why_it_matters": (
                f"{resource} is reachable from the public internet and the software behind it "
                f"carries {n} severe vulnerabilities{extra}. {evidence}. Individually these are "
                f"routine tickets in separate tools; together they form a single reachable "
                f"attack surface, which is why this is ranked above any of its parts."
            ),
            "what_is_at_risk": (
                "An attacker needs no foothold to begin - the vulnerable service is directly "
                "reachable. Successful exploitation could mean remote code execution on a "
                "production-facing host, and from there access to data and credentials."
            ),
            "recommended_action": (
                f"Close the exposure first: restrict ingress on {resource} to trusted CIDR "
                f"ranges. That single change removes the reachability for all {n} findings at "
                f"once. Then upgrade the affected packages, starting with {cve}."
            ),
        }

    # Rule A - the same CVE in both code and container
    pkg = next((m.affected_resource for m in members if m.source == "trivy"),
               "the affected component")
    return {
        "why_it_matters": (
            f"{cve} was found by the code scanner and again by the container scanner. That "
            f"agreement confirms the vulnerability survived the build into the deployed "
            f"artifact rather than being a false positive in source analysis."
        ),
        "what_is_at_risk": (
            "The vulnerable code is running, not merely committed, so any exploit for this "
            "CVE applies to the live service."
        ),
        "recommended_action": (
            f"Upgrade {pkg} to a fixed version, rebuild the image and redeploy. Verify the "
            f"next scan reports the CVE cleared in both tools."
        ),
    }


def explain_all(findings: list[Finding], clusters: list[dict]) -> None:
    for f in findings:
        f.explanation = explain_finding(f)
    by_id = {f.id: f for f in findings}
    for c in clusters:
        members = [by_id[i] for i in c["finding_ids"] if i in by_id]
        c["explanation"] = explain_cluster(c, members)
