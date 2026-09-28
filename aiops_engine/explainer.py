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
# Each entry: (keywords, kind, why, action). `kind` is a short, human label
# for the dashboard's summary cards (e.g. "SQL Injection") - distinct from
# `why`, the fuller sentence explaining the mechanism.
# ---------------------------------------------------------------------------
_CODE_PATTERNS: list[tuple[tuple[str, ...], str, str, str]] = [
    # "sql" is required: the word "injection" alone also covers code, command
    # and template injection, which need a different explanation and fix.
    (("sql",), "SQL Injection",
     "user input reaches a database query without sanitisation, allowing SQL injection",
     "Use parameterised queries or an ORM so input can never alter query structure."),
    (("code injection", "execution of code", "dynamic injection", "dynamically executed", "eval("),
     "Code Injection",
     "code is built or executed dynamically, so input that reaches it could run as code",
     "Avoid eval and dynamic code execution; pass input as data and validate it against an allow-list."),
    (("xss", "cross-site", "cross site"), "Cross-Site Scripting (XSS)",
     "unescaped user input is rendered in the page, allowing cross-site scripting (XSS)",
     "Escape or encode all user-controlled output and apply a Content-Security-Policy."),
    (("cors", "access-control-allow-origin", "any origin"), "Permissive CORS Policy",
     "the CORS policy trusts any origin, letting untrusted sites call the API with credentials",
     "Restrict Access-Control-Allow-Origin to an explicit allow-list of trusted domains."),
    (("path traversal", "directory traversal", "../"), "Path Traversal",
     "user input is used in a file path, allowing directory traversal",
     "Canonicalise and validate paths against an allowed base directory."),
    (("command", "os command", "rce", "remote code execution"), "Command Injection",
     "user input reaches a system command, allowing command injection",
     "Avoid shelling out; if unavoidable, use argument arrays and strict allow-lists."),
    (("deserial", "insecure deserialization"), "Insecure Deserialization",
     "untrusted data is deserialised, which can lead to remote code execution",
     "Avoid native deserialisation of untrusted input; use a safe data format such as JSON with a schema."),
    (("hardcoded", "hard-coded"), "Hardcoded Credential",
     "a credential is embedded directly in source code",
     "Move the value to a secret manager and rotate the exposed credential."),
    # Last, so any more specific injection template above wins.
    (("injection",), "Injection",
     "input reaches an interpreter without sanitisation, allowing injection",
     "Validate input and use APIs that keep data separate from code or queries."),
]

# Secret rule id / description -> (kind, what the secret unlocks)
_SECRET_HINTS: list[tuple[tuple[str, ...], str, str]] = [
    (("aws", "akia"), "AWS Credential", "grant direct access to the AWS account"),
    (("stripe", "sk_live", "payment"), "Payment API Key", "allow fraudulent charges through the payment provider"),
    (("github", "ghp_", "gitlab"), "Source Control Token", "grant write access to source repositories"),
    (("private key", "-----begin"), "Private Key", "allow an attacker to impersonate the service"),
]

_SECRET_FIX = "Rotate the credential immediately and remove it from git history."


def _match(text: str, keywords: tuple[str, ...]) -> bool:
    t = text.lower()
    return any(k in t for k in keywords)


def _explain_code_vuln(f: Finding) -> tuple[str, str, str]:
    """Returns (kind, narrative, fix)."""
    text = f"{f.title} {f.description}"
    for keywords, kind, why, action in _CODE_PATTERNS:
        if _match(text, keywords):
            return kind, f"At {f.affected_resource}, {why}. {action}", action
    fix = "Review and remediate before release."
    return "Code Vulnerability", f"{f.title} at {f.affected_resource}. {fix}", fix


def _explain_cve(f: Finding) -> tuple[str, str, str]:
    exploited = f.scores.get("S_EPSS", 0) >= 0.9
    tail = " and is on public exploitation feeds, so treat it as urgent" if exploited else ""
    sev = f.severity.title()
    cvss = f" (CVSS {f.cvss_score})" if f.cvss_score is not None else ""
    kind = "Known Vulnerability (CVE)"

    if f.merged_count > 1:
        fix = f"Upgrade this package - clears all {f.merged_count} CVEs at once."
        narrative = (f"{f.merged_count} vulnerabilities affect {f.affected_resource}; the most "
                     f"severe is {f.cve_id}{cvss}, a {sev.lower()} issue{tail}. A single upgrade of "
                     f"this package clears all {f.merged_count}, so treat it as one action rather "
                     f"than {f.merged_count} separate tickets.")
        return kind, narrative, fix

    fix = "Upgrade the package to a fixed version and redeploy."
    narrative = (f"{f.cve_id}{cvss} is a {sev.lower()} vulnerability affecting "
                 f"{f.affected_resource}{tail}. {fix}")
    return kind, narrative, fix


def _explain_secret(f: Finding) -> tuple[str, str, str]:
    text = f"{f.title} {f.description}"
    kind, impact = "Exposed Secret", "be reused by anyone with repository access"
    for keywords, hint_kind, effect in _SECRET_HINTS:
        if _match(text, keywords):
            kind, impact = hint_kind, effect
            break
    narrative = (f"A secret was committed at {f.affected_resource}; it could {impact}. {_SECRET_FIX}")
    return kind, narrative, _SECRET_FIX


def _explain_misconfig(f: Finding) -> tuple[str, str, str]:
    if f.internet_facing or "0.0.0.0/0" in f.title:
        fix = "Restrict ingress to known CIDR ranges."
        narrative = (f"{f.title} ({f.affected_resource}) leaves the resource open to the whole "
                     f"internet. {fix}")
        return "Public Network Exposure", narrative, fix
    fix = "Apply the recommended secure configuration in the infrastructure code."
    narrative = f"{f.title} at {f.affected_resource}. {fix}"
    return "Misconfiguration", narrative, fix


def _explain_exposure(f: Finding) -> tuple[str, str, str]:
    fix = "Limit access to trusted networks."
    narrative = (f"{f.title} The resource {f.affected_resource} is reachable from the public "
                 f"internet, widening the attack surface. {fix}")
    return "Internet Exposure", narrative, fix


def _explain_iam(f: Finding) -> tuple[str, str, str]:
    fix = "Apply least-privilege and remove wildcard/admin grants."
    narrative = (f"{f.title} on {f.affected_resource}. Over-broad permissions let a compromised "
                 f"identity do far more damage. {fix}")
    return "Excess IAM Permissions", narrative, fix


def explain_finding_structured(f: Finding) -> dict:
    """The full picture behind a finding's explanation: a short `kind` label
    for a quick-scan summary card, the full `narrative` sentence (what
    explain_finding() has always returned), and `fix` - the actionable
    clause on its own, not buried at the end of a paragraph."""
    if f.type == "SECRET":
        kind, narrative, fix = _explain_secret(f)
    elif f.type == "VULNERABILITY":
        kind, narrative, fix = _explain_cve(f) if f.cve_id else _explain_code_vuln(f)
    elif f.type == "MISCONFIGURATION":
        kind, narrative, fix = _explain_misconfig(f)
    elif f.type == "IAM":
        kind, narrative, fix = _explain_iam(f)
    elif f.type == "EXPOSURE":
        kind, narrative, fix = _explain_exposure(f)
    else:
        kind, narrative, fix = f.type.replace("_", " ").title(), f.title, ""
    return {"kind": kind, "narrative": narrative, "fix": fix}


def explain_finding(f: Finding) -> str:
    return explain_finding_structured(f)["narrative"]


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
        struct = explain_finding_structured(f)
        f.explanation = struct["narrative"]
        f.explanation_kind = struct["kind"]
        f.explanation_fix = struct["fix"]
    by_id = {f.id: f for f in findings}
    for c in clusters:
        members = [by_id[i] for i in c["finding_ids"] if i in by_id]
        c["explanation"] = explain_cluster(c, members)
