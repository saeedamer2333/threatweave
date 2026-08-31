"""Deduplicator: reduce raw tool output to a list of distinct, actionable items.

Two passes, because there are two different kinds of duplication in real data:

  Pass 1 - the same issue reported by different tools.
           Keyed on CVE id, or type + affected resource when there is no CVE.
           Example: SonarQube and Trivy both report CVE-2021-44228.

  Pass 2 - many distinct CVEs that share a single remediation.
           A container image typically reports a dozen CVEs for one outdated
           package; the developer performs ONE upgrade to clear them all.
           Collapsing these to one actionable item is what makes the output
           triageable, and it mirrors how Snyk and Dependabot present results.
           The individual CVE ids are preserved in `related_cves`, so nothing
           is hidden - only regrouped.
"""
from __future__ import annotations

import re

from schema import Finding, SEVERITIES, finding_identity

# "image (debian 13.5) / tar-1.34+dfsg-1.2" -> "tar"
# "Node.js / lodash-4.17.15"                -> "lodash"
_PKG = re.compile(r"/\s*([A-Za-z0-9@._+-]+?)-\d[\w.+~-]*\s*$")

# finding_identity() lives in schema.py so finding_tracker.py can reuse the
# exact same "same underlying issue" definition for cross-run tracking -
# aliased here under the original name so the rest of this file (and its
# own comment about *why* rule_id has to be part of the key) reads
# unchanged.
_key = finding_identity


def _more_severe(a: str, b: str) -> str:
    return a if SEVERITIES.index(a) <= SEVERITIES.index(b) else b


def _package_of(f: Finding) -> str | None:
    """Package name for dependency findings, else None."""
    if f.type != "VULNERABILITY" or not f.cve_id:
        return None
    m = _PKG.search(f.affected_resource)
    return m.group(1).lower() if m else None


def _pass1_cross_tool(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for f in findings:
        k = _key(f)
        keep = merged.get(k)
        if keep is None:
            merged[k] = f
            continue
        keep.severity = _more_severe(keep.severity, f.severity)
        if f.cvss_score and (keep.cvss_score is None or f.cvss_score > keep.cvss_score):
            keep.cvss_score = f.cvss_score
        keep.internet_facing = keep.internet_facing or f.internet_facing
        for tool in f.reported_by:
            if tool not in keep.reported_by:
                keep.reported_by.append(tool)
    return list(merged.values())


def _pass2_same_remediation(findings: list[Finding]) -> list[Finding]:
    groups: dict[str, list[Finding]] = {}
    passthrough: list[Finding] = []
    for f in findings:
        pkg = _package_of(f)
        if pkg is None:
            passthrough.append(f)
        else:
            groups.setdefault(pkg, []).append(f)

    out = list(passthrough)
    for pkg, members in groups.items():
        if len(members) == 1:
            out.append(members[0])
            continue
        # representative = most severe, then highest CVSS
        members.sort(key=lambda x: (SEVERITIES.index(x.severity), -(x.cvss_score or 0)))
        rep = members[0]
        others = members[1:]

        rep.related_cves = [m.cve_id for m in members if m.cve_id]
        rep.merged_count = len(members)
        for m in others:
            rep.internet_facing = rep.internet_facing or m.internet_facing
            for tool in m.reported_by:
                if tool not in rep.reported_by:
                    rep.reported_by.append(tool)
        rep.title = (f"{len(members)} vulnerabilities in {pkg} "
                     f"(most severe: {rep.cve_id})")
        out.append(rep)
    return out


def deduplicate(findings: list[Finding]) -> list[Finding]:
    stage1 = _pass1_cross_tool(findings)
    stage2 = _pass2_same_remediation(stage1)
    print(f"      cross-tool merge: {len(findings)} -> {len(stage1)}")
    print(f"      same-remediation grouping: {len(stage1)} -> {len(stage2)}")
    return stage2
