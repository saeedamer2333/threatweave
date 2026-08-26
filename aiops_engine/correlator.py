"""Correlator - the novel contribution.

Individually, a vulnerable dependency and an open security group are two
medium-priority tickets in two different tools. Together, on the same asset,
they are one exploitable route. This module finds those routes.

Two rules, deliberately kept few so that a cluster always means something:

  Rule A - Cross-source CVE.
           The same CVE is reported in the source code (SonarQube) and in the
           built container (Trivy). This proves the vulnerability survived
           into the deployed artifact rather than staying theoretical.

  Rule B - Exposed vulnerable asset.
           Something reachable from the internet (an AWS security group open
           to 0.0.0.0/0, or that exposure declared in infrastructure code)
           combined with the severe vulnerabilities present on that asset.

Rule B produces one cluster per distinct exposed resource, each holding the
severe vulnerabilities not already claimed by a stronger exposure - not one
cluster per CVE (pairing every CVE with the same open port would produce
dozens of near-identical "paths" and destroy the signal the analyst is meant
to act on), and not a single cluster for the whole run either (a security
group open to the world, an EC2 instance with a public IP, and an exposed S3
bucket are three different attack paths, not variations on one).
"""
from __future__ import annotations

from schema import Finding

# Exposure can be evidenced two ways, and both are valid links in an attack
# path: the AWS monitor observing a live open security group, or Checkov
# finding 0.0.0.0/0 declared in the infrastructure code that will create one.
_EXPOSURE_SOURCES = ("aws", "checkov")

# How many contributing vulnerabilities to name inside an exposure cluster.
_MAX_MEMBERS = 8


def _exposure_points(findings: list[Finding]) -> list[Finding]:
    """One evidence finding per distinct exposed resource, strongest first.

    AWS and Checkov use unrelated identifier schemes (a live security group
    ID versus a Terraform resource address), so there is no reliable way to
    tell whether two exposure findings describe the same real asset. Where
    they happen to share an affected_resource string, they are treated as
    the same exposure point and runtime evidence (AWS) wins over declared
    evidence (Checkov) as the stronger claim; distinct resource strings are
    always distinct exposure points, even across sources.
    """
    by_resource: dict[str, list[Finding]] = {}
    for f in findings:
        if f.source in _EXPOSURE_SOURCES and f.internet_facing:
            by_resource.setdefault(f.affected_resource, []).append(f)

    points: list[Finding] = []
    for candidates in by_resource.values():
        for source in _EXPOSURE_SOURCES:          # aws before checkov -> runtime wins
            same_source = [c for c in candidates if c.source == source]
            if same_source:
                points.append(max(same_source, key=lambda x: x.risk_score))
                break
    points.sort(key=lambda x: -x.risk_score)       # strongest exposure claims first
    return points


def _rule_a_cross_source(findings: list[Finding], start_n: int) -> tuple[list[dict], set[str]]:
    """Same CVE seen by both a code scanner and a container scanner."""
    clusters: list[dict] = []
    used: set[str] = set()
    by_cve: dict[str, list[Finding]] = {}
    for f in findings:
        if f.cve_id:
            by_cve.setdefault(f.cve_id.upper(), []).append(f)

    n = start_n
    for cve, members in by_cve.items():
        tools = {t for m in members for t in m.reported_by}
        if not ({"sonarqube"} & tools and {"trivy"} & tools):
            continue
        n += 1
        cid = f"cluster-{n}"
        for m in members:
            m.cluster_id = cid
            used.add(m.id)
        clusters.append({
            "cluster_id": cid,
            "title": f"{cve} reaches production (code and container)",
            "risk_score": max(m.risk_score for m in members),
            "attack_path": "Code vulnerability (SonarQube) -> same CVE in deployed container (Trivy)",
            "finding_ids": [m.id for m in members],
            "cve_id": cve,
            "internet_exposed": False,
            "rule": "A: cross-source CVE",
        })
    return clusters, used


def _rule_b_exposed_asset(findings: list[Finding], exposure: Finding,
                          already_used: set[str], start_n: int) -> list[dict]:
    """One cluster: the exposure point plus the severe vulnerabilities behind it."""
    severe = [
        f for f in findings
        if f.id != exposure.id
        and f.id not in already_used
        and f.severity in ("CRITICAL", "HIGH")
        and f.type == "VULNERABILITY"
    ]
    if not severe:
        return []

    severe.sort(key=lambda x: -x.risk_score)
    members = severe[:_MAX_MEMBERS]
    cid = f"cluster-{start_n + 1}"
    for m in members:
        m.cluster_id = cid
    exposure.cluster_id = cid

    total_cves = sum(max(m.merged_count, 1) for m in severe)
    runtime = exposure.source == "aws"
    exposure_label = ("host publicly exposed (AWS security group)" if runtime
                      else "exposure declared in infrastructure code (Checkov)")

    return [{
        "cluster_id": cid,
        "title": f"Internet-exposed asset running {len(severe)} severe vulnerabilities",
        "risk_score": max([exposure.risk_score] + [m.risk_score for m in members]),
        "attack_path": (f"Vulnerable dependency in deployed container (Trivy) -> "
                        f"{exposure_label}"),
        "finding_ids": [exposure.id] + [m.id for m in members],
        "cve_id": members[0].cve_id,
        "internet_exposed": True,
        "exposure_source": exposure.source,
        "exposure_resource": exposure.affected_resource,
        "severe_count": len(severe),
        "total_cves": total_cves,
        "rule": "B: exposed vulnerable asset",
    }]


def correlate(findings: list[Finding]) -> list[dict]:
    clusters, used = _rule_a_cross_source(findings, 0)

    # Strongest exposure first, so the most concerning attack path claims the
    # most concerning vulnerabilities before a weaker exposure point is left
    # to explain what remains.
    for exposure in _exposure_points(findings):
        if exposure.id in used:
            continue
        new = _rule_b_exposed_asset(findings, exposure, used, len(clusters))
        if not new:
            continue
        clusters += new
        used.add(exposure.id)
        used.update(fid for c in new for fid in c["finding_ids"])

    # Title breaks ties so the cluster order is stable between runs.
    clusters.sort(key=lambda c: (-c["risk_score"], c["title"]))
    return clusters
