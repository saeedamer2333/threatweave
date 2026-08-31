"""Unified Finding schema.

Every tool (Trivy, SonarQube, GitLeaks, Checkov, AWS) reports in its own
format. The normaliser converts each into this single shape so the rest of
the engine can treat all findings the same way.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional


SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass
class Finding:
    source: str                       # trivy | sonarqube | gitleaks | checkov | aws
    type: str                         # VULNERABILITY | SECRET | MISCONFIGURATION | IAM | EXPOSURE
    severity: str                     # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str
    affected_resource: str
    description: str = ""
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    rule_id: Optional[str] = None      # tool's own rule/check id, used for suppression
    environment: str = "production"
    internet_facing: bool = False
    # Set by the scorer when this finding is not itself the exposure, but sits
    # on an asset something else proved reachable - a vulnerable package in a
    # container running behind an open security group. Weaker evidence than
    # internet_facing, and scored accordingly.
    reachable_via_exposure: bool = False
    reported_by: list[str] = field(default_factory=list)

    # set by the deduplicator when several CVEs collapse into one action
    related_cves: list[str] = field(default_factory=list)
    merged_count: int = 1
    fix_version: Optional[str] = None

    # filled in by later stages
    id: str = field(default_factory=lambda: f"f-{uuid.uuid4().hex[:8]}")
    risk_score: int = 0
    scores: dict = field(default_factory=lambda: {"P_RF": 0.0, "S_retrieval": 0.0, "S_asset": 0.0, "S_EPSS": 0.0})
    confidence: str = "Needs Analyst Review"
    cluster_id: Optional[str] = None
    explanation: str = ""
    # Short, human label for a quick-scan summary card (e.g. "SQL Injection",
    # "Exposed Secret") and the actionable clause on its own, separate from
    # the full `explanation` sentence - built for a UI that shows these as
    # scannable cards rather than requiring a full paragraph read to find
    # "what kind of issue is this" and "what do I actually do about it".
    explanation_kind: str = ""
    explanation_fix: str = ""
    # Concrete, per-finding evidence behind each of the four score components
    # - not the formula (WEIGHTS in scorer.py already documents that), the
    # actual reason *this* finding landed where it did: which words drove
    # the ML probability, which known CVEs its text most resembles, why its
    # asset-exposure band is what it is, whether EPSS had data for it at all.
    score_evidence: dict = field(default_factory=dict)
    # When this exact finding (by finding_identity(), below) was first and
    # most recently seen across scan runs - None until finding_tracker.py
    # populates them, since a finding's own `id` is regenerated fresh every
    # run and cannot answer "how long has this been open".
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            self.severity = "MEDIUM"
        if not self.reported_by:
            self.reported_by = [self.source]

    def to_dict(self) -> dict:
        return asdict(self)


def finding_identity(f: Finding) -> str:
    """A stable key for "is this the same underlying issue" that survives
    across separate scan runs, unlike `Finding.id` (a fresh UUID every run).

    Originally lived in deduplicator.py as a same-run merge key (CVE, or
    rule+resource, or type+resource) - moved here so finding_tracker.py can
    reuse the exact same identity for cross-run first_seen/last_seen
    tracking without a second, potentially-diverging definition of "same
    finding" existing anywhere in the codebase.
    """
    if f.cve_id:
        return f"cve:{f.cve_id.upper()}"
    if f.rule_id:
        # Checkov reports several distinct checks against one Terraform
        # resource, all sharing the same (coarse, first-line-of-range)
        # affected_resource. Without rule_id in the key, unrelated checks
        # (e.g. "EC2 is EBS optimized" and "EC2 should not have public IP")
        # would collapse into one record.
        return f"rule:{f.source}:{f.rule_id}:{f.affected_resource.lower()}"
    return f"{f.type}:{f.affected_resource.lower()}"
