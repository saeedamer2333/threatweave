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

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            self.severity = "MEDIUM"
        if not self.reported_by:
            self.reported_by = [self.source]

    def to_dict(self) -> dict:
        return asdict(self)
