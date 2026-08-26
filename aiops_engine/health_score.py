"""Health score: one 0-100 number summarising the security posture of a run.

A naive "subtract N points per finding" model collapses to zero as soon as a
real image is scanned (a typical container reports 90+ CVEs), which makes the
score useless for tracking improvement over time. Instead the penalty is fed
through a saturating curve:

    score = 100 * K / (K + penalty)

This is strictly decreasing, never negative, and stays sensitive at both ends:
a handful of medium findings barely moves it, while each additional critical
still lowers it - so the trend line remains meaningful across runs.
"""
from __future__ import annotations

from schema import Finding

_PENALTY = {"CRITICAL": 12, "HIGH": 6, "MEDIUM": 2, "LOW": 0.5, "INFO": 0}
_CLUSTER_PENALTY = 25          # a proven attack path is worse than its parts
_K = 120.0                     # curve constant: ~10 highs -> about 65


def compute(findings: list[Finding], clusters: list[dict]) -> int:
    penalty = 0.0
    for f in findings:
        base = _PENALTY.get(f.severity, 1.5)
        # a grouped finding covering many CVEs carries somewhat more weight,
        # but sub-linearly - one upgrade still fixes them all
        if f.merged_count > 1:
            base *= 1 + min(f.merged_count - 1, 10) * 0.08
        if f.internet_facing:
            base *= 1.5
        penalty += base

    penalty += _CLUSTER_PENALTY * len(clusters)
    score = 100.0 * _K / (_K + penalty)
    return max(0, min(100, round(score)))


def summarise(raw_count: int, findings: list[Finding], clusters: list[dict]) -> dict:
    after = len(findings)
    reduction = round((1 - after / raw_count) * 100, 1) if raw_count else 0.0
    counts = {s: 0 for s in ("critical", "high", "medium", "low")}
    for f in findings:
        key = f.severity.lower()
        if key in counts:
            counts[key] += 1
    return {
        "raw_findings": raw_count,
        "after_dedup": after,
        "reduction_pct": reduction,
        "clusters": len(clusters),
        **counts,
    }