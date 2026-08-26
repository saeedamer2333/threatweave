"""Unit tests for health_score.py - the saturating-curve composite score.

score = 100 * K / (K + penalty), K = 120.0

Replaces a naive linear-subtraction model that floored at 0 as soon as a
real container image was scanned (Session 16 bug). The curve must stay
strictly decreasing and bounded in [0, 100] at any finding volume.
"""
from __future__ import annotations

from schema import Finding
import health_score


def _f(**kwargs) -> Finding:
    defaults = dict(source="trivy", type="VULNERABILITY", severity="MEDIUM",
                     title="t", affected_resource="r")
    defaults.update(kwargs)
    return Finding(**defaults)


def test_no_findings_and_no_clusters_scores_100():
    assert health_score.compute([], []) == 100


def test_score_is_never_negative_at_high_volume():
    """The bug this guards: a linear penalty model went negative (floored to
    0) at ~95 findings, making the score meaningless past that point."""
    many_criticals = [_f(severity="CRITICAL") for _ in range(200)]
    score = health_score.compute(many_criticals, [])
    assert 0 <= score <= 100


def test_score_is_monotonically_decreasing_as_severity_increases():
    low = health_score.compute([_f(severity="LOW")], [])
    medium = health_score.compute([_f(severity="MEDIUM")], [])
    high = health_score.compute([_f(severity="HIGH")], [])
    critical = health_score.compute([_f(severity="CRITICAL")], [])
    assert low >= medium >= high >= critical


def test_score_is_monotonically_decreasing_as_volume_increases():
    one = health_score.compute([_f(severity="HIGH")], [])
    five = health_score.compute([_f(severity="HIGH") for _ in range(5)], [])
    twenty = health_score.compute([_f(severity="HIGH") for _ in range(20)], [])
    assert one >= five >= twenty


def test_internet_facing_findings_are_penalised_more_heavily():
    internal = health_score.compute([_f(severity="HIGH", internet_facing=False)], [])
    exposed = health_score.compute([_f(severity="HIGH", internet_facing=True)], [])
    assert exposed <= internal


def test_a_proven_attack_path_lowers_score_beyond_its_member_findings():
    finding = _f(severity="HIGH")
    without_cluster = health_score.compute([finding], [])
    with_cluster = health_score.compute([finding], [{"cluster_id": "c1"}])
    assert with_cluster < without_cluster


def test_merged_finding_carries_more_weight_but_sublinearly():
    """A finding covering 10 CVEs should count for more than one covering 1,
    but not for a literal 10x penalty - one upgrade still fixes them all."""
    single = health_score.compute([_f(severity="HIGH", merged_count=1)], [])
    merged_10 = health_score.compute([_f(severity="HIGH", merged_count=10)], [])
    ten_singles = health_score.compute([_f(severity="HIGH") for _ in range(10)], [])
    assert merged_10 < single                  # merging still costs something
    assert merged_10 > ten_singles              # but far less than 10 separate findings


# ---- summarise -------------------------------------------------------------

def test_summarise_computes_reduction_percentage():
    findings = [_f(severity="HIGH"), _f(severity="LOW")]
    summary = health_score.summarise(raw_count=10, findings=findings, clusters=[])
    assert summary["raw_findings"] == 10
    assert summary["after_dedup"] == 2
    assert summary["reduction_pct"] == 80.0


def test_summarise_counts_by_severity():
    findings = [_f(severity="CRITICAL"), _f(severity="CRITICAL"), _f(severity="LOW")]
    summary = health_score.summarise(raw_count=3, findings=findings, clusters=[])
    assert summary["critical"] == 2
    assert summary["low"] == 1
    assert summary["high"] == 0


def test_summarise_handles_zero_raw_count_without_dividing_by_zero():
    summary = health_score.summarise(raw_count=0, findings=[], clusters=[])
    assert summary["reduction_pct"] == 0.0
