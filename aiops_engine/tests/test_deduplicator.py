"""Unit tests for deduplicator.py - the two-pass reduction behind the
project's headline noise-reduction figure.

Pass 1 merges the same issue reported by different tools (keyed on CVE, or
type+resource when there is no CVE). Pass 2 groups distinct CVEs that share
one remediation (one package upgrade clears several CVE ids).
"""
from __future__ import annotations

from schema import Finding
import deduplicator


def _f(**kwargs) -> Finding:
    defaults = dict(
        source="trivy", type="VULNERABILITY", severity="HIGH",
        title="t", affected_resource="r",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---- Pass 1: cross-tool merge -------------------------------------------

def test_same_cve_from_two_tools_merges_into_one():
    a = _f(source="sonarqube", cve_id="CVE-2021-44228", severity="HIGH", cvss_score=7.5,
            affected_resource="src/log.ts:10")
    b = _f(source="trivy", cve_id="CVE-2021-44228", severity="CRITICAL", cvss_score=10.0,
            affected_resource="image / log4j-2.14.1")

    out = deduplicator.deduplicate([a, b])

    assert len(out) == 1
    merged = out[0]
    assert set(merged.reported_by) == {"sonarqube", "trivy"}
    assert merged.severity == "CRITICAL"       # more severe of the two wins
    assert merged.cvss_score == 10.0           # higher of the two wins


def test_findings_without_cve_key_on_type_and_resource():
    a = _f(source="checkov", type="MISCONFIGURATION", cve_id=None,
           affected_resource="aws_s3_bucket.logs")
    b = _f(source="checkov", type="MISCONFIGURATION", cve_id=None,
           affected_resource="aws_s3_bucket.logs")
    c = _f(source="checkov", type="MISCONFIGURATION", cve_id=None,
           affected_resource="aws_s3_bucket.other")

    out = deduplicator.deduplicate([a, b, c])

    assert len(out) == 2                       # a+b collapse, c stays distinct


def test_key_is_case_insensitive_on_cve_id():
    a = _f(cve_id="cve-2021-1", affected_resource="x/pkg-1.0")
    b = _f(cve_id="CVE-2021-1", affected_resource="y/pkg-1.0")
    out = deduplicator.deduplicate([a, b])
    assert len(out) == 1


def test_distinct_checkov_checks_on_same_resource_are_not_merged():
    """Regression: Checkov reports its checks with only the resource's
    starting line, so several unrelated checks against the same resource
    (e.g. EBS optimization and "should not have public IP") used to share
    an affected_resource string and collapse into one record via the
    type+resource fallback key -- silently OR-merging internet_facing from
    an unrelated check onto a finding that has nothing to do with exposure.
    rule_id in the key keeps them distinct."""
    ebs = _f(source="checkov", type="MISCONFIGURATION", cve_id=None,
             rule_id="CKV_AWS_135", internet_facing=False,
             affected_resource="aws_instance.juice_shop (/main.tf:73)")
    public_ip = _f(source="checkov", type="MISCONFIGURATION", cve_id=None,
                    rule_id="CKV_AWS_88", internet_facing=True,
                    affected_resource="aws_instance.juice_shop (/main.tf:73)")

    out = deduplicator.deduplicate([ebs, public_ip])

    assert len(out) == 2
    by_rule = {f.rule_id: f for f in out}
    assert by_rule["CKV_AWS_135"].internet_facing is False
    assert by_rule["CKV_AWS_88"].internet_facing is True


def test_internet_facing_is_or_combined_across_merged_findings():
    a = _f(cve_id="CVE-1", internet_facing=False, affected_resource="x/pkg-1.0")
    b = _f(cve_id="CVE-1", internet_facing=True, affected_resource="x/pkg-1.0")
    merged = deduplicator.deduplicate([a, b])[0]
    assert merged.internet_facing is True


# ---- Pass 2: same-remediation grouping -----------------------------------

def test_multiple_cves_in_one_package_group_into_one_actionable_item():
    findings = [
        _f(cve_id="CVE-2019-1", severity="HIGH", cvss_score=7.0,
           affected_resource="Node.js / lodash-4.17.11"),
        _f(cve_id="CVE-2019-2", severity="CRITICAL", cvss_score=9.8,
           affected_resource="Node.js / lodash-4.17.11"),
        _f(cve_id="CVE-2019-3", severity="MEDIUM", cvss_score=5.0,
           affected_resource="Node.js / lodash-4.17.11"),
    ]
    out = deduplicator.deduplicate(findings)

    assert len(out) == 1
    rep = out[0]
    assert rep.severity == "CRITICAL"          # representative = most severe member
    assert rep.merged_count == 3
    assert set(rep.related_cves) == {"CVE-2019-1", "CVE-2019-2", "CVE-2019-3"}
    assert "3 vulnerabilities in lodash" in rep.title
    assert "CVE-2019-2" in rep.title           # names the most severe CVE


def test_single_cve_package_is_not_rewritten():
    """A package with only one CVE should pass through unchanged - no
    misleading '1 vulnerabilities in ...' title, no merged_count inflation."""
    f = _f(cve_id="CVE-2019-1", affected_resource="Node.js / express-4.16.0")
    out = deduplicator.deduplicate([f])

    assert len(out) == 1
    assert out[0].title == "t"                 # untouched
    assert out[0].merged_count == 1


def test_findings_without_cve_bypass_remediation_grouping():
    """SonarQube/GitLeaks/Checkov findings have no package version string to
    group on and must pass straight through pass 2 rather than being dropped."""
    findings = [
        _f(source="sonarqube", type="VULNERABILITY", cve_id=None, affected_resource="src/a.ts:1"),
        _f(source="gitleaks", type="SECRET", cve_id=None, affected_resource="src/b.ts:2"),
    ]
    out = deduplicator.deduplicate(findings)
    assert len(out) == 2


def test_different_packages_are_not_merged_together():
    findings = [
        _f(cve_id="CVE-1", affected_resource="Node.js / lodash-4.17.11"),
        _f(cve_id="CVE-2", affected_resource="Node.js / express-4.16.0"),
    ]
    out = deduplicator.deduplicate(findings)
    assert len(out) == 2


def test_end_to_end_reduction_count_example():
    """A concrete worked example: 5 raw findings (one cross-tool duplicate,
    three sharing one package) should reduce to 2 actionable items."""
    raw = [
        _f(source="sonarqube", cve_id="CVE-2021-44228", affected_resource="src/log.ts:10"),
        _f(source="trivy", cve_id="CVE-2021-44228", affected_resource="image / log4j-2.14.1"),
        _f(source="trivy", cve_id="CVE-2019-1", severity="HIGH",
           affected_resource="Node.js / lodash-4.17.11"),
        _f(source="trivy", cve_id="CVE-2019-2", severity="CRITICAL",
           affected_resource="Node.js / lodash-4.17.11"),
        _f(source="trivy", cve_id="CVE-2019-3", severity="MEDIUM",
           affected_resource="Node.js / lodash-4.17.11"),
    ]
    out = deduplicator.deduplicate(raw)
    assert len(out) == 2
