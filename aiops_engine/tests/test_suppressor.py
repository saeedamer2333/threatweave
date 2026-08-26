"""Unit tests for suppressor.py - the analyst feedback loop.

Rules match on stable identity (source/rule_id/cve/type/severity plus glob
patterns on resource/title), never on the finding's per-run uuid. A rule
with no conditions must be refused, since it would silently suppress
everything.
"""
from __future__ import annotations

import json

import pytest

from schema import Finding
import suppressor


def _f(**kwargs) -> Finding:
    defaults = dict(
        source="gitleaks", type="SECRET", severity="HIGH",
        title="Hardcoded API key", affected_resource="test/fixtures/creds.json",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_rule_with_matching_source_and_resource_pattern_suppresses_finding():
    rule = {"id": "sup-1", "source": "gitleaks", "resource_pattern": "test/*",
            "reason": "test fixtures", "active": True}
    finding = _f(affected_resource="test/fixtures/creds.json")

    kept, summary = suppressor.apply([finding], rules=[rule])

    assert kept == []
    assert summary[0]["suppressed_count"] == 1


def test_rule_does_not_match_a_finding_outside_its_pattern():
    rule = {"id": "sup-1", "source": "gitleaks", "resource_pattern": "test/*", "reason": "x"}
    real_secret = _f(affected_resource="src/config/prod.env")

    kept, summary = suppressor.apply([real_secret], rules=[rule])

    assert len(kept) == 1                       # not suppressed
    assert summary[0]["suppressed_count"] == 0


def test_rule_matching_is_case_insensitive():
    rule = {"id": "sup-1", "source": "GitLeaks", "reason": "x"}
    finding = _f(source="gitleaks")
    kept, _ = suppressor.apply([finding], rules=[rule])
    assert kept == []


def test_multiple_conditions_on_one_rule_must_all_match():
    rule = {"id": "sup-1", "source": "trivy", "severity": "LOW", "reason": "x"}
    matches_both = _f(source="trivy", severity="LOW")
    matches_only_source = _f(source="trivy", severity="CRITICAL")

    kept, summary = suppressor.apply([matches_both, matches_only_source], rules=[rule])

    assert matches_only_source in kept
    assert matches_both not in kept
    assert summary[0]["suppressed_count"] == 1


def test_first_matching_rule_wins_and_only_counts_once():
    rule_a = {"id": "sup-a", "source": "gitleaks", "reason": "a"}
    rule_b = {"id": "sup-b", "type": "SECRET", "reason": "b"}
    finding = _f(source="gitleaks", type="SECRET")

    kept, summary = suppressor.apply([finding], rules=[rule_a, rule_b])

    assert kept == []
    counts = {s["id"]: s["suppressed_count"] for s in summary}
    assert counts["sup-a"] == 1
    assert counts["sup-b"] == 0                  # not double-counted


def test_no_rules_returns_all_findings_unchanged():
    findings = [_f(), _f(title="another")]
    kept, summary = suppressor.apply(findings, rules=[])
    assert kept == findings
    assert summary == []


def test_resource_pattern_glob_matching():
    rule = {"id": "sup-1", "resource_pattern": "*/fixtures/*", "reason": "x"}
    inside = _f(affected_resource="test/fixtures/a.json")
    outside = _f(affected_resource="src/real/b.json")

    kept, _ = suppressor.apply([inside, outside], rules=[rule])

    assert inside not in kept
    assert outside in kept


# ---- add_rule: refuses a condition-less rule ------------------------------
#
# add_rule() raises before touching the filesystem, so this needs no path
# isolation. Persistence (save_rules/load_rules) is tested separately below
# with an explicit path, rather than through add_rule's internal
# save_rules(all_rules) call - that call relies on save_rules' own default
# argument, which is bound once at import time and would NOT pick up a
# monkeypatched suppressor.RULES_PATH, so routing through add_rule here
# would silently write into the real project's suppression_rules.json.

def test_add_rule_refuses_when_no_condition_supplied():
    with pytest.raises(ValueError):
        suppressor.add_rule(reason="no conditions at all")


def test_add_rule_builds_a_well_formed_rule_shape(tmp_path, monkeypatch):
    monkeypatch.setattr(suppressor, "RULES_PATH", tmp_path / "suppression_rules.json")
    monkeypatch.setattr(suppressor, "save_rules", lambda rules, path=None: None)

    rule = suppressor.add_rule(reason="test fixtures", source="gitleaks")

    assert rule["id"].startswith("sup-")
    assert rule["created_at"]
    assert rule["active"] is True
    assert rule["reason"] == "test fixtures"
    assert rule["source"] == "gitleaks"


def test_save_rules_then_load_rules_round_trips_via_explicit_path(tmp_path):
    rules_path = tmp_path / "suppression_rules.json"
    rules = [{"id": "sup-1", "reason": "x", "source": "gitleaks", "active": True}]

    suppressor.save_rules(rules, path=rules_path)
    loaded = suppressor.load_rules(path=rules_path)

    assert loaded[0]["id"] == "sup-1"


def test_load_rules_skips_inactive_rules():
    rules_path_data = {"rules": [
        {"id": "sup-1", "reason": "x", "active": True},
        {"id": "sup-2", "reason": "y", "active": False},
    ]}
    import tempfile, os
    fd, path_str = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(rules_path_data, fh)
        from pathlib import Path
        loaded = suppressor.load_rules(path=Path(path_str))
        assert [r["id"] for r in loaded] == ["sup-1"]
    finally:
        os.remove(path_str)


def test_load_rules_honours_no_suppression_env_override(monkeypatch, tmp_path):
    rules_path = tmp_path / "suppression_rules.json"
    suppressor.save_rules([{"id": "sup-1", "reason": "x", "active": True}], path=rules_path)
    monkeypatch.setenv("THREATWEAVE_NO_SUPPRESSION", "1")

    assert suppressor.load_rules(path=rules_path) == []
