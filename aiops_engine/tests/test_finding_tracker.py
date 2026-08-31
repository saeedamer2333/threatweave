"""Unit tests for finding_tracker.py - persists first_seen/last_seen across
scan runs, keyed on finding_identity() rather than Finding.id (a fresh UUID
every run).
"""
from __future__ import annotations

import json

from schema import Finding
import finding_tracker


def _f(**kwargs) -> Finding:
    defaults = dict(
        source="trivy", type="VULNERABILITY", severity="HIGH",
        title="t", affected_resource="r",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_new_finding_gets_first_seen_equal_to_last_seen(tmp_path):
    path = tmp_path / "first_seen.json"
    f = _f(cve_id="CVE-2024-0001")

    finding_tracker.track([f], path, "2026-08-01T00:00:00Z")

    assert f.first_seen == "2026-08-01T00:00:00Z"
    assert f.last_seen == "2026-08-01T00:00:00Z"


def test_first_seen_stays_fixed_across_runs_while_last_seen_advances(tmp_path):
    path = tmp_path / "first_seen.json"
    f1 = _f(cve_id="CVE-2024-0001")
    finding_tracker.track([f1], path, "2026-08-01T00:00:00Z")

    f2 = _f(cve_id="CVE-2024-0001")
    finding_tracker.track([f2], path, "2026-08-05T00:00:00Z")

    assert f2.first_seen == "2026-08-01T00:00:00Z"   # unchanged
    assert f2.last_seen == "2026-08-05T00:00:00Z"    # advanced


def test_distinct_findings_in_the_same_run_share_the_run_timestamp(tmp_path):
    path = tmp_path / "first_seen.json"
    a = _f(cve_id="CVE-2024-0001")
    b = _f(cve_id="CVE-2024-0002")

    finding_tracker.track([a, b], path, "2026-08-01T00:00:00Z")

    assert a.first_seen == b.first_seen == "2026-08-01T00:00:00Z"


def test_store_persists_to_disk_between_calls(tmp_path):
    path = tmp_path / "first_seen.json"
    finding_tracker.track([_f(cve_id="CVE-2024-0001")], path, "2026-08-01T00:00:00Z")

    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["cve:CVE-2024-0001"] == "2026-08-01T00:00:00Z"


def test_resolved_then_reintroduced_finding_keeps_its_original_first_seen(tmp_path):
    path = tmp_path / "first_seen.json"
    finding_tracker.track([_f(cve_id="CVE-2024-0001")], path, "2026-08-01T00:00:00Z")
    # a run where the finding is absent (fixed) does not touch the store
    finding_tracker.track([], path, "2026-08-02T00:00:00Z")

    reintroduced = _f(cve_id="CVE-2024-0001")
    finding_tracker.track([reintroduced], path, "2026-08-10T00:00:00Z")

    assert reintroduced.first_seen == "2026-08-01T00:00:00Z"
    assert reintroduced.last_seen == "2026-08-10T00:00:00Z"


def test_handles_missing_file_gracefully(tmp_path):
    path = tmp_path / "does_not_exist_yet" / "first_seen.json"
    f = _f(cve_id="CVE-2024-0001")

    finding_tracker.track([f], path, "2026-08-01T00:00:00Z")

    assert path.exists()
    assert f.first_seen == "2026-08-01T00:00:00Z"


def test_handles_corrupt_existing_file_gracefully(tmp_path):
    path = tmp_path / "first_seen.json"
    path.write_text("not valid json", encoding="utf-8")
    f = _f(cve_id="CVE-2024-0001")

    finding_tracker.track([f], path, "2026-08-01T00:00:00Z")

    assert f.first_seen == "2026-08-01T00:00:00Z"
