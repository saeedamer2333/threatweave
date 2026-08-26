"""Unit tests for history_tracker.py - the trend data behind the History
page (Section 4.4.4). Stores summary metrics only, capped at the most
recent 30 runs, keyed so a re-run of the same run_id replaces rather than
duplicates its entry.
"""
from __future__ import annotations

import json

import history_tracker


def _output(run_id, health=50, raw=10, after=5):
    return {
        "run_id": run_id,
        "generated_at": f"2026-08-{run_id[-2:]}T00:00:00Z",
        "health_score": health,
        "summary": {
            "raw_findings": raw, "after_dedup": after, "reduction_pct": 50.0,
            "suppressed": 0, "clusters": 0, "critical": 0, "high": 0,
        },
    }


def test_record_creates_a_new_history_file(tmp_path):
    path = tmp_path / "history.json"
    runs = history_tracker.record(path, _output("run-01"))

    assert path.exists()
    assert len(runs) == 1
    assert runs[0]["run_id"] == "run-01"
    assert runs[0]["health_score"] == 50


def test_record_appends_to_existing_history(tmp_path):
    path = tmp_path / "history.json"
    history_tracker.record(path, _output("run-01"))
    runs = history_tracker.record(path, _output("run-02"))

    assert len(runs) == 2
    assert {r["run_id"] for r in runs} == {"run-01", "run-02"}


def test_record_replaces_entry_with_same_run_id_rather_than_duplicating(tmp_path):
    path = tmp_path / "history.json"
    history_tracker.record(path, _output("run-01", health=30))
    runs = history_tracker.record(path, _output("run-01", health=90))

    assert len(runs) == 1                      # not 2
    assert runs[0]["health_score"] == 90        # the newer value wins


def test_record_caps_at_max_runs(tmp_path):
    path = tmp_path / "history.json"
    for i in range(35):
        history_tracker.record(path, _output(f"run-{i:02d}"))

    runs = json.loads(path.read_text(encoding="utf-8"))["runs"]
    assert len(runs) == 30                      # MAX_RUNS


def test_record_stores_summary_fields_only_not_findings(tmp_path):
    path = tmp_path / "history.json"
    output = _output("run-01")
    output["findings"] = [{"id": "f-1", "title": "should not be stored"}]

    runs = history_tracker.record(path, output)

    assert "findings" not in runs[0]
    assert set(runs[0].keys()) == {
        "run_id", "generated_at", "health_score", "raw_findings",
        "after_dedup", "reduction_pct", "suppressed", "clusters",
        "critical", "high",
    }


def test_record_handles_missing_history_file_gracefully(tmp_path):
    path = tmp_path / "does_not_exist_yet" / "history.json"
    runs = history_tracker.record(path, _output("run-01"))
    assert len(runs) == 1
    assert path.exists()                        # parent dir created
