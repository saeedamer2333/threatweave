"""Unit tests for gitleaks_merge.py - folding an incremental GitLeaks scan
(new commits only) into the running total from prior scans, so a finding
from a commit outside this run's range doesn't silently vanish from the
report just because it wasn't rescanned.
"""
from __future__ import annotations

import json

from gitleaks_merge import _load, main, merge_findings


def _leak(fingerprint, file="a.ts", commit="abc123"):
    return {
        "RuleID": "generic-api-key",
        "Description": "Detected a Generic API Key",
        "StartLine": 1,
        "File": file,
        "Commit": commit,
        "Fingerprint": fingerprint,
    }


def test_merge_keeps_findings_from_both_previous_and_new_scans():
    previous = [_leak("commit-a:a.ts:generic-api-key:1")]
    new = [_leak("commit-b:b.ts:generic-api-key:1", file="b.ts", commit="commit-b")]

    merged = merge_findings(previous, new)

    fingerprints = {leak["Fingerprint"] for leak in merged}
    assert fingerprints == {"commit-a:a.ts:generic-api-key:1", "commit-b:b.ts:generic-api-key:1"}


def test_merge_deduplicates_by_fingerprint_not_by_object_identity():
    # The exact same leak reported again (e.g. HEAD scanned twice with no
    # new commits in between) must not produce a duplicate entry.
    shared = _leak("commit-a:a.ts:generic-api-key:1")
    previous = [shared]
    new = [dict(shared)]  # a different object, same Fingerprint

    merged = merge_findings(previous, new)

    assert len(merged) == 1


def test_merge_lets_a_new_scan_of_the_same_fingerprint_override_the_old_entry():
    previous = [{**_leak("fp-1"), "Description": "stale description"}]
    new = [{**_leak("fp-1"), "Description": "fresh description"}]

    merged = merge_findings(previous, new)

    assert len(merged) == 1
    assert merged[0]["Description"] == "fresh description"


def test_merge_ignores_leaks_with_no_fingerprint_rather_than_crashing():
    previous = [{"RuleID": "x"}]  # malformed / missing Fingerprint
    new = [_leak("fp-1")]

    merged = merge_findings(previous, new)

    assert len(merged) == 1
    assert merged[0]["Fingerprint"] == "fp-1"


def test_load_returns_empty_list_for_a_missing_file(tmp_path):
    assert _load(tmp_path / "does-not-exist.json") == []


def test_load_returns_empty_list_for_an_empty_file(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("", encoding="utf-8")

    assert _load(path) == []


def test_main_writes_the_merged_result_to_the_output_path(tmp_path, monkeypatch):
    previous_path = tmp_path / "previous.json"
    new_path = tmp_path / "new.json"
    output_path = tmp_path / "nested" / "output.json"

    previous_path.write_text(json.dumps([_leak("fp-1")]), encoding="utf-8")
    new_path.write_text(json.dumps([_leak("fp-2")]), encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        ["gitleaks_merge.py", "--previous", str(previous_path), "--new", str(new_path), "--output", str(output_path)],
    )
    main()

    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert {leak["Fingerprint"] for leak in written} == {"fp-1", "fp-2"}


def test_main_handles_a_previous_file_that_does_not_exist_yet(tmp_path, monkeypatch):
    # The very first run of a repo: no cumulative store yet.
    previous_path = tmp_path / "does-not-exist.json"
    new_path = tmp_path / "new.json"
    output_path = tmp_path / "output.json"

    new_path.write_text(json.dumps([_leak("fp-1")]), encoding="utf-8")

    monkeypatch.setattr(
        "sys.argv",
        ["gitleaks_merge.py", "--previous", str(previous_path), "--new", str(new_path), "--output", str(output_path)],
    )
    main()

    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(written) == 1
