"""Finding tracker - persists first_seen/last_seen across scan runs.

A finding's own `id` is a fresh UUID every run, so on its own it cannot
answer "how long has this been open" - only finding_identity() (a stable
key that survives across runs, see schema.py) can. This module is the
persistent memory that turns that stable key into real first_seen/last_seen
dates, the same way history_tracker.py persists run-level summaries.
"""
from __future__ import annotations

import json
from pathlib import Path

from schema import Finding, finding_identity


def _load(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"      [tracker] could not read existing first-seen record: {e}")
        return {}


def track(findings: list[Finding], path: Path, now: str) -> None:
    """Sets first_seen/last_seen on every finding in place, and persists the
    updated store to `path`.

    `now` is the current run's own timestamp (an ISO string), passed in
    rather than computed here so this is fully deterministic to test and so
    every finding in one run shares the exact same instant rather than
    drifting by however long the run itself took.

    A finding whose identity is not in the store yet is new to it:
    first_seen = last_seen = now. One already known keeps its original
    first_seen - only last_seen advances - which is the entire point of
    this module. Deliberately never pruned: if the exact same issue
    reappears after being fixed, continuing from its original first_seen is
    at least as informative as resetting it, and pruning would need a
    policy for how long to keep resolved entries around that this project
    has no real basis for choosing.
    """
    store = _load(path)
    for f in findings:
        key = finding_identity(f)
        first_seen = store.get(key, now)
        f.first_seen = first_seen
        f.last_seen = now
        store[key] = first_seen

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2), encoding="utf-8")
