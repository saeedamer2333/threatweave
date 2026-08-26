"""History tracker - persists a compact record of every engine run.

A single health score says whether today is bad. A series says whether the
team is getting better, which is the question an SME actually cares about and
the basis of the trend chart on the dashboard.

Only summary metrics are stored, never the findings themselves, so the file
stays small enough to read on every request. The newest MAX_RUNS entries are
kept and older ones are discarded.
"""
from __future__ import annotations

import json
from pathlib import Path

MAX_RUNS = 30


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        return data.get("runs", [])
    except Exception as e:
        print(f"      [history] could not read existing history: {e}")
        return []


def record(path: Path, output: dict) -> list[dict]:
    """Append this run's summary and return the trimmed history."""
    runs = _load(path)
    summary = output.get("summary", {})

    entry = {
        "run_id": output["run_id"],
        "generated_at": output["generated_at"],
        "health_score": output["health_score"],
        "raw_findings": summary.get("raw_findings", 0),
        "after_dedup": summary.get("after_dedup", 0),
        "reduction_pct": summary.get("reduction_pct", 0.0),
        "suppressed": summary.get("suppressed", 0),
        "clusters": summary.get("clusters", 0),
        "critical": summary.get("critical", 0),
        "high": summary.get("high", 0),
    }

    # Re-running on the same day replaces that day's entry rather than
    # stacking duplicates, so the trend line stays one point per run id.
    runs = [r for r in runs if r.get("run_id") != entry["run_id"]]
    runs.append(entry)
    runs.sort(key=lambda r: r.get("generated_at", ""))
    runs = runs[-MAX_RUNS:]

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"runs": runs}, indent=2), encoding="utf-8")
    return runs
