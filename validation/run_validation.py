"""Run the three validation scenarios and produce an evaluation report.

Each scenario is executed through the real engine (no shortcuts, no mocking)
and measured against the acceptance criteria defined in the project plan. The
result is written as both JSON and a Markdown table suitable for the report.

Suppression is disabled during validation so that the measured reduction comes
from deduplication and remediation grouping alone - analyst suppression is a
separate, human-driven effect and mixing the two would overstate the engine.

Run:  python validation/run_validation.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMPL = HERE.parent
ENGINE_DIR = IMPL / "aiops_engine"
SCENARIOS = HERE / "scenarios"
RESULTS = HERE / "results"

# Acceptance criteria from the project plan.
CRITERIA = {
    "scenario-1-baseline": {
        "label": "Baseline (remediated)",
        "health_min": 80, "health_max": 100,
        "max_clusters": 0,
        "expect": "Health above 80, no attack paths",
    },
    "scenario-2-moderate": {
        "label": "Moderate risk (partially remediated)",
        "health_min": 40, "health_max": 79,
        "max_clusters": None,
        "min_internet_facing": 1,
        "expect": "Health 40-79, remaining internet exposure surfaced",
    },
    "scenario-3-critical": {
        "label": "Critical (unremediated)",
        "health_min": 0, "health_max": 39,
        "min_clusters": 1,
        "expect": "Health below 40, at least one attack path",
    },
}


def run_engine(scenario: str) -> dict:
    """Execute the engine against one scenario and return its output."""
    out_file = RESULTS / f"{scenario}.json"
    hist_file = RESULTS / "validation-history.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    started = time.time()
    proc = subprocess.run(
        [sys.executable, "engine.py",
         "--input", str(SCENARIOS / scenario),
         "--output", str(out_file),
         "--history", str(hist_file),
         "--run-id", scenario],
        cwd=ENGINE_DIR,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**__import__("os").environ, "THREATWEAVE_NO_SUPPRESSION": "1"},
    )
    elapsed = time.time() - started

    if proc.returncode != 0:
        print(proc.stdout[-2000:])
        print(proc.stderr[-2000:])
        raise SystemExit(f"Engine failed for {scenario}")

    data = json.loads(out_file.read_text(encoding="utf-8"))
    data["_runtime_seconds"] = round(elapsed, 1)
    return data


def evaluate(scenario: str, data: dict) -> dict:
    c = CRITERIA[scenario]
    health = data["health_score"]
    clusters = len(data["clusters"])
    s = data["summary"]

    checks = []
    checks.append((
        f"health {c['health_min']}-{c['health_max']}",
        c["health_min"] <= health <= c["health_max"],
        health,
    ))
    if c.get("min_clusters") is not None:
        checks.append((f"clusters >= {c['min_clusters']}",
                       clusters >= c["min_clusters"], clusters))
    if c.get("max_clusters") is not None:
        checks.append((f"clusters <= {c['max_clusters']}",
                       clusters <= c["max_clusters"], clusters))
    if c.get("min_internet_facing") is not None:
        exposed = sum(1 for f in data["findings"] if f.get("internet_facing"))
        checks.append((f"internet-facing findings >= {c['min_internet_facing']}",
                       exposed >= c["min_internet_facing"], exposed))

    return {
        "scenario": scenario,
        "label": c["label"],
        "expected": c["expect"],
        "health_score": health,
        "raw_findings": s["raw_findings"],
        "actionable": s["after_dedup"],
        "reduction_pct": s["reduction_pct"],
        "clusters": clusters,
        "critical": s.get("critical", 0),
        "high": s.get("high", 0),
        "runtime_seconds": data["_runtime_seconds"],
        "checks": [{"name": n, "passed": p, "actual": a} for n, p, a in checks],
        "passed": all(p for _, p, _ in checks),
    }


def markdown(rows: list[dict]) -> str:
    lines = [
        "# Validation Results",
        "",
        "Each scenario was executed through the production engine against real "
        "scan data captured from OWASP Juice Shop and a live AWS account. "
        "Analyst suppression was disabled so the reduction figures reflect "
        "deduplication and remediation grouping only.",
        "",
        "| Scenario | Health | Raw | Actionable | Reduction | Attack paths | Crit/High | Runtime | Result |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['label']} | {r['health_score']}/100 | {r['raw_findings']} | "
            f"{r['actionable']} | {r['reduction_pct']}% | {r['clusters']} | "
            f"{r['critical']}/{r['high']} | {r['runtime_seconds']}s | "
            f"{'PASS' if r['passed'] else 'FAIL'} |"
        )

    lines += ["", "## Acceptance criteria", ""]
    for r in rows:
        lines.append(f"**{r['label']}** — expected: {r['expected']}")
        for c in r["checks"]:
            mark = "PASS" if c["passed"] else "FAIL"
            lines.append(f"- {mark}: {c['name']} (actual: {c['actual']})")
        lines.append("")
    return "\n".join(lines)


def main():
    if not SCENARIOS.exists():
        raise SystemExit("No scenarios found. Run validation/build_scenarios.py first.")

    RESULTS.mkdir(parents=True, exist_ok=True)
    hist = RESULTS / "validation-history.json"
    if hist.exists():
        hist.unlink()          # start each validation run from a clean trend

    rows = []
    for scenario in ("scenario-1-baseline", "scenario-2-moderate", "scenario-3-critical"):
        print(f"\n{'=' * 60}\nRunning {scenario}\n{'=' * 60}")
        data = run_engine(scenario)
        row = evaluate(scenario, data)
        rows.append(row)
        print(f"  health {row['health_score']} | {row['raw_findings']} -> {row['actionable']} "
              f"({row['reduction_pct']}%) | {row['clusters']} attack path(s) "
              f"| {'PASS' if row['passed'] else 'FAIL'}")

    (RESULTS / "validation-summary.json").write_text(
        json.dumps(rows, indent=2), encoding="utf-8")
    (RESULTS / "VALIDATION.md").write_text(markdown(rows), encoding="utf-8")

    passed = sum(1 for r in rows if r["passed"])
    print(f"\n{'=' * 60}")
    print(f"{passed}/{len(rows)} scenarios met their acceptance criteria")
    print(f"Report: {RESULTS / 'VALIDATION.md'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
