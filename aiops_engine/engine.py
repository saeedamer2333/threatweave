"""AIOps engine entry point.

Pipeline:
    aggregate -> normalise -> deduplicate -> score -> correlate -> explain
             -> health score -> write aiops-output.json

Usage:
    python engine.py [--input DIR] [--output FILE]
Defaults use the bundled sample_inputs so it runs with no arguments.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import aggregator
import deduplicator
import suppressor
import scorer
import correlator
import explainer
import health_score
import history_tracker
from schema import SEVERITIES

HERE = Path(__file__).resolve().parent


def _rank(f) -> tuple:
    """Deterministic ordering for the findings list.

    Risk score decides first. Ties then fall to the tool's own severity, then
    CVSS, then title. Sorting on risk score alone left equal scores in
    insertion order, which put a LOW finding above a CRITICAL one whenever
    both landed on the same score - an accident of ordering that reads as a
    ranking error to anyone looking at the dashboard.
    """
    severity = (SEVERITIES.index(f.severity)
                if f.severity in SEVERITIES else len(SEVERITIES))
    return (-f.risk_score, severity, -(f.cvss_score or 0.0), f.title or "")


def run(input_dir: Path, output_file: Path,
        history_file: Path | None = None, run_id: str | None = None) -> dict:
    history_file = history_file or output_file.parent / "history.json"
    print("AIOps engine starting")
    print("1/6 aggregate + normalise")
    raw = aggregator.load_all(input_dir)
    raw_count = len(raw)
    print(f"      total raw findings: {raw_count}")

    print("2/7 deduplicate")
    findings = deduplicator.deduplicate(raw)
    print(f"      after dedup: {len(findings)}")

    print("3/7 suppress")
    before_suppression = len(findings)
    findings, suppressions = suppressor.apply(findings)
    suppressed_count = before_suppression - len(findings)
    if not suppressed_count:
        print("      no findings suppressed")

    print("4/7 score")
    findings = scorer.score(findings)

    print("5/7 correlate")
    clusters = correlator.correlate(findings)
    print(f"      attack-path clusters: {len(clusters)}")

    print("6/7 explain")
    explainer.explain_all(findings, clusters)

    print("7/7 health score")
    health = health_score.compute(findings, clusters)
    summary = health_score.summarise(raw_count, findings, clusters)

    now = datetime.now(timezone.utc)
    output = {
        # minute-resolution so several validation runs on one day stay distinct
        "run_id": run_id or f"run-{now:%Y-%m-%d-%H%M}",
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "health_score": health,
        "summary": {**summary, "suppressed": suppressed_count},
        "suppressions": suppressions,
        "clusters": clusters,
        "findings": [f.to_dict() for f in sorted(findings, key=_rank)],
    }

    history = history_tracker.record(history_file, output)
    output["history"] = history
    print(f"      recorded run {output['run_id']} ({len(history)} run(s) in history)")

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2)
    print(f"\nWrote {output_file}")
    print(f"Health score: {health}   |   {summary['reduction_pct']}% reduction   |   {len(clusters)} attack paths")
    return output


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(HERE / "sample_inputs"))
    ap.add_argument("--output", default=str(HERE.parent / "findings" / "aiops-output.json"))
    ap.add_argument("--history", default=str(HERE.parent / "findings" / "history.json"))
    ap.add_argument("--run-id", default=None,
                    help="label this run, e.g. scenario-1-baseline")
    args = ap.parse_args()
    run(Path(args.input), Path(args.output), Path(args.history), args.run_id)


if __name__ == "__main__":
    main()
