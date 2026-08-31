"""Merges a GitLeaks incremental scan into a persisted running total.

Rescanning a large repo's full git history on every run is the second most
expensive part of a scan (minutes, on top of SonarQube's own dominant cost).
Once a commit range has been scanned, it never needs scanning again - so the
pipeline scans only new commits each run (see the Jenkinsfile's GitLeaks
branch) and this module folds that into what was already found, rather than
letting the report silently narrow to just the newest commits. Without this,
a finding from a commit outside the new range would vanish from the report
even though the secret is still sitting in the repo, unremediated - not a
speed optimisation, a real loss of coverage.

Deduplication is by GitLeaks' own `Fingerprint` field
(`commit:file:rule:startline`), the same identity GitLeaks itself uses.
"""
import argparse
import json
from pathlib import Path


def merge_findings(previous: list[dict], new: list[dict]) -> list[dict]:
    by_fingerprint: dict[str, dict] = {}
    for leak in previous:
        fp = leak.get("Fingerprint")
        if fp:
            by_fingerprint[fp] = leak
    for leak in new:
        fp = leak.get("Fingerprint")
        if fp:
            by_fingerprint[fp] = leak
    return list(by_fingerprint.values())


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    return json.loads(text)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous", required=True, type=Path,
                         help="Path to the cumulative findings from prior runs (may not exist yet)")
    parser.add_argument("--new", required=True, type=Path,
                         help="Path to this run's (possibly incremental) GitLeaks report")
    parser.add_argument("--output", required=True, type=Path,
                         help="Where to write the merged result - used as both this run's report and the new cumulative store")
    args = parser.parse_args()

    merged = merge_findings(_load(args.previous), _load(args.new))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(merged, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
