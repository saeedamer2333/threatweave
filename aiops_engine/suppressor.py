"""Suppressor - the analyst feedback loop.

Scanners produce false positives, and the same ones recur on every run. A
secret scanner flagging fixtures under test/ is not a leak; an IaC check the
team has consciously accepted is not a risk. Without a way to record those
judgements the analyst re-reads the same noise forever, which is the core of
alert fatigue.

A suppression rule records that judgement once. Matching findings are removed
from the active list on every subsequent run, with the reason and author kept
for audit. Nothing is deleted: suppressed findings are counted and can be
listed, so a suppression can always be reviewed or revoked.

Rules are matched on stable identity - tool, rule id, CVE, resource pattern -
never on the finding's generated uuid, which changes every run.
"""
from __future__ import annotations

import fnmatch
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from schema import Finding

RULES_PATH = Path(__file__).resolve().parent / "suppression_rules.json"

# A rule may constrain any of these; all present conditions must match.
_MATCHABLE = ("source", "rule_id", "cve_id", "type", "severity")


def load_rules(path: Path = RULES_PATH) -> list[dict]:
    # Validation runs disable suppression so that measured noise reduction
    # reflects deduplication and grouping only. Analyst suppression is a
    # human-driven effect and reporting them combined would overstate the
    # engine's own contribution.
    if os.environ.get("THREATWEAVE_NO_SUPPRESSION") == "1":
        print("      [suppress] disabled for this run (THREATWEAVE_NO_SUPPRESSION=1)")
        return []
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return [r for r in data.get("rules", []) if r.get("active", True)]
    except Exception as e:
        print(f"  [suppress] could not read rules: {e}")
        return []


def save_rules(rules: list[dict], path: Path = RULES_PATH) -> None:
    path.write_text(json.dumps({"rules": rules}, indent=2), encoding="utf-8")


def _matches(f: Finding, rule: dict) -> bool:
    for key in _MATCHABLE:
        want = rule.get(key)
        if want is None:
            continue
        got = getattr(f, key, None)
        if got is None or str(got).lower() != str(want).lower():
            return False

    pattern = rule.get("resource_pattern")
    if pattern and not fnmatch.fnmatch(f.affected_resource.lower(), pattern.lower()):
        return False

    title_pattern = rule.get("title_pattern")
    if title_pattern and not fnmatch.fnmatch(f.title.lower(), title_pattern.lower()):
        return False

    # a rule with no conditions at all would suppress everything - refuse it
    has_condition = any(rule.get(k) for k in _MATCHABLE) or pattern or title_pattern
    return has_condition


def apply(findings: list[Finding], rules: list[dict] | None = None
          ) -> tuple[list[Finding], list[dict]]:
    """Return (kept findings, suppression summary per rule)."""
    rules = load_rules() if rules is None else rules
    if not rules:
        return findings, []

    counts: dict[str, int] = {r["id"]: 0 for r in rules}
    kept: list[Finding] = []
    for f in findings:
        hit = next((r for r in rules if _matches(f, r)), None)
        if hit is None:
            kept.append(f)
        else:
            counts[hit["id"]] += 1

    summary = [{
        "id": r["id"],
        "reason": r.get("reason", ""),
        "created_by": r.get("created_by", "analyst"),
        "created_at": r.get("created_at"),
        "suppressed_count": counts[r["id"]],
    } for r in rules]

    total = sum(counts.values())
    if total:
        print(f"      suppressed {total} finding(s) via {len(rules)} rule(s)")
    return kept, summary


def add_rule(*, reason: str, created_by: str = "analyst", **conditions) -> dict:
    """Create and persist a suppression rule. Used by the CLI and the API."""
    conditions = {k: v for k, v in conditions.items() if v}
    if not conditions:
        raise ValueError("a suppression rule needs at least one condition")

    rule = {
        "id": f"sup-{uuid.uuid4().hex[:8]}",
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "created_by": created_by,
        "reason": reason,
        "active": True,
        **conditions,
    }
    all_rules = []
    if RULES_PATH.exists():
        all_rules = json.loads(RULES_PATH.read_text(encoding="utf-8")).get("rules", [])
    all_rules.append(rule)
    save_rules(all_rules)
    return rule
