"""Manage suppression rules from the command line.

    python suppress_cli.py list
    python suppress_cli.py add --source gitleaks --rule-id generic-api-key \
        --resource "*/test/*" --reason "test fixtures, not real credentials"
    python suppress_cli.py revoke sup-1a2b3c4d
"""
from __future__ import annotations

import argparse
import json

import suppressor


def cmd_list(_args):
    rules = []
    if suppressor.RULES_PATH.exists():
        rules = json.loads(suppressor.RULES_PATH.read_text(encoding="utf-8")).get("rules", [])
    if not rules:
        print("No suppression rules defined.")
        return
    for r in rules:
        state = "active" if r.get("active", True) else "revoked"
        conds = {k: v for k, v in r.items()
                 if k not in ("id", "created_at", "created_by", "reason", "active")}
        print(f"{r['id']}  [{state}]  {r.get('reason','')}")
        print(f"    by {r.get('created_by')} on {r.get('created_at')}")
        print(f"    matches: {conds}")


def cmd_add(args):
    rule = suppressor.add_rule(
        reason=args.reason,
        created_by=args.by,
        source=args.source,
        rule_id=args.rule_id,
        cve_id=args.cve,
        type=args.type,
        severity=args.severity,
        resource_pattern=args.resource,
        title_pattern=args.title,
    )
    print(f"Added {rule['id']}: {rule['reason']}")


def cmd_revoke(args):
    data = json.loads(suppressor.RULES_PATH.read_text(encoding="utf-8"))
    found = False
    for r in data.get("rules", []):
        if r["id"] == args.rule:
            r["active"] = False
            found = True
    if not found:
        print(f"No rule {args.rule}")
        return
    suppressor.save_rules(data["rules"])
    print(f"Revoked {args.rule}")


def main():
    ap = argparse.ArgumentParser(description="Manage suppression rules")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list").set_defaults(func=cmd_list)

    a = sub.add_parser("add")
    a.add_argument("--reason", required=True)
    a.add_argument("--by", default="analyst")
    a.add_argument("--source")
    a.add_argument("--rule-id")
    a.add_argument("--cve")
    a.add_argument("--type")
    a.add_argument("--severity")
    a.add_argument("--resource", help="glob against affected_resource, e.g. */test/*")
    a.add_argument("--title", help="glob against the title")
    a.set_defaults(func=cmd_add)

    r = sub.add_parser("revoke")
    r.add_argument("rule")
    r.set_defaults(func=cmd_revoke)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
