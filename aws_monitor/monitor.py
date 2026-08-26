"""AWS cloud governance monitor.

Reads the live state of an AWS account using Boto3 and reports security
findings as JSON for the AIOps engine to consume.

Credentials: resolved by Boto3's normal chain -- IAM role (when running on
EC2), then environment variables, then ~/.aws/credentials. Nothing is stored
by this tool and no keys appear in code.

Permissions: read-only. Every call is a describe/list/get. The monitor cannot
modify any resource, which matches the project's "advise only" constraint.

Usage:
    python monitor.py                       # all checks, default region
    python monitor.py --region eu-west-1
    python monitor.py --checks ec2,sg       # subset
    python monitor.py --demo                # no AWS needed, sample output
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE.parent / "findings" / "aws-findings.json"

# Ports that should never be open to the whole internet.
SENSITIVE_PORTS = {
    22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch", 1433: "MSSQL",
}

ALL_CHECKS = ("ec2", "sg", "s3", "iam")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _finding(check, resource, severity, detail, *, attached_to=None,
             internet_facing=False, ports=None) -> dict:
    f = {
        "check": check,
        "resource": resource,
        "severity": severity,
        "detail": detail,
        "internet_facing": internet_facing,
    }
    if attached_to:
        f["attached_to"] = attached_to
    if ports:
        f["ports"] = ports
    return f


def _open_to_world(ip_ranges, ipv6_ranges) -> bool:
    if any(r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges or []):
        return True
    return any(r.get("CidrIpv6") == "::/0" for r in ipv6_ranges or [])


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------
def check_ec2(session, region) -> list[dict]:
    out = []
    ec2 = session.client("ec2", region_name=region)
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for res in page.get("Reservations", []):
            for inst in res.get("Instances", []):
                if inst.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                    continue
                iid = inst["InstanceId"]
                name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), iid)
                public_ip = inst.get("PublicIpAddress")
                if public_ip:
                    out.append(_finding(
                        "ec2_public_ip", iid, "MEDIUM",
                        f"EC2 instance has a public IPv4 address ({public_ip}).",
                        attached_to=name, internet_facing=True,
                    ))
                if not inst.get("MetadataOptions", {}).get("HttpTokens") == "required":
                    out.append(_finding(
                        "ec2_imdsv2_not_enforced", iid, "MEDIUM",
                        "Instance metadata service v2 (IMDSv2) is not enforced, "
                        "allowing SSRF attacks to steal instance credentials.",
                        attached_to=name,
                    ))
    return out


def check_security_groups(session, region) -> list[dict]:
    out = []
    ec2 = session.client("ec2", region_name=region)

    # which security groups are actually attached to a running instance
    attached: dict[str, str] = {}
    try:
        for page in ec2.get_paginator("describe_instances").paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    if inst.get("State", {}).get("Name") == "terminated":
                        continue
                    label = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                                 inst["InstanceId"])
                    for g in inst.get("SecurityGroups", []):
                        attached[g["GroupId"]] = f'{inst["InstanceId"]} ({label})'
    except Exception:
        pass

    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page.get("SecurityGroups", []):
            gid = sg["GroupId"]
            open_ports: list[int] = []
            world_open = False
            for perm in sg.get("IpPermissions", []):
                if not _open_to_world(perm.get("IpRanges"), perm.get("Ipv6Ranges")):
                    continue
                world_open = True
                frm, to = perm.get("FromPort"), perm.get("ToPort")
                if frm is None:                       # all traffic
                    open_ports.append(-1)
                    continue
                for port in SENSITIVE_PORTS:
                    if frm <= port <= to:
                        open_ports.append(port)
            if not world_open:
                continue

            named = sorted({SENSITIVE_PORTS[p] for p in open_ports if p in SENSITIVE_PORTS})
            if -1 in open_ports:
                sev, what = "CRITICAL", "ALL ports"
            elif named:
                sev, what = "HIGH", ", ".join(named)
            else:
                sev, what = "MEDIUM", "one or more ports"

            out.append(_finding(
                "security_group_open_ingress", gid, sev,
                f"Inbound rule allows 0.0.0.0/0 on {what} for security group "
                f'"{sg.get("GroupName", gid)}".',
                attached_to=attached.get(gid),
                internet_facing=True,
                ports=[p for p in open_ports if p > 0] or None,
            ))
    return out


def check_s3(session, region) -> list[dict]:
    out = []
    s3 = session.client("s3", region_name=region)
    buckets = s3.list_buckets().get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        # public access block
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(cfg.get(k) for k in
                       ("BlockPublicAcls", "IgnorePublicAcls",
                        "BlockPublicPolicy", "RestrictPublicBuckets")):
                out.append(_finding(
                    "s3_public_access_block_disabled", f"s3://{name}", "HIGH",
                    "Bucket does not fully block public access.",
                    internet_facing=True,
                ))
        except Exception as e:
            if "NoSuchPublicAccessBlockConfiguration" in str(e):
                out.append(_finding(
                    "s3_public_access_block_missing", f"s3://{name}", "HIGH",
                    "Bucket has no public access block configured.",
                    internet_facing=True,
                ))
        # encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except Exception as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                out.append(_finding(
                    "s3_encryption_disabled", f"s3://{name}", "MEDIUM",
                    "Bucket does not have default server-side encryption enabled.",
                ))
    return out


def check_iam(session, region) -> list[dict]:
    out = []
    iam = session.client("iam")

    for page in iam.get_paginator("list_roles").paginate():
        for role in page.get("Roles", []):
            rname = role["RoleName"]
            if rname.startswith("AWSServiceRole"):        # AWS-managed, skip
                continue
            try:
                attached = iam.list_attached_role_policies(RoleName=rname)
                for p in attached.get("AttachedPolicies", []):
                    if p["PolicyName"] in ("AdministratorAccess",):
                        out.append(_finding(
                            "iam_admin_policy", f"role/{rname}", "HIGH",
                            "IAM role has the AdministratorAccess policy attached.",
                        ))
            except Exception:
                continue

    for page in iam.get_paginator("list_users").paginate():
        for user in page.get("Users", []):
            uname = user["UserName"]
            try:
                for p in iam.list_attached_user_policies(UserName=uname).get("AttachedPolicies", []):
                    if p["PolicyName"] == "AdministratorAccess":
                        out.append(_finding(
                            "iam_admin_policy", f"user/{uname}", "HIGH",
                            "IAM user has the AdministratorAccess policy attached directly.",
                        ))
                keys = iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", [])
                if len(keys) > 1:
                    out.append(_finding(
                        "iam_multiple_access_keys", f"user/{uname}", "MEDIUM",
                        f"IAM user has {len(keys)} active access keys; unused keys widen the attack surface.",
                    ))
            except Exception:
                continue
    return out


CHECK_FUNCS = {
    "ec2": ("EC2 instances", check_ec2),
    "sg": ("Security groups", check_security_groups),
    "s3": ("S3 buckets", check_s3),
    "iam": ("IAM roles and users", check_iam),
}


# ---------------------------------------------------------------------------
# demo mode
# ---------------------------------------------------------------------------
def demo_findings() -> list[dict]:
    return [
        _finding("security_group_open_ingress", "sg-0af12", "HIGH",
                 "Inbound rule allows 0.0.0.0/0 on SSH, MySQL for security group \"app-sg\".",
                 attached_to="i-09bc (juice-shop)", internet_facing=True, ports=[22, 3306]),
        _finding("ec2_public_ip", "i-09bc", "MEDIUM",
                 "EC2 instance has a public IPv4 address (54.12.9.7).",
                 attached_to="juice-shop", internet_facing=True),
        _finding("s3_public_access_block_disabled", "s3://app-user-uploads", "HIGH",
                 "Bucket does not fully block public access.", internet_facing=True),
        _finding("iam_admin_policy", "role/app-deploy", "HIGH",
                 "IAM role has the AdministratorAccess policy attached."),
    ]


# ---------------------------------------------------------------------------
def run(region: str | None, checks: tuple[str, ...], demo: bool, out_path: Path) -> dict:
    now = datetime.now(timezone.utc)
    findings: list[dict] = []
    account = "demo"
    used_region = region or "us-east-1"
    status = "ok"

    if demo:
        print("Running in demo mode (no AWS calls)")
        findings = demo_findings()
    else:
        try:
            import boto3
            from botocore.exceptions import BotoCoreError, ClientError

            session = boto3.Session()
            used_region = region or session.region_name or "us-east-1"
            ident = session.client("sts").get_caller_identity()
            account = ident["Account"]
            print(f"Connected to AWS account {account}, region {used_region}")
            print(f"Identity: {ident['Arn']}\n")

            for key in checks:
                label, func = CHECK_FUNCS[key]
                print(f"  checking {label} ...", end=" ", flush=True)
                try:
                    got = func(session, used_region)
                    findings.extend(got)
                    print(f"{len(got)} finding(s)")
                except (ClientError, BotoCoreError) as e:
                    code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
                    if code in ("AccessDenied", "UnauthorizedOperation"):
                        print("access denied (skipped)")
                    else:
                        print(f"error: {code or e}")
                except Exception as e:
                    print(f"error: {e}")

        except Exception as e:
            # No credentials / offline / boto3 missing -> never break the pipeline.
            status = "unavailable"
            print(f"AWS unavailable: {e}")
            print("Writing an empty findings file so the engine can still run.")

    report = {
        "scanned_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "account": account,
        "region": used_region,
        "status": status,
        "checks_run": list(checks),
        "findings": findings,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nWrote {len(findings)} finding(s) -> {out_path}")
    return report


def main():
    ap = argparse.ArgumentParser(description="AWS cloud governance monitor")
    ap.add_argument("--region", default=None, help="AWS region (default: profile region)")
    ap.add_argument("--checks", default=",".join(ALL_CHECKS),
                    help=f"comma-separated subset of {','.join(ALL_CHECKS)}")
    ap.add_argument("--demo", action="store_true", help="emit sample findings, no AWS calls")
    ap.add_argument("--output", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    checks = tuple(c.strip() for c in args.checks.split(",") if c.strip() in CHECK_FUNCS)
    run(args.region, checks, args.demo, Path(args.output))


if __name__ == "__main__":
    main()
