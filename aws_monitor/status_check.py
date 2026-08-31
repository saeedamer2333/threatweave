"""AWS connection + permission status for the dashboard's Settings page.

`sts.get_caller_identity()` alone proves credentials are *valid*, nothing
more - it is one of the very few AWS API calls that requires no IAM
permission at all, so a user could see "Connected" with a real account
number showing while every real check in monitor.py silently fails with
AccessDenied. This probes the same services monitor.py's checks actually
read from (EC2, S3, IAM), using the same top-level call each of those checks
depends on, so "connected" here means "the scan will actually produce
findings," not just "the credentials parse."

Usage:
    python status_check.py
"""
from __future__ import annotations

import json


def _is_access_denied(err: Exception) -> bool:
    """True only for a genuine permission error, not a network blip, a
    throttling error, or a misconfigured region - those are not evidence of
    a missing policy and should not be reported as one."""
    response = getattr(err, "response", None)
    if not response:
        return False
    code = response.get("Error", {}).get("Code", "")
    return code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation")


def check_permissions(session) -> dict[str, bool]:
    """One representative, read-only probe call per service monitor.py's
    checks use - not exhaustive, but each is the specific call every check
    in that service depends on (check_ec2/check_security_groups both start
    from describe_instances; check_s3 from list_buckets; check_iam from
    list_roles). True means either the call succeeded, or it failed for a
    reason other than a permission error (see _is_access_denied) - only a
    confirmed AccessDenied-shaped error reports False."""
    results: dict[str, bool] = {}

    try:
        session.client("ec2", region_name=session.region_name).describe_instances(MaxResults=5)
        results["ec2"] = True
    except Exception as e:
        results["ec2"] = not _is_access_denied(e)

    try:
        session.client("s3").list_buckets()
        results["s3"] = True
    except Exception as e:
        results["s3"] = not _is_access_denied(e)

    try:
        session.client("iam").list_roles(MaxItems=1)
        results["iam"] = True
    except Exception as e:
        results["iam"] = not _is_access_denied(e)

    return results


def check_status(session=None) -> dict:
    """Full status: identity plus, only once identity is confirmed valid,
    the permission probes above. A dead/invalid credential short-circuits
    before attempting any of them - there is nothing useful to probe with
    credentials that do not even authenticate."""
    import boto3

    session = session or boto3.Session()
    try:
        identity = session.client("sts").get_caller_identity()
    except Exception as e:
        return {"connected": False, "message": str(e)[:200]}

    permissions = check_permissions(session)
    return {
        "connected": True,
        "account": identity["Account"],
        "arn": identity["Arn"],
        "region": session.region_name,
        "permissions": permissions,
        "hasFullAccess": all(permissions.values()),
    }


def main() -> None:
    print(json.dumps(check_status()))


if __name__ == "__main__":
    main()
