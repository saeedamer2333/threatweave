"""Unit tests for aws_monitor/monitor.py.

boto3 clients are never called for real: each check function receives an
already-constructed `session` object, so tests pass a lightweight fake that
mimics only the boto3 surface each check actually uses (get_paginator/
paginate, or a handful of direct methods). No network access, no real AWS
account needed.
"""
from __future__ import annotations

import json

import monitor


# ---------------------------------------------------------------------------
# Fakes - minimal stand-ins for the boto3 client surface each check uses.
# ---------------------------------------------------------------------------
class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self):
        return iter(self._pages)


class FakeEc2Client:
    def __init__(self, instance_pages=None, sg_pages=None):
        self._instance_pages = instance_pages or []
        self._sg_pages = sg_pages or []

    def get_paginator(self, name):
        if name == "describe_instances":
            return FakePaginator(self._instance_pages)
        if name == "describe_security_groups":
            return FakePaginator(self._sg_pages)
        raise ValueError(f"unexpected paginator {name}")


class FakeS3Client:
    def __init__(self, buckets, public_access_blocks=None, encryption_errors=None, pab_errors=None):
        self._buckets = buckets
        self._pab = public_access_blocks or {}
        self._pab_errors = pab_errors or {}
        self._enc_errors = encryption_errors or {}

    def list_buckets(self):
        return {"Buckets": [{"Name": n} for n in self._buckets]}

    def get_public_access_block(self, Bucket):
        if Bucket in self._pab_errors:
            raise Exception(self._pab_errors[Bucket])
        return {"PublicAccessBlockConfiguration": self._pab.get(Bucket, {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        })}

    def get_bucket_encryption(self, Bucket):
        if Bucket in self._enc_errors:
            raise Exception(self._enc_errors[Bucket])
        return {}


class FakeIamClient:
    def __init__(self, role_pages=None, user_pages=None, role_policies=None,
                 user_policies=None, access_keys=None):
        self._role_pages = role_pages or []
        self._user_pages = user_pages or []
        self._role_policies = role_policies or {}
        self._user_policies = user_policies or {}
        self._access_keys = access_keys or {}

    def get_paginator(self, name):
        if name == "list_roles":
            return FakePaginator(self._role_pages)
        if name == "list_users":
            return FakePaginator(self._user_pages)
        raise ValueError(f"unexpected paginator {name}")

    def list_attached_role_policies(self, RoleName):
        return {"AttachedPolicies": self._role_policies.get(RoleName, [])}

    def list_attached_user_policies(self, UserName):
        return {"AttachedPolicies": self._user_policies.get(UserName, [])}

    def list_access_keys(self, UserName):
        return {"AccessKeyMetadata": self._access_keys.get(UserName, [])}


class FakeSession:
    """A fake boto3.Session that dispatches to a dict of fake clients."""

    def __init__(self, clients: dict):
        self._clients = clients
        self.region_name = "us-east-1"

    def client(self, service, region_name=None):
        return self._clients[service]


# ---------------------------------------------------------------------------
# _finding / _open_to_world
# ---------------------------------------------------------------------------

def test_finding_includes_optional_fields_only_when_provided():
    f = monitor._finding("check", "resource", "HIGH", "detail")
    assert "attached_to" not in f
    assert "ports" not in f

    f2 = monitor._finding("check", "resource", "HIGH", "detail", attached_to="i-1", ports=[22])
    assert f2["attached_to"] == "i-1"
    assert f2["ports"] == [22]


def test_open_to_world_detects_ipv4_wildcard():
    assert monitor._open_to_world([{"CidrIp": "0.0.0.0/0"}], []) is True


def test_open_to_world_detects_ipv6_wildcard():
    assert monitor._open_to_world([], [{"CidrIpv6": "::/0"}]) is True


def test_open_to_world_false_for_restricted_cidr():
    assert monitor._open_to_world([{"CidrIp": "10.0.0.0/8"}], []) is False


def test_open_to_world_false_for_empty_ranges():
    assert monitor._open_to_world(None, None) is False


# ---------------------------------------------------------------------------
# check_ec2
# ---------------------------------------------------------------------------

def test_check_ec2_flags_public_ip():
    pages = [{"Reservations": [{"Instances": [{
        "InstanceId": "i-1", "State": {"Name": "running"},
        "PublicIpAddress": "1.2.3.4", "Tags": [{"Key": "Name", "Value": "juice-shop"}],
        "MetadataOptions": {"HttpTokens": "required"},
    }]}]}]
    session = FakeSession({"ec2": FakeEc2Client(instance_pages=pages)})

    findings = monitor.check_ec2(session, "us-east-1")

    assert len(findings) == 1
    assert findings[0]["check"] == "ec2_public_ip"
    assert findings[0]["internet_facing"] is True
    assert findings[0]["attached_to"] == "juice-shop"


def test_check_ec2_flags_imdsv2_not_enforced():
    pages = [{"Reservations": [{"Instances": [{
        "InstanceId": "i-1", "State": {"Name": "running"},
        "Tags": [], "MetadataOptions": {"HttpTokens": "optional"},
    }]}]}]
    session = FakeSession({"ec2": FakeEc2Client(instance_pages=pages)})

    findings = monitor.check_ec2(session, "us-east-1")

    assert any(f["check"] == "ec2_imdsv2_not_enforced" for f in findings)


def test_check_ec2_skips_terminated_instances():
    pages = [{"Reservations": [{"Instances": [{
        "InstanceId": "i-1", "State": {"Name": "terminated"},
        "PublicIpAddress": "1.2.3.4", "Tags": [],
    }]}]}]
    session = FakeSession({"ec2": FakeEc2Client(instance_pages=pages)})

    assert monitor.check_ec2(session, "us-east-1") == []


def test_check_ec2_no_findings_for_a_locked_down_instance():
    pages = [{"Reservations": [{"Instances": [{
        "InstanceId": "i-1", "State": {"Name": "running"}, "Tags": [],
        "MetadataOptions": {"HttpTokens": "required"},
    }]}]}]
    session = FakeSession({"ec2": FakeEc2Client(instance_pages=pages)})

    assert monitor.check_ec2(session, "us-east-1") == []


# ---------------------------------------------------------------------------
# check_security_groups
# ---------------------------------------------------------------------------

def test_check_security_groups_flags_open_sensitive_port():
    sg_pages = [{"SecurityGroups": [{
        "GroupId": "sg-1", "GroupName": "app-sg",
        "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    }]}]
    session = FakeSession({"ec2": FakeEc2Client(instance_pages=[], sg_pages=sg_pages)})

    findings = monitor.check_security_groups(session, "us-east-1")

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "SSH" in findings[0]["detail"]


def test_check_security_groups_all_ports_open_is_critical():
    sg_pages = [{"SecurityGroups": [{
        "GroupId": "sg-1", "GroupName": "wide-open",
        "IpPermissions": [{"FromPort": None, "ToPort": None, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    }]}]
    session = FakeSession({"ec2": FakeEc2Client(sg_pages=sg_pages)})

    findings = monitor.check_security_groups(session, "us-east-1")

    assert findings[0]["severity"] == "CRITICAL"


def test_check_security_groups_ignores_restricted_ingress():
    sg_pages = [{"SecurityGroups": [{
        "GroupId": "sg-1", "GroupName": "internal-only",
        "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}],
    }]}]
    session = FakeSession({"ec2": FakeEc2Client(sg_pages=sg_pages)})

    assert monitor.check_security_groups(session, "us-east-1") == []


def test_check_security_groups_links_attached_instance_name():
    instance_pages = [{"Reservations": [{"Instances": [{
        "InstanceId": "i-1", "State": {"Name": "running"},
        "Tags": [{"Key": "Name", "Value": "juice-shop"}],
        "SecurityGroups": [{"GroupId": "sg-1"}],
    }]}]}]
    sg_pages = [{"SecurityGroups": [{
        "GroupId": "sg-1", "GroupName": "app-sg",
        "IpPermissions": [{"FromPort": 3306, "ToPort": 3306, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    }]}]
    session = FakeSession({"ec2": FakeEc2Client(instance_pages=instance_pages, sg_pages=sg_pages)})

    findings = monitor.check_security_groups(session, "us-east-1")

    assert findings[0]["attached_to"] == "i-1 (juice-shop)"


# ---------------------------------------------------------------------------
# check_s3
# ---------------------------------------------------------------------------

def test_check_s3_flags_disabled_public_access_block():
    s3 = FakeS3Client(
        buckets=["app-uploads"],
        public_access_blocks={"app-uploads": {
            "BlockPublicAcls": False, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        }},
    )
    session = FakeSession({"s3": s3})

    findings = monitor.check_s3(session, "us-east-1")

    assert any(f["check"] == "s3_public_access_block_disabled" for f in findings)


def test_check_s3_flags_missing_public_access_block_configuration():
    s3 = FakeS3Client(buckets=["b1"], pab_errors={"b1": "NoSuchPublicAccessBlockConfiguration"})
    session = FakeSession({"s3": s3})

    findings = monitor.check_s3(session, "us-east-1")

    assert any(f["check"] == "s3_public_access_block_missing" for f in findings)


def test_check_s3_flags_disabled_encryption():
    s3 = FakeS3Client(buckets=["b1"], encryption_errors={"b1": "ServerSideEncryptionConfigurationNotFoundError"})
    session = FakeSession({"s3": s3})

    findings = monitor.check_s3(session, "us-east-1")

    assert any(f["check"] == "s3_encryption_disabled" for f in findings)


def test_check_s3_clean_bucket_produces_no_findings():
    s3 = FakeS3Client(buckets=["b1"])
    session = FakeSession({"s3": s3})

    assert monitor.check_s3(session, "us-east-1") == []


# ---------------------------------------------------------------------------
# check_iam
# ---------------------------------------------------------------------------

def test_check_iam_flags_admin_role():
    role_pages = [{"Roles": [{"RoleName": "app-deploy"}]}]
    iam = FakeIamClient(
        role_pages=role_pages,
        role_policies={"app-deploy": [{"PolicyName": "AdministratorAccess"}]},
    )
    session = FakeSession({"iam": iam})

    findings = monitor.check_iam(session, "us-east-1")

    assert any(f["check"] == "iam_admin_policy" and f["resource"] == "role/app-deploy" for f in findings)


def test_check_iam_skips_aws_managed_service_roles():
    role_pages = [{"Roles": [{"RoleName": "AWSServiceRoleForSupport"}]}]
    iam = FakeIamClient(role_pages=role_pages, role_policies={
        "AWSServiceRoleForSupport": [{"PolicyName": "AdministratorAccess"}],
    })
    session = FakeSession({"iam": iam})

    assert monitor.check_iam(session, "us-east-1") == []


def test_check_iam_flags_admin_user_and_excess_access_keys():
    user_pages = [{"Users": [{"UserName": "cli-access"}]}]
    iam = FakeIamClient(
        user_pages=user_pages,
        user_policies={"cli-access": [{"PolicyName": "AdministratorAccess"}]},
        access_keys={"cli-access": [{"AccessKeyId": "AKIA1"}, {"AccessKeyId": "AKIA2"}]},
    )
    session = FakeSession({"iam": iam})

    findings = monitor.check_iam(session, "us-east-1")
    checks = {f["check"] for f in findings}

    assert "iam_admin_policy" in checks
    assert "iam_multiple_access_keys" in checks


def test_check_iam_single_access_key_is_not_flagged():
    user_pages = [{"Users": [{"UserName": "normal-user"}]}]
    iam = FakeIamClient(user_pages=user_pages, access_keys={"normal-user": [{"AccessKeyId": "AKIA1"}]})
    session = FakeSession({"iam": iam})

    assert monitor.check_iam(session, "us-east-1") == []


# ---------------------------------------------------------------------------
# demo_findings / run()
# ---------------------------------------------------------------------------

def test_demo_findings_is_non_empty_and_well_formed():
    findings = monitor.demo_findings()
    assert len(findings) > 0
    assert all("check" in f and "severity" in f for f in findings)


def test_run_in_demo_mode_writes_the_report_file(tmp_path):
    out_path = tmp_path / "aws-findings.json"

    report = monitor.run(region=None, checks=monitor.ALL_CHECKS, demo=True, out_path=out_path)

    assert out_path.exists()
    saved = json.loads(out_path.read_text(encoding="utf-8"))
    assert saved["status"] == "ok"
    assert saved["findings"] == monitor.demo_findings()
    assert report == saved


def test_run_with_a_fake_session_aggregates_findings_from_all_checks(tmp_path, monkeypatch):
    fake_session = FakeSession({
        "ec2": FakeEc2Client(),
        "s3": FakeS3Client(buckets=[]),
        "iam": FakeIamClient(),
    })

    class FakeSts:
        def get_caller_identity(self):
            return {"Account": "194722404383", "Arn": "arn:aws:iam::194722404383:user/cli"}

    fake_session._clients["sts"] = FakeSts()

    import boto3
    monkeypatch.setattr(boto3, "Session", lambda: fake_session)

    out_path = tmp_path / "aws-findings.json"
    report = monitor.run(region="ap-southeast-1", checks=("ec2", "s3", "iam"), demo=False, out_path=out_path)

    assert report["status"] == "ok"
    assert report["account"] == "194722404383"
    assert report["checks_run"] == ["ec2", "s3", "iam"]
    assert out_path.exists()


def test_run_falls_back_to_empty_findings_when_aws_is_unavailable(tmp_path, monkeypatch):
    import boto3

    def raise_no_credentials():
        raise Exception("Unable to locate credentials")

    monkeypatch.setattr(boto3, "Session", raise_no_credentials)

    out_path = tmp_path / "aws-findings.json"
    report = monitor.run(region=None, checks=monitor.ALL_CHECKS, demo=False, out_path=out_path)

    assert report["status"] == "unavailable"
    assert report["findings"] == []
    assert out_path.exists()          # engine can still run on an empty report
