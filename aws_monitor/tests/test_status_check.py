"""Unit tests for aws_monitor/status_check.py.

Real boto3 is never called: a fake session/client stands in, matching the
pattern already used in test_monitor.py. The point of these checks is that
"connected" distinguishes "credentials are valid" from "credentials can
actually read anything" - get_caller_identity() alone cannot tell those
apart, since it needs no IAM permission at all.
"""
from __future__ import annotations

import status_check


class _AccessDeniedError(Exception):
    """Mimics botocore.exceptions.ClientError's shape closely enough for
    _is_access_denied to recognise it - a real ClientError also exposes
    .response the same way."""
    def __init__(self, code="AccessDenied"):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _OtherError(Exception):
    """A non-permission failure (network timeout, throttling, ...) shaped
    like a boto exception but with an unrelated error code."""
    def __init__(self):
        super().__init__("Throttling")
        self.response = {"Error": {"Code": "ThrottlingException"}}


class _FakeEc2:
    def __init__(self, error=None):
        self._error = error

    def describe_instances(self, MaxResults=None):
        if self._error:
            raise self._error
        return {"Reservations": []}


class _FakeS3:
    def __init__(self, error=None):
        self._error = error

    def list_buckets(self):
        if self._error:
            raise self._error
        return {"Buckets": []}


class _FakeIam:
    def __init__(self, error=None):
        self._error = error

    def list_roles(self, MaxItems=None):
        if self._error:
            raise self._error
        return {"Roles": []}


class _FakeSession:
    def __init__(self, ec2_error=None, s3_error=None, iam_error=None, region="us-east-1"):
        self._clients = {
            "ec2": _FakeEc2(ec2_error),
            "s3": _FakeS3(s3_error),
            "iam": _FakeIam(iam_error),
        }
        self.region_name = region

    def client(self, name, region_name=None):
        return self._clients[name]


# ---------------------------------------------------------------------------
# check_permissions
# ---------------------------------------------------------------------------

def test_all_permissions_true_when_every_probe_call_succeeds():
    result = status_check.check_permissions(_FakeSession())
    assert result == {"ec2": True, "s3": True, "iam": True}


def test_reports_false_only_for_the_service_with_a_genuine_access_denied():
    result = status_check.check_permissions(_FakeSession(s3_error=_AccessDeniedError()))
    assert result == {"ec2": True, "s3": False, "iam": True}


def test_reports_all_three_false_when_all_three_lack_permission():
    result = status_check.check_permissions(_FakeSession(
        ec2_error=_AccessDeniedError(), s3_error=_AccessDeniedError(), iam_error=_AccessDeniedError(),
    ))
    assert result == {"ec2": False, "s3": False, "iam": False}


def test_a_non_permission_error_does_not_report_missing_access():
    # Throttling, a network blip, a bad region - none of these mean the
    # policy is missing, and reporting it as such would be actively
    # misleading (the user would go add a policy that was never the issue).
    result = status_check.check_permissions(_FakeSession(ec2_error=_OtherError()))
    assert result["ec2"] is True


def test_recognises_unauthorized_operation_as_well_as_access_denied():
    result = status_check.check_permissions(_FakeSession(iam_error=_AccessDeniedError("UnauthorizedOperation")))
    assert result["iam"] is False


# ---------------------------------------------------------------------------
# check_status
# ---------------------------------------------------------------------------

class _FakeSts:
    def __init__(self, identity=None, error=None):
        self._identity = identity
        self._error = error

    def get_caller_identity(self):
        if self._error:
            raise self._error
        return self._identity


class _FullFakeSession(_FakeSession):
    def __init__(self, identity, sts_error=None, **kwargs):
        super().__init__(**kwargs)
        self._clients["sts"] = _FakeSts(identity, sts_error)


def test_check_status_reports_full_access_when_every_probe_succeeds():
    identity = {"Account": "111122223333", "Arn": "arn:aws:iam::111122223333:user/test"}
    session = _FullFakeSession(identity)

    result = status_check.check_status(session)

    assert result["connected"] is True
    assert result["account"] == "111122223333"
    assert result["hasFullAccess"] is True
    assert result["permissions"] == {"ec2": True, "s3": True, "iam": True}


def test_check_status_reports_partial_access_when_one_service_lacks_permission():
    identity = {"Account": "111122223333", "Arn": "arn:aws:iam::111122223333:user/test"}
    session = _FullFakeSession(identity, s3_error=_AccessDeniedError())

    result = status_check.check_status(session)

    assert result["connected"] is True
    assert result["hasFullAccess"] is False
    assert result["permissions"]["s3"] is False


def test_check_status_reports_not_connected_when_identity_itself_fails():
    # Invalid/expired credentials - nothing downstream is worth probing.
    session = _FullFakeSession(identity=None, sts_error=Exception("InvalidClientTokenId"))

    result = status_check.check_status(session)

    assert result == {"connected": False, "message": "InvalidClientTokenId"}
    # Confirms the short-circuit: none of the three probe clients were
    # even asked, since the fakes would happily succeed if called.
