"""Tests for github-webhook-receiver.py.

verify_signature is the security boundary here (anyone who finds this
endpoint's URL could otherwise trigger `git pull` on the box, or worse if
this were ever extended) - covered directly. The routing behaviour (ping vs
push, branch filtering, missing-secret refusal) is covered end-to-end
against a real running server, since that is where a wiring mistake would
actually show up.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

SCRIPT_PATH = Path(__file__).parent.parent / "github-webhook-receiver.py"


def _load_module(monkeypatch, secret="test-secret", branch="refs/heads/main"):
    monkeypatch.setenv("WEBHOOK_SECRET", secret)
    monkeypatch.setenv("WEBHOOK_BRANCH", branch)
    monkeypatch.setenv("TARGET_DIR", "/tmp/does-not-matter")
    spec = importlib.util.spec_from_file_location("github_webhook_receiver", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sign(secret: str, payload: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


# ---- verify_signature: the actual security boundary ----

def test_verify_signature_accepts_a_correctly_signed_payload(monkeypatch):
    mod = _load_module(monkeypatch)
    payload = b'{"ref": "refs/heads/main"}'
    assert mod.verify_signature("test-secret", payload, _sign("test-secret", payload)) is True


def test_verify_signature_rejects_a_payload_signed_with_the_wrong_secret(monkeypatch):
    mod = _load_module(monkeypatch)
    payload = b'{"ref": "refs/heads/main"}'
    assert mod.verify_signature("test-secret", payload, _sign("wrong-secret", payload)) is False


def test_verify_signature_rejects_a_tampered_payload(monkeypatch):
    mod = _load_module(monkeypatch)
    signed_for = b'{"ref": "refs/heads/main"}'
    tampered = b'{"ref": "refs/heads/evil"}'
    assert mod.verify_signature("test-secret", tampered, _sign("test-secret", signed_for)) is False


def test_verify_signature_rejects_a_missing_header(monkeypatch):
    mod = _load_module(monkeypatch)
    assert mod.verify_signature("test-secret", b"{}", None) is False


def test_verify_signature_rejects_a_header_without_the_sha256_prefix(monkeypatch):
    # GitHub's own format is always "sha256=<hex>" - a bare hex digest (the
    # legacy sha1 scheme's shape) must not be accepted as if it matched.
    mod = _load_module(monkeypatch)
    payload = b"{}"
    bare_digest = hmac.new(b"test-secret", payload, hashlib.sha256).hexdigest()
    assert mod.verify_signature("test-secret", payload, bare_digest) is False


# ---- end-to-end: real server, real HTTP requests ----

@pytest.fixture
def running_server(monkeypatch, tmp_path):
    mod = _load_module(monkeypatch, secret="itsasecret")
    monkeypatch.setattr(mod, "TARGET_DIR", str(tmp_path))
    pulls = []
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: pulls.append(a) or _FakeResult())
    triggers = []
    # Real network calls (the default trigger_scan) would try to resolve
    # "api", which does not exist in the test environment - not just slow,
    # but exercising real DNS/network behaviour instead of this module's own
    # logic. Faked here; the fallback-on-failure path gets its own test below.
    monkeypatch.setattr(mod, "trigger_scan", lambda: triggers.append(1) or "scan triggered (201)")

    server = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address, pulls, triggers
    finally:
        server.shutdown()
        thread.join(timeout=5)


class _FakeResult:
    returncode = 0
    stdout = "Already up to date.\n"
    stderr = ""


class _FailedPullResult:
    returncode = 1
    stdout = ""
    stderr = "fatal: not a git repository"


def _post(address, path, body: bytes, headers: dict) -> tuple[int, str]:
    req = urllib.request.Request(
        f"http://{address[0]}:{address[1]}{path}", data=body, headers=headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_a_correctly_signed_push_to_the_configured_branch_triggers_a_pull(running_server):
    address, pulls, triggers = running_server
    body = json.dumps({"ref": "refs/heads/main"}).encode()
    status, text = _post(address, "/webhook", body, {
        "X-GitHub-Event": "push",
        "X-Hub-Signature-256": _sign("itsasecret", body),
    })
    assert status == 200
    assert len(pulls) == 1


def test_a_successful_pull_immediately_triggers_a_scan_via_the_dashboard_api(running_server):
    # This is the actual point of the receiver beyond just keeping the clone
    # up to date - without it, a push would sit unscanned until Jenkins'
    # own poll happens to tick (up to 5 minutes later).
    address, pulls, triggers = running_server
    body = json.dumps({"ref": "refs/heads/main"}).encode()
    status, text = _post(address, "/webhook", body, {
        "X-GitHub-Event": "push",
        "X-Hub-Signature-256": _sign("itsasecret", body),
    })
    assert status == 200
    assert len(triggers) == 1
    assert "scan triggered" in text


def test_a_failed_pull_does_not_attempt_to_trigger_a_scan(monkeypatch, tmp_path):
    mod = _load_module(monkeypatch, secret="itsasecret")
    monkeypatch.setattr(mod, "TARGET_DIR", str(tmp_path))
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: _FailedPullResult())
    triggers = []
    monkeypatch.setattr(mod, "trigger_scan", lambda: triggers.append(1) or "scan triggered")

    server = mod.ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body = json.dumps({"ref": "refs/heads/main"}).encode()
        status, text = _post(server.server_address, "/webhook", body, {
            "X-GitHub-Event": "push",
            "X-Hub-Signature-256": _sign("itsasecret", body),
        })
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert status == 502
    assert triggers == []


def test_trigger_scan_failure_does_not_fail_the_webhook_response(monkeypatch):
    # The pull already succeeded and is the important side effect - Jenkins'
    # own poll is a safety net regardless, so a network hiccup reaching the
    # dashboard API here should degrade gracefully, not turn into a 500.
    mod = _load_module(monkeypatch)

    def raise_url_error(*a, **k):
        raise mod.urllib.error.URLError("connection refused")
    monkeypatch.setattr(mod.urllib.request, "urlopen", raise_url_error)

    result = mod.trigger_scan()

    assert "could not trigger a scan" in result
    assert "poll will still pick this up" in result


def test_an_unsigned_request_is_rejected_and_does_not_trigger_a_pull(running_server):
    address, pulls, triggers = running_server
    body = json.dumps({"ref": "refs/heads/main"}).encode()
    status, _ = _post(address, "/webhook", body, {"X-GitHub-Event": "push"})
    assert status == 401
    assert pulls == []


def test_a_push_to_a_different_branch_is_ignored(running_server):
    address, pulls, triggers = running_server
    body = json.dumps({"ref": "refs/heads/feature-x"}).encode()
    status, text = _post(address, "/webhook", body, {
        "X-GitHub-Event": "push",
        "X-Hub-Signature-256": _sign("itsasecret", body),
    })
    assert status == 202
    assert pulls == []


def test_a_ping_event_is_acknowledged_without_pulling(running_server):
    address, pulls, triggers = running_server
    body = b"{}"
    status, text = _post(address, "/webhook", body, {
        "X-GitHub-Event": "ping",
        "X-Hub-Signature-256": _sign("itsasecret", body),
    })
    assert status == 200
    assert pulls == []
