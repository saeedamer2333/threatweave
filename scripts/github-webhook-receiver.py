"""Minimal GitHub webhook receiver: on a push to the configured branch, runs
`git pull` in the target directory, then immediately asks the dashboard API
to start a scan - the same `/api/pipeline/run` endpoint the dashboard's own
"Run scan" button calls, so it shows up in the dashboard's live tracking
exactly like a manual click would (build number, current stage, all of it).

Triggering directly here, rather than waiting for Jenkins' own polling (the
Jenkinsfile's `cron('H/5 * * * *')`) to notice the change on its next tick,
is what makes a push scan-worthy within seconds instead of within minutes.
The poll stays in place regardless, as a safety net - if the trigger call
below fails for any reason, the change is still on disk and gets picked up
on the next tick.

Deliberately does not give Jenkins its own GitHub checkout/SCM trigger -
that would mean every deployment (local laptop or EC2) needs its own GitHub
App/credentials wired into Jenkins. Instead, this one small, replaceable
piece keeps a local clone in sync and kicks the scan off; everything
downstream (the scanners, the dashboard) is exactly what already runs today
for a purely local target.

Stdlib only, deliberately - this is a small trust boundary (it runs `git
pull` in response to a network request) and pulling in a web framework here
would be more surface area than the job needs.
"""
import hashlib
import hmac
import json
import os
import subprocess
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
TARGET_DIR = os.environ.get("TARGET_DIR", "/target")
WEBHOOK_BRANCH = os.environ.get("WEBHOOK_BRANCH", "refs/heads/main")
PORT = int(os.environ.get("PORT", "9000"))
# The compose service name, not localhost - this receiver and the api
# service are sibling containers on the same compose network.
API_URL = os.environ.get("API_URL", "http://api:4000")


def trigger_scan() -> str:
    """Best-effort - a failure here is not fatal, since the pull already
    succeeded and Jenkins' own poll will pick the change up regardless
    (just up to 5 minutes later instead of immediately)."""
    try:
        req = urllib.request.Request(f"{API_URL}/api/pipeline/run", method="POST", data=b"")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return f"scan triggered ({resp.status})"
    except urllib.error.URLError as e:
        return f"could not trigger a scan ({e}) - Jenkins' own poll will still pick this up within a few minutes"


def verify_signature(secret: str, payload: bytes, header_value: str | None) -> bool:
    """GitHub signs the payload with the shared secret (HMAC-SHA256) so an
    attacker who merely guesses this endpoint's URL cannot trigger a `git
    pull` - without this check, anyone on the network could POST here."""
    if not header_value or not header_value.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", header_value)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # noqa: A002 - stdlib override signature
        print(f"[webhook] {self.address_string()} - {fmt % args}")

    def _respond(self, status: int, message: str) -> None:
        body = message.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - required BaseHTTPRequestHandler name
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length)

        if not WEBHOOK_SECRET:
            self._respond(500, "WEBHOOK_SECRET is not configured on the receiver - refusing to process unauthenticated webhooks")
            return
        if not verify_signature(WEBHOOK_SECRET, payload, self.headers.get("X-Hub-Signature-256")):
            self._respond(401, "invalid or missing signature")
            return

        event = self.headers.get("X-GitHub-Event", "")
        if event == "ping":
            self._respond(200, "pong")
            return
        if event != "push":
            self._respond(202, f"ignored: not a push event ({event})")
            return

        try:
            body = json.loads(payload or b"{}")
        except json.JSONDecodeError:
            self._respond(400, "invalid JSON payload")
            return

        ref = body.get("ref", "")
        if ref != WEBHOOK_BRANCH:
            self._respond(202, f"ignored: push to {ref}, not the configured branch {WEBHOOK_BRANCH}")
            return

        # Fixed command, no request-derived input reaches the shell - ref/
        # branch are only ever compared against, never interpolated in.
        result = subprocess.run(
            ["git", "-C", TARGET_DIR, "pull", "--ff-only"],
            capture_output=True, text=True, timeout=60,
        )
        print(f"[webhook] git pull in {TARGET_DIR}: {result.returncode}\n{result.stdout}{result.stderr}")
        if result.returncode != 0:
            self._respond(502, f"git pull failed: {result.stderr.strip()[:500]}")
            return

        trigger_result = trigger_scan()
        print(f"[webhook] {trigger_result}")
        self._respond(200, f"pulled latest for {ref}; {trigger_result}")


def main() -> None:
    if not WEBHOOK_SECRET:
        print("WARNING: WEBHOOK_SECRET is not set - every request will be rejected. Set it to the same value configured in the GitHub webhook.")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[webhook] listening on :{PORT}, pulling {TARGET_DIR} on push to {WEBHOOK_BRANCH}")
    server.serve_forever()


if __name__ == "__main__":
    main()
