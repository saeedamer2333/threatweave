"""Target detection: what to scan, and where things live on the host.

One implementation used in three places, so they can never disagree:

  startup-env   The all-in-one image's entrypoint runs this before Jenkins and
                the API start. It prints `export` lines for anything the user
                did not pass themselves:
                  - HOST_WORKSPACE / HOST_FINDINGS / TARGET_PATH, read from this container's own
                    mounts through the Docker socket (scanners run as sibling
                    containers, so they need real host paths);
                  - SCAN_SOURCE_DIR / SCAN_IAC_DIR / SCAN_SONAR_KEY, detected
                    from the project mounted at /target.
                A value the user passed with -e always wins, even an empty one.
  targets       Used by the dashboard's Settings page to suggest values.
  check         Used by the Settings page to confirm a typed path, or a
                container image name, before a ten-minute scan finds out it
                was wrong.

Detection never guesses a container image: an image name cannot be derived
from source code, so SCAN_IMAGE is only ever set by the user.

Usage:
    python target_detect.py startup-env
    python target_detect.py targets [--root /target]
    python target_detect.py check --kind iac|source --path /target/infra
    python target_detect.py check --kind image --path myapp:latest
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import shlex
import socket
import sys
from urllib.parse import quote
from pathlib import Path, PurePosixPath

TARGET = "/target"
WORKSPACE = "/workspace"
FINDINGS = "/workspace/findings"
DOCKER_SOCKET = "/var/run/docker.sock"

# Never descended into while searching: dependencies, VCS data, build output.
SKIP_DIRS = {
    "node_modules", ".git", ".hg", ".svn", "dist", "build", "out", "coverage",
    ".venv", "venv", "env", "__pycache__", ".terraform", ".next", ".nuxt",
    "vendor", ".idea", ".vscode", ".cache", ".pytest_cache", ".threatweave",
}
MAX_DEPTH = 6
MAX_ENTRIES = 20000          # stop walking a huge tree rather than hang startup
SNIFF_BYTES = 4096


# --------------------------------------------------------------------- paths
def to_host_path(source: str) -> str:
    """Docker Desktop reports Windows mounts as D:\\a\\b; the scanners are
    started with forward slashes (D:/a/b), which Docker accepts everywhere."""
    return source.replace("\\", "/").rstrip("/") or "/"


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 5.0):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def _docker_get(path: str, socket_path: str = DOCKER_SOCKET, timeout: float = 5.0) -> int:
    """HTTP status of a GET against the Docker Engine API (0 if unreachable)."""
    try:
        conn = _UnixHTTPConnection(socket_path, timeout=timeout)
        conn.request("GET", path)
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status
    except (OSError, http.client.HTTPException):
        return 0


def own_mounts(socket_path: str = DOCKER_SOCKET) -> list[dict]:
    """This container's mounts, from the Docker Engine API. The hostname is the
    container's short ID unless --hostname was given; fall back to scanning
    /proc for the full ID in that case."""
    ids = [os.environ.get("HOSTNAME", "")]
    try:
        text = Path("/proc/self/mountinfo").read_text()
        ids += re.findall(r"/containers/([0-9a-f]{64})/", text)
    except OSError:
        pass
    for cid in [i for i in ids if i]:
        try:
            conn = _UnixHTTPConnection(socket_path)
            conn.request("GET", f"/containers/{cid}/json")
            resp = conn.getresponse()
            body = resp.read()
            conn.close()
            if resp.status == 200:
                return json.loads(body).get("Mounts", [])
        except (OSError, ValueError, http.client.HTTPException):
            continue
    return []


def host_paths(mounts: list[dict]) -> dict[str, str]:
    """HOST_WORKSPACE, HOST_FINDINGS and TARGET_PATH from the mounts, when
    they can be known.

    HOST_WORKSPACE is the host folder behind /workspace: either /workspace
    itself (a clone of the repository) or the parent of a folder mounted at
    /workspace/findings (results only - the engine is already in the image).
    HOST_FINDINGS is the results folder itself, which need not be called
    "findings" on the host - scanners write their reports into it.
    """
    by_dest = {m.get("Destination"): to_host_path(m.get("Source", "")) for m in mounts
               if m.get("Source")}
    out: dict[str, str] = {}
    if WORKSPACE in by_dest:
        out["HOST_WORKSPACE"] = by_dest[WORKSPACE]
    elif FINDINGS in by_dest:
        out["HOST_WORKSPACE"] = str(PurePosixPath(by_dest[FINDINGS]).parent)
    if FINDINGS in by_dest:
        out["HOST_FINDINGS"] = by_dest[FINDINGS]
    if TARGET in by_dest:
        out["TARGET_PATH"] = by_dest[TARGET]
    return out


# ------------------------------------------------------------ what to scan
def _has_entries(path: Path) -> bool:
    try:
        return any(path.iterdir())
    except OSError:
        return False


def _sniff(path: Path) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read(SNIFF_BYTES)
    except OSError:
        return ""


def _is_cloudformation(path: Path) -> bool:
    name = path.name.lower()
    if name.endswith(".template.json"):
        return True
    if not name.endswith((".json", ".yaml", ".yml", ".template")):
        return False
    if name in ("package.json", "package-lock.json", "tsconfig.json", "cdk.json",
                "cdk.context.json", "composer.json"):
        return False
    head = _sniff(path)
    return ("AWSTemplateFormatVersion" in head
            or ('"Resources"' in head and '"AWS::' in head)
            or ("Resources:" in head and "Type: AWS::" in head))


def iac_counts(directory: Path) -> dict[str, int]:
    """IaC files directly inside one folder, by kind."""
    counts = {"terraform": 0, "cloudformation": 0}
    try:
        for entry in directory.iterdir():
            if not entry.is_file():
                continue
            if entry.suffix == ".tf":
                counts["terraform"] += 1
            elif _is_cloudformation(entry):
                counts["cloudformation"] += 1
    except OSError:
        pass
    return counts


def iac_candidates(root: Path) -> list[dict]:
    """Every folder under root holding Terraform or CloudFormation (including
    CDK's synthesized cdk.out), best first: most files, then shallowest."""
    found: list[dict] = []
    visited = 0
    stack = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        visited += 1
        if visited > MAX_ENTRIES:
            break
        counts = iac_counts(directory)
        total = counts["terraform"] + counts["cloudformation"]
        if total:
            kind = "terraform" if counts["terraform"] >= counts["cloudformation"] else "cloudformation"
            if directory.name == "cdk.out":
                kind = "cdk"
            found.append({"path": directory.as_posix(), "kind": kind, "files": total, "depth": depth})
        # cdk.out's asset.* folders are bundled Lambda code, not more templates.
        if depth >= MAX_DEPTH or directory.name == "cdk.out":
            continue
        try:
            children = sorted((c for c in directory.iterdir()
                               if c.is_dir() and c.name not in SKIP_DIRS and not c.is_symlink()),
                              key=lambda c: c.name, reverse=True)
        except OSError:
            continue
        stack.extend((c, depth + 1) for c in children)
    found.sort(key=lambda c: (-c["files"], c["depth"], c["path"]))
    for c in found:
        del c["depth"]
    return found


def source_dir(root: Path) -> str:
    """The folder to scan for code and secrets. Usually root itself; when root
    is only a wrapper around a single Git repository (the bundled demo keeps
    OWASP Juice Shop one level down), that repository."""
    if (root / ".git").exists():
        return root.as_posix()
    try:
        repos = [c for c in root.iterdir() if c.is_dir() and (c / ".git").exists()]
    except OSError:
        repos = []
    return repos[0].as_posix() if len(repos) == 1 else root.as_posix()


def sonar_key(name: str) -> str:
    """SonarQube accepts letters, digits and - _ . : in project keys."""
    return re.sub(r"[^A-Za-z0-9._:-]", "-", name.strip()) or "project"


def project_name(source: Path, host_target: str = "") -> str:
    pkg = source / "package.json"
    if pkg.is_file():
        try:
            name = json.loads(pkg.read_text(encoding="utf-8")).get("name")
            if isinstance(name, str) and name.strip():
                return sonar_key(name.split("/")[-1])
        except (OSError, ValueError):
            pass
    base = PurePosixPath(host_target).name if host_target else source.name
    return sonar_key(base or "project")


def detect_targets(root: str = TARGET, host_target: str = "") -> dict:
    """Suggested scan targets for the project mounted at root. An empty
    sourceDir means nothing is mounted."""
    rootp = Path(root)
    if not _has_entries(rootp):
        return {"sourceDir": "", "hasDockerfile": False, "iacCandidates": []}
    src = source_dir(rootp)
    candidates = iac_candidates(Path(src))
    result = {
        "sourceDir": src,
        "projectName": project_name(Path(src), host_target),
        "hasDockerfile": (Path(src) / "Dockerfile").is_file(),
        "iacCandidates": candidates,
    }
    if candidates:
        result["iacDir"] = candidates[0]["path"]
    return result


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def check_path(kind: str, path: str, allowed: tuple[str, ...] = (TARGET, WORKSPACE)) -> dict:
    """Is a typed path usable? Returns ok/level/message for the Settings page."""
    p = path.strip()
    if not p:
        return {"ok": True, "level": "info", "message": "Empty: this scanner is skipped."}
    if not any(_within(Path(p), Path(a)) for a in allowed):
        return {"ok": False, "level": "error",
                "message": "Use a path inside /target (your project) - other container paths are not scanned."}
    real = Path(p)
    # In the split docker-compose setup the API container does not have
    # Jenkins' /workspace, so a /workspace path cannot be verified from here.
    if _within(real, Path(WORKSPACE)) and not Path(WORKSPACE).exists():
        return {"ok": True, "level": "info", "message": "This path is inside ThreatWeave itself and cannot be checked here."}
    if not real.exists():
        return {"ok": False, "level": "error", "message": f"{p} does not exist."}
    if not real.is_dir():
        return {"ok": False, "level": "error", "message": f"{p} is a file, not a folder."}
    if kind == "iac":
        cands = iac_candidates(real)
        total = sum(c["files"] for c in cands)
        if not total:
            return {"ok": True, "level": "warn",
                    "message": f"{p} exists but has no Terraform, CDK or CloudFormation files - Checkov would find nothing."}
        inside = [c for c in cands if c["path"] == real.as_posix()]
        if inside:
            c = inside[0]
            label = {"terraform": "Terraform", "cdk": "CDK CloudFormation", "cloudformation": "CloudFormation"}[c["kind"]]
            return {"ok": True, "level": "ok", "message": f"Found {c['files']} {label} file(s) in {p}."}
        return {"ok": True, "level": "ok",
                "message": f"Found {total} IaC file(s) in {len(cands)} folder(s) under {p}; Checkov scans them all."}
    # source
    if not _has_entries(real):
        return {"ok": True, "level": "warn", "message": f"{p} is empty - nothing to scan."}
    if not (real / ".git").exists() and not any((a / ".git").exists() for a in real.parents):
        return {"ok": True, "level": "warn",
                "message": f"{p} is not in a Git repository - SonarQube will scan it, but GitLeaks needs Git history, "
                           "and automatic runs cannot tell when the code changed. If the repository root is a parent "
                           "folder, start ThreatWeave from that folder instead so its .git is mounted too."}
    return {"ok": True, "level": "ok", "message": f"{p} looks good."}


IMAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$")


def check_image(name: str, docker_get=_docker_get) -> dict:
    """Can Trivy get this image? Local first, then the registry, the same
    order the pipeline uses (docker image inspect, then docker pull)."""
    n = name.strip()
    if not n:
        return {"ok": True, "level": "info", "message": "Empty: Trivy is skipped."}
    if not IMAGE_NAME.match(n):
        return {"ok": False, "level": "error", "message": f"{n} is not a valid image name, e.g. myapp:latest."}
    ref = quote(n, safe="/:@")
    local = docker_get(f"/images/{ref}/json")
    if local == 200:
        return {"ok": True, "level": "ok", "message": f"{n} is built on this machine - Trivy will scan it."}
    if local == 0:
        return {"ok": True, "level": "info", "message": "Docker is not reachable from here, so the image cannot be checked."}
    # Asks the registry for the manifest without pulling anything.
    remote = docker_get(f"/distribution/{ref}/json", timeout=15.0)
    if remote == 200:
        return {"ok": True, "level": "warn",
                "message": f"{n} is not built on this machine, but exists in a registry - it will be pulled at scan time."}
    return {"ok": False, "level": "error",
            "message": f"{n} was not found on this machine or in a public registry. Build it first "
                       f"(docker build -t {n} .) or check the name - otherwise Trivy will fail."}


# ------------------------------------------------------------------ startup
def startup_env(environ: dict | None = None, mounts: list[dict] | None = None,
                root: str = TARGET) -> dict[str, str]:
    """Values to add to the environment before Jenkins and the API start. Only
    keys the user did not set are returned; SCAN_DETECTED lists which SCAN_*
    values came from detection, so Settings can label them."""
    env = os.environ if environ is None else environ
    out: dict[str, str] = {}

    missing_paths = [k for k in ("HOST_WORKSPACE", "HOST_FINDINGS", "TARGET_PATH") if k not in env]
    if missing_paths:
        found = host_paths(own_mounts() if mounts is None else mounts)
        for k in missing_paths:
            if k in found:
                out[k] = found[k]

    host_target = env.get("TARGET_PATH") or out.get("TARGET_PATH", "")
    targets = detect_targets(root, host_target)
    if not targets["sourceDir"]:
        return out
    detected = {
        "SCAN_SOURCE_DIR": targets["sourceDir"],
        "SCAN_IAC_DIR": targets.get("iacDir", ""),
        "SCAN_SONAR_KEY": targets.get("projectName", ""),
    }
    filled = []
    for key, value in detected.items():
        if key not in env and value:
            out[key] = value
            filled.append(key)
    if filled:
        out["SCAN_DETECTED"] = ",".join(filled)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("startup-env")
    t = sub.add_parser("targets")
    t.add_argument("--root", default=TARGET)
    c = sub.add_parser("check")
    c.add_argument("--kind", choices=("iac", "source", "image"), required=True)
    c.add_argument("--path", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "startup-env":
        values = startup_env()
        for key, value in values.items():
            print(f"export {key}={shlex.quote(value)}")
        # Human-readable summary for the container log (stderr, so the
        # entrypoint can eval stdout safely).
        for key, value in values.items():
            print(f"[threatweave] {key}={value}", file=sys.stderr)
    elif args.cmd == "targets":
        print(json.dumps(detect_targets(args.root, os.environ.get("TARGET_PATH", ""))))
    elif args.kind == "image":
        print(json.dumps(check_image(args.path)))
    else:
        print(json.dumps(check_path(args.kind, args.path)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
