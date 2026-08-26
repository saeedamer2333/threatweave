"""Build the three validation scenarios from real captured scan data.

The evaluation needs a controlled gradient of security posture, but inventing
findings would make the results meaningless. Every scenario here is therefore
derived from the real reports captured by the pipeline against OWASP Juice
Shop and the author's AWS account - scenarios differ only in WHICH subset of
that real evidence is present, mirroring how the same system would look at
three different stages of remediation.

  Scenario 1 - Baseline (remediated)
      Dependencies patched, secrets removed from source, infrastructure
      hardened. Only low-severity residue remains.
      Expected: health > 80, no attack paths.

  Scenario 2 - Moderate risk (partially remediated)
      Critical CVEs fixed and secrets cleaned, but medium-severity
      dependencies and one internet-facing exposure remain.
      Expected: health 40-70, exposure visible.

  Scenario 3 - Critical (unremediated)
      The untouched real scan: full Juice Shop CVE set, all leaked secrets,
      the deliberately insecure Terraform, and live AWS IAM findings.
      Expected: health < 30, at least one attack path.

Run:  python validation/build_scenarios.py
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
IMPL = HERE.parent
SOURCE = IMPL / "aiops_engine" / "sample_inputs"
OUT = HERE / "scenarios"

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _read(name: str):
    path = SOURCE / name
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _write(scenario: str, name: str, data) -> None:
    d = OUT / scenario
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(data, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- filters --
def filter_trivy(report: dict, keep: set[str]) -> dict:
    """Keep only vulnerabilities whose severity is in `keep`."""
    out = json.loads(json.dumps(report))
    for result in out.get("Results", []):
        vulns = result.get("Vulnerabilities") or []
        result["Vulnerabilities"] = [
            v for v in vulns if (v.get("Severity") or "UNKNOWN").upper() in keep
        ]
    return out


def filter_gitleaks(report: list, keep_rules: set[str] | None) -> list:
    if keep_rules is None:
        return []
    return [leak for leak in report if leak.get("RuleID") in keep_rules]


def filter_checkov(report, keep_ids: set[str] | None) -> dict:
    blocks = report if isinstance(report, list) else [report]
    block = json.loads(json.dumps(blocks[0]))
    checks = block.get("results", {}).get("failed_checks", []) or []
    if keep_ids is None:
        block["results"]["failed_checks"] = []
    else:
        block["results"]["failed_checks"] = [
            c for c in checks if c.get("check_id") in keep_ids
        ]
    return block


def filter_aws(report: dict, keep_checks: set[str] | None) -> dict:
    out = json.loads(json.dumps(report))
    if keep_checks is None:
        out["findings"] = []
    else:
        out["findings"] = [f for f in out.get("findings", []) if f.get("check") in keep_checks]
    return out


# -------------------------------------------------------------- scenarios --
def build():
    trivy = _read("trivy-report.json")
    gitleaks = _read("gitleaks-report.json")
    checkov = _read("checkov-report.json")
    aws = _read("aws-findings.json")

    missing = [n for n, v in
               [("trivy", trivy), ("gitleaks", gitleaks), ("checkov", checkov), ("aws", aws)]
               if v is None]
    if missing:
        raise SystemExit(f"Missing source reports: {', '.join(missing)}. "
                         f"Run the pipeline first so real data exists.")

    if OUT.exists():
        shutil.rmtree(OUT)

    # --- Scenario 1: remediated baseline --------------------------------
    # Only LOW-severity dependency findings remain; secrets removed, IaC
    # hardened, no cloud exposure.
    _write("scenario-1-baseline", "trivy-report.json", filter_trivy(trivy, {"LOW"}))
    _write("scenario-1-baseline", "gitleaks-report.json", filter_gitleaks(gitleaks, None))
    _write("scenario-1-baseline", "checkov-report.json", filter_checkov(checkov, set()))
    _write("scenario-1-baseline", "aws-findings.json", filter_aws(aws, set()))

    # --- Scenario 2: partially remediated -------------------------------
    # Criticals patched, secrets cleaned, but MEDIUM dependencies remain and
    # one internet-facing security-group rule is still open.
    _write("scenario-2-moderate", "trivy-report.json", filter_trivy(trivy, {"MEDIUM", "LOW"}))
    _write("scenario-2-moderate", "gitleaks-report.json", filter_gitleaks(gitleaks, None))
    _write("scenario-2-moderate", "checkov-report.json",
           filter_checkov(checkov, {"CKV_AWS_24", "CKV_AWS_23"}))
    _write("scenario-2-moderate", "aws-findings.json",
           filter_aws(aws, {"iam_multiple_access_keys"}))

    # --- Scenario 3: unremediated (the real scan, untouched) ------------
    for name in ("trivy-report.json", "gitleaks-report.json",
                 "checkov-report.json", "aws-findings.json"):
        shutil.copy(SOURCE / name, OUT / "scenario-3-critical" / name
                    if (OUT / "scenario-3-critical").exists()
                    else _ensure(OUT / "scenario-3-critical") / name)

    print(f"Scenarios written to {OUT}")
    for d in sorted(OUT.iterdir()):
        sizes = {p.name: p.stat().st_size for p in sorted(d.glob('*.json'))}
        print(f"  {d.name}: " + ", ".join(f"{k} {v}B" for k, v in sizes.items()))


def _ensure(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p


if __name__ == "__main__":
    build()
