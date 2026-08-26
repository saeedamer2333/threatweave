"""Download real CVE records from the NVD API and save a compact training set.

Pulls recent CVEs that carry a CVSS v3.1 base score, extracts a small set of
features per CVE, and writes them to ml/data/cve_dataset.json.

No API key required. NVD rate limit without a key is ~5 requests / 30s, so we
sleep between pages. Run once:  python ml/download_nvd.py
"""
from __future__ import annotations

import json
import subprocess
import time
import urllib.parse
from pathlib import Path

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000            # max NVD allows per request
SLEEP = 7             # seconds between requests (stay under the rate limit)
OUT = Path(__file__).resolve().parent / "data" / "cve_dataset.json"

# Recent 120-day windows (NVD caps each query at a 120-day span). Recent CVEs
# almost all carry a CVSS v3.1 score, which is what we train on.
WINDOWS = [
    ("2025-01-01T00:00:00.000", "2025-04-30T23:59:59.999"),
    ("2024-09-01T00:00:00.000", "2024-12-30T23:59:59.999"),
    ("2024-05-01T00:00:00.000", "2024-08-29T23:59:59.999"),
    ("2024-01-01T00:00:00.000", "2024-04-29T23:59:59.999"),
]


def _cvss_v3(metrics: dict) -> tuple[float, str] | None:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            score = data.get("baseScore")
            vector = data.get("vectorString", "")
            if score is not None:
                return float(score), vector
    return None


def _row(cve: dict) -> dict | None:
    metrics = cve.get("metrics", {})
    v3 = _cvss_v3(metrics)
    if v3 is None:
        return None                       # only keep CVEs with a CVSS v3 score
    score, vector = v3
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)
    return {
        "id": cve.get("id"),
        "cvss": score,
        "vector": vector,
        "cwes": cwes,
        "description": desc,
    }


def _fetch(url: str) -> dict:
    # urllib gets a 404 from NVD in this environment while curl works, so use curl.
    for attempt in range(2):
        res = subprocess.run(
            ["curl", "-s", "--max-time", "90", url],
            capture_output=True,   # raw bytes; decode utf-8 ourselves
        )
        if res.returncode == 0 and res.stdout:
            try:
                return json.loads(res.stdout.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        print(f"   fetch failed (attempt {attempt+1}); retrying after {SLEEP}s")
        time.sleep(SLEEP)
    raise RuntimeError(f"could not fetch {url}")


def _save(rows: list[dict]) -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(rows, fh)


def main():
    rows: list[dict] = []
    for wi, (start_date, end_date) in enumerate(WINDOWS):
        start = 0
        while True:
            params = urllib.parse.urlencode({
                "pubStartDate": start_date,
                "pubEndDate": end_date,
                "resultsPerPage": PAGE,
                "startIndex": start,
            })
            url = f"{API}?{params}"
            print(f"[window {wi+1}/{len(WINDOWS)}] {start_date[:10]}..{end_date[:10]} startIndex={start}", flush=True)
            try:
                data = _fetch(url)
            except RuntimeError as e:
                print(f"   window failed ({e}); saving progress and moving on")
                _save(rows)
                break
            total = data.get("totalResults", 0)
            got = 0
            for item in data.get("vulnerabilities", []):
                row = _row(item.get("cve", {}))
                if row:
                    rows.append(row)
                    got += 1
            print(f"   kept {got} (window total {total}, running total {len(rows)})")
            _save(rows)                      # save after every page
            start += PAGE
            time.sleep(SLEEP)
            if start >= total or start >= 6000:   # cap per window
                break
        if len(rows) >= 5000:                # already plenty to train on
            print("   reached target size; stopping early")
            break

    _save(rows)
    print(f"\nSaved {len(rows)} CVEs -> {OUT}")


if __name__ == "__main__":
    main()
