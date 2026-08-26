"""S_EPSS - Exploit Prediction Scoring System lookup (FIRST.org).

EPSS gives the probability (0-1) that a CVE will be exploited in the wild in
the next 30 days. It is updated daily and is free with no API key. This is a
much sharper signal than CVSS alone: a CVSS 9.8 that nobody exploits matters
less than a CVSS 7.5 that is being actively weaponised.

Scores are fetched in one batched request per run and cached on disk so
repeated runs (and offline runs) do not hammer the API.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

API = "https://api.first.org/data/v1/epss"
CACHE = Path(__file__).resolve().parent / "ml" / "data" / "epss_cache.json"
CACHE_TTL = 24 * 60 * 60          # refresh daily
BATCH = 100                        # CVEs per request


def _load_cache() -> dict:
    if not CACHE.exists():
        return {}
    try:
        blob = json.loads(CACHE.read_text(encoding="utf-8"))
        if time.time() - blob.get("fetched_at", 0) > CACHE_TTL:
            return {}                       # stale, refetch
        return blob.get("scores", {})
    except Exception:
        return {}


def _save_cache(scores: dict) -> None:
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps({"fetched_at": time.time(), "scores": scores}), encoding="utf-8")


def _fetch(cve_ids: list[str]) -> dict[str, float]:
    """Batched EPSS lookup. Returns {} on any failure (offline-safe)."""
    out: dict[str, float] = {}
    for i in range(0, len(cve_ids), BATCH):
        chunk = cve_ids[i:i + BATCH]
        url = f"{API}?cve={','.join(chunk)}"
        try:
            res = subprocess.run(["curl", "-s", "--max-time", "30", url], capture_output=True)
            if res.returncode != 0 or not res.stdout:
                continue
            data = json.loads(res.stdout.decode("utf-8"))
            for row in data.get("data", []):
                out[row["cve"].upper()] = float(row["epss"])
        except Exception as e:
            print(f"  [epss] lookup failed: {e}")
            continue
    return out


def scores_for(cve_ids: list[str]) -> dict[str, float]:
    """Return {CVE_ID: epss_probability} using cache where possible."""
    wanted = sorted({c.upper() for c in cve_ids if c})
    if not wanted:
        return {}

    cached = _load_cache()
    missing = [c for c in wanted if c not in cached]
    if missing:
        print(f"  [epss] fetching {len(missing)} CVE scores from FIRST.org")
        fresh = _fetch(missing)
        cached.update(fresh)
        # remember misses as 0.0 so we do not refetch unknown CVEs every run
        for c in missing:
            cached.setdefault(c, 0.0)
        _save_cache(cached)
    else:
        print(f"  [epss] all {len(wanted)} CVE scores served from cache")

    return {c: cached.get(c, 0.0) for c in wanted}
