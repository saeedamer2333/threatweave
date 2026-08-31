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
import time
import urllib.error
import urllib.parse
import urllib.request
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
    """One batched EPSS lookup (at most BATCH CVEs - callers chunk larger
    lists). Raises on a genuine failure to reach FIRST.org at all (network
    down, DNS failure, timeout) rather than swallowing it and returning {} -
    scores_for() needs to tell "asked and got a real, empty answer" apart
    from "never got an answer", since only the former is safe to cache as a
    confirmed miss. An offline run silently caching every CVE as a
    permanent miss would be a worse outcome than just retrying next time.

    Uses the standard library's urllib rather than shelling out to curl -
    confirmed live that curl is not installed in every container this code
    runs in (the dashboard's own local re-score path, specifically), which
    made EPSS silently non-functional there with no visible error.
    """
    params = urllib.parse.urlencode({"cve": ",".join(cve_ids)})
    req = urllib.request.Request(f"{API}?{params}", headers={"User-Agent": "ThreatWeave-aiops-engine"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return {row["cve"].upper(): float(row["epss"]) for row in data.get("data", [])}


def scores_for(cve_ids: list[str]) -> dict[str, float]:
    """Return {CVE_ID: epss_probability} for CVEs FIRST.org actually has
    data for. A CVE FIRST.org has never heard of (confirmed live: every
    forward-dated demo CVE ID in this project's own sample data) is omitted
    entirely, not defaulted to 0.0 - the two look identical to a caller
    otherwise, and "we checked and found nothing" is a materially different
    claim from "we checked and it is a real, near-zero score." The score
    the finding is weighted by still defaults to 0.0 either way (nothing
    downstream changes there); what changes is that a caller asking "was
    real exploitation data actually found for this CVE" now gets a true
    answer instead of "yes" for every CVE that was merely *looked up*.
    """
    wanted = sorted({c.upper() for c in cve_ids if c})
    if not wanted:
        return {}

    cached = _load_cache()
    missing = [c for c in wanted if c not in cached]
    if missing:
        print(f"  [epss] fetching {len(missing)} CVE scores from FIRST.org")
        for i in range(0, len(missing), BATCH):
            chunk = missing[i:i + BATCH]
            try:
                fresh = _fetch(chunk)
            except Exception as e:
                # Never reached FIRST.org for this batch at all (offline,
                # DNS failure, timeout, curl/network issue) - leave these
                # CVEs out of the cache entirely so they are retried on the
                # next run, rather than wrongly remembering them as
                # confirmed misses just because they could not be asked
                # about.
                print(f"  [epss] lookup failed for {len(chunk)} CVE(s), will retry next run: {e}")
                continue
            cached.update(fresh)
            # A real response that omitted a requested CVE is a confirmed
            # miss - remembered as None so it is not re-fetched later, but
            # explicitly distinct from a real 0.0 score.
            for c in chunk:
                cached.setdefault(c, None)
        _save_cache(cached)
    else:
        print(f"  [epss] all {len(wanted)} CVE scores served from cache")

    return {c: cached[c] for c in wanted if cached.get(c) is not None}
