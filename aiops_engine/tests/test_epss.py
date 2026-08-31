"""Unit tests for epss.py.

Regression: confirmed live against the actual re-scored dashboard output -
every finding's "Why this score" panel claimed "Live exploitation-probability
data from FIRST.org's EPSS dataset for <CVE>" even though the EPSS bar showed
0.00 for nearly every finding. The cause: a CVE FIRST.org has no data for
(every forward-dated demo CVE ID in this project's own sample data included)
was cached as a real score of 0.0, identical in shape to a genuine near-zero
score - so a caller checking "is this CVE a key in the results" could never
tell "no data" apart from "real data, happens to be 0". Fixed by caching a
confirmed miss as `None` and omitting it from what scores_for() returns, so
absence from the dict now means what a caller would assume it means.

Network access and the real on-disk cache file are never touched: `_fetch`
is monkeypatched directly, and CACHE is redirected to a tmp_path file.
"""
from __future__ import annotations

import json

import pytest

import epss


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(epss, "CACHE", tmp_path / "epss_cache.json")


def test_scores_for_returns_real_hits(monkeypatch):
    monkeypatch.setattr(epss, "_fetch", lambda ids: {"CVE-2021-44228": 0.97})

    result = epss.scores_for(["cve-2021-44228"])  # lowercase in, uppercase out

    assert result == {"CVE-2021-44228": 0.97}


def test_scores_for_omits_a_cve_first_org_has_no_data_for(monkeypatch):
    # The actual regression: _fetch found nothing for this CVE (e.g. it does
    # not exist yet in FIRST.org's dataset), which must not look identical
    # to "found a real score of 0.0".
    monkeypatch.setattr(epss, "_fetch", lambda ids: {})

    result = epss.scores_for(["CVE-2026-19499"])

    assert "CVE-2026-19499" not in result
    assert result == {}


def test_a_confirmed_miss_is_not_refetched_on_a_later_call(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(epss, "_fetch", lambda ids: calls.append(list(ids)) or {})

    epss.scores_for(["CVE-2026-19499"])   # first call: miss, gets cached
    epss.scores_for(["CVE-2026-19499"])   # second call: should not re-fetch

    assert len(calls) == 1


def test_a_real_score_is_served_from_cache_on_a_later_call(monkeypatch):
    calls = []

    def fetch(ids):
        calls.append(list(ids))
        return {"CVE-2021-44228": 0.97}
    monkeypatch.setattr(epss, "_fetch", fetch)

    first = epss.scores_for(["CVE-2021-44228"])
    second = epss.scores_for(["CVE-2021-44228"])

    assert first == second == {"CVE-2021-44228": 0.97}
    assert len(calls) == 1


def test_a_mix_of_hits_and_misses_only_returns_the_hits(monkeypatch):
    monkeypatch.setattr(epss, "_fetch", lambda ids: {"CVE-2021-44228": 0.97})

    result = epss.scores_for(["CVE-2021-44228", "CVE-2026-19499"])

    assert result == {"CVE-2021-44228": 0.97}


def test_empty_input_returns_empty_dict_without_touching_the_cache(monkeypatch):
    called = []
    monkeypatch.setattr(epss, "_fetch", lambda ids: called.append(1) or {})

    assert epss.scores_for([]) == {}
    assert called == []


def test_a_fetch_failure_is_not_cached_as_a_confirmed_miss(monkeypatch):
    # Regression: confirmed live - curl is not installed in every container
    # this code runs in, so _fetch used to silently return {} on a total
    # failure to reach FIRST.org, indistinguishable from "asked and FIRST.org
    # genuinely has nothing". That permanently poisoned the cache: every CVE
    # in an otherwise-healthy environment got wrongly remembered as a
    # confirmed miss the first time this ran inside a container missing
    # curl. A real failure to reach the API must leave the CVE unresolved,
    # not confirmed-absent, so a later run (in a working environment, or
    # once the network is back) gets a real chance to look it up.
    def raise_network_error(ids):
        raise OSError("No such file or directory: 'curl'")
    monkeypatch.setattr(epss, "_fetch", raise_network_error)

    result = epss.scores_for(["CVE-2021-44228"])

    assert result == {}


def test_a_fetch_failure_lets_a_later_successful_call_still_find_the_real_score(monkeypatch):
    attempt = {"n": 0}

    def flaky_fetch(ids):
        attempt["n"] += 1
        if attempt["n"] == 1:
            raise OSError("network unreachable")
        return {"CVE-2021-44228": 0.97}
    monkeypatch.setattr(epss, "_fetch", flaky_fetch)

    first = epss.scores_for(["CVE-2021-44228"])   # fails, nothing cached
    second = epss.scores_for(["CVE-2021-44228"])  # succeeds this time

    assert first == {}
    assert second == {"CVE-2021-44228": 0.97}


def test_the_cache_file_stores_a_miss_as_null_not_zero(tmp_path, monkeypatch):
    cache_path = tmp_path / "epss_cache.json"
    monkeypatch.setattr(epss, "CACHE", cache_path)
    monkeypatch.setattr(epss, "_fetch", lambda ids: {})

    epss.scores_for(["CVE-2026-19499"])

    saved = json.loads(cache_path.read_text(encoding="utf-8"))
    assert saved["scores"]["CVE-2026-19499"] is None
