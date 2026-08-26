"""S_retrieval - BM25 retrieval over a corpus of known-scored vulnerabilities.

Why this exists: many findings (SonarQube code smells, secrets, misconfigs)
have no CVE and therefore no CVSS score. This module estimates their severity
by *retrieving* the most textually similar real CVEs from the NVD corpus we
downloaded, and averaging their normalised CVSS scores, weighted by BM25
similarity.

BM25 is chosen over vector/embedding search because security text is
keyword-dense ("SQL injection", "deserialization", "0.0.0.0/0"). Exact term
matching outperforms semantic similarity here, and it needs no model, no GPU
and no external API.

    S_retrieval = sum(bm25_i * cvss_i/10) / sum(bm25_i)   over the top-k hits
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

CORPUS_PATH = Path(__file__).resolve().parent / "ml" / "data" / "cve_dataset.json"
TOP_K = 10

_TOKEN = re.compile(r"[a-z0-9\-]+")


def _tokenise(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


@lru_cache(maxsize=1)
def _index():
    """Build the BM25 index once. Returns (bm25, cvss_list) or None."""
    if not CORPUS_PATH.exists():
        return None
    try:
        from rank_bm25 import BM25Okapi
    except ImportError:
        print("  [bm25] rank_bm25 not installed; S_retrieval falls back")
        return None

    rows = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    docs, scores = [], []
    for r in rows:
        text = f"{r.get('description', '')} {' '.join(r.get('cwes', []))}"
        tokens = _tokenise(text)
        if not tokens:
            continue
        docs.append(tokens)
        scores.append(float(r["cvss"]))
    if not docs:
        return None
    return BM25Okapi(docs), scores


def is_available() -> bool:
    return _index() is not None


def retrieve_score(query_text: str) -> float | None:
    """Return S_retrieval in 0-1, or None if the index is unavailable."""
    idx = _index()
    if idx is None:
        return None
    bm25, cvss = idx
    tokens = _tokenise(query_text)
    if not tokens:
        return None

    scores = bm25.get_scores(tokens)
    # take the top-k most similar corpus entries
    ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:TOP_K]
    total_w = sum(scores[i] for i in ranked)
    if total_w <= 0:
        return None
    weighted = sum(scores[i] * (cvss[i] / 10.0) for i in ranked)
    return max(0.0, min(1.0, weighted / total_w))


def explain_matches(query_text: str, k: int = 3) -> list[tuple[str, float]]:
    """Debug helper: which corpus CVEs matched (for the report / viva)."""
    idx = _index()
    if idx is None:
        return []
    bm25, cvss = idx
    rows = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    scores = bm25.get_scores(_tokenise(query_text))
    ranked = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
    return [(rows[i]["id"], round(scores[i], 2)) for i in ranked]
