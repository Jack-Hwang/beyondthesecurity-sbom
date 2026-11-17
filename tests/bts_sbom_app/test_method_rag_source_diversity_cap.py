"""Per-source diversity cap on RAG top-k results (MMR-lite).

Index.search() fuses BM25/TF-IDF rankings via RRF but, before this change, never capped how many of the
k results could share a chunk ``source`` - one long or repetitive document could occupy the whole answer
window and crowd out other relevant sources. This asserts the cap holds on a synthetic index where one
source dominates relevance, and that the existing golden-set recall@5 does not regress beyond the
project's standard 0.02 delta (see bts_sbom_app/loop.py gate default) because of the cap.
"""
from __future__ import annotations

from collections import Counter

from bts_sbom_app import evals, rag


def _chunk(source: str, idx: int, text: str) -> dict:
    return {"id": "%s#%d" % (source, idx), "source": source, "heading": "", "text": text, "meta": {}}


def _dominated_index() -> rag.Index:
    # "docA" repeats every query term, so unmodified RRF ranks all 4 of its chunks above every other source.
    dominant_text = "zeltar vruxon plindak thorbis zeltar vruxon plindak thorbis zeltar vruxon plindak thorbis"
    chunks = [_chunk("docA", i, dominant_text) for i in range(4)]
    chunks += [
        _chunk("docB", 0, "zeltar vruxon context passage one"),
        _chunk("docC", 0, "plindak thorbis context passage two"),
        _chunk("docD", 0, "zeltar thorbis context passage three"),
        _chunk("docE", 0, "vruxon plindak context passage four"),
    ]
    return rag.Index(chunks)


def test_top5_never_has_more_than_2_results_from_one_source():
    """AC: BSA-AC-211"""
    idx = _dominated_index()
    res = idx.search("zeltar vruxon plindak thorbis", k=5)
    assert len(res["results"]) == 5
    counts = Counter(r["chunk"]["source"] for r in res["results"])
    assert max(counts.values()) <= 2, counts


def test_golden_recall_at_5_stays_within_the_0_02_regression_delta():
    """AC: BSA-AC-211"""
    out = evals.rag_eval()
    # test_golden_retrieval_thresholds (test_ai_rag_loop.py) pins the pre-cap baseline at >= 0.85.
    assert out["recall_at_k"] >= 0.85 - 0.02
