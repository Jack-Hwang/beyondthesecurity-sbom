"""Reliability calibration for the RAG confidence gate (course: D-심화 보강③, 2-2 필드 신뢰도 보정, calibration.md).

The gate's ``min_bm25`` threshold (see ``rag.Index.search``) was hand-tuned by eyeballing recall/precision/OOD
deltas on the three pinned eval sets (see the dated comments in rag.py). That is a real measurement, but it is
a single point, not a reliability curve: it does not say what happens to a question that scores a little above
or a little below the line, only that total recall/precision/OOD did not move on the 61 questions that exist
today. ``reliability_table`` answers the curve question - bucket every question's top-hit BM25 score and show
accuracy (in-domain) and false-accept rate (out-of-domain) per bucket - and ``check_threshold`` says whether the
*committed* threshold sits in a bucket that is actually safe (OOD false-accept <= 5%).

Read-only with respect to the product: this module only calls the shipped ``rag.Index.search`` exactly as the
chatbot calls it (no retrieval-behaviour change) and only *reads* the three pinned eval sets (golden/dev/test)
through ``evals.rag_set_items`` - nothing here writes to or edits those files, so their fingerprints are untouched.

Honesty note on bucket granularity: with 61 questions and 5 buckets (~12 each), a bucket can straddle the exact
threshold value and mix items that are individually above and below it - it can call a bucket "unsafe" even
when the threshold itself has zero false accepts, if other items on the losing side of the threshold happen to
share its bucket. ``check_threshold`` therefore reports BOTH the coarse bucket verdict (the course-derived
method, literal) and an exact per-item re-check at the precise threshold value, and says which one to trust
when they disagree. Absent evidence is never reported as a pass - a bucket with no in-domain items reports
``accuracy: None``, not 0.0 or 1.0.
"""
from __future__ import annotations

import inspect
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import evals, rag

DEFAULT_BUCKETS = 5
DEFAULT_MAX_FALSE_ACCEPT = 0.05


def committed_min_bm25() -> float:
    """The min_bm25 threshold actually shipped in rag.py, read from the function's own default (never hand-copied,
    so this stays correct if the threshold is ever retuned without anyone remembering to update a calibration script)."""
    return float(inspect.signature(rag.Index.search).parameters["min_bm25"].default)


def probe_corpus(root: Optional[str] = None, k: int = 5) -> List[Dict[str, Any]]:
    """Per-question raw probe over the three PINNED eval sets (golden+dev+test, 61 questions as shipped today):
    the top-hit BM25 score, whether the question is OOD, and whether the gate's top answer would be correct.

    Calls ``rag.Index.search`` with its own default arguments - the same call the chatbot makes - so this is a
    measurement of the shipped gate, not a reimplementation of it. The three eval sets are read, never written."""
    idx = evals.build_index(root)
    out: List[Dict[str, Any]] = []
    for name, items in evals.rag_set_items(root).items():
        for g in items:
            res = idx.search(g["q"], k=k)
            top = res["results"][0] if res["results"] else None
            bm25 = float(top["bm25"]) if top else 0.0
            ood = bool(g.get("ood"))
            correct = (not ood) and bool(top) and any(top["chunk"]["source"].startswith(e) for e in (g.get("expect") or []))
            out.append({"set": name, "q": g["q"], "bm25": bm25, "ood": ood, "correct": correct})
    return out


def reliability_table(results: Sequence[Dict[str, Any]], buckets: int = DEFAULT_BUCKETS) -> List[Dict[str, Any]]:
    """Bucket the top-hit BM25 score of every probed question into ``buckets`` equal-sized quantile bins
    (ascending by score), reporting per bin: how many questions landed there, in-domain ACCURACY (of the
    in-domain questions in this score range, how many would get the right document) and the OOD FALSE-ACCEPT
    RATE (of all questions in this score range, how many are actually out-of-domain - there is no such thing as
    a correct OOD accept, so any OOD item in an accepted bucket is a false accept by definition).

    A bucket with zero in-domain items reports ``accuracy: None`` (absent evidence is not a pass, not a fail).
    Buckets are split by rank (index), not by raw score width, so a bucket is never empty merely because many
    questions share a score - the price is that a bucket's score ``range`` can be wide when scores cluster."""
    rows = sorted(results or [], key=lambda r: r["bm25"])
    n = len(rows)
    if n == 0:
        return []
    buckets = max(1, min(int(buckets), n))
    out: List[Dict[str, Any]] = []
    for b in range(buckets):
        start, end = (n * b) // buckets, (n * (b + 1)) // buckets
        chunk = rows[start:end]
        if not chunk:
            continue
        indomain = [r for r in chunk if not r["ood"]]
        ood_n = len(chunk) - len(indomain)
        correct_n = sum(1 for r in indomain if r["correct"])
        out.append({
            "bucket": len(out), "range": [round(chunk[0]["bm25"], 2), round(chunk[-1]["bm25"], 2)], "n": len(chunk),
            "indomain_n": len(indomain), "accuracy": round(correct_n / len(indomain), 3) if indomain else None,
            "ood_n": ood_n, "ood_false_accept_rate": round(ood_n / len(chunk), 3),
        })
    return out


def _bucket_of(table: Sequence[Dict[str, Any]], score: float) -> Optional[Dict[str, Any]]:
    """The bucket whose score range contains ``score``; clamped to the nearest edge bucket when ``score`` falls
    outside every measured range (a threshold more extreme than anything in the probed corpus is still reported
    against the closest evidence available, not left undecided)."""
    if not table:
        return None
    rows = sorted(table, key=lambda r: r["range"][0])
    for row in rows:
        lo, hi = row["range"]
        if lo <= score <= hi:
            return row
    return rows[0] if score < rows[0]["range"][0] else rows[-1]


def exact_ood_false_accept_rate(results: Sequence[Dict[str, Any]], min_bm25: float) -> Optional[float]:
    """Precise point re-check: of all OOD questions in ``results``, what fraction score >= ``min_bm25`` (and so
    would actually be accepted at exactly this threshold)? None when the corpus carries no OOD question at all."""
    ood = [r for r in (results or []) if r["ood"]]
    if not ood:
        return None
    return round(sum(1 for r in ood if r["bm25"] >= min_bm25) / len(ood), 3)


def safe_range(table: Sequence[Dict[str, Any]], max_false_accept: float = DEFAULT_MAX_FALSE_ACCEPT) -> Optional[Tuple[float, float]]:
    """The contiguous score range, read from the top bucket down, where every bucket's OOD false-accept rate
    stays at or below ``max_false_accept``. None if even the highest-scoring bucket is unsafe."""
    lo: Optional[float] = None
    hi: Optional[float] = None
    for row in sorted(table or [], key=lambda r: -r["range"][0]):
        rate = row["ood_false_accept_rate"]
        if rate is None or rate > max_false_accept:
            break
        lo = row["range"][0]
        hi = row["range"][1] if hi is None else hi
    return (lo, hi) if lo is not None else None


def check_threshold(min_bm25: Optional[float] = None, results: Optional[Sequence[Dict[str, Any]]] = None,
                     table: Optional[Sequence[Dict[str, Any]]] = None, buckets: int = DEFAULT_BUCKETS,
                     max_false_accept: float = DEFAULT_MAX_FALSE_ACCEPT, root: Optional[str] = None) -> Dict[str, Any]:
    """Does the committed min_bm25 sit inside a safe bucket? Builds the real probe + table itself when not given,
    so one call (the future ``evalrag --calibrate`` CLI flag) gets an honest, self-contained answer.

    Reports TWO numbers on purpose, because they can disagree at this corpus size (61 questions / 5 buckets,
    ~12 per bucket): ``bucket_safe`` is the course-derived, literal check (the enclosing bucket's own OOD
    false-accept rate <= ``max_false_accept``); ``exact_safe`` re-checks the SAME threshold per-item, which is
    the number to trust when a bucket is coarse enough to mix items from both sides of the threshold."""
    threshold = committed_min_bm25() if min_bm25 is None else float(min_bm25)
    if results is None:
        results = probe_corpus(root)
    if table is None:
        table = reliability_table(results, buckets=buckets)
    row = _bucket_of(table, threshold)
    bucket_rate = row["ood_false_accept_rate"] if row else None
    bucket_safe = bool(row is not None and bucket_rate is not None and bucket_rate <= max_false_accept)
    exact_rate = exact_ood_false_accept_rate(results, threshold)
    exact_safe = exact_rate is not None and exact_rate <= max_false_accept
    rng = safe_range(table, max_false_accept)
    note = ("the %d-bucket table is coarse at n=%d (~%d per bucket); when bucket_safe and exact_safe disagree, "
            "exact_safe (the precise per-item re-check at this exact threshold) is the one to trust" %
            (len(table), len(results), max(1, len(results) // max(1, len(table)))))
    return {
        "min_bm25": threshold, "bucket": row, "bucket_safe": bucket_safe, "bucket_false_accept_rate": bucket_rate,
        "exact_ood_false_accept_rate": exact_rate, "exact_safe": exact_safe,
        "safe_range": list(rng) if rng else None, "in_range": bucket_safe,
        "max_false_accept": max_false_accept, "note": note,
    }
