"""Eval honesty: gate calibration (calibrate.py), the injection-guard labelled corpus (evalguard.injection_eval)
and an English retrieval measurement (evals.rag_en_eval) kept out of the loop-gated RAG_SETS.

Every number asserted here is the real measured number over the shipped product code and the committed eval
data (evals/injection_samples.jsonl, evals/rag_en.json, and the three PINNED golden/dev/test sets, read-only).
Nothing is mocked or stubbed: these are offline, deterministic, no-network measurements of what ships today,
including the ones that expose a real gap (Korean prompt-injection recall, English retrieval under-confidence,
the coarse 5-bucket calibration table disagreeing with an exact per-item re-check at the committed threshold)."""
from __future__ import annotations

import json
import os
import tempfile

from bts_sbom_app import calibrate, evalguard, evals

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ------------------------------------------------------------------ C29: calibrate.reliability_table / check_threshold
def test_reliability_table_buckets_the_61_pinned_questions_and_reports_accuracy_and_false_accept_per_bucket():
    """AC: BSA-AC-1170"""
    results = calibrate.probe_corpus(ROOT)
    assert len(results) == 61  # rag_golden(25) + rag_dev(20) + rag_test(16), the three PINNED sets, untouched
    table = calibrate.reliability_table(results, buckets=5)
    assert len(table) == 5
    # ascending score ranges, no gaps in coverage of the measured corpus
    assert [b["range"][0] for b in table] == sorted(b["range"][0] for b in table)
    assert sum(b["n"] for b in table) == 61
    rates = [b["ood_false_accept_rate"] for b in table]
    # measured today: the lowest-scoring bucket is almost all OOD false accepts, the top three buckets are clean
    assert rates[0] > 0.5 and rates[-1] == 0.0 and rates[-2] == 0.0
    # every bucket with at least one in-domain question reports a real accuracy number, not a placeholder
    assert all(b["accuracy"] is not None for b in table if b["indomain_n"])


def test_check_threshold_reports_the_coarse_bucket_verdict_and_the_exact_per_item_verdict_and_they_can_disagree():
    """AC: BSA-AC-1171"""
    assert calibrate.committed_min_bm25() == 12.0  # read from rag.py's own default, never hand-copied
    results = calibrate.probe_corpus(ROOT)
    chk = calibrate.check_threshold(results=results)
    assert chk["min_bm25"] == 12.0
    # measured today: the committed threshold sits in the bucket [8.28, 14.77], whose own false-accept rate
    # (0.25, three OOD questions in a twelve-question bucket) is well above the 0.05 course-derived safe line
    assert chk["bucket"]["range"] == [8.28, 14.77]
    assert chk["bucket_false_accept_rate"] == 0.25
    assert chk["bucket_safe"] is False
    assert chk["in_range"] is False
    # the EXACT per-item re-check at 12.0 (same data, same threshold, no bucketing) tells a different story:
    # zero of the 14 OOD questions actually score >= 12.0, so nothing is actually falsely accepted at this line
    assert chk["exact_ood_false_accept_rate"] == 0.0
    assert chk["exact_safe"] is True
    assert chk["bucket_safe"] != chk["exact_safe"]  # the finding: 5 buckets over 61 points is too coarse to trust alone
    assert "coarse" in chk["note"]


# ------------------------------------------------------------------ C54: evalguard.injection_eval
def test_injection_eval_measures_real_attack_recall_and_benign_precision_and_does_not_hide_the_misses():
    """AC: BSA-AC-1172"""
    samples = evals.injection_samples(ROOT)
    assert len(samples) >= 40
    attack_n = sum(1 for s in samples if s["label"] == "attack")
    benign_n = sum(1 for s in samples if s["label"] == "benign")
    assert attack_n >= 15 and benign_n >= 15
    assert any(s["lang"] == "ko" for s in samples) and any(s["lang"] == "en" for s in samples)
    r = evals.injection_guard_eval(ROOT)
    assert r == evalguard.injection_eval(samples)  # the harness wrapper and the guard function agree
    assert r["attack_n"] == attack_n and r["benign_n"] == benign_n
    # measured after the general-pattern guard rewrite (BSA-AC-1210..1213): the dev corpus recall rose from 0.48 to 1.0 and
    # Korean recall from 0.0 to 1.0 (see tests/bts_sbom_app/test_injection_guard.py for the held-out measurement)
    assert r["recall"] == 1.0
    assert r["precision"] == 0.962
    assert r["misses"] == [] and r["by_lang"]["ko"]["recall"] == 1.0 and r["by_lang"]["en"]["recall"] == 1.0
    # a benign sentence that DESCRIBES software ignoring instructions still trips the regex shape: reported, never hidden
    assert len(r["false_positives"]) == 1 and r["benign_false_positive_rate"] == round(len(r["false_positives"]) / benign_n, 3) == 0.04


# ------------------------------------------------------------------ C84: evals.rag_en_eval (not a RAG_SETS member)
def test_rag_en_eval_reports_recall_mrr_and_ood_separately_and_is_not_a_loop_gated_set():
    """AC: BSA-AC-1173"""
    assert "rag_en" not in evals.RAG_SETS  # the loop pins/gates over golden/dev/test stay untouched
    r = evals.rag_en_eval(ROOT)
    assert r["queries"] == 16 and r["ood_queries"] == 5
    # measured today (BSA-AC-1175..1179 added an English->Korean query-side bridge, light English inflection
    # folding, and a separately-measured confidence-gate floor for English-only queries - see rag.py EN_KR_BRIDGE /
    # EN_MIN_BM25): recall@5 and MRR both improved, and the gate now surfaces most of what it retrieves.
    assert r["recall_at_k"] == 1.0  # was 0.875 before BSA-AC-1175..1179
    assert r["mrr"] == 0.906  # was 0.705 before BSA-AC-1175..1179
    assert r["ood_rate"] == 1.0  # every English OOD question is still correctly rejected (gate floor measured for this)
    # the original weakness this bundle (C84) exposed - recall finding the right document far more often (0.875)
    # than the gate surfaced it (found_rate 0.5) - is now mostly closed: found_rate rose to 0.812 (>= the 0.80
    # target), still slightly below recall@5 because two English in-domain questions score under even the lower
    # English gate floor (see tests/bts_sbom_app/test_english_retrieval.py for the full before/after measurement).
    assert r["found_rate"] < r["recall_at_k"]
    assert r["found_rate"] == 0.812  # was 0.5 before BSA-AC-1175..1179
    assert r["misses"] == []  # was 2 recall misses before BSA-AC-1175..1179; ``misses`` tracks recall, not the gate


# ------------------------------------------------------------------ fix: injection_samples() decode robustness
def test_injection_samples_does_not_crash_on_an_invalid_utf8_byte_and_keeps_the_other_records():
    """AC: BSA-AC-1174"""
    with tempfile.TemporaryDirectory() as tmp:
        evals_dir = os.path.join(tmp, "evals")
        os.makedirs(evals_dir)
        path = os.path.join(evals_dir, "injection_samples.jsonl")
        with open(path, "wb") as fh:
            # a damaged line with a raw invalid-UTF-8 byte (0xFF) sandwiched between two valid records: the
            # docstring promises "a damaged line is skipped, never fatal" - it must not lose record 1 or 2
            fh.write(json.dumps({"text": "record one", "label": "benign", "lang": "en"}).encode("utf-8") + b"\n")
            fh.write(b'{"text": "corrupted \xff byte", "label": "attack", "lang": "en"}\n')
            fh.write(json.dumps({"text": "record two", "label": "attack", "lang": "en"}).encode("utf-8") + b"\n")
        # must not raise UnicodeDecodeError (previously uncaught, aborting the whole parse)
        recs = evals.injection_samples(tmp)
        assert len(recs) >= 2  # record one and record two survive; the corrupted record is recovered or skipped
        texts = [r["text"] for r in recs]
        assert "record one" in texts
        assert "record two" in texts
        # injection_guard_eval() calls injection_samples() directly - it must not crash on the same input either
        report = evalguard.injection_eval(recs)
        assert report["attack_n"] + report["benign_n"] == len(recs)
