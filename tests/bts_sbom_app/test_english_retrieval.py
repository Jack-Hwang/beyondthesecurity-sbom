"""English-language retrieval over the largely-Korean knowledge base (bts_sbom_app/rag.py): an English->Korean
technical-term bridge (``rag.EN_KR_BRIDGE`` + the reverse of ``rag.SYNONYMS``) and light English inflection
folding (``rag._en_stem_variants``), applied ONLY to queries with no Hangul character, plus a separately-measured
confidence-gate floor for those same English-only queries (``rag.EN_MIN_BM25``).

Every number here is measured over the shipped product code and committed eval data: evals/rag_en.json (pinned,
untouched, written by an earlier bundle), evals/rag_en_holdout.json (written by THIS bundle, never tuned on -
different wording and topics from rag_en.json), and the three PINNED golden/dev/test Korean sets (also untouched -
the whole point of this bundle is that the English fix moves nothing Korean). Nothing is mocked: offline,
deterministic, no network."""
from __future__ import annotations

import json
import os

from bts_sbom_app import calibrate, evals, rag

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _holdout():
    with open(os.path.join(ROOT, "evals", "rag_en_holdout.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)


def test_rag_en_json_found_rate_recovers_without_losing_recall_or_ood_rejection():
    """AC: BSA-AC-1175"""
    r = evals.rag_en_eval(ROOT)
    assert r["queries"] == 16 and r["ood_queries"] == 5
    # measured before this bundle: recall_at_k 0.875, mrr 0.705, found_rate 0.5 (the gate hid half the real finds)
    assert r["recall_at_k"] == 1.0 and r["recall_at_k"] >= 0.875          # never below what shipped before
    assert r["mrr"] == 0.906 and r["mrr"] >= 0.705
    assert r["found_rate"] == 0.812 and r["found_rate"] >= 0.80            # the target this bundle was asked to hit
    assert r["ood_rate"] == 1.0                                           # every English OOD question still rejected
    assert r["misses"] == []


def test_rag_en_holdout_is_a_fresh_untuned_probe_and_also_clears_the_target():
    """AC: BSA-AC-1176"""
    data = _holdout()
    n_in = sum(1 for g in data if not g.get("ood"))
    n_ood = sum(1 for g in data if g.get("ood"))
    assert n_in >= 14 and n_ood >= 6
    # different wording/topics from rag_en.json: no exact-string overlap between the two question sets
    en_qs = {g["q"] for g in json.load(open(os.path.join(ROOT, "evals", "rag_en.json"), encoding="utf-8"))}
    assert not ({g["q"] for g in data} & en_qs)
    idx = evals.build_index(ROOT)
    out = rag.evaluate(idx, data, k=5)
    assert out["queries"] == n_in and out["ood_queries"] == n_ood
    assert out["recall_at_k"] == 1.0
    assert out["found_rate"] == 0.875 and out["found_rate"] >= 0.80
    assert out["ood_rate"] == 1.0
    assert out["misses"] == []


def test_korean_pinned_sets_and_chat_eval_are_byte_identical_to_before_this_bundle():
    """AC: BSA-AC-1177"""
    r = evals.rag_sets_eval(ROOT)
    assert (r["rag_golden"]["recall_at_k"], r["rag_golden"]["mrr"], r["rag_golden"]["found_rate"], r["rag_golden"]["ood_rate"]) == (1.0, 0.95, 0.85, 1.0)
    assert (r["rag_dev"]["recall_at_k"], r["rag_dev"]["mrr"], r["rag_dev"]["found_rate"], r["rag_dev"]["ood_rate"]) == (1.0, 0.836, 0.933, 1.0)
    assert (r["rag_test"]["recall_at_k"], r["rag_test"]["mrr"], r["rag_test"]["found_rate"], r["rag_test"]["ood_rate"]) == (0.917, 0.75, 0.917, 1.0)
    rg = evals.rag_eval(ROOT)
    assert rg["queries"] == 20 and rg["recall_at_k"] == 1.0 and rg["mrr"] == 0.95 and rg["ndcg_at_k"] == 0.943
    assert rg["ood_queries"] == 5 and rg["ood_rejected"] == 5
    c = evals.chat_eval(ROOT)
    assert c["found_rate"] == 1.0 and c["tool_routing_rate"] == 1.0 and c["citation_accuracy"] == 1.0
    assert c["paraphrase_routing_rate_regex"] == 0.0
    # the committed Korean gate itself: unchanged default, unchanged calibration measurement
    assert calibrate.committed_min_bm25() == 12.0
    chk = calibrate.check_threshold(results=calibrate.probe_corpus(ROOT))
    assert chk["bucket"]["range"] == [8.28, 14.77] and chk["bucket_false_accept_rate"] == 0.25
    assert chk["exact_ood_false_accept_rate"] == 0.0 and chk["exact_safe"] is True


def test_english_gate_floor_is_only_reachable_through_the_committed_default():
    """AC: BSA-AC-1178"""
    idx = evals.build_index(ROOT)
    # a Korean query (has Hangul) always uses the literal min_bm25 it was called with, never EN_MIN_BM25
    ko_default = idx.search("라이선스는 어떻게 찾아")
    ko_explicit_low = idx.search("라이선스는 어떻게 찾아", min_bm25=0.0)
    assert ko_default["found"] is True and ko_explicit_low["found"] is True
    assert ko_default["results"][0]["bm25"] == ko_explicit_low["results"][0]["bm25"]  # scoring itself never changes
    # an English in-domain query whose top-hit BM25 (11.28, measured) sits strictly between EN_MIN_BM25 and the
    # Korean-committed 12.0: this is the exact case the gate adjustment exists for.
    q = "What EARS pattern and acceptance criteria format is used?"
    assert idx.search(q)["results"][0]["bm25"] == 11.28
    assert idx.search(q)["found"] is True                                  # default: reads EN_MIN_BM25 (10.0) -> passes
    assert idx.search(q, min_bm25=11.5)["found"] is False                  # explicit, non-default override is honoured
    # passing the literal committed default (12.0) explicitly is indistinguishable from leaving it unset by design
    # (documented in rag.py): both read EN_MIN_BM25 for an English-only query, so both pass here too.
    assert idx.search(q, min_bm25=12.0)["found"] is True
    # an explicit override on an English OOD query is still honoured exactly (never silently replaced)
    assert idx.search("What is the weather like in Seoul today?", min_bm25=0.0)["found"] is True
    assert idx.search("What is the weather like in Seoul today?", min_bm25=50.0)["found"] is False


def test_en_stem_variants_and_bridge_are_query_side_only_and_leave_the_corpus_untouched():
    """AC: BSA-AC-1179"""
    # light inflection folding: additive, never replaces the original token, only for words long enough to be safe
    assert "hotspot" in rag._en_stem_variants("hotspots")
    assert "dependency" in rag._en_stem_variants("dependencies")
    assert "calculate" in rag._en_stem_variants("calculated")
    assert rag._en_stem_variants("is") == []                               # too short to touch
    assert rag._en_stem_variants("spdx") == []                             # no matching suffix: no variants invented
    # the bridge is reachable in both directions it claims: SYNONYMS reversed, plus the hand-written supplement
    assert "순환" in rag._REVERSE_SYNONYMS.get("circular", [])
    assert "락파일" in rag.EN_KR_BRIDGE.get("lockfile", [])
    # corpus-side tokenization (what Index.add indexes) takes no for_query argument and is untouched by any of this
    chunk_tokens = rag.tokenize("The lockfile tracks hotspots and dependencies.")
    assert "lockfile" in chunk_tokens and "hotspots" in chunk_tokens
    assert "락파일" not in chunk_tokens and "핫스팟" not in chunk_tokens and "순환" not in chunk_tokens
    # query-side expansion only fires for a query with no Hangul at all; a mixed Korean+English query is untouched
    mixed = rag.tokenize("requests 컴포넌트 라이선스는 뭐야", for_query=True)
    assert "락파일" not in mixed and "핫스팟" not in mixed
