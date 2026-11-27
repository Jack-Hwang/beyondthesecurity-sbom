"""Eval-set integrity: segment gate, pinned eval-set version, leak / composition check, and a re-baseline that cannot launder a regression."""
from __future__ import annotations

import json
import os

import pytest

from bts_sbom_app import cli, evalguard as eg, evals, loop, rag


def _set(mrr_a=1.0, mrr_b=1.0, *, n_a=2, n_b=2, fp="aaaaaaaaaaaa", recall_a=1.0, recall_b=1.0, misses=None, ood=1.0):
    """A monkeypatched rag_sets_eval result for one set with two topic segments (totals are the mean of the two)."""
    return {"recall_at_k": round((recall_a + recall_b) / 2, 3), "mrr": round((mrr_a + mrr_b) / 2, 3), "ndcg_at_k": 1.0, "ood_rate": ood, "found_rate": 1.0,
            "misses": misses or [], "fingerprint": fp,
            "segments": {"area:licenses": {"n": n_a, "recall": recall_a, "mrr": mrr_a}, "area:remediation": {"n": n_b, "recall": recall_b, "mrr": mrr_b},
                         "ood": {"n": 3, "ood_rate": ood}}}


def _pass(tmp_path, monkeypatch, sets, **kw):
    monkeypatch.setattr(loop.evals, "rag_sets_eval", lambda root: sets["v"])
    return loop.run_rag_pass(kw.pop("tag", "t"), str(tmp_path), str(tmp_path), variable=kw.pop("variable", "x"), **kw)


# ------------------------------------------------------------------ segments
def test_an_item_is_assigned_to_its_segments_by_topic_language_and_out_of_domain():
    """AC: BSA-AC-1060"""
    assert eg.segment_names({"q": "라이선스는 어떤 순서로 찾아?", "expect": ["domain/licenses.md"]}) == ["area:licenses", "lang:ko"]
    assert eg.segment_names({"q": "how is a CVSS score computed", "expect": ["domain/vulnerabilities.md", "lecture/"]}) == ["area:vulnerabilities", "lang:en"]
    assert eg.segment_names({"q": "회귀 게이트", "expect": ["lecture/"]}) == ["area:lecture", "lang:ko"]
    assert eg.segment_names({"q": "오늘 서울 날씨 어때", "ood": True}) == ["ood"]
    assert eg.area_of({"q": "x", "expect": []}) == "none" and eg.lang_of(None) == "en"


def test_the_retrieval_evaluation_reports_per_segment_metrics_that_add_up_to_the_totals():
    """AC: BSA-AC-1061"""
    golden = [{"q": "라이선스는 어떤 순서로 찾아?", "expect": ["domain/licenses.md"]},
              {"q": "GPL 의존성이 있으면 정책이 어떻게 판정되나", "expect": ["domain/licenses.md"]},
              {"q": "락파일은 왜 직접 수정하지 않아", "expect": ["domain/remediation_patching.md"]},
              {"q": "오늘 서울 날씨 어때", "ood": True}]
    out = rag.evaluate(evals.build_index(), golden)
    seg = out["segments"]
    assert set(seg) == {"area:licenses", "area:remediation_patching", "lang:ko", "ood"}
    assert seg["ood"] == {"n": 1, "ood_rate": out["ood_rate"]} and seg["lang:ko"]["n"] == out["queries"] == 3
    assert seg["lang:ko"]["recall"] == out["recall_at_k"] and seg["lang:ko"]["mrr"] == out["mrr"]                 # one language: the segment IS the total
    assert seg["area:licenses"]["n"] == 2 and seg["area:remediation_patching"]["n"] == 1
    weighted = (seg["area:licenses"]["mrr"] * 2 + seg["area:remediation_patching"]["mrr"] * 1) / 3
    assert abs(weighted - out["mrr"]) < 0.002                                                                         # segments partition the in-domain items
    assert rag.evaluate(evals.build_index(), [])["segments"] == {}


def test_a_segment_that_dropped_blocks_the_pass_even_when_the_total_is_flat(tmp_path, monkeypatch):
    """AC: BSA-AC-1062"""
    sets = {"v": {"rag_dev": _set(mrr_a=1.0, mrr_b=0.5)}}
    assert _pass(tmp_path, monkeypatch, sets)["decision"] == "baseline"
    sets["v"] = {"rag_dev": _set(mrr_a=0.5, mrr_b=1.0)}                       # one topic got worse, another better: the mean did not move
    bad = _pass(tmp_path, monkeypatch, sets)
    assert bad["metrics"]["dev_mrr"] == 0.75 and all(abs(d) < 1e-9 for d in bad["gate"]["deltas"].values())            # the aggregate gate sees nothing
    assert bad["decision"] == "rollback" and bad["gate"]["segment_only"] is True
    assert bad["gate"]["failed"] == ["segment rag_dev/area:licenses mrr: 1.000 -> 0.500 (n=2)"]
    sets["v"] = {"rag_dev": _set(mrr_a=0.97, mrr_b=0.5)}                      # within the segment tolerance and the total tolerance
    assert _pass(tmp_path, monkeypatch, sets)["decision"] == "accept"


def test_thin_segments_are_reported_not_gated_and_a_vanished_segment_is_undecidable(tmp_path, monkeypatch):
    """AC: BSA-AC-1063"""
    sets = {"v": {"rag_dev": _set(n_a=1, n_b=2)}}
    _pass(tmp_path, monkeypatch, sets)
    sets["v"] = {"rag_dev": _set(mrr_a=0.0, recall_a=0.0, n_a=1, n_b=2)}      # the n=1 segment collapsed: reported, never gated (the case gate owns single queries)
    thin = _pass(tmp_path, monkeypatch, sets)
    assert not [f for f in thin["gate"]["failed"] if "area:licenses" in f] and any("too thin to gate" in w and "rag_dev/area:licenses (n=1)" in w for w in thin["gate"]["warnings"])
    gone = _set(n_b=2)
    del gone["segments"]["area:remediation"]
    sets["v"] = {"rag_dev": gone}
    res = _pass(tmp_path, monkeypatch, sets)
    assert res["decision"] == "rollback" and any("area:remediation" in u and "candidate has none" in u for u in res["gate"]["undecidable"])
    failed, undecidable, _ = eg.segment_gate({"s": {"a": {"n": 3, "recall": 1.0}}}, {"s": {"a": {"n": 3, "recall": None}}})
    assert failed == [] and len(undecidable) == 1                                                                       # an absent value is not a pass


# ------------------------------------------------------------------ pin
def test_the_eval_set_fingerprint_ignores_order_and_spacing_but_not_content():
    """AC: BSA-AC-1064"""
    a = [{"q": "라이선스는 어떤 순서로 찾아?", "expect": ["domain/licenses.md"]}, {"q": "오늘 날씨", "ood": True}]
    b = [{"q": "  오늘   날씨 ", "ood": True}, {"q": "라이선스는 어떤 순서로 찾아", "expect": ["domain/licenses.md"]}]
    assert eg.fingerprint(a) == eg.fingerprint(b) and len(eg.fingerprint(a)) == 12
    assert eg.fingerprint(a) != eg.fingerprint(a[:1]) and eg.fingerprint(a) != eg.fingerprint([dict(a[0], expect=["domain/other.md"]), a[1]])
    assert eg.fingerprint(a) != eg.fingerprint([a[0], {"q": "오늘 날씨", "ood": False, "expect": []}]) and eg.fingerprint(None) == eg.fingerprint([])


def test_a_baseline_measured_on_another_version_of_an_eval_set_is_undecidable(tmp_path, monkeypatch):
    """AC: BSA-AC-1065"""
    sets = {"v": {"rag_dev": _set(fp="111111111111"), "rag_test": _set(fp="222222222222")}}
    first = _pass(tmp_path, monkeypatch, sets)
    assert first["decision"] == "baseline" and first["eval_sets"] == {"rag_dev": "111111111111", "rag_test": "222222222222"}
    assert _pass(tmp_path, monkeypatch, sets)["decision"] == "accept"
    sets["v"] = {"rag_dev": _set(fp="111111111111"), "rag_test": _set(fp="333333333333")}       # identical numbers, but the holdout is another version
    bad = _pass(tmp_path, monkeypatch, sets)
    assert bad["decision"] == "rollback" and bad["gate"]["failed"] == []
    assert len(bad["gate"]["undecidable"]) == 1 and "rag_test: eval set changed since the baseline (222222222222 -> 333333333333)" in bad["gate"]["undecidable"][0]
    sets["v"] = {"rag_dev": _set(fp="111111111111"), "rag_test": _set(fp="222222222222"), "rag_golden": _set(fp="444444444444")}
    new = _pass(tmp_path, monkeypatch, sets)
    assert new["decision"] == "accept" and any("rag_golden: eval set is new since the baseline" in w for w in new["gate"]["warnings"])


def test_a_baseline_that_predates_pinning_still_compares_but_says_so(tmp_path, monkeypatch):
    """AC: BSA-AC-1066"""
    old = {"rag_dev": _set()}
    for v in old.values():
        v.pop("fingerprint")
        v.pop("segments")
    sets = {"v": old}
    assert _pass(tmp_path, monkeypatch, sets)["decision"] == "baseline"
    sets["v"] = {"rag_dev": _set()}
    res = _pass(tmp_path, monkeypatch, sets)
    assert res["decision"] == "accept" and res["gate"]["undecidable"] == []
    assert any("predates eval-set pinning" in w for w in res["gate"]["warnings"]) and any("predates segment metrics" in w for w in res["gate"]["warnings"])
    assert eg.pin_check({}, {}) == ([], [], []) and eg.pin_check(None, None) == ([], [], [])


def test_a_rebaseline_follows_a_deliberate_eval_set_change_and_can_never_launder_a_regression(tmp_path, monkeypatch):
    """AC: BSA-AC-1067"""
    sets = {"v": {"rag_dev": _set(fp="111111111111")}}
    with pytest.raises(ValueError, match="no accepted baseline"):
        _pass(tmp_path, monkeypatch, sets, rebaseline="the set was rewritten")
    _pass(tmp_path, monkeypatch, sets)
    sets["v"] = {"rag_dev": _set(mrr_a=0.2, mrr_b=0.2, fp="111111111111")}                      # a real regression on the SAME eval set
    with pytest.raises(ValueError, match="no eval set changed since pass 1"):
        _pass(tmp_path, monkeypatch, sets, rebaseline="make the numbers pass")
    assert _pass(tmp_path, monkeypatch, sets)["decision"] == "rollback"
    sets["v"] = {"rag_dev": _set(mrr_a=0.2, mrr_b=0.2, fp="999999999999")}                      # the set itself changed, deliberately
    with pytest.raises(ValueError, match="at least 8 characters"):
        _pass(tmp_path, monkeypatch, sets, rebaseline="ok")
    new = _pass(tmp_path, monkeypatch, sets, rebaseline="rag_dev rewritten: 4 queries added for the new sectors")
    assert new["decision"] == "baseline" and new["gate"]["pass"] is True and new["eval_sets"] == {"rag_dev": "999999999999"}
    assert new["rebaseline"] == {"reason": "rag_dev rewritten: 4 queries added for the new sectors", "replaces_pass": 1, "eval_sets_changed": ["rag_dev"]}
    after = _pass(tmp_path, monkeypatch, sets)
    assert after["decision"] == "accept" and after["baseline_pass"] if "baseline_pass" in after else after["decision"] == "accept"


# ------------------------------------------------------------------ leak and composition
def test_a_holdout_that_repeats_a_tuned_query_is_a_blocking_leak_and_a_repeat_among_tuned_sets_is_a_warning():
    """AC: BSA-AC-1068"""
    sets = {"rag_golden": [{"q": "라이선스는 어떤 순서로 찾아?", "expect": ["domain/licenses.md"]}, {"q": "비트코인 시세", "ood": True}],
            "rag_dev": [{"q": "라이선스는 어떤 순서로 찾아", "expect": ["domain/licenses.md"]}],
            "rag_test": [{"q": "GPL 의존성이 있으면 정책이 어떻게 판정되나", "expect": ["domain/licenses.md"]}, {"q": "라이선스는 어떤 순서로 찾아요", "expect": ["domain/licenses.md"]},
                         {"q": "승인 없이 패치를 요청하면 어떻게 되나", "expect": ["domain/remediation_patching.md"]}]}
    r = eg.leak_check(sets)
    kinds = {(f["kind"], tuple(f["sets"]), f["severity"]) for f in r["findings"]}
    assert ("duplicate", ("rag_dev", "rag_golden"), "warning") in kinds                                             # tuned vs tuned: wasted, not invalid
    assert ("near_duplicate", ("rag_golden", "rag_test"), "blocking") in kinds and ("near_duplicate", ("rag_dev", "rag_test"), "blocking") in kinds
    assert r["blocking"] == 2 and r["clean"] is False
    twice = eg.leak_check({"rag_test": [{"q": "same question here", "expect": ["a"]}, {"q": "Same question, here!", "expect": ["a"]}]})
    assert [(f["kind"], f["severity"]) for f in twice["findings"]] == [("duplicate", "warning")]
    assert eg.leak_check({"rag_test": [{"q": "첫번째 질문 입니다", "expect": ["a"]}], "rag_dev": [{"q": "완전히 다른 두번째 질문", "expect": ["b"]}]})["clean"] is True
    assert "near_duplicate [rag_golden/rag_test]" in eg.describe([f for f in r["findings"] if f["severity"] == "blocking"][0])


def test_a_query_copied_into_the_corpus_and_an_unreachable_expectation_are_findings():
    """AC: BSA-AC-1069"""
    chunks = [{"source": "domain/licenses.md", "heading": "Order", "text": "How is the licence found? first the registry, then the repository."},
              {"source": "lecture/rag.md", "heading": "RRF", "text": "k is 60."}]
    sets = {"rag_test": [{"q": "How is the licence found?", "expect": ["domain/licenses.md"]}, {"q": "how is k chosen", "expect": ["lecture/"]},
                         {"q": "an expectation nobody can meet", "expect": ["domain/nothing.md"]}, {"q": "short", "ood": True}],
            "rag_dev": [{"q": "How is the licence found?", "expect": ["domain/licenses.md"]}]}
    r = eg.leak_check(sets, chunks)
    got = {(f["kind"], tuple(f["sets"]), f["severity"]) for f in r["findings"]}
    assert ("in_corpus", ("rag_test",), "blocking") in got and ("in_corpus", ("rag_dev",), "warning") in got and ("dangling_expectation", ("rag_test",), "blocking") in got
    assert not [f for f in r["findings"] if f.get("q") in ("how is k chosen", "short")]                           # reachable prefix, and an out-of-domain item has no expectation
    assert eg.leak_check(sets)["findings"] and not [f for f in eg.leak_check(sets)["findings"] if f["kind"] in ("in_corpus", "dangling_expectation")]    # no corpus given: no corpus findings


def test_the_composition_table_names_thin_segments_and_a_language_that_is_not_measured():
    """AC: BSA-AC-1070"""
    sets = {"rag_dev": [{"q": "라이선스는 어떤 순서로 찾아?", "expect": ["domain/licenses.md"]}, {"q": "GPL 정책 판정", "expect": ["domain/licenses.md"]},
                        {"q": "락파일 직접 수정", "expect": ["domain/remediation_patching.md"]}, {"q": "오늘 날씨", "ood": True}],
            "rag_empty": []}
    c = eg.composition(sets)
    d = c["rag_dev"]
    assert (d["n"], d["in_domain"], d["ood"], d["ood_share"]) == (4, 3, 1, 0.25) and d["segments"]["area:licenses"] == 2 and d["thin"] == ["area:remediation_patching", "ood"]
    assert d["missing"] == ["lang:en"] and len(d["fingerprint"]) == 12
    assert c["rag_empty"]["n"] == 0 and c["rag_empty"]["ood_share"] is None and c["rag_empty"]["missing"] == []


# ------------------------------------------------------------------ the loop and the CLI over a real folder
def _root(tmp_path, golden, dev, test):
    root = tmp_path / "repo"
    (root / "knowledge" / "domain").mkdir(parents=True)
    (root / "evals").mkdir()
    (root / "knowledge" / "domain" / "licenses.md").write_text("# Licenses\n\nThe licence is found first in the registry and then in the repository.\n", encoding="utf-8")
    (root / "knowledge" / "domain" / "remediation_patching.md").write_text("# Patching\n\nA lockfile is never edited by hand; the manifest is changed and the lockfile regenerated.\n", encoding="utf-8")
    for name, items in (("rag_golden", golden), ("rag_dev", dev), ("rag_test", test)):
        (root / "evals" / (name + ".json")).write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")
    return root


GOLD = [{"q": "licence found registry repository order", "expect": ["domain/licenses.md"]}, {"q": "lockfile edited by hand manifest regenerated", "expect": ["domain/remediation_patching.md"]},
        {"q": "weather in seoul tomorrow", "ood": True}]
DEV = [{"q": "where is the licence found first", "expect": ["domain/licenses.md"]}]
TEST = [{"q": "which file is regenerated after a manifest change", "expect": ["domain/remediation_patching.md"]}]


def test_a_leaking_holdout_makes_every_later_pass_undecidable_and_the_cli_reports_it(tmp_path, capsys):
    """AC: BSA-AC-1071"""
    root = _root(tmp_path, GOLD, DEV, TEST)
    base = loop.run_rag_pass("a", str(root / "evidence" / "loop"), str(root), variable="v0")
    assert base["decision"] == "baseline" and base["eval_integrity"]["blocking"] == 0 and set(base["eval_sets"]) == {"rag_golden", "rag_dev", "rag_test"}
    assert cli.main(["--root", str(root), "evalsets"]) == 0 and "leak check: 0 blocking, 0 warning" in capsys.readouterr().out
    same = loop.run_rag_pass("b", str(root / "evidence" / "loop"), str(root), variable="v1")
    assert same["decision"] == "accept" and same["gate"]["undecidable"] == [] and same["eval_integrity"]["blocking"] == 0
    (root / "evals" / "rag_test.json").write_text(json.dumps(TEST + [dict(GOLD[0])]), encoding="utf-8")                       # the holdout now repeats a tuned-on query
    bad = loop.run_rag_pass("c", str(root / "evidence" / "loop"), str(root), variable="v2")
    assert bad["decision"] == "rollback" and bad["eval_integrity"]["blocking"] == 1
    assert any("eval set integrity: 1 blocking finding" in u for u in bad["gate"]["undecidable"]) and any("rag_test: eval set changed" in u for u in bad["gate"]["undecidable"])
    assert cli.main(["--root", str(root), "evalsets"]) == 1
    out = capsys.readouterr().out
    assert "leak check: 1 blocking" in out and "[blocking] duplicate [rag_golden/rag_test]" in out
    assert cli.main(["--root", str(root), "evalsets", "--json"]) == 1 and json.loads(capsys.readouterr().out)["leak"]["blocking"] == 1


def test_the_ragloop_cli_refuses_a_rebaseline_without_an_eval_set_change_and_accepts_one_after_a_change(tmp_path, capsys):
    """AC: BSA-AC-1072"""
    root = _root(tmp_path, GOLD, DEV, TEST)
    args = ["--root", str(root), "ragloop", "--variable", "v"]
    assert cli.main(args) == 0                                                                                       # the first pass records the baseline
    capsys.readouterr()
    assert cli.main(args + ["--rebaseline", "trying to reset the reference"]) == 2
    assert "no eval set changed since pass 1" in capsys.readouterr().out
    (root / "evals" / "rag_dev.json").write_text(json.dumps(DEV + [{"q": "licence repository registry order again", "expect": ["domain/licenses.md"]}]), encoding="utf-8")
    assert cli.main(args) == 1                                                                                       # a changed holdout version: the plain pass is rolled back
    capsys.readouterr()
    assert cli.main(args + ["--rebaseline", "rag_dev gained one licence query"]) == 0
    hist = json.load(open(os.path.join(str(root), "evidence", "loop", "rag_history.json"), encoding="utf-8"))
    assert [h["decision"] for h in hist] == ["baseline", "rollback", "baseline"] and hist[2]["rebaseline"]["eval_sets_changed"] == ["rag_dev"]


def test_the_real_eval_sets_have_an_honest_holdout():
    """AC: BSA-AC-1073"""
    rep = evals.eval_integrity()
    assert rep["leak"]["blocking"] == 0, [evalguard_line for evalguard_line in rep["leak"]["findings"] if evalguard_line["severity"] == "blocking"]
    assert not [f for f in rep["leak"]["findings"] if "rag_test" in f["sets"]]                                       # the holdout is not copied into the corpus nor repeats a tuned query
    assert set(rep["pins"]) == set(evals.RAG_SETS) and all(len(v) == 12 for v in rep["pins"].values())
    res = evals.rag_sets_eval()
    assert all(r["fingerprint"] == rep["pins"][n] and r["segments"] for n, r in res.items())
