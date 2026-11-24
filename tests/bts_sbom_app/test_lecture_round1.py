"""Lecture round 1 (Metanet advanced weeks 1-2) adoption: retrieval precision observability, conflict annotation,
case-level regression rate, requirement-kind map, trim accounting and the chat answer renderer.

Every behavior here is measured or observable: the lexical re-ranker itself was measured and REJECTED as an
ordering change (ADR-0016 records the numbers) - what ships is the annotation. The chat answer renderer is the
pure bts_ui.renderChatAnswer, exercised through tests/js/render_harness.js (skipped when node is absent).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from bts_sbom_app import ai, chat, evals, loop, rag, speclint

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "js", "render_harness.js")


def js(*calls):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    payload = json.dumps([{"mod": m, "fn": f, "args": list(a)} for m, f, *a in calls])
    p = subprocess.run([node, HARNESS], input=payload, capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def _idx(*chunks):
    return rag.Index([dict(c, meta=c.get("meta") or {"kind": "knowledge"}) for c in chunks])


# ------------------------------------------------------------------ retrieval precision observability (ADR-0016: rejected as ordering, shipped as annotation)
def test_a_heading_match_reports_a_positive_lex_signal():
    """AC: BSA-AC-486."""
    idx = _idx({"id": "k/a#0", "source": "k/retry.md", "heading": "Retry budget", "text": "The retry budget is 3 attempts per stage."})
    r = idx.search("retry budget per stage", k=3)
    hit = [x for x in r["results"] if x["chunk"]["source"] == "k/retry.md"][0]
    assert hit["lex"] > 0


def test_no_heading_match_stays_at_lex_zero_with_untouched_scores():
    """AC: BSA-AC-487."""
    idx = _idx({"id": "k/b#0", "source": "k/limits.md", "heading": "Limits", "text": "The upgrade budget per stage is 3 attempts."})
    r = idx.search("upgrade budget", k=3)
    hit = r["results"][0]
    assert hit["lex"] == 0 and hit["rrf"] > 0 and hit["bm25"] > 0


def test_the_lex_annotation_never_reorders_the_fused_ranking():
    """AC: BSA-AC-488."""
    idx = _idx({"id": "k/a#0", "source": "k/retry.md", "heading": "Retry budget", "text": "The retry budget is 3 attempts per stage."},
               {"id": "k/c#0", "source": "k/patch.md", "heading": "Patching", "text": "Patch plans list verified upgrade targets per component."},
               {"id": "k/d#0", "source": "k/overview.md", "heading": "Overview", "text": "retry budget overview of the whole staged rollout."})
    r = idx.search("retry budget per stage", k=3)
    rrf_order = [x["rrf"] for x in r["results"]]
    assert rrf_order == sorted(rrf_order, reverse=True)                      # reported order == reported rrf order, even where lex > 0


def test_the_rerank_block_counts_the_pool_and_the_lex_candidates():
    """AC: BSA-AC-489."""
    idx = _idx({"id": "k/a#0", "source": "k/retry.md", "heading": "Retry budget", "text": "The retry budget is 3 attempts per stage."},
               {"id": "k/c#0", "source": "k/patch.md", "heading": "Patching", "text": "Patch plans list verified upgrade targets per component."})
    r = idx.search("retry budget per stage", k=2)
    assert r["rerank"] == {"pool": 2, "lex_candidates": 1}


def test_relaxed_stem_match_connects_patch_and_patching():
    """AC: BSA-AC-490."""
    assert rag._relaxed("patch", "patching") is True and rag._relaxed("patching", "patch") is True
    assert rag._relaxed("patch", "patch") is True
    assert rag._relaxed("patch", "p2p") is False and rag._relaxed("cv", "cve") is False          # short tokens stay exact


# ------------------------------------------------------------------ conflict annotation
def test_the_same_label_with_different_numbers_in_two_sources_is_one_escalated_conflict():
    """AC: BSA-AC-491."""
    res = [{"chunk": {"source": "k/retry.md", "text": "The retry budget is 3 attempts per stage."}},
           {"chunk": {"source": "k/limits.md", "text": "The retry budget is 5 attempts per stage when offline."}}]
    c = rag.conflicts(res)
    assert len(c) == 1 and c[0]["label"] == "retry budget" and c[0]["rule"] == "escalate" and c[0]["status"] == "unresolved"
    assert c[0]["a"] == {"source": "k/retry.md", "value": "3"} and c[0]["b"] == {"source": "k/limits.md", "value": "5"}


def test_the_same_label_with_the_same_number_in_two_sources_is_no_conflict():
    """AC: BSA-AC-492."""
    res = [{"chunk": {"source": "k/a.md", "text": "한도: 80"}},
           {"chunk": {"source": "k/b.md", "text": "한도: 80"}}]
    assert rag.conflicts(res) == []


def test_two_different_numbers_inside_one_source_are_no_cross_source_conflict():
    """AC: BSA-AC-493."""
    res = [{"chunk": {"source": "k/a.md", "text": "한도: 80 이고 예산: 40"}}]
    assert rag.conflicts(res) == []


def test_the_chatbot_annotates_a_conflict_in_the_answer_and_the_result():
    """AC: BSA-AC-494."""
    fillers = [{"id": "f#%d" % i, "source": "f%d.md" % i, "heading": "Filler topic %d" % i,
                "text": "topic %d discusses widget %d with zeta%d eta%d parameters only." % (i, i, i, i)} for i in range(60)]
    idx = _idx({"id": "k/a#0", "source": "k/retry.md", "heading": "Retry budget", "text": "The retry budget is 3 attempts per stage."},
               {"id": "k/b#0", "source": "k/limits.md", "heading": "Limits", "text": "The retry budget is 5 attempts per stage when offline mode."},
               *fillers)
    bot = chat.Chatbot(idx, {"demo": evals.synthetic_project()})
    r = bot.ask("retry budget attempts stage offline mode", project="demo")
    assert r["found"] is True and len(r["conflicts"]) == 1
    assert r["answer"].count("[conflict]") == 1 and "judgement stays with you" in r["answer"]


def test_an_out_of_corpus_question_reports_no_conflicts():
    """AC: BSA-AC-495."""
    bot = chat.Chatbot(evals.build_index(), {"demo": evals.synthetic_project()})
    r = bot.ask("오늘 점심 메뉴 추천해줘", project="demo")
    assert r["found"] is False and r["conflicts"] == []


# ------------------------------------------------------------------ case-level regression rate (pass -> fail)
def test_case_regressions_lists_only_queries_that_lost_their_expected_document():
    """AC: BSA-AC-496."""
    base = {"golden": [{"q": "kept"}], "dev": [{"q": "gone"}]}
    cand = {"golden": [{"q": "new"}], "dev": []}                 # dev recovered (improvement), golden lost "kept"
    out = loop.case_regressions(base, cand)
    assert out == [{"set": "golden", "q": "new"}]
    assert loop.case_regressions({}, cand) == []                 # a set the baseline never measured is skipped


def test_a_passing_query_that_now_fails_blocks_the_pass_even_with_flat_aggregates(tmp_path, monkeypatch):
    """AC: BSA-AC-497."""
    sets = {"v": {"rag_golden": {"recall_at_k": 1.0, "mrr": 1.0, "ndcg_at_k": 1.0, "ood_rate": 1.0, "found_rate": 1.0,
                                 "misses": [{"q": "b", "why": "x", "top": None}]}}}          # baseline: "a" passes, "b" fails
    monkeypatch.setattr(loop.evals, "rag_sets_eval", lambda root: sets["v"])
    loop.run_rag_pass("base", str(tmp_path), str(tmp_path), variable="v0")
    sets["v"] = {"rag_golden": {"recall_at_k": 1.0, "mrr": 1.0, "ndcg_at_k": 1.0, "ood_rate": 1.0, "found_rate": 1.0,
                                "misses": [{"q": "a", "why": "x", "top": None}]}}            # aggregates identical: "a" now fails, "b" recovered
    e = loop.run_rag_pass("cand", str(tmp_path), str(tmp_path), variable="v1")
    assert e["decision"] == "rollback" and e["case_regressions"] == [{"set": "rag_golden", "q": "a"}]
    assert any("case regression" in f for f in e["gate"]["failed"])


def test_a_query_that_passes_now_but_failed_before_is_an_improvement_not_a_regression(tmp_path, monkeypatch):
    """AC: BSA-AC-498."""
    sets = {"v": {"rag_golden": {"recall_at_k": 0.9, "mrr": 0.9, "ndcg_at_k": 0.9, "ood_rate": 1.0, "found_rate": 0.9,
                                 "misses": [{"q": "a", "why": "x", "top": None}]}}}
    monkeypatch.setattr(loop.evals, "rag_sets_eval", lambda root: sets["v"])
    loop.run_rag_pass("base", str(tmp_path), str(tmp_path), variable="v0")
    sets["v"] = {"rag_golden": {"recall_at_k": 1.0, "mrr": 1.0, "ndcg_at_k": 1.0, "ood_rate": 1.0, "found_rate": 1.0, "misses": []}}
    e = loop.run_rag_pass("cand", str(tmp_path), str(tmp_path), variable="v1")
    assert e["decision"] == "accept" and e["case_regressions"] == []


def test_a_vanished_eval_set_stays_undecidable_and_invents_zero_regressions(tmp_path, monkeypatch):
    """AC: BSA-AC-499."""
    full = {"rag_golden": {"recall_at_k": 1.0, "mrr": 1.0, "ndcg_at_k": 1.0, "ood_rate": 1.0, "found_rate": 1.0, "misses": []},
            "rag_dev": {"recall_at_k": 0.9, "mrr": 0.9, "ndcg_at_k": 0.9, "ood_rate": 1.0, "found_rate": 0.9,
                        "misses": [{"q": "d1", "why": "x", "top": None}]}}
    sets = {"v": dict(full)}
    monkeypatch.setattr(loop.evals, "rag_sets_eval", lambda root: sets["v"])
    loop.run_rag_pass("base", str(tmp_path), str(tmp_path), variable="v0")
    sets["v"] = {"rag_golden": full["rag_golden"], "rag_dev": dict(full["rag_dev"], misses=[])}
    ok = loop.run_rag_pass("cand", str(tmp_path), str(tmp_path), variable="v1")
    assert ok["decision"] == "accept" and ok["case_regressions"] == []
    sets["v"] = {"rag_golden": full["rag_golden"]}                                           # the dev set vanished entirely
    bad = loop.run_rag_pass("gone", str(tmp_path), str(tmp_path), variable="v2")
    assert bad["decision"] == "rollback" and len(bad["gate"]["undecidable"]) == 5 and bad["case_regressions"] == []


def test_the_first_pass_of_a_fresh_loop_is_the_baseline_with_no_regressions(tmp_path, monkeypatch):
    """AC: BSA-AC-500."""
    monkeypatch.setattr(loop.evals, "rag_sets_eval", lambda root: {"rag_golden": {"recall_at_k": 1.0, "mrr": 1.0, "ndcg_at_k": 1.0,
                                                                                  "ood_rate": 1.0, "found_rate": 1.0, "misses": []}})
    e = loop.run_rag_pass("base", str(tmp_path), str(tmp_path), variable="v0")
    assert e["decision"] == "baseline" and e["case_regressions"] == []


# ------------------------------------------------------------------ requirement-kind map
def _spec(tmp_path, lines):
    p = tmp_path / "spec.md"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


def test_security_and_performance_requirements_are_tagged_secr_and_per(tmp_path):
    """AC: BSA-AC-501."""
    p = _spec(tmp_path, ["- BSA-AC-1 [Event] When the user approves, the approval token the user typed shall be required (1 of 1 tokens).",
                         "- BSA-AC-2 [Event] When a chat answer starts, the first token shall arrive within 2 seconds (p95 2s)."])
    rm = speclint.reqmap(p)
    assert rm["ids"]["SECR"] == ["BSA-AC-1"] and rm["ids"]["PER"] == ["BSA-AC-2"]


def test_data_and_interface_requirements_are_tagged_dar_and_sir(tmp_path):
    """AC: BSA-AC-502."""
    p = _spec(tmp_path, ["- BSA-AC-1 [Ubiquitous] The evidence record shall carry 1 schema version field (1 of 1 fields).",
                         "- BSA-AC-2 [Event] When the client asks /api/chat, the route shall answer in 1 json body (1 of 1 bodies)."])
    rm = speclint.reqmap(p)
    assert rm["ids"]["DAR"] == ["BSA-AC-1"] and rm["ids"]["SIR"] == ["BSA-AC-2"]


def test_constraints_are_conr_and_plain_functionality_defaults_to_sfr(tmp_path):
    """AC: BSA-AC-503."""
    p = _spec(tmp_path, ["- BSA-AC-1 [Unwanted] If a dependency were added, the build shall still use 0 non-stdlib packages (0 third-party modules).",
                         "- BSA-AC-2 [Event] When a report runs, the writer shall write exactly 3 files (3 of 3 files)."])
    rm = speclint.reqmap(p)
    assert rm["ids"]["CONR"] == ["BSA-AC-1"] and rm["ids"]["SFR"] == ["BSA-AC-2"] and rm["defaults"] == 1


def test_the_real_spec_partitions_every_ac_into_exactly_one_kind():
    """AC: BSA-AC-504."""
    spec = os.path.join(evals.repo_root(), "specs", "bts_sbom_app_features.md")
    rm = speclint.reqmap(spec)
    assert rm["total"] == len(speclint.parse(spec)) and sum(rm["kinds"].values()) == rm["total"]
    assert sorted(sum(rm["ids"].values(), [])) == sorted(speclint.parse(spec))


# ------------------------------------------------------------------ prompt trim accounting
def _big_rec() -> dict:
    vul = [{"id": "CVE-2020-%04d" % i, "aliases": [], "osv_ids": [], "package": "p%d" % i, "version": "1", "ecosystem": "PyPI",
            "purl": "pkg:pypi/p%d@1" % i, "severity": "LOW", "cvss": 1.0, "fixed_version": "2", "summary": "s", "files": []} for i in range(20)]
    plans = [{"component": "p%d" % i, "ecosystem": "PyPI", "current_version": "1", "safe_version": "2", "status": "upgrade", "clears": [],
              "uncleared": [], "cve_count": 1, "major_bump": False, "breaking_risk": "low", "files": [], "max_severity": "LOW", "max_cvss": 1.0,
              "verification": {"clean": True, "method": "osv_recheck", "rounds": 1, "residual": []}} for i in range(20)]
    comps = [{"name": "p%d" % i, "version": "1", "ecosystem": "PyPI", "license": "", "license_source": "", "license_category": "unknown",
              "vulns": 0, "files": []} for i in range(20)]
    return {"name": "big", "components": comps, "vulns": vul, "plans": plans, "license": {"stats": {}, "policy": []}, "arch": {}}


def test_over_cap_lists_report_the_exact_number_of_dropped_rows():
    """AC: BSA-AC-505."""
    ev = ai.evidence(_big_rec())
    assert len(ev["vulns"]) == 12 and ev["trimmed"]["vulns"] == 8
    assert len(ev["plans"]) == 12 and ev["trimmed"]["plans"] == 8
    assert len(ev["license"]["unresolved"]) == 12 and ev["trimmed"]["unresolved_licenses"] == 8


def test_a_small_project_trims_nothing_and_the_counts_stay_zero():
    """AC: BSA-AC-506."""
    ev = ai.evidence(evals.synthetic_project())
    assert ev["trimmed"] == {"vulns": 0, "plans": 0, "unresolved_licenses": 0, "policy": 0, "hotspots": 0, "cycles": 0,
                             "runtime_eol": 0, "extraction_candidates": 0}


# ------------------------------------------------------------------ chat answer renderer (pure, via node harness)
ANSWER = {"found": True, "answer": "요약 답변", "answer_source": "tools", "citation_accuracy": 1.0, "routing": "regex",
          "routing_note": "", "contains_untrusted": False, "conflicts": [],
          "retrieval": {"top": [{"source": "k/a.md", "heading": "Retry budget", "rrf": 0.049},
                                {"source": "k/b.md", "heading": "Limits", "rrf": 0.048}]}}


def test_the_renderer_escapes_every_dynamic_value_from_untrusted_sources():
    """AC: BSA-AC-507."""
    d = json.loads(json.dumps(ANSWER))
    d["retrieval"]["top"][0]["heading"] = "<script>alert(1)</script>"
    d["answer"] = 'quote "x" & <b>'
    m = js(("ui", "renderChatAnswer", d))[0]
    assert "<script>" not in m and "&lt;script&gt;alert(1)&lt;/script&gt;" in m
    assert "&quot;" in m and "&amp;" in m and "<b>" not in m.split("bts-chat-out")[1].split("</div>")[0]


def test_untrusted_quotes_and_conflicts_render_one_warning_note_each():
    """AC: BSA-AC-508."""
    d = json.loads(json.dumps(ANSWER))
    d["contains_untrusted"] = True
    d["conflicts"] = [{"label": "retry budget", "a": {"source": "a", "value": "3"}, "b": {"source": "b", "value": "5"}},
                      {"label": "timeout", "a": {"source": "a", "value": "30"}, "b": {"source": "b", "value": "60"}}]
    m = js(("ui", "renderChatAnswer", d))[0]
    assert m.count("bts-note warn") == 3 and m.count("[conflict]") == 2 and "never obeyed" in m
    plain = js(("ui", "renderChatAnswer", json.loads(json.dumps(ANSWER))))[0]
    assert plain.count("bts-note") == 0


def test_the_renderer_shows_two_evidence_chips_and_the_routing_line_only_when_a_note_exists():
    """AC: BSA-AC-509."""
    m = js(("ui", "renderChatAnswer", json.loads(json.dumps(ANSWER))))[0]
    assert m.count("bts-chat-chip\"") == 2 and "Retry budget" in m and "rrf 0.049" in m
    assert "routing: regex" in m and "unavailable" not in m
    d = json.loads(json.dumps(ANSWER))
    d["routing_note"] = "LLM plan had no valid tool call -> regex router"
    m2 = js(("ui", "renderChatAnswer", d))[0]
    assert m2.count("LLM plan had no valid tool call") == 1
