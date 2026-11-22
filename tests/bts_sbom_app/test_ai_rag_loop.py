"""EXAONE lane (fake transport), retrieval/chatbot grounding, loop gate."""
from __future__ import annotations

import json

import pytest

from bts_sbom_app import ai, chat, evals, loop
from bts_sbom_app.llm import ChatClient, LLMError, LLMUnavailable


def _ok(content: str):
    return 200, json.dumps({"choices": [{"message": {"content": content}}], "usage": {"prompt_tokens": 5, "completion_tokens": 7}})


def test_http_429_day_limit_downgrades_after_one_call(world):
    """AC: BSA-AC-33"""
    world.llm_handler = lambda body: (429, '{"error": "daily request limit exceeded"}')
    res = ai.propose(evals.synthetic_project(), client=ChatClient("k"), use_llm=True)
    assert res["source"] == "deterministic" and "429" in res["llm_note"] and world.llm_calls == 1 and res["items"]


def test_four_layer_validation_keeps_exactly_one(world):
    """AC: BSA-AC-34"""
    props = [{"title": "ok", "action": "upgrade", "refs": ["requests"], "target_version": "2.20.0", "rationale": "r", "risk": "low"},
             {"title": "bad action", "action": "explode", "refs": ["requests"], "target_version": None, "rationale": "r", "risk": "low"},
             {"title": "ghost", "action": "upgrade", "refs": ["ghost-lib"], "target_version": "1.0", "rationale": "r", "risk": "low"},
             {"title": "wrong version", "action": "upgrade", "refs": ["requests"], "target_version": "9.9.9", "rationale": "r", "risk": "low"}]
    world.llm_handler = lambda body: _ok(json.dumps({"summary": "s", "proposals": props}))
    res = ai.propose(evals.synthetic_project(), client=ChatClient("k"), use_llm=True)
    assert res["source"] == "exaone" and len(res["items"]) == 1
    assert res["dropped"] == {"schema": 0, "rule": 1, "semantic": 1, "cross_field": 1}


def test_same_evidence_costs_one_call(world, tmp_path):
    """AC: BSA-AC-35"""
    good = [{"title": "ok", "action": "upgrade", "refs": ["requests"], "target_version": "2.20.0", "rationale": "r", "risk": "low"}]
    world.llm_handler = lambda body: _ok(json.dumps({"summary": "s", "proposals": good}))
    c = ChatClient("k")
    a = ai.propose(evals.synthetic_project(), client=c, cache_dir=str(tmp_path), use_llm=True)
    b = ai.propose(evals.synthetic_project(), client=c, cache_dir=str(tmp_path), use_llm=True)
    assert world.llm_calls == 1 and a["source"] == b["source"] == "exaone" and b["cached"] is True


def test_budget_reached_makes_zero_network_calls(world):
    """AC: BSA-AC-36"""
    with pytest.raises(LLMUnavailable):
        ChatClient("k", daily_budget=0).complete("s", "u")
    assert world.llm_calls == 0


def test_api_key_never_surfaces_in_errors(world):
    """AC: BSA-AC-37"""
    world.llm_handler = lambda body: (401, '{"error": "invalid key SECRETKEY123"}')
    with pytest.raises(LLMError) as ei:
        ChatClient("SECRETKEY123").complete("s", "u")
    assert str(ei.value).count("SECRETKEY123") == 0


def test_golden_retrieval_thresholds():
    """AC: BSA-AC-38, BSA-AC-39"""
    r = evals.rag_eval()
    assert r["queries"] == 20 and r["recall_at_k"] >= 0.85 and r["mrr"] >= 0.6 and r["ndcg_at_k"] >= 0.7
    assert r["ood_queries"] == 5 and r["ood_rejected"] == 5


def test_chat_answers_from_tools_with_perfect_citation_and_rejects_forgery():
    """AC: BSA-AC-40"""
    c = evals.chat_eval()
    assert c["found_rate"] == 1.0 and c["tool_routing_rate"] == 1.0 and c["citation_accuracy"] == 1.0
    forged = chat.verify_claims([{"quote": "this sentence is not in the source", "source": "s1"}], {"s1": "real text only"})
    assert forged["verified"] == 0 and forged["claims"] == 1


def test_claim_pointing_to_unretrieved_source_is_rejected():
    """AC: BSA-AC-41"""
    v = chat.verify_claims([{"quote": "real text", "source": "chunk-not-retrieved"}], {"s1": "real text"})
    assert v["verified"] == 0


def test_regression_gate_blocks_drop_over_delta():
    """AC: BSA-AC-42"""
    base = {"license_resolved_rate": 0.80, "sbom_ref_rate": 1.0, "stage_errors": 0}
    assert loop.gate(base, dict(base))["pass"] is True
    worse = dict(base, license_resolved_rate=0.70)
    g = loop.gate(base, worse)
    assert g["pass"] is False and g["failed"]


def test_plateau_after_three_identical_passes():
    """AC: BSA-AC-43"""
    h = [{"metrics": {"a": 1}} for _ in range(3)]
    assert loop.plateau(h, 3) is True and loop.plateau(h[:2] + [{"metrics": {"a": 2}}], 3) is False


def test_hypotheses_citing_unknown_cluster_are_dropped():
    """AC: BSA-AC-44"""
    class Fake:
        def complete(self, system, user, max_tokens=0, json_mode=False):
            return json.dumps({"hypotheses": [
                {"cluster": "license:unresolved:Go", "variable": "add proxy.golang.org lookup", "expected_effect": "license_resolved_rate up", "risk": "low"},
                {"cluster": "patch:blocked:npm", "variable": "support overrides", "expected_effect": "fix_applied_rate up", "risk": "low"},
                {"cluster": "made:up:cluster", "variable": "magic", "expected_effect": "everything", "risk": "low"}]})
    clusters = [{"key": "license:unresolved:Go", "count": 9, "examples": []}, {"key": "patch:blocked:npm", "count": 3, "examples": []}]
    res = loop.propose_variables(clusters, client=Fake())
    assert res["source"] == "exaone" and len(res["items"]) == 2


def test_untouched_test_set_answerable_rate_and_ood():
    """AC: BSA-AC-61"""
    r = evals.rag_sets_eval()["rag_test"]
    assert r["queries"] == 12 and r["found_rate"] >= 0.8 and r["ood_queries"] == 4 and r["ood_rejected"] == 4


def test_llm_calls_are_serialized(world):
    """AC: BSA-AC-62"""
    import threading
    import time
    state = {"now": 0, "max": 0}
    lock = threading.Lock()

    def handler(body):
        with lock:
            state["now"] += 1
            state["max"] = max(state["max"], state["now"])
        time.sleep(0.05)
        with lock:
            state["now"] -= 1
        return _ok("{}")

    world.llm_handler = handler
    c = ChatClient("k")
    ts = [threading.Thread(target=lambda: c.complete("s", "u")) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert state["max"] == 1 and world.llm_calls == 2


def test_ledger_counts_failed_attempts(world, tmp_path, monkeypatch):
    """AC: BSA-AC-63"""
    from bts_sbom_app import llm as llmmod
    monkeypatch.setattr(llmmod.time, "sleep", lambda s: None)
    world.llm_handler = lambda body: (500, "boom")
    c = ChatClient("k", ledger=str(tmp_path / "l.json"))
    with pytest.raises(LLMError):
        c.complete("s", "u")
    assert c.calls_today() == 2


def test_invalid_answer_is_not_cached(world, tmp_path):
    """AC: BSA-AC-64"""
    world.llm_handler = lambda body: _ok('{"summary": "cut off", "proposals": [{"title": "x"')       # truncated JSON
    res = ai.propose(evals.synthetic_project(), client=ChatClient("k"), cache_dir=str(tmp_path), use_llm=True)
    assert res["source"] == "deterministic" and "unparseable" in res["llm_note"]
    assert list(tmp_path.glob("ai_*.json")) == []


def test_refs_with_only_versions_are_repaired_from_the_title():
    """AC: BSA-AC-65"""
    rec = evals.synthetic_project()
    ev = ai.evidence(rec)
    props = [{"title": "requests 업그레이드", "action": "upgrade", "refs": ["2.19.1", "2.20.0"], "target_version": "2.20.0", "rationale": "r", "risk": "low"},
             {"title": "requests and leftpad 업그레이드", "action": "upgrade", "refs": ["2.19.1"], "target_version": "2.20.0", "rationale": "r", "risk": "low"}]
    v = ai.validate({"summary": "s", "proposals": props}, rec, ev)
    assert len(v["items"]) == 1 and v["repaired"] == 1 and v["dropped"]["cross_field"] == 1
    assert v["items"][0]["refs"][0] == "requests"


def _chat_with(world, claims):
    from bts_sbom_app import chat as chatmod
    bot = chatmod.Chatbot(evals.build_index(), {"demo": evals.synthetic_project()}, ChatClient("k"))
    world.llm_handler = lambda body: _ok(json.dumps({"answer": "요약", "claims": claims}))
    return bot.ask("CVE-2018-18074 는 어떤 취약점이야", project="demo", use_llm=True)


def test_chat_accepts_bracketed_ids_and_rejects_translated_quotes(world):
    """AC: BSA-AC-67"""
    src = "project:demo:vuln_lookup"
    quote = "CVE-2018-18074 affects requests 2.19.1, severity HIGH (CVSS 7.5), fixed in 2.20.0."
    good = _chat_with(world, [{"text": "a", "quote": quote, "source": "[%s]" % src},
                              {"text": "b", "quote": quote, "source": "wrong-id-but-quote-is-in-exactly-one-passage"}])
    assert good["answer_source"] == "exaone" and good["citation_accuracy"] == 1.0 and len([c for c in good["claims"] if c["trust"] != "untrusted-quote"]) == 2
    bad = _chat_with(world, [{"text": "c", "quote": "CVE-2018-18074 는 requests 2.19.1 에 영향을 주며 심각도는 HIGH 입니다", "source": src}])
    assert bad["answer_source"] == "tools" and "rejected" in bad["llm_note"]


def test_azure_openai_uses_api_key_header_and_deployment_url(monkeypatch):
    """Azure OpenAI: api-key header + deployment-scoped URL, no Bearer, no model key in body."""
    from bts_sbom_app import llm as llm_mod
    seen = {}

    def transport(url, headers, body):
        seen["url"], seen["headers"], seen["body"] = url, headers, body
        return _ok("hi")

    monkeypatch.setattr(llm_mod, "TRANSPORT", transport)
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "azkey")
    monkeypatch.setenv("AZURE_OPENAI_BASE_URL", "https://test-res.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5-mini")
    monkeypatch.delenv("EXAONE_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    c = llm_mod.ChatClient.from_env()
    out = c.complete("sys", "user")
    assert out == "hi" and c.provider == "azure"
    assert seen["url"] == "https://test-res.openai.azure.com/openai/deployments/gpt-5-mini/chat/completions?api-version=2025-04-01-preview"
    assert seen["headers"].get("api-key") == "azkey" and "Authorization" not in seen["headers"]
    assert "model" not in seen["body"] and "max_tokens" not in seen["body"]
    assert seen["body"]["max_completion_tokens"] == 2048 and seen["body"]["reasoning_effort"] == "low"


def test_azure_config_file_keys_win_over_exaone(monkeypatch, tmp_path):
    """azure_* config keys route the client to the azure provider."""
    from bts_sbom_app import llm as llm_mod
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({"azure_api_key": "k2", "azure_base_url": "https://r.openai.azure.com",
                               "azure_deployment": "d1", "azure_api_version": "2025-04-01"}), encoding="utf-8")
    monkeypatch.setenv("BTS_SBOM_LLM_CONFIG", str(cfg))
    monkeypatch.setenv("EXAONE_API_KEY", "exaone-key")
    c = llm_mod.ChatClient.from_env()
    assert c.provider == "azure" and c.api_key == "k2" and c.model == "d1" and c.api_version == "2025-04-01"
    assert c.base_url == "https://r.openai.azure.com"


def test_from_config_autodetects_azure_by_base_url():
    """A web-console client pointed at an Azure endpoint routes to the azure provider with a gpt-5-aware default api-version."""
    from bts_sbom_app.llm import ChatClient
    c = ChatClient.from_config("k", "https://res.openai.azure.com", "gpt-5-mini")
    assert c.provider == "azure" and c.api_version == "2025-04-01-preview"
    c2 = ChatClient.from_config("k", "https://res.openai.azure.com", "gpt-4o")
    assert c2.provider == "azure" and c2.api_version == "2024-10-21"
    c3 = ChatClient.from_config("k", "https://api.exaone.ai/v1", "k-exaone_v2.5")
    assert c3.provider == "exaone"
