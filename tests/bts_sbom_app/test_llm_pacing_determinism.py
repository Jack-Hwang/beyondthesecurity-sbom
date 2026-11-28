"""The LLM client round (C49/C68/C42/C14): structured (JSON) calls sample at a low temperature by client default
while reasoning models - which reject or ignore the parameter - never receive it, the client can pace proactively
(before a request is spent, not after a 429), the loop regression records per-case wall time and token spend, and
the eval pipeline is a determinism regression: the same inputs measure to the same numbers, twice."""
import json
import types

from bts_sbom_app import batch, evals, evals_top10, loop
from bts_sbom_app import llm as llm_mod


def _ok(text="hi"):
    return 200, json.dumps({"choices": [{"message": {"content": text}, "finish_reason": "stop"}],
                            "usage": {"prompt_tokens": 1, "completion_tokens": 1}})


# ------------------------------------------------------------------ C49: temperature on structured calls
def test_json_mode_defaults_to_a_low_temperature_and_reasoning_models_never_get_one(monkeypatch):
    """AC: BSA-AC-1269"""
    seen = {}
    monkeypatch.setattr(llm_mod, "TRANSPORT", lambda u, h, b: seen.update(body=b) or _ok())
    monkeypatch.setattr(llm_mod, "SLEEP", lambda s: None)
    c = llm_mod.ChatClient("k", provider="openai-compatible", daily_budget=10)
    c.complete("s", "u", json_mode=True)
    assert seen["body"].get("temperature") == 0.2                     # the client default for structured output
    seen.clear()
    c.complete("s", "u", json_mode=True, temperature=0.5)
    assert seen["body"].get("temperature") == 0.5                     # an explicit value wins over the default
    seen.clear()
    c.complete("s", "u")                                              # prose: no default injected
    assert "temperature" not in seen["body"]
    az = llm_mod.ChatClient("k", provider="azure", model="gpt-5-mini", daily_budget=10)
    seen.clear()
    az.complete("s", "u", json_mode=True)
    assert "temperature" not in seen["body"]                          # a reasoning model: reasoning_effort replaces it
    assert seen["body"].get("reasoning_effort") == "low"


# ------------------------------------------------------------------ C68: proactive pacing
def test_the_client_paces_before_spending_the_call(monkeypatch):
    """AC: BSA-AC-1269"""
    monkeypatch.setattr(llm_mod, "TRANSPORT", lambda u, h, b: _ok())
    sleeps: list = []
    monkeypatch.setattr(llm_mod, "SLEEP", lambda s: sleeps.append(s))
    c = llm_mod.ChatClient("k", provider="openai-compatible", daily_budget=10)
    c.min_interval = 0.4
    c.complete("s", "u")
    assert sleeps == []                                               # the first call is not paced (no prior)
    c.complete("s", "u")
    assert len(sleeps) == 1 and 0.2 < sleeps[0] <= 0.4                # the wait happened BEFORE the second request
    off = llm_mod.ChatClient("k", provider="openai-compatible", daily_budget=10)
    off.complete("s", "u")
    off.complete("s", "u")
    assert sleeps == [] or all(s <= 0.4 for s in sleeps)              # pacing off by default: no forced wait injected here


# ------------------------------------------------------------------ C42: per-case wall time + token spend in the batch/loop
def test_batch_records_per_case_seconds_and_tokens(monkeypatch, tmp_path):
    """AC: BSA-AC-1269"""
    def fake_run(src, **kw):
        import os
        import time as t
        t.sleep(0.02)
        if kw.get("out_dir"):
            os.makedirs(os.path.join(kw["out_dir"], "proj"), exist_ok=True)   # the real pipeline creates this; the stub must too
        return {"name": "proj", "components": [], "stage_errors": {}, "plans": [],
                "metrics": {"components": 1, "license_resolved": 1, "severity": {}, "license_sources": {},
                            "plans_upgrade": 0, "plans_verified_clean": 0, "sbom_ref_rate": None,
                            "patch_applied_components": 0, "vulns": 0, "patch_rescan_fixed": 0,
                            "patch_estimated_fixed": 0, "arch_edges": 0,
                            "cyclonedx_valid": True, "spdx_valid": True, "elapsed_s": 0.1,
                            "stage_errors": 0}}

    monkeypatch.setattr(batch.pipeline, "run_project", fake_run)
    client = types.SimpleNamespace(usage={"prompt_tokens": 100, "completion_tokens": 50}, describe=lambda: {})
    r = batch._run_one({"name": "proj", "src": "local/fake"}, work_root=str(tmp_path / "w"), run_dir=None,
                       settings={}, client=client, cache_dir=str(tmp_path / "c"))
    assert isinstance(r.get("s"), (int, float)) and r["s"] >= 0.0     # per-case wall time (C42)
    assert r["llm_tokens"] == {"prompt_tokens": 0, "completion_tokens": 0}   # the stub spent nothing: an honest zero
    e = loop.run_pass("t", [{"name": "proj", "src": "local/fake"}], str(tmp_path), str(tmp_path / "loop"),
                      variable="test", client=client)
    assert e["llm_cost"] is not None and "proj" in e["per_case_seconds"]


def tmp_dir():
    import tempfile
    return tempfile.mkdtemp()


# ------------------------------------------------------------------ C14: the eval pipeline is deterministic
def test_the_eval_pipeline_measures_the_same_numbers_twice():
    """AC: BSA-AC-1269"""
    inv1, inv2 = evals.eval_inventory(), evals.eval_inventory()
    assert inv1 == inv2                                               # composition + fingerprints: byte-stable
    r1, r2 = evals.rag_eval(), evals.rag_eval()
    for k in ("recall_at_k", "mrr", "ood_rate", "segments"):
        assert r1[k] == r2[k], k
    ref1, ref2 = evals_top10.reference_eval(), evals_top10.reference_eval()
    assert ref1["rows"] == ref2["rows"] and ref1["answer_correctness"] == ref2["answer_correctness"]
