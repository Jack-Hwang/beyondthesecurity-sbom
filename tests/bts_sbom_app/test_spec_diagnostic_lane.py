"""The spec/diagnostic lane (C83/C53/C51/C58/C70/C65 + the FT decision table + pass lineage): prompt conflicts
linted by rule with the offending ids named, every tool carrying a worked example and its boundary against the
confusable neighbour, MCP calls audited with per-tool error rates and a bounded wall clock, maturity MEASURED
from repo artifacts instead of self-attested, a crash leaving a phase checkpoint instead of nothing, and the
fine-tuning decision answered from the measured gaps - which, per the course's proportionality rule, defaults
against fine-tuning."""
import json
import os
import types

from bts_sbom_app import chat, ft_decision, loop, maturity, prompt_lint, evals
from bts_sbom_app import mcp_server
from bts_sbom_app import pipeline


# ------------------------------------------------------------------ C83: the instruction-conflict lint
def _pkg(tmp_path, files):
    pkg = tmp_path / "bts_sbom_app"
    pkg.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (pkg / name).write_text(text, encoding="utf-8")
    return str(tmp_path)


def test_prompt_conflicts_are_linted_by_rule_with_ids_named(tmp_path):
    """AC: BSA-AC-1271"""
    root = _pkg(tmp_path, {
        "a.py": 'X_SYSTEM = "You are a careful reviewer. Respond with ONLY valid JSON, no prose, no code fences, ever."\nY_SYSTEM = "You write a friendly summary. Answer in at most 20 words, politely, in prose form."\n',
        "b.py": 'Z_SYSTEM = "You are a careful reviewer. Respond with ONLY valid JSON, no prose, no code fences, ever."\n',
        "c.py": 'W_SYSTEM = "Write at least 30 words of careful analysis but at most 20 words of prose in the final answer."\n',
    })
    r = prompt_lint.lint(root)
    rules = {f["rule"]: f for f in r["findings"]}
    assert "duplicate_content" in rules and set(rules["duplicate_content"]["ids"]) == {"a.X_SYSTEM", "b.Z_SYSTEM"}
    assert "contract_mismatch" in rules and rules["contract_mismatch"]["ids"]["json_only"] == ["a.X_SYSTEM"]
    assert "numeric_bounds_conflict" in rules and rules["numeric_bounds_conflict"]["ids"] == ["c.W_SYSTEM"]
    assert r["prompts_scanned"] == 4 and r["clean"] is False
    real = prompt_lint.lint(evals.repo_root())
    assert real["clean"] is True, real["findings"]                                        # this repo: measured clean


# ------------------------------------------------------------------ C53 + C51: examples, boundaries, accessible labels
def test_every_tool_has_a_worked_example_and_a_stated_boundary():
    """AC: BSA-AC-1271"""
    cat = chat.TOOL_CATALOG
    missing = [k for k, v in cat.items() if not (v.get("example") or "").strip() or not (v.get("boundary") or "").strip()]
    assert missing == [], missing                                                        # 28/28: example + boundary present
    assert "component_lookup" in cat["overview"]["boundary"]                             # the boundary names the confusable neighbour
    offered = chat.catalog(False)
    assert all(v.get("example") for v in offered.values())                               # the offered catalog carries them too
    panel = open("bts_sbom_app/web/bts_chat_panel.js", encoding="utf-8").read()
    assert "aria-label" in panel and "승인" in panel                                      # the approval button is labelled too (C51)


# ------------------------------------------------------------------ C58: the MCP lane is audited and bounded
def _call(monkeypatch, tmp_path, tool_fn=None, timeout=None):
    monkeypatch.setattr(mcp_server, "_TOOL_STATS", {})
    monkeypatch.setattr(mcp_server, "_tool_result", tool_fn or (lambda s, n, a, notify, token: {"value": 1}))
    if timeout is not None:
        monkeypatch.setattr(mcp_server, "_MCP_TIMEOUT", timeout)
    s = types.SimpleNamespace(evidence=str(tmp_path))
    msg = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "engine_status", "arguments": {"project": "demo"}}}
    return mcp_server.handle(s, msg)


def test_mcp_calls_are_audited_and_errors_counted_per_tool(tmp_path, monkeypatch):
    """AC: BSA-AC-1271"""
    r = _call(monkeypatch, tmp_path)
    assert r["result"]["isError"] is False
    lines = open(tmp_path / "mcp_audit.jsonl", encoding="utf-8").read().splitlines()
    rec = json.loads(lines[0])
    assert rec["tool"] == "engine_status" and rec["outcome"] == "ok" and isinstance(rec["duration_ms"], int)
    assert rec["arg_keys"] == ["project"]                                                 # argument KEYS only, never the caller's values
    st = mcp_server.tool_stats()
    assert st["engine_status"]["calls"] == 1 and st["engine_status"]["errors"] == 0
    def boom(s, n, a, notify, token):
        raise ValueError("bad input")
    _call(monkeypatch, tmp_path, boom)
    st2 = mcp_server.tool_stats()
    assert st2["engine_status"]["calls"] == 1 and st2["engine_status"]["errors"] == 1 and st2["engine_status"]["error_rate"] == 1.0


def test_an_mcp_call_is_bounded_and_sampling_is_honestly_refused(tmp_path, monkeypatch):
    """AC: BSA-AC-1271"""
    import time as _t

    def slow(s, n, a, notify, token):
        _t.sleep(0.5)
        return {}

    r = _call(monkeypatch, tmp_path, slow, timeout=0.15)
    assert r["result"]["isError"] is True and "NOT cancelled" in r["result"]["content"][0]["text"]   # the honest timeout note
    samp = mcp_server.handle(types.SimpleNamespace(evidence=str(tmp_path)),
                             {"jsonrpc": "2.0", "id": 8, "method": "sampling/createMessage", "params": {}})
    assert samp["error"]["code"] == -32601 and "gated LLM client" in samp["error"]["message"]


# ------------------------------------------------------------------ C70 + FT: maturity measured, FT decided from gaps
def test_maturity_is_measured_and_the_ft_verdict_names_its_gap():
    """AC: BSA-AC-1271"""
    m = maturity.diagnose()
    assert m["overall_level"] >= 1 and all(d["artifact_present"] for d in m["dimensions"].values())
    assert m["blockers"] == [] or all(m["dimensions"][b]["level"] == m["overall_level"] for b in m["blockers"])
    ft = ft_decision.decide()
    assert ft["dominant"] in ("knowledge", "format", "routing", None) and ft["recommendation"]
    assert "FT" in ft["recommendation"] or "RAG" in ft["recommendation"] or "라우팅" in ft["recommendation"]
    assert "측정" in ft["honesty"]                                                        # the verdict cites its own measurement


# ------------------------------------------------------------------ C65 + lineage: the crash leaves a trace
def test_the_stage_checkpoint_records_how_far_an_analysis_got(tmp_path):
    """AC: BSA-AC-1271"""
    cp = str(tmp_path / "proj.checkpoint.json")
    rec: dict = {"name": "proj", "timings": {}, "stage_errors": {}}
    S = pipeline._Stages(rec, checkpoint_path=cp)
    S.run("prepare", lambda: "ok")
    S.run("analyze", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    c = json.load(open(cp, encoding="utf-8"))
    assert c["last_completed_stage"] == "prepare" and c["stage"] == "analyze" and c["ok"] is False   # how far it got: measured
    assert "boom" in (c["error"] or "")
    assert rec["timings"]["analyze"] >= 0


def test_the_loop_pass_lineage_pins_its_eval_set_versions(tmp_path):
    """AC: BSA-AC-1271"""
    def fake_run(src, **kw):
        os.makedirs(os.path.join(kw["out_dir"], "proj"), exist_ok=True)
        return {"name": "proj", "components": [], "stage_errors": {}, "plans": [],
                "metrics": {"components": 1, "license_resolved": 1, "severity": {}, "license_sources": {},
                            "plans_upgrade": 0, "plans_verified_clean": 0, "sbom_ref_rate": None,
                            "patch_applied_components": 0, "vulns": 0, "patch_rescan_fixed": 0,
                            "patch_estimated_fixed": 0, "arch_edges": 0, "cyclonedx_valid": True,
                            "spdx_valid": True, "elapsed_s": 0.1, "stage_errors": 0}}
    orig = loop.batch.pipeline.run_project
    loop.batch.pipeline.run_project = fake_run
    try:
        e = loop.run_pass("t", [{"name": "proj", "src": "local/fake"}], str(tmp_path), str(tmp_path / "loop"), variable="test")
    finally:
        loop.batch.pipeline.run_project = orig
    assert "eval_pins" in e and "rag_golden" in e["eval_pins"]                            # WHICH eval-set versions measured this pass
    assert e["eval_pins"]["rag_golden"] == evals.evalguard.fingerprint(evals.rag_set_items()["rag_golden"])
