"""Arch Intel insights units (arch_flow.py): the book-grounded heuristic families over one measured structure -
flow blockers, bounded context candidates, the style hypothesis, antipattern signals and the modularity summary.
Every insight is derived ONLY from the measured facts it cites; each family carries an honesty note. Pure
functions over synthetic structures - no tree, no network, no LLM."""
from __future__ import annotations

import json

from bts_sbom_app import arch_flow, arch_intel, chat

CYCLED = {"graph": {"cycles": [["a", "b", "a"]]}}


# ------------------------------------------------------------------- AC: BSA-AC-461
def test_flow_blockers_list_import_cycles_in_order():
    """AC: BSA-AC-461"""
    fb = arch_flow.flow_blockers(CYCLED)
    assert fb["count"] == 1 and len(fb["blockers"]) == 1
    b = fb["blockers"][0]
    assert b["kind"] == "cycle" and b["what"] == "a → b → a" and b["evidence"] == "import graph SCC"


# ------------------------------------------------------------------- AC: BSA-AC-462
def test_flow_blockers_name_unstable_hubs_in_both_recorded_forms():
    """AC: BSA-AC-462"""
    fb = arch_flow.flow_blockers({"graph": {"unstable_hubs": [["hub.mod", 0.8], "plain.hub"]}})
    whats = [b["what"] for b in fb["blockers"]]
    assert fb["count"] == 2 and all(b["kind"] == "unstable_hub" for b in fb["blockers"])
    assert "hub.mod (instability 0.8)" in whats and "plain.hub (instability ?)" in whats


# ------------------------------------------------------------------- AC: BSA-AC-463
def test_flow_blockers_list_only_the_hidden_change_coupling_pairs():
    """AC: BSA-AC-463"""
    st = {"coupling": {"pairs": [{"a": "x.py", "b": "y.py", "shared": 3, "hidden": True},
                                 {"a": "p.py", "b": "q.py", "shared": 2, "hidden": False}]}}
    fb = arch_flow.flow_blockers(st)
    assert fb["count"] == 1
    assert fb["blockers"][0]["kind"] == "hidden_change_coupling"
    assert fb["blockers"][0]["what"] == "x.py + y.py (shared 3)"
    assert all("q.py" not in b["what"] for b in fb["blockers"])       # the plain pair never becomes a blocker


# ------------------------------------------------------------------- AC: BSA-AC-464
def test_hotspot_concentration_fires_only_above_the_threshold():
    """AC: BSA-AC-464"""
    def hot(scores):
        return [{"file": "f%d.py" % i, "commits": s, "score": float(s)} for i, s in enumerate(scores)]
    fb = arch_flow.flow_blockers({"hotspots": hot([12, 2, 1])})
    kinds = [b["kind"] for b in fb["blockers"]]
    assert "hotspot_concentration" in kinds and "f0.py (12 commits)" in [b["what"] for b in fb["blockers"]]
    assert arch_flow.flow_blockers({"hotspots": hot([5, 4, 3])})["count"] == 0      # no 3x concentration
    assert arch_flow.flow_blockers({"hotspots": hot([12, 2])})["count"] == 0        # fewer than 3 hotspots


# ------------------------------------------------------------------- AC: BSA-AC-465
def test_high_tangle_blocker_follows_the_measured_ratio():
    """AC: BSA-AC-465"""
    hot = arch_flow.flow_blockers({"graph": {"tangle_ratio": 0.3}})
    assert hot["count"] == 1 and hot["blockers"][0]["kind"] == "high_tangle" and hot["blockers"][0]["what"] == "tangle_ratio 0.3"
    assert arch_flow.flow_blockers({"graph": {"tangle_ratio": 0.2}})["count"] == 0


# ------------------------------------------------------------------- AC: BSA-AC-466
def test_a_clean_structure_reports_zero_blockers_and_invents_none():
    """AC: BSA-AC-466"""
    fb = arch_flow.flow_blockers({"graph": {}, "coupling": {"pairs": []}, "hotspots": []})
    assert fb["count"] == 0 and fb["blockers"] == []
    assert fb["note"]                                                  # the honesty note is always attached


# ------------------------------------------------------------------- AC: BSA-AC-467
def test_bounded_context_candidates_list_only_extraction_candidates_ordered_by_cohesion():
    """AC: BSA-AC-467"""
    st = {"clusters": [
        {"domain": "zeta", "cohesion": 0.7, "inbound": 1, "outbound": 2, "modules": 3, "extraction_candidate": True},
        {"domain": "mid", "cohesion": 0.5, "inbound": 4, "outbound": 1, "modules": 2, "extraction_candidate": False},
        {"domain": "alpha", "cohesion": 0.9, "inbound": 0, "outbound": 1, "modules": 2, "extraction_candidate": True}]}
    members = {"zeta": ["z/%d.py" % i for i in range(8)], "alpha": ["a/one.py"]}
    bcc = arch_flow.bounded_context_candidates(st, members)
    assert bcc["count"] == 2 and [c["name"] for c in bcc["candidates"]] == ["alpha", "zeta"]   # cohesion descending
    assert len(bcc["candidates"][1]["files"]) == 6                     # the member list is capped at 6 files
    assert bcc["candidates"][0]["files"] == ["a/one.py"]


# ------------------------------------------------------------------- AC: BSA-AC-468
def test_no_candidate_clusters_yield_an_empty_honest_list():
    """AC: BSA-AC-468"""
    st = {"clusters": [{"domain": "mid", "cohesion": 0.5, "inbound": 4, "outbound": 1, "modules": 2,
                        "extraction_candidate": False}]}
    bcc = arch_flow.bounded_context_candidates(st, {})
    assert bcc["count"] == 0 and bcc["candidates"] == [] and "mid" not in json.dumps(bcc)
    assert bcc["note"]


# ------------------------------------------------------------------- AC: BSA-AC-469
def test_layer_names_in_three_groups_read_as_a_layered_hypothesis():
    """AC: BSA-AC-469"""
    st = {"files_all": ["web/ui/page.py", "services/order.py", "repositories/store.py"]}
    sh = arch_flow.style_hypothesis(st, {})
    assert sh["style"] == "layered" and len(sh["signals"]) == 3        # one signal per observed layer group
    assert sh["note"]


# ------------------------------------------------------------------- AC: BSA-AC-470
def test_compose_manifest_reads_distributed_and_single_entry_with_domains_reads_modular_monolith():
    """AC: BSA-AC-470"""
    dist = arch_flow.style_hypothesis({"files_all": [], "entry_points": [], "clusters": []},
                                      {"docker-compose.yml": True})
    assert dist["style"] == "distributed" and any("manifests: 1" in s for s in dist["signals"])
    mono = arch_flow.style_hypothesis({"files_all": [], "entry_points": [{"path": "main.py", "kind": "python-main"}],
                                       "clusters": [{"domain": "svc-a", "modules": 3}, {"domain": "svc-b", "modules": 2}]}, {})
    assert mono["style"] == "modular_monolith" and mono["signals"] == ["entry points: 1", "cohesive domains: 2"]


# ------------------------------------------------------------------- AC: BSA-AC-471
def test_no_signals_carry_an_empty_style_and_name_none():
    """AC: BSA-AC-471"""
    sh = arch_flow.style_hypothesis({"files_all": [], "entry_points": [], "clusters": []}, {})
    assert sh["style"] == "" and sh["signals"] == [] and sh["why"] == ""
    assert sh["note"]                                                  # and the honesty note says it is a hypothesis


# ------------------------------------------------------------------- AC: BSA-AC-472
def test_big_ball_of_mud_and_low_cohesion_signals_carry_their_measurements():
    """AC: BSA-AC-472"""
    st = {"graph": {"tangle_ratio": 0.3, "cycle_count": 3},
          "clusters": [{"cohesion": 0.3}, {"cohesion": 0.3}, {"cohesion": 0.3}], "files_all": []}
    ap = arch_flow.antipattern_signals(st)
    codes = [s["code"] for s in ap["signals"]]
    assert codes == ["big_ball_of_mud", "low_cohesion"]
    mud = ap["signals"][0]["measured"]
    assert mud == {"tangle_ratio": 0.3, "cycles": 3}
    assert ap["signals"][1]["measured"]["avg_cohesion"] == 0.3


# ------------------------------------------------------------------- AC: BSA-AC-473
def test_root_sprawl_fires_at_the_measured_share_and_stays_silent_below_it():
    """AC: BSA-AC-473"""
    def files(root):
        return ["f%d.py" % i for i in range(root)] + ["d%d/g.py" % i for i in range(20 - root)]
    ap = arch_flow.antipattern_signals({"graph": {}, "clusters": [], "files_all": files(8)})
    sprawl = [s for s in ap["signals"] if s["code"] == "root_sprawl"]
    assert len(sprawl) == 1 and sprawl[0]["measured"]["root_share"] == 0.4
    assert all(s["code"] != "root_sprawl" for s in arch_flow.antipattern_signals({"graph": {}, "clusters": [], "files_all": files(7)})["signals"])


# ------------------------------------------------------------------- AC: BSA-AC-474
def test_a_clean_structure_reports_no_antipattern_signals_and_never_a_verdict():
    """AC: BSA-AC-474"""
    ap = arch_flow.antipattern_signals({"graph": {}, "clusters": [], "files_all": []})
    assert ap["count"] == 0 and ap["signals"] == []
    assert ap["note"] and "판정" in ap["note"]                          # the report names risk signals, never a verdict


# ------------------------------------------------------------------- AC: BSA-AC-475
def test_modularity_summary_computes_cohesion_acyclic_and_candidate_flags():
    """AC: BSA-AC-475"""
    st = {"clusters": [
        {"domain": "a", "cohesion": 0.9, "modules": 2, "inbound": 0, "outbound": 1, "extraction_candidate": True},
        {"domain": "b", "cohesion": 0.6, "modules": 3, "inbound": 2, "outbound": 2, "extraction_candidate": False},
        {"domain": "c", "cohesion": 0.3, "modules": 2, "inbound": 1, "outbound": 0, "extraction_candidate": True}],
        "graph": {"nodes_in_graph": 10, "modules_in_cycles": 2}}
    mod = arch_flow.modularity_summary(st)
    assert mod["avg_cohesion"] == 0.6
    assert mod["acyclic_percent"] == 80.0
    assert [r["bounded_context_candidate"] for r in mod["clusters"]] == [True, False, True]


# ------------------------------------------------------------------- AC: BSA-AC-476
def test_build_insights_returns_the_schema_and_all_six_families_with_notes():
    """AC: BSA-AC-476"""
    st = {"graph": {"cycles": [["a", "b", "a"]]},
          "clusters": [{"domain": "svc/pay", "cohesion": 0.8, "inbound": 0, "outbound": 1, "modules": 2,
                        "extraction_candidate": True}],
          "files_all": ["svc/pay/a.py", "svc/pay/b.py"]}
    pack = arch_flow.build_insights(st, {"Dockerfile": True})
    assert set(pack) == {"schema", "flow_blockers", "bounded_context_candidates", "style_hypothesis",
                         "antipattern_signals", "modularity", "code_smells"}
    assert pack["schema"] == arch_flow.SCHEMA
    for family in ("flow_blockers", "bounded_context_candidates", "style_hypothesis",
                   "antipattern_signals", "modularity", "code_smells"):
        assert pack[family]["note"], family                            # every family stays honest about being a heuristic
    assert pack["flow_blockers"]["count"] == 1
    assert pack["bounded_context_candidates"]["candidates"][0]["files"] == ["svc/pay/a.py", "svc/pay/b.py"]


# ------------------------------------------------------------------- AC: BSA-AC-477
def test_prompt_evidence_carries_insights_as_metadata_only():
    """AC: BSA-AC-477"""
    st = {"stack": {"languages": {"Python": {"files": 1, "loc": 5}}}, "files": ["svc/pay/a.py"],
          "graph": {"import_edges": 1, "cycle_count": 0, "cycles": []},
          "clusters": [], "hotspots": [], "runtime_eol": [], "notes": [], "files_all": ["svc/pay/a.py"],
          "files_count": 1, "total_loc": 5, "entry_points": [], "key_files": [], "modules": [], "edges": []}
    lic = {"project_license": "MIT", "category": "permissive", "obligations": ["keep notices"]}
    pack = arch_flow.build_insights(st, {})
    ev = arch_intel.prompt_evidence("p", lic, st, pack)
    blob = json.dumps(ev["insights"])
    assert set(ev["insights"]) == {"flow_blockers", "bounded_context_candidates", "style_hypothesis", "code_smells"}
    assert all(f not in blob for f in st["files_all"])                 # insight file lists never reach the prompt


# ------------------------------------------------------------------- AC: BSA-AC-479
def test_report_md_writes_the_insights_section_only_when_insights_exist():
    """AC: BSA-AC-479"""
    res = {"meta": {"id": "a" * 10, "source": "repo", "tool_version": "0.3.0"},
           "license": {"project_license": "MIT", "category": "permissive", "obligations": []},
           "insights": arch_flow.build_insights({"graph": {"cycles": [["a", "b", "a"]]}, "clusters": [], "files_all": []}, {})}
    md = arch_intel.report_md(res)
    assert "## Insights (measured, heuristic)" in md and "| cycle |" in md and "Style hypothesis" not in md
    bare = arch_intel.report_md({"meta": res["meta"], "license": res["license"]})
    assert "Insights" not in bare                                      # no insights measured -> no section is invented


# ------------------------------------------------------------------- AC: BSA-AC-480
def _fake_run(tmp_path, jid, source, finished, insights):
    d = tmp_path / jid
    d.mkdir()
    doc = {"schema": "bts-sbom.arch-intel.v1",
           "meta": {"id": jid, "source": source, "finished": finished, "lang": "ko", "distribution": "binary"},
           "license": {"project_license": "GPL-3.0-only", "category": "strong-copyleft", "obligations": ["keep notices"]},
           "ai_source": "deterministic", "insights": insights}
    (d / "result.json").write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    return str(d)


def test_latest_arch_chat_tool_summarises_the_latest_recorded_run(tmp_path):
    """AC: BSA-AC-480"""
    pack = arch_flow.build_insights({"graph": {"cycles": [["a", "b", "a"]]}, "clusters": [
        {"domain": "svc", "cohesion": 0.8, "inbound": 0, "outbound": 1, "modules": 2, "extraction_candidate": True}],
        "files_all": ["svc/a.py"]}, {})
    _fake_run(tmp_path, "0123456789", "old/repo", "2026-11-20T10:00:00", pack)
    _fake_run(tmp_path, "fedcba9876", "new/repo", "2026-11-21T10:00:00", pack)
    res = chat.run_tool(None, "latest_arch", {}, arch_dir=str(tmp_path))
    line = res[0]["lines"]
    assert len(line) == 7 and res[0]["source"] == "archintel:latest"
    assert "new/repo" in line[0] and "old/repo" not in "".join(line)   # the latest finished stamp wins
    assert "GPL-3.0-only" in line[1] and "keep notices" in line[1]
    assert "Flow blockers (1)" in line[2] and "cycle" in line[2]
    assert "svc (cohesion 0.8)" in line[3] and "never a verdict" in line[6]
    for empty_dir in (str(tmp_path / "nowhere"), None):
        empty = chat.run_tool(None, "latest_arch", {}, arch_dir=empty_dir)[0]["lines"]
        assert len(empty) == 1 and ("No Arch Intel" in empty[0] or "run has been recorded" in empty[0])
