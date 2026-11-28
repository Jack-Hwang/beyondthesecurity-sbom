# -*- coding: utf-8 -*-
"""diagrams.py: the EA-17.2 diagram catalog over measured data (ADR-0024; AC: BSA-AC-573, BSA-AC-574, BSA-AC-575, BSA-AC-578).

Catalog identity: the kind list mirrors the New-Diagram registry REA extracted from the shipped artefact
(easetup_x64.msi 17.2.1721.15, embedded technology XML inside EA.exe + MDG technology files) - the tests pin the
groups so a rename drifts loudly. Every builder is deterministic: same record, same Mermaid text. A kind without
measured input returns mermaid == "" plus an honest note - never a plausible fake. One data source: the synthetic
record below (fixtures stay hand-written, never invented from live scans).
"""
import pytest

from bts_sbom_app import chat as chatmod
from bts_sbom_app import decision as dmn
from bts_sbom_app import diagrams as dg

REC = {
    "name": "demo",
    "components": [
        {"name": "requests", "ecosystem": "pypi", "version": "2.19.1", "license": "Apache-2.0", "vulns": 2},
        {"name": "mysql-connector", "ecosystem": "pypi", "version": "8.0", "license": "GPL-2.0", "vulns": 1},
    ],
    "vulns": [
        {"id": "CVE-2024-0001", "package": "requests", "severity": "HIGH", "cvss": 8.1, "fixed_version": "2.20.0",
         "published": "2024-01-15T00:00:00", "malicious": False},
        {"id": "MAL-2024-0009", "package": "evil-pkg", "severity": "CRITICAL", "cvss": 9.8, "fixed_version": "",
         "published": "2024-03-01T00:00:00", "malicious": True},
    ],
    "plans": [{"component": "requests", "ecosystem": "pypi", "current_version": "2.19.1", "safe_version": "2.20.0",
               "status": "upgrade", "verification": {"clean": True}, "major_bump": False, "breaking_risk": "low"}],
    "license": {"project_license": "MIT", "stats": {}, "policy": []},
    "conformance": {"status": "OK", "format": "CycloneDX 1.5", "components": 2,
                    "regimes": {"ntia-2021": {"title": "NTIA 2021", "verdict": "pass", "pass": 5, "partial": 0, "gap": 0, "total": 5, "draft": False, "as_of": "2026-01-01"}},
                    "elements": {}, "fix_once": []},
    "changes": {"verdict": "worse", "compared_at": "2026-01-01",
                "summary": {"vulns_new": 1, "vulns_resolved": 1, "vulns_rescored": 0, "alerts": 1},
                "new": [{"id": "CVE-2024-0001", "package": "requests"}],
                "resolved": [{"id": "CVE-2023-0001", "package": "flask"}], "rescored": [],
                "alerts": [{"severity": "HIGH", "kind": "new-critical", "package": "evil-pkg", "id": "MAL-2024-0009", "detail": "malware"}]},
    "patch": {"rounds": 1},
    "layer_validation": {"checked": 1, "unknown_layer_edges": 0, "layers_declared": 2,
                         "violations": [{"edge": ["app/ui.py", "infra/db.py"], "from_layer": "ui", "to_layer": "db", "why": "not in may_depend_on"}],
                         "bypassed": [], "verdict": "fail"},
    "arch": {
        "stack": {"languages": {"python": {"files": 2, "loc": 40}}, "files": 2, "loc": 40},
        "graph": {"modules": 2, "import_edges": 1},
        "edges": [["app/ui.py", "app/logic.py"], ["app/logic.py", "infra/db.py"]],
        "clusters": [{"domain": "app", "modules": 2, "internal_edges": 1, "outbound": 0, "inbound": 0, "cohesion": 1.0}],
        "runtime_eol": [{"product": "python", "cycle": "3.9", "declared_in": ".python-version", "status": "eol", "eol_date": "2025-10-31", "source": "embedded-table"}],
        "code": {"language": "python",
                 "classes": [{"name": "Scanner", "file": "app/scan.py", "line": 1, "bases": ["Base"], "methods": ["run"]},
                             {"name": "Base", "file": "app/base.py", "line": 1, "bases": [], "methods": ["x"]}],
                 "functions": [{"id": "app/scan.py::run", "name": "run", "cls": "Scanner", "file": "app/scan.py", "line": 1,
                                "complexity": 9, "fan_in": 1, "fan_out": 1},
                               {"id": "app/base.py::x", "name": "x", "cls": "Base", "file": "app/base.py", "line": 1,
                                "complexity": 2, "fan_in": 1, "fan_out": 0}],
                 "call_edges": [{"from": "app/scan.py::run", "to": "app/base.py::x"}],
                 "metrics": {"functions": 2, "max_complexity": {"name": "run", "file": "app/scan.py", "cc": 9}},
                 "notes": []},
    },
}


# --------------------------------------------------------------------------- catalog identity (the REA census)
def test_catalog_carries_the_ea17_groups_from_the_rea_extraction():
    groups = {v["group"] for v in dg.CATALOG.values()}
    assert {"UML Structural", "UML Behavioral", "Extended", "Data & Process", "Enterprise", "Code Intel"} <= groups


def test_catalog_covers_every_uml_core_kind_verified_in_the_artifact():
    # the six structural + seven behavioral kinds of the embedded UML technology, plus the EA-named extensions
    for kind in ("package", "class", "object", "composite", "component", "deployment",
                 "usecase", "activity", "state", "communication", "sequence", "timing", "interaction",
                 "requirements", "maintenance", "custom", "erd", "dfd", "decision", "archimate", "mindmap", "kanban"):
        assert kind in dg.CATALOG, kind


def test_sysml_kinds_exist_after_the_round2_rea_correction():
    # round-2 REA corrected the first-pass claim: EA 17.2 ships SysML natively (UTF-16 evidence:
    # "MDG Technology for SysML", "SysML Block Definition Diagram", "SysML Parametric Diagram", ...).
    for kind, ea in (("bdd", "SysML Block Definition Diagram"), ("ibd", "SysML Internal Block Diagram"),
                     ("parametric", "SysML Parametric Diagram"), ("robustness", "Robustness Diagram (ICONIX)")):
        assert kind in dg.CATALOG and dg.CATALOG[kind]["ea"] == ea, kind
    assert dg.CATALOG["timing"]["ea"].startswith("Timing / Timeline")


def test_bdd_draws_blocks_and_generalization_and_names_what_it_cannot_measure():
    out = dg.build("bdd", REC)
    assert "<<block>>" in out["mermaid"] and "generalization" in out["mermaid"]
    assert "측정하지 않아" in out["note"]


def test_parametric_maps_the_policy_table_to_constraint_blocks():
    out = dg.build("parametric", REC)
    assert "«constraint»" in out["mermaid"] and "«value»" in out["mermaid"]
    assert "FIRE" in out["mermaid"] and "우리 정책 제약망" in out["note"]


def test_robustness_states_its_heuristic_rules():
    doc = {"structure": {"entry_points": [{"path": "app/main.py"}]}}
    out = dg.build("robustness", REC, doc)
    assert "«boundary»" in out["mermaid"] and "«control»" in out["mermaid"]
    assert "휴리스틱" in out["note"]


def test_catalog_is_honest_about_what_this_tool_cannot_measure():
    assert "ui" in dg.CATALOG                                     # EA Wireframing: user-authored, not derivable
    out = dg.build("ui", REC)
    assert out["mermaid"] == "" and "측정" in out["note"]


def test_catalog_doc_and_lines_agree_with_the_registry():
    doc = dg.catalog_doc()
    assert len(doc) == len(dg.CATALOG)
    lines = dg.catalog_lines()
    assert any("UML Structural:" in ln for ln in lines) and any("class" in ln for ln in lines)


# --------------------------------------------------------------------------- every kind draws or explains itself
def test_every_kind_returns_mermaid_or_an_honest_note():
    for kind in dg.CATALOG:
        out = dg.build(kind, REC, None, target="Scanner" if kind in ("composite", "butterfly") else None,
                       spec="A -> B -> C" if kind == "custom" else None)
        assert isinstance(out["mermaid"], str) and isinstance(out["note"], str), kind
        assert out["mermaid"] or out["note"], kind                # never silently empty


def test_needs_project_kinds_refuse_without_a_record():
    for kind in ("package", "class", "state", "erd", "call"):
        out = dg.build(kind, None)
        assert out["mermaid"] == "" and "분석된 프로젝트" in out["note"], kind


def test_decision_kind_without_a_record_falls_through_to_the_catch_all_rule_honestly():
    out = dg.build("decision", None)
    assert out["mermaid"] and "FIRE R8" in out["mermaid"]        # the documented (*) rule: monitor, no invention
    assert "팩트 없음" in out["note"]


# --------------------------------------------------------------------------- determinism + measured sources
def test_same_record_yields_the_same_diagram():
    a = dg.build("class", REC)
    b = dg.build("class", REC)
    assert a["mermaid"] == b["mermaid"] and a["note"] == b["note"]


def test_class_diagram_draws_measured_inheritance_only():
    out = dg.build("class", REC)
    assert "Scanner" in out["mermaid"] and "Base" in out["mermaid"]
    assert "--|>" in out["mermaid"] and "1건" in out["note"]


def test_package_diagram_aggregates_the_recorded_import_edges():
    out = dg.build("package", REC)
    assert "flowchart" in out["mermaid"] and "app" in out["mermaid"]
    rec2 = {**REC, "arch": {**REC["arch"], "edges": [["app/ui.py", "app/logic.py"]]}}
    out2 = dg.build("package", rec2)
    assert out2["mermaid"] == "" and "같은 도메인 내부" in out2["note"]   # intra-domain edges make no boundary
    rec3 = {**REC, "arch": {**REC["arch"], "edges": []}}
    out3 = dg.build("package", rec3)
    assert out3["mermaid"] == "" and "기록된 import 엣지가 없습니다" in out3["note"]


def test_decision_diagram_marks_the_fired_rule():
    out = dg.build("decision", REC)
    assert "FIRE R1" in out["mermaid"]                          # REC carries a malware advisory => R1 quarantine
    assert "decided" in out["note"]


def test_state_machine_counts_are_the_record_numbers():
    out = dg.build("state", REC)
    assert "악성 1" in out["note"] and "수정판 있음 1" in out["note"] and "stateDiagram" in out["mermaid"]


def test_timing_only_uses_iso_dates_present_in_the_record():
    out = dg.build("timing", REC)
    assert "gantt" in out["mermaid"] and "2024-01-15" in out["mermaid"]


def test_erd_states_it_draws_this_tools_evidence_schema():
    out = dg.build("erd", REC)
    assert "COMPONENT" in out["mermaid"] and "증거 스키마" in out["note"]


# --------------------------------------------------------------------------- custom spec (conversational drawing)
def test_custom_spec_parses_arrow_chains_verbatim():
    out = dg.build("custom", None, spec="사용자 -> 게이트웨이 -> 스캐너\n스캐너 -> 리포트")
    assert out["mermaid"].count("-->") == 3
    assert 'n1["사용자"]' in out["mermaid"] and 'n3["스캐너"]' in out["mermaid"]


def test_custom_spec_rejects_prose_without_arrows_honestly():
    out = dg.build("custom", None, spec="그냥 문장만 있는 질문")
    assert out["mermaid"] == "" and "해석하지 못했습니다" in out["note"]


def test_custom_node_ids_are_stable_across_nodes_and_edges():
    out = dg.build("custom", None, spec="A -> B -> C")
    ids = [ln.split('["')[0].strip() for ln in out["mermaid"].splitlines()[1:4]]
    assert ids == ["n1", "n2", "n3"], ids


# --------------------------------------------------------------------------- chat + policy integration
def test_draw_diagram_tool_returns_lines_and_a_diagram_card():
    res = chatmod.run_tool(REC, "draw_diagram", {"kind": "class"}, None, None)
    assert res[0]["lines"] and res[0]["cards"][0]["kind"] == "diagram_ref"   # the card IS the render payload
    assert res[0]["cards"][0]["mermaid"].startswith("classDiagram")
    assert res[0]["source"] == "diagrams:class"


def test_draw_diagram_catalog_kind_needs_no_project():
    res = chatmod.run_tool(None, "draw_diagram", {"kind": "catalog"}, None, None)
    assert any("UML Structural" in ln for ln in res[0]["lines"])
    assert "diagrams" not in res[0]                             # a listing is text, not a drawing


def test_draw_diagram_custom_without_a_project_draws_the_spec():
    res = chatmod.run_tool(None, "draw_diagram", {"kind": "custom", "spec": "A -> B"}, None, None)
    assert res[0]["cards"][0]["mermaid"].startswith("flowchart")          # the card is the render payload


def test_decide_tool_runs_inference_and_attaches_the_decision_diagram():
    res = chatmod.run_tool(REC, "decide", {}, None, None)
    assert any("verdict=decided" in ln for ln in res[0]["lines"])
    assert res[0]["diagrams"][0]["mermaid"].startswith("flowchart")
    facts = dg.facts_from_record(REC)
    assert facts["severity"] == "critical" and facts["malicious"] is True


def test_validate_calls_drops_unknown_kinds_and_passes_known_ones():
    calls, dropped = chatmod.validate_calls([{"tool": "draw_diagram", "args": {"kind": "nope"}}], REC, "x")
    assert not calls and dropped["semantic"] == 1
    ok, _ = chatmod.validate_calls([{"tool": "draw_diagram", "args": {"kind": "erd"}}], REC, "erd")
    assert ok


def test_ask_attaches_diagrams_to_the_answer(monkeypatch):
    class DummyIndex:
        def search(self, q, k=4, filters=None):
            return {"found": False, "coverage": 0.0, "results": []}
    bot = chatmod.Chatbot(DummyIndex(), projects={"demo": REC})
    res = bot.ask("A -> B -> C 사용자 게이트웨이 스캐너 리포트 다이어그램 그려줘")
    assert "draw_diagram" in res["tools"]
    drawn = res["cards"][0] if (res.get("cards") or []) else (res.get("diagrams") or [{}])[0]
    assert drawn["mermaid"].startswith("flowchart")                       # card path since the diagram_ref kind


def test_facts_from_record_prefers_explicit_overrides():
    facts = dg.facts_from_record(REC, {"distribution": "saas"})
    assert facts["distribution"] == "saas" and facts["severity"] == "critical"


def test_policy_table_stays_pure_and_editable():
    t = dmn.remediation_policy()
    assert t.hit_policy == "F" and len(t.rules) == 8
    r = dmn.evaluate(t, dg.facts_from_record(REC))
    assert r["verdict"] == "decided" and r["matched"] == ["R1"]   # malware present -> quarantine, always first


# --------------------------------------------------------------------------- /api/diagrams over a real server
def test_api_diagrams_catalog_and_kind_routes(tmp_path):
    import json
    import socket
    import threading
    import urllib.request
    from http.server import ThreadingHTTPServer
    from bts_sbom_app import evals, pipeline, server
    import os
    base = str(tmp_path / "ev")
    os.makedirs(os.path.join(base, "projects", "demo"), exist_ok=True)
    with open(os.path.join(base, "projects", "demo", "demo.json"), "w", encoding="utf-8") as fh:
        json.dump({"schema": pipeline.PROJECT_SCHEMA, "name": "demo", "components": REC["components"],
                   "vulns": REC["vulns"], "plans": REC["plans"], "license": REC["license"],
                   "conformance": REC["conformance"], "changes": REC["changes"], "patch": REC["patch"],
                   "arch": REC["arch"]}, fh, ensure_ascii=False)
    st = server.State(evals.repo_root(), base, None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        root = "http://127.0.0.1:%d" % httpd.server_address[1]
        with urllib.request.urlopen(root + "/api/diagrams", timeout=10) as r:
            cat = json.loads(r.read())["catalog"]
        assert len(cat) == len(dg.CATALOG) and any(c["kind"] == "decision" for c in cat)
        with urllib.request.urlopen(root + "/api/diagrams/class?project=demo", timeout=10) as r:
            d = json.loads(r.read())
        assert d["mermaid"].startswith("classDiagram") and d["group"] == "UML Structural"
        with urllib.request.urlopen(root + "/api/diagrams/custom?spec=A%20-%3E%20B", timeout=10) as r:
            assert json.loads(r.read())["mermaid"].startswith("flowchart")
        for url, code in (("/api/diagrams/nope", 404), ("/api/diagrams/erd?project=ghost", 404)):
            try:
                urllib.request.urlopen(root + url, timeout=10)
                raise AssertionError("expected 404 for " + url)
            except urllib.error.HTTPError as e:
                assert e.code == code, (url, e.code)
    finally:
        httpd.shutdown()
