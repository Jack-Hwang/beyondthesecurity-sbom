"""V&V evidence report (task 30, TR 8477 P1-A, AC 721-730)."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from bts_sbom_app import evals, pipeline, server, vnv
from conftest import FakeScanner


def _rec(tmp_path, make_repo, world, offline=False, requirements="requests==2.19.1\n"):
    origin = make_repo({"requirements.txt": requirements})
    ev = str(tmp_path / "ev")
    return pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                                run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"),
                                offline=offline, online_license=not offline)


def test_online_clean_project_reports_pass(tmp_path, make_repo, world):
    """AC: BSA-AC-721"""
    rec = _rec(tmp_path, make_repo, world)
    rep = vnv.report(rec)
    assert rep["results"]["grade"] == "pass" and rep["scope"]["exclusions"]
    assert rep["scope"]["exclusions"][-1]["item"] == "exploitability"          # the fixed existence-only line stays
    assert rep["traceability"]["online"] is True and rep["traceability"]["commit"]


def test_offline_is_pass_with_restrictions_never_pass(tmp_path, make_repo, world):
    """AC: BSA-AC-722"""
    rec = _rec(tmp_path, make_repo, world, offline=True)
    rep = vnv.report(rec)
    assert rep["results"]["grade"] == "pass with restrictions"
    assert any("오프라인" in x["reason"] for x in rep["scope"]["exclusions"])
    assert rep["traceability"]["online"] is False


def test_unresolved_license_adds_a_restriction(tmp_path, make_repo, world):
    """AC: BSA-AC-723"""
    rec = _rec(tmp_path, make_repo, world, requirements="requests==2.19.1\n" + "LicenseRef-mystery==1.0\n")
    rep = vnv.report(rec)
    assert any("unresolved license" in x["item"] for x in rep["scope"]["exclusions"])
    assert rep["results"]["grade"] == "pass with restrictions"


def test_a_failed_analysis_is_fail(tmp_path, make_repo, world, monkeypatch):
    """AC: BSA-AC-724"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(tmp_path / "ev"), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    rec["error"] = "engine exploded"
    assert vnv.report(rec)["results"]["grade"] == "fail"


def test_zero_components_is_restricted_never_pass(tmp_path):
    """AC: BSA-AC-725"""
    rec = {"name": "x", "components": [], "vulns": [], "plans": [], "metrics": {}, "stage_errors": {},
           "status": {"mode": "online"}, "engine": {"core": "", "unsupported": []}, "lineage": {}, "error": None}
    rep = vnv.report(rec)
    assert rep["results"]["grade"] == "pass with restrictions"
    assert any("0개다" in x["reason"] for x in rep["scope"]["exclusions"])


def test_the_fixed_exploitability_statement_is_always_in_scope(tmp_path, make_repo, world):
    """AC: BSA-AC-726"""
    rec = _rec(tmp_path, make_repo, world)
    rep = vnv.report(rec)
    assert rep["scope"]["exploitability"] == vnv.FIXED_SCOPE
    assert "입증" in rep["scope"]["exploitability"] and "확인" in rep["scope"]["exploitability"]


def test_traceability_carries_user_refs_and_versions(tmp_path, make_repo, world):
    """AC: BSA-AC-727"""
    rec = _rec(tmp_path, make_repo, world)
    rep = vnv.report(rec, plan_ref="PLAN-42 rev2", req_ref="REQ-7")
    tr = rep["traceability"]
    assert tr["plan_ref"] == "PLAN-42 rev2" and tr["req_ref"] == "REQ-7"
    assert tr["tool"] == "bts_sbom_app" and tr["workflow_version"]


def test_deterministic_bytes_and_markdown_surfaces(tmp_path, make_repo, world):
    """AC: BSA-AC-728"""
    rec = _rec(tmp_path, make_repo, world)
    a = json.dumps(vnv.report(rec), sort_keys=True, ensure_ascii=False)
    b = json.dumps(vnv.report(rec), sort_keys=True, ensure_ascii=False)
    assert a == b
    md = vnv.render_md(vnv.report(rec))
    assert md == vnv.render_md(vnv.report(rec))
    assert vnv.DISCLAIMER in md and "## Results" in md and "## Conclusion" in md


def test_the_api_answers_for_a_project_and_404s_for_unknown(tmp_path, make_repo, world):
    """AC: BSA-AC-729"""
    rec = _rec(tmp_path, make_repo, world)
    st = server.State(evals.repo_root(), str(tmp_path / "ev"), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        with urllib.request.urlopen(base + "/api/vnv/" + rec["name"], timeout=10) as r:
            body = json.loads(r.read())
        assert body["schema"] == vnv.SCHEMA
        try:
            urllib.request.urlopen(base + "/api/vnv/nope", timeout=10)
            raise AssertionError("expected 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        httpd.shutdown()


def test_deviations_list_stage_errors(tmp_path, make_repo, world, monkeypatch):
    """AC: BSA-AC-730"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    from bts_sbom_app import obligations
    monkeypatch.setattr(obligations, "assess", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(tmp_path / "ev"), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    rep = vnv.report(rec)
    assert any(d["stage"] == "obligations" for d in rep["deviations"])
