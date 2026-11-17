"""Cross-project questions (fleet), the chatbot tools built on them, and the matching CLI / API."""
from __future__ import annotations

import copy
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import changes, chat, cli, conformance, evals, fleet, pipeline, sbom, server
from conftest import FakeScanner


def _v(vid, pkg="requests", ver="2.19.1", sev="HIGH", aliases=(), fixed="2.20.0"):
    return {"id": vid, "aliases": list(aliases), "osv_ids": [], "package": pkg, "version": ver, "ecosystem": "PyPI", "severity": sev, "cvss": None,
            "fixed_version": fixed, "summary": "s", "files": ["requirements.txt"], "malicious": False}


def _c(name, ver, vulns=0, lic="MIT"):
    return {"name": name, "version": ver, "ecosystem": "PyPI", "license": lic, "relationship": "direct", "vulns": vulns, "files": ["requirements.txt"]}


def _projects():
    return {"alpha": {"name": "alpha", "components": [_c("requests", "2.19.1", 2), _c("idna", "2.7")],
                      "vulns": [_v("CVE-2018-18074", aliases=["GHSA-x84v-xcm2-53pg"]), _v("CVE-2099-0001", sev="CRITICAL", fixed="")]},
            "beta": {"name": "beta", "components": [_c("requests", "2.31.0"), _c("Flask", "2.0.0", lic="")], "vulns": []},
            "gamma": {"name": "gamma", "components": [_c("Requests", "2.19.1", 1), _c("noversion", "")],
                      "vulns": [_v("CVE-2018-18074", aliases=["GHSA-x84v-xcm2-53pg"])]}}


# ------------------------------------------------------------------ fleet
def test_an_advisory_lookup_lists_exactly_the_projects_it_hits_and_matches_aliases():
    """AC: BSA-AC-166"""
    for ident in ("CVE-2018-18074", "ghsa-x84v-xcm2-53pg"):
        r = fleet.affected(_projects(), vuln_id=ident)
        assert [p["project"] for p in r["projects"]] == ["alpha", "gamma"] and r["not_found_in"] == ["beta"] and r["analysed_projects"] == 3
    both = fleet.affected(_projects(), vuln_id="CVE-2018-18074", component="idna")
    assert both["project_count"] == 0                                                              # the advisory is on requests, not on idna
    with pytest.raises(ValueError):
        fleet.affected(_projects())


def test_component_lookup_honours_version_constraints_and_reports_an_unknown_version_instead_of_hiding_it():
    """AC: BSA-AC-167"""
    p = _projects()
    hit = fleet.affected(p, component="requests", version="<2.20,>=2.0")
    assert [r["project"] for r in hit["projects"]] == ["alpha", "gamma"]                          # canonical name: Requests == requests
    assert [r["project"] for r in fleet.affected(p, component="requests", version=">=2.20")["projects"]] == ["beta"]
    assert [r["project"] for r in fleet.affected(p, component="requests", version="2.19.1")["projects"]] == ["alpha", "gamma"]
    unknown = fleet.affected(p, component="noversion", version="<2.0")
    assert unknown["projects"][0]["matches"][0]["kind"] == "version_unknown"
    assert fleet.affected(p, component="noversion")["projects"][0]["matches"][0]["kind"] == "component"
    for junk in ("<>", "latest", "1.0,,"):
        with pytest.raises(ValueError):
            fleet.parse_spec(junk)
    assert fleet.in_spec("2.19.1", fleet.parse_spec("<2.20,>=2.0")) and not fleet.in_spec("2.20.0", fleet.parse_spec("<2.20,>=2.0"))


def test_rollup_ranks_projects_by_weighted_findings_and_lists_advisories_shared_by_projects():
    """AC: BSA-AC-168"""
    r = fleet.rollup(_projects())
    assert [x["project"] for x in r["ranking"]] == ["alpha", "gamma", "beta"] and [x["weighted"] for x in r["ranking"]] == [15, 5, 0]
    shared = [e for e in r["shared_advisories"] if e["project_count"] > 1]
    assert [(e["id"], e["project_count"]) for e in shared] == [("CVE-2018-18074", 2)] and r["unfixed_findings"] == 1
    assert r["projects"] == 3 and r["components"] == 6 and r["vulns"] == 3 and r["severity"] == {"HIGH": 2, "CRITICAL": 1}
    assert "requests" in [e["name"].lower() for e in r["shared_components"]]
    md = fleet.render_rollup_md(r)
    assert "| alpha |" in md and "Advisories shared" in md and "not a risk metric" in md
    assert "Advisories shared" not in fleet.render_rollup_md(fleet.rollup({"beta": _projects()["beta"], "x": _projects()["beta"]}))


@pytest.fixture
def svc(tmp_path, make_repo, world):
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False, scanner=FakeScanner(), run_arch=False, cache_dir=str(tmp_path / "c"))
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "rec": rec, "ev": ev}
    httpd.shutdown()


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_service_answers_the_rollup_and_the_affected_query_and_rejects_an_empty_query(svc):
    """AC: BSA-AC-169"""
    code, roll = _get(svc["base"] + "/api/fleet")
    assert code == 200 and roll["projects"] == 1 and roll["vulns"] == 2
    code, hit = _get(svc["base"] + "/api/affected?cve=CVE-2020-1111")
    assert code == 200 and hit["project_count"] == 1 and hit["projects"][0]["matches"][0]["package"] == "requests"
    assert _get(svc["base"] + "/api/affected?component=requests&version=%3C2.0")[1]["project_count"] == 0
    assert _get(svc["base"] + "/api/affected")[0] == 400 and _get(svc["base"] + "/api/affected?component=x&version=latest")[0] == 400


# ------------------------------------------------------------------ chatbot tools
def _bot(projects=None, client=None):
    return chat.Chatbot(evals.build_index(), projects or _projects(), client)


def test_a_question_across_projects_is_answered_by_the_fleet_tool_with_verified_citations():
    """AC: BSA-AC-170"""
    for q in ("CVE-2018-18074 영향받는 프로젝트가 어디야?", "Which projects are affected by CVE-2018-18074?", "GHSA-x84v-xcm2-53pg 가 어느 프로젝트에 있어"):
        r = _bot().ask(q)
        assert r["found"] is True and r["tools"] == ["affected_projects"] and r["citation_accuracy"] == 1.0, q
        assert "2 of 3 analysed projects: alpha, gamma" in r["answer"] and "beta" not in r["answer"].split("\n")[0]
    r = _bot().ask("requests 2.19.1 쓰는 프로젝트 알려줘")
    assert r["tools"] == ["affected_projects"] and "alpha, gamma" in r["answer"] and "beta" not in r["answer"]
    miss = _bot().ask("CVE-2001-9999 영향받는 프로젝트가 어디야?")
    assert miss["found"] is True and "was not found in any of the 3 analysed projects" in miss["answer"]
    assert _bot().ask("오늘 점심 메뉴 추천해줘")["found"] is False                                      # unrelated questions still decline
    named = _bot().ask("alpha 에서 CVE-2018-18074 를 쓰는 프로젝트는 몇 개야", project="alpha")
    assert "affected_projects" in named["tools"] and "vuln_lookup" in named["tools"]


def test_the_model_may_plan_the_three_new_tools_and_invalid_plans_are_dropped():
    """AC: BSA-AC-171"""
    rec = evals.synthetic_project()
    good = [{"tool": "affected_projects", "args": {"id": "cve-2018-18074"}}, {"tool": "affected_projects", "args": {"component": "requests", "version": "<2.20"}},
            {"tool": "sbom_conformance", "args": {"regime": "NTIA-2021"}}, {"tool": "what_changed", "args": {}}]
    ok, dropped = chat.validate_calls(good, rec)
    assert len(ok) == 4 and sum(dropped.values()) == 0
    assert ok[0]["args"]["id"] == "CVE-2018-18074" and ok[2]["args"]["regime"] == "ntia-2021"
    bad = [{"tool": "affected_projects", "args": {}}, {"tool": "affected_projects", "args": {"id": "not-an-id"}},
           {"tool": "affected_projects", "args": {"component": "requests", "version": "latest"}}, {"tool": "sbom_conformance", "args": {"regime": "iso-9999"}}]
    ok2, d2 = chat.validate_calls(bad, rec)
    assert ok2 == [] and d2["semantic"] == 4
    assert chat.run_tool(rec, "affected_projects", {"id": "CVE-2018-18074"})[0]["lines"][0].startswith("CVE-2018-18074 is present in 1 of 1")


def test_conformance_and_change_questions_cite_the_recorded_results_and_say_when_nothing_was_recorded():
    """AC: BSA-AC-172"""
    rec = evals.synthetic_project()
    doc = sbom.cyclonedx("demo", rec["components"], rec["vulns"])
    rec["conformance"] = conformance.compact(conformance.evaluate(doc))
    bot = _bot({"demo": rec})
    r = bot.ask("NTIA 최소 요소 충족하는지 알려줘", project="demo")
    assert "sbom_conformance" in r["tools"] and r["citation_accuracy"] == 1.0 and "SBOM regime ntia-2021: verdict" in r["answer"]
    assert "Fix once:" in r["answer"] and "not a legal conformity assessment" in r["answer"]
    r2 = bot.ask("지난 분석 이후 뭐가 바뀌었어?", project="demo")
    assert "what_changed" in r2["tools"] and "nothing to compare with" in r2["answer"]
    nodata = copy.deepcopy(rec)
    nodata["conformance"] = {}
    assert "No SBOM conformance result is recorded" in _bot({"demo": nodata}).ask("CISA SBOM 요건은?", project="demo")["answer"]
    after = copy.deepcopy(rec)
    after["components"][0]["version"] = "2.20.0"
    after["vulns"] = []
    rec["changes"] = changes.compact(changes.diff(rec, after))
    r3 = _bot({"demo": rec}).ask("what changed since the last scan?", project="demo")
    assert "Since the previous analysis of demo: verdict better, 0 new vulnerabilities, 1 resolved" in r3["answer"] and r3["citation_accuracy"] == 1.0


# ------------------------------------------------------------------ CLI
def test_cli_vex_applies_triage_fail_closed_and_fleet_answers_over_the_evidence_folder(svc, tmp_path, capsys):
    """AC: BSA-AC-175"""
    store = tmp_path / "triage.json"
    store.write_text(json.dumps({
        "CVE-2020-1111": {"status": "false-positive", "note": "the vulnerable function is never called", "justification": "vulnerable_code_not_in_execute_path"},
        "CVE-2020-2222": {"status": "false-positive", "note": "no justification given here"}}), encoding="utf-8")
    out = tmp_path / "vex.json"
    assert cli.main(["vex", svc["rec"]["name"], "--evidence", str(svc["ev"]), "--triage", str(store), "--out", str(out), "--today", "2026-11-17"]) == 0
    err = capsys.readouterr().err
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert sorted(s["status"] for s in doc["statements"]) == ["affected", "not_affected"] and "not applied: CVE-2020-2222" in err and "rejected 1" in err
    assert cli.main(["vex", svc["rec"]["name"], "--evidence", str(svc["ev"]), "--today", "yesterday"]) == 2
    assert cli.main(["vex", "nope", "--evidence", str(svc["ev"])]) == 2
    capsys.readouterr()
    assert cli.main(["fleet", "--evidence", str(svc["ev"]), "--cve", "CVE-2020-2222", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["project_count"] == 1
    assert cli.main(["fleet", "--evidence", str(svc["ev"])]) == 0 and "# Portfolio" in capsys.readouterr().out
    assert cli.main(["fleet", "--evidence", str(tmp_path / "empty"), "--cve", "CVE-2020-2222"]) == 2
    assert cli.main(["review", svc["rec"]["name"], "--evidence", str(svc["ev"])]) == 0
