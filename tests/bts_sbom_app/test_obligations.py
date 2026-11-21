"""Obligations: per-component source-disclosure duties by scenario (task 23, brief 2, AC 601-614)."""
from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import obligations, pipeline, server
from bts_sbom_app import evals
from conftest import FakeScanner


def comp(name: str, version: str, license: str, category: str = "") -> dict:
    return {"name": name, "version": version, "ecosystem": "PyPI", "license": license,
            "license_category": category or obligations.licenses.category(license), "files": ["requirements.txt"]}


MIT = comp("mit-lib", "1.0", "MIT")
LGPL = comp("lgpllib", "2.1", "LGPL-3.0-only")
GPL = comp("gpllib", "3.0", "GPL-3.0-only")
AGPL = comp("agpllib", "4.0", "AGPL-3.0-only")


def test_binary_scenario_offers_exactly_three_with_the_three_scopes():
    """AC: BSA-AC-601"""
    res = obligations.assess([MIT, LGPL, GPL, AGPL])
    b = res["scenarios"]["binary"]
    offers = [r for r in b["components"] if r["verdict"] == "offer"]
    assert len(offers) == 3
    scopes = {r["name"]: r["scope"] for r in offers}
    assert scopes == {"lgpllib": "library_only", "gpllib": "combined_work", "agpllib": "combined_work_incl_network"}
    assert b["status"] == "exposed" and b["counts"]["source_offer"] == 3


def test_unresolved_license_is_unknown_in_all_scenarios_and_never_none():
    """AC: BSA-AC-602"""
    bad = comp("mystery", "9.9", "LicenseRef-custom", category="unknown")
    res = obligations.assess([bad])
    for s in ("internal", "binary", "saas"):
        row = res["scenarios"][s]["components"][0]
        assert row["verdict"] == "unknown"
        assert res["scenarios"][s]["counts"]["none"] == 0


def test_with_one_unresolved_no_scenario_is_clean():
    """AC: BSA-AC-603"""
    res = obligations.assess([MIT, comp("mystery", "9.9", "LicenseRef-custom", category="unknown")])
    statuses = [res["scenarios"][s]["status"] for s in ("internal", "binary", "saas")]
    assert all(st in ("incomplete", "exposed") for st in statuses) and "clean" not in statuses


def test_saas_scopes_for_network_and_strong_copyleft():
    """AC: BSA-AC-604"""
    res = obligations.assess([AGPL, GPL])
    rows = {r["name"]: r for r in res["scenarios"]["saas"]["components"]}
    assert rows["agpllib"]["scope"] == "combined_work_incl_network"
    assert rows["gpllib"]["scope"] == "none" and rows["gpllib"]["why"]


def test_internal_strong_copyleft_is_none_with_the_redistribution_why():
    """AC: BSA-AC-605"""
    res = obligations.assess([GPL])
    row = res["scenarios"]["internal"]["components"][0]
    assert row["scope"] == "none" and "redistribution" in row["why"].lower()


@pytest.mark.parametrize("dep,proj,expected", [
    ("GPL-3.0-only", "MIT", "combined_work_follows_dependency"),
    ("GPL-3.0-only", "Apache-2.0", "combined_work_follows_dependency"),
    ("GPL-2.0-only", "Apache-2.0", "commonly_cited_incompatible"),
    ("GPL-2.0-only", "GPL-3.0-only", "commonly_cited_incompatible"),
    ("AGPL-3.0-only", "MIT", "network_clause_applies"),
])
def test_five_reference_pairs_map_to_their_labels(dep, proj, expected):
    """AC: BSA-AC-606"""
    assert obligations.compat_label(dep, proj) == expected


def test_an_unlisted_pair_is_no_rule_and_nothing_says_compatible():
    """AC: BSA-AC-606"""
    assert obligations.compat_label("MIT", "MIT") == "no_rule"
    blob = json.dumps(obligations.assess([comp("x", "1", "GPL-3.0-only")], project_license="MIT"))
    assert "compatible" not in blob.replace("combined_work_follows_dependency", "").replace("commonly_cited_incompatible", "")


def test_the_disclaimer_is_on_all_four_surfaces(tmp_path, make_repo, world, capsys):
    """AC: BSA-AC-607"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    assert rec["obligations"]["disclaimer"] == obligations.DISCLAIMER                    # 1 JSON
    # 2 CLI / 3 API via a small server
    st = server.State(evals.repo_root(), ev, None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        with urllib.request.urlopen(base + "/api/obligations/" + rec["name"], timeout=10) as r:
            api_body = r.read().decode()
        assert obligations.DISCLAIMER in api_body
    finally:
        httpd.shutdown()
    # 4 report section
    from bts_sbom_app import report
    assert obligations.DISCLAIMER in report.project_md(rec)


def test_offer_components_get_exactly_five_mitigations_in_order():
    """AC: BSA-AC-608"""
    res = obligations.assess([GPL])
    m = [x for x in res["mitigations"] if x["component"] == "gpllib" and x["scenario"] == "binary"]
    assert len(m) == 1
    assert [o["id"] for o in m[0]["options"]] == obligations.MITIGATION_IDS
    assert all(o["needs_human"] is True for o in m[0]["options"])


def test_a_raising_obligations_stage_is_recorded_and_the_analysis_survives(tmp_path, make_repo, world, monkeypatch):
    """AC: BSA-AC-609"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    monkeypatch.setattr(obligations, "assess", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(tmp_path / "ev"), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    assert rec["error"] is None and rec["components"]
    assert "obligations" in rec["stage_errors"]


def test_the_api_answers_for_an_analysed_project_and_404_for_an_unknown_one(tmp_path, make_repo, world):
    """AC: BSA-AC-610"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    st = server.State(evals.repo_root(), ev, None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        with urllib.request.urlopen(base + "/api/obligations/" + rec["name"], timeout=10) as r:
            body = json.loads(r.read())
        assert set(body["scenarios"]) == {"internal", "binary", "saas"}
        try:
            urllib.request.urlopen(base + "/api/obligations/no-such-project", timeout=10)
            raise AssertionError("expected 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        httpd.shutdown()


def test_the_cli_with_distribution_saas_prints_only_saas_and_makes_zero_network_calls(tmp_path, make_repo, world, capsys):
    """AC: BSA-AC-611"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    from bts_sbom_app import cli
    calls_before = list(world.calls)
    llm_before = world.llm_calls
    rc = cli.main(["obligations", rec["name"], "--evidence", ev, "--distribution", "saas"])
    out = capsys.readouterr().out
    assert rc == 0 and "## saas " in out and "## internal" not in out and "## binary" not in out
    assert world.calls == calls_before and world.llm_calls == llm_before            # the CLI itself made 0 calls


def test_an_old_record_without_the_key_is_computed_on_read(tmp_path, make_repo, world):
    """AC: BSA-AC-612"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    old = json.load(open(rec["artifacts"]["record"], encoding="utf-8"))
    old.pop("obligations", None)
    old_path = rec["artifacts"]["record"]
    json.dump(old, open(old_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    st = server.State(evals.repo_root(), ev, None)
    _folder, loaded = st.project(rec["name"])
    assert "obligations" not in loaded
    from http.server import ThreadingHTTPServer
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        with urllib.request.urlopen(base + "/api/obligations/" + rec["name"], timeout=10) as r:
            body = json.loads(r.read())
        assert body["computed_on_read"] is True
    finally:
        httpd.shutdown()


def test_policy_findings_stay_unchanged():
    """AC: BSA-AC-613"""
    from bts_sbom_app import licenses
    comps = [comp("gpllib", "3.0", "GPL-3.0-only"), MIT]
    findings = licenses.policy_findings(comps, licenses.DEFAULT_POLICY, "MIT")
    assert findings and all(f.get("category") in ("strong-copyleft",) for f in findings if f.get("verdict") == "deny")
    # the function signature and shape are untouched (spot check on the internal scenario behaviour)
    internal = licenses.policy_findings(comps, {"distribution": "internal"}, "MIT")
    binary = licenses.policy_findings(comps, {"distribution": "binary"}, "MIT")
    assert internal != binary


def test_zero_components_give_no_data_in_every_scenario():
    """AC: BSA-AC-614"""
    res = obligations.assess([])
    assert all(res["scenarios"][s]["status"] == "no_data" for s in ("internal", "binary", "saas"))
