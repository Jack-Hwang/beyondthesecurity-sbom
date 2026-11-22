"""Supply-chain name checks: what is detected, what is not covered, failures that must not look clean, the internal-name policy and reviews."""
from __future__ import annotations

import json
import os

import test_console_ui
from test_console_ui import _get, _post

from bts_sbom_app import console, engine, supply

ui = test_console_ui.ui                                # the analysed-project + running-service fixture of the console tests, shared


def comp(name, eco, ver="1.0", files=("requirements.txt",)):
    return {"name": name, "ecosystem": eco, "version": ver, "files": list(files)}


def _kinds(doc):
    return {(f["package"], f["kind"], f["confidence"]) for f in doc["findings"]}


def test_look_alike_names_are_found_once_and_exact_popular_names_never(ui):
    """AC: BSA-AC-108"""
    comps = [comp("reqeusts", "PyPI", "1.0", ["a/requirements.txt"]), comp("reqeusts", "PyPI", "2.0", ["b/requirements.txt"]), comp("requestss", "PyPI"),
             comp("f1ask", "PyPI"), comp("@evil/lodash", "npm"), comp("lodahs", "npm"), comp("react-official", "npm"), comp("railz", "RubyGems"),
             comp("Serde", "crates.io"), comp("serda", "crates.io"), comp("com.google.guavaa:guava", "Maven"),
             # exact popular names, a scope that is exempt, and a name under the minimum length: nothing may be flagged
             comp("requests", "PyPI"), comp("lodash", "npm"), comp("@types/react", "npm"), comp("rails", "RubyGems"), comp("serde", "crates.io"),
             comp("com.google.guava:guava", "Maven"), comp("sx", "PyPI")]
    doc = supply.analyse(comps)
    assert doc["status"] == "ok" and doc["errors"] == 0 and doc["packages"] == 17                       # reqeusts counted once
    assert _kinds(doc) == {("reqeusts", "typosquat", "medium"), ("requestss", "typosquat", "high"), ("f1ask", "homoglyph", "high"),
                           ("@evil/lodash", "namespace-confusion", "high"), ("lodahs", "typosquat", "medium"), ("react-official", "typosquat", "medium"),
                           ("railz", "typosquat", "high"), ("Serde", "namespace-confusion", "medium"), ("serda", "typosquat", "medium"),
                           ("com.google.guavaa:guava", "namespace-confusion", "medium")}                  # 10 of 10 look-alikes, 0 of 7 genuine names
    one = [f for f in doc["findings"] if f["package"] == "reqeusts"][0]
    assert one["versions"] == ["1.0", "2.0"] and one["files"] == ["a/requirements.txt", "b/requirements.txt"] and one["resembles"] == "requests"
    assert one["key"] == "supply:pypi:reqeusts" and [f["confidence"] for f in doc["findings"]] == ["high"] * 4 + ["medium"] * 6      # high confidence first
    rec = ui["rec"]
    view = console.build_view(dict(rec, components=rec["components"] + [comp("reqeusts", "PyPI")]))
    assert [f["package"] for f in view["supply"]["findings"]] == ["reqeusts"] and view["supply"]["counts"]["medium"] == 1   # the view carries it


def test_an_ecosystem_without_a_name_list_is_reported_as_not_checked():
    """AC: BSA-AC-109"""
    comps = [comp("github.com/gin-gonic/gin", "Go"), comp("reqeusts", "Go"), comp("requests", "PyPI"), comp("flask", "PyPI")]
    doc = supply.analyse(comps)
    by = {e["ecosystem"]: e for e in doc["ecosystems"]}
    assert by["go"]["covered"] is False and by["go"]["seed"] == 0 and by["go"]["packages"] == 2                 # Go cannot be checked and says so
    assert by["pypi"]["covered"] is True and by["pypi"]["seed"] > 0
    assert doc["packages"] == 4 and doc["checked"] == 2 and doc["findings"] == []                              # the Go look-alike is not judged: 2 of 4 checked
    named = supply.analyse([comp("acme-billing", "Go"), comp("acme-core", "PyPI")], ["Acme-Billing"])
    kinds = [(f["package"], f["kind"], f["confidence"], bool(f.get("note"))) for f in named["findings"]]
    assert kinds == [("acme-billing", "dependency-confusion", "high", True)]                                   # only the declared name, even in Go, with the caveat
    assert [f for f in supply.analyse([comp("acme-billing", "Go")])["findings"]] == []                          # no internal list: 0 dependency-confusion findings


def test_a_failing_analyzer_is_never_reported_as_a_clean_result(monkeypatch):
    """AC: BSA-AC-110"""
    comps = [comp("requestss", "PyPI"), comp("boom", "PyPI"), comp("flask", "PyPI")]
    engine._import_core()
    from bts_sbom import supply_chain as core
    real = core.SupplyChainAnalyzer.analyze_one

    def flaky(self, name, eco):
        if name == "boom":
            raise RuntimeError("boom")
        return real(self, name, eco)

    monkeypatch.setattr(core.SupplyChainAnalyzer, "analyze_one", flaky)
    part = supply.analyse(comps)
    assert part["status"] == "partial" and part["errors"] == 1 and "boom" in part["error"] and [f["package"] for f in part["findings"]] == ["requestss"]

    def always(self, name, eco):
        raise RuntimeError("down")

    monkeypatch.setattr(core.SupplyChainAnalyzer, "analyze_one", always)
    dead = supply.analyse(comps)
    assert dead["status"] == "failed" and dead["errors"] == 3 and dead["findings"] == [] and "down" in dead["error"]
    monkeypatch.undo()

    def no_core():
        raise ImportError("bts_sbom is required")

    monkeypatch.setattr(engine, "_import_core", no_core)
    gone = supply.analyse(comps)
    assert gone["status"] == "failed" and gone["findings"] == [] and "ImportError" in gone["error"]            # 3 of 3 failures are not "ok"


def test_internal_names_are_validated_stored_and_reviews_survive_in_the_view(ui):
    """AC: BSA-AC-111"""
    base, ev, name = ui["base"], ui["ev"], ui["rec"]["name"]
    bad = ["requests", [1], ["a b; rm -rf"], ["x" * 215], ["n%d" % i for i in range(201)]]
    assert [_post(base + "/api/supply-policy", {"internal_names": b})[0] for b in bad] == [400] * 5            # 5 of 5 refused
    code, out = _post(base + "/api/supply-policy", {"internal_names": ["requests", " requests ", "Acme-Core"]})
    assert code == 200 and out["internal_names"] == ["requests", "Acme-Core"] and os.path.isfile(os.path.join(str(ev), ".supply_policy.json"))
    view = json.loads(_get(base + "/api/view/" + name)[2])
    f = view["supply"]["findings"]
    assert view["supply"]["internal"] == ["requests", "Acme-Core"] and [(x["package"], x["kind"], x["confidence"]) for x in f] == [("requests", "dependency-confusion", "high")]
    assert f[0]["versions"] == ["2.19.1"] and f[0]["note"] and view["supply"]["counts"]["open"] == 1
    code, out = _post(base + "/api/triage", {"check_id": f[0]["key"], "status": "false-positive", "note": "our own package"})
    assert code == 200
    rv = json.loads(_get(base + "/api/view/" + name)[2])["supply"]
    assert rv["findings"][0]["review"] == {"status": "false-positive", "note": "our own package"} and rv["counts"] == {"high": 0, "medium": 0, "open": 0, "reviewed": 1}
    assert _post(base + "/api/supply-policy", {"internal_names": []})[0] == 200
    assert json.loads(_get(base + "/api/view/" + name)[2])["supply"]["findings"] == []                         # removing the name removes the finding
    assert [r["name"] for r in json.loads(_get(base + "/api/history")[2])["history"]] == [name]                # the policy file is not a project
