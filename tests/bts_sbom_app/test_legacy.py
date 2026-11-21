"""Legacy/EOL component assessment (task 24, brief 2, AC 616-628)."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from bts_sbom_app import arch, legacy, pipeline, server
from bts_sbom_app import evals
from conftest import FakeScanner


def comp(name, version, eco="PyPI"):
    return {"name": name, "version": version, "ecosystem": eco, "relationship": "direct", "files": ["requirements.txt"]}


PLAN = {"component": "django", "status": "no_fix", "cve_count": 2, "max_severity": "HIGH"}


def _patch_lookup(monkeypatch, table):
    def lookup(product, cycle, online):
        return table.get((product, cycle), {"status": "unknown", "eol_date": None, "source": "none"})
    monkeypatch.setattr(arch, "eol_lookup", lookup)


def test_an_eol_cycle_is_high_with_the_endoflife_source(monkeypatch):
    """AC: BSA-AC-616"""
    _patch_lookup(monkeypatch, {("django", "4.2"): {"status": "eol", "eol_date": "2020-04-01", "source": "endoflife.date"}})
    res = legacy.assess([comp("django", "4.2.11")], [])
    row = res["rows"][0]
    assert row["eol"]["status"] == "eol" and row["eol"]["source"] == "endoflife.date" and row["eol"]["product"] == "django"
    assert row["risk"] == "high" and res["summary"]["eol"] == 1


def test_a_supported_cycle_is_low_with_the_end_date(monkeypatch):
    """AC: BSA-AC-617"""
    _patch_lookup(monkeypatch, {("django", "4.2"): {"status": "supported", "eol_date": "2028-04-01", "source": "endoflife.date"}})
    res = legacy.assess([comp("django", "4.2.11")], [])
    row = res["rows"][0]
    assert row["eol"]["status"] == "supported" and row["eol"]["eol_date"] == "2028-04-01" and row["risk"] == "low"


def test_unmapped_or_unresolvable_is_never_supported(monkeypatch):
    """AC: BSA-AC-618"""
    _patch_lookup(monkeypatch, {})
    rows = {r["component"]: r for r in legacy.assess([comp("unmapped-lib", "1.0"), comp("django", "4.2.11")], [])["rows"]}
    assert rows["unmapped-lib"]["eol"] is None                        # no mapping at all
    assert rows["django"]["eol"]["status"] == "unknown"
    _patch_lookup(monkeypatch, {("django", "4.2"): {"status": "unknown", "eol_date": None, "source": "none"}})
    row = legacy.assess([comp("django", "4.2.11")], [])["rows"][0]
    assert row["eol"]["status"] == "unknown"
    row2 = legacy.assess([comp("django", "not-a-version")], [])["rows"][0]
    assert row2["eol"]["status"] == "unknown" and row2["eol"]["cycle"] == ""      # version unparseable
    for r in (rows["unmapped-lib"], row, row2):
        assert r["eol"] is None or r["eol"]["status"] != "supported"


def test_offline_makes_zero_network_calls_and_keeps_unverified(monkeypatch):
    """AC: BSA-AC-619"""
    def forbidden(url, headers=None, body=None):
        raise AssertionError("no network in offline assessment")
    monkeypatch.setattr(arch.net, "TRANSPORT", forbidden)
    _patch_lookup(monkeypatch, {("django", "4.2"): {"status": "eol", "eol_date": "2020-04-01", "source": "embedded-table (UNVERIFIED)"}})
    res = legacy.assess([comp("django", "4.2.11")], [], online=False)
    assert "UNVERIFIED" in res["rows"][0]["eol"]["source"]
    assert any("UNVERIFIED" in r for r in res["rows"][0]["reasons"])


def test_no_fix_plans_drive_no_upstream_fix_and_the_risk(monkeypatch):
    """AC: BSA-AC-620"""
    _patch_lookup(monkeypatch, {})
    rows = {r["component"]: r for r in legacy.assess([comp("oldlib", "1.0")],
            [{"component": "oldlib", "status": "no_fix", "cve_count": 3, "max_severity": "HIGH"}])["rows"]}
    assert rows["oldlib"]["no_upstream_fix"] is True and rows["oldlib"]["risk"] == "high"
    rows2 = {r["component"]: r for r in legacy.assess([comp("oldlib", "1.0")],
             [{"component": "oldlib", "status": "no_fix", "cve_count": 1, "max_severity": "MEDIUM"}])["rows"]}
    assert rows2["oldlib"]["risk"] == "medium"
    assert any("OSV" in r for r in rows2["oldlib"]["reasons"]) and "abandoned" not in json.dumps(rows2).lower()


def test_an_upgrade_plan_is_not_no_upstream_fix(monkeypatch):
    """AC: BSA-AC-621"""
    _patch_lookup(monkeypatch, {("django", "4.2"): {"status": "supported", "eol_date": "2028-04-01", "source": "endoflife.date"}})
    row = legacy.assess([comp("django", "4.2.11")],
                        [{"component": "django", "status": "upgrade", "cve_count": 1, "max_severity": "HIGH"}])["rows"][0]
    assert row["no_upstream_fix"] is False and row["risk"] == "low"


def test_rows_sort_by_risk_then_name_and_bytes_match(monkeypatch):
    """AC: BSA-AC-622"""
    _patch_lookup(monkeypatch, {})
    comps = [comp("zeta-lib", "1.0"), comp("alpha-lib", "1.0")]
    plans = [{"component": "alpha-lib", "status": "no_fix", "cve_count": 2, "max_severity": "CRITICAL"}]
    a = json.dumps(legacy.assess(comps, plans), sort_keys=True)
    b = json.dumps(legacy.assess(list(reversed(comps)), plans), sort_keys=True)
    assert a == b
    rows = legacy.assess(comps, plans)["rows"]
    assert rows[0]["component"] == "alpha-lib" and rows[0]["risk"] == "high" and rows[1]["component"] == "zeta-lib"


def test_malformed_product_entries_are_rejected():
    """AC: BSA-AC-623"""
    legacy.PRODUCTS.append({"ecosystem": "PyPI", "name": "bad1"})
    legacy.PRODUCTS.append({"ecosystem": "PyPI", "name": "bad2", "product": "p", "cycle_rule": "bogus"})
    try:
        loaded = legacy.load_products()
        assert len(loaded) == len(legacy.PRODUCTS) - 2
        assert len(legacy._LOAD_ERRORS) == 2
    finally:
        legacy.PRODUCTS[:] = [p for p in legacy.PRODUCTS if p.get("name") not in ("bad1", "bad2")]


def test_a_raising_legacy_stage_is_recorded(tmp_path, make_repo, world, monkeypatch):
    """AC: BSA-AC-624"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    monkeypatch.setattr(legacy, "assess", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(tmp_path / "ev"), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    assert rec["error"] is None and "legacy" in rec["stage_errors"]


def test_an_old_record_without_the_key_is_computed_on_read(tmp_path, make_repo, world):
    """AC: BSA-AC-625"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    st = server.State(evals.repo_root(), ev, None)
    res = legacy.assess(rec.get("components") or [], rec.get("plans") or [])
    assert res["computed_on_read"] is False and res["schema"] == legacy.SCHEMA     # the shape a read-computed result carries


def test_the_api_answers_and_404s(tmp_path, make_repo, world):
    """AC: BSA-AC-626"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    st = server.State(evals.repo_root(), ev, None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        with urllib.request.urlopen(base + "/api/legacy/" + rec["name"], timeout=10) as r:
            body = json.loads(r.read())
        assert set(body["summary"]) == {"high", "medium", "low", "unknown", "eol", "no_upstream_fix"}
        try:
            urllib.request.urlopen(base + "/api/legacy/no-such", timeout=10)
            raise AssertionError("expected 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        httpd.shutdown()


def test_arch_runtime_eol_output_is_untouched(monkeypatch):
    """AC: BSA-AC-627"""
    import inspect
    sig = inspect.signature(arch.eol_lookup)
    assert list(sig.parameters) == ["product", "cycle", "online"]
    monkeypatch.setattr(arch, "eol_lookup", lambda p, c, online: {"status": "unknown", "eol_date": None, "source": "none"})
    out = arch.eol_lookup("python", "3.12", online=False)
    assert out == {"status": "unknown", "eol_date": None, "source": "none"}


def test_the_disclaimer_is_on_three_surfaces(tmp_path, make_repo, world):
    """AC: BSA-AC-628"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    res = legacy.assess(rec.get("components") or [], rec.get("plans") or [])
    assert res["disclaimer"] == legacy.DISCLAIMER                    # 1 JSON
    text = legacy.DISCLAIMER                                          # 2 CLI (json.dumps also embeds it)
    assert text in json.dumps(res, ensure_ascii=False)
    from bts_sbom_app import report                                   # 3 report section
    rec2 = dict(rec, legacy=res)
    assert legacy.DISCLAIMER in report.project_md(rec2)
