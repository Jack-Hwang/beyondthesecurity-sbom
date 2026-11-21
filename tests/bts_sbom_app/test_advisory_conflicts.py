"""Advisory-source conflicts are shown, never hidden (task 7, AC 413-424)."""
from __future__ import annotations

import json

from bts_sbom_app import chat, engine
from conftest import FakeScanner

V3_98 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V3_75 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


def _osv(vid: str, fixed: str | None, vec: str = V3_98, modified: str = "2020-01-02T00:00:00Z") -> dict:
    ev = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {"id": vid, "aliases": ["CVE-2020-1111"], "published": "2020-01-01T00:00:00Z", "modified": modified,
            "severity": [{"type": "CVSS_V3", "score": vec}],
            "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}, "ranges": [{"type": "ECOSYSTEM", "events": ev}]}]}


def test_two_records_disagreeing_on_the_fix_get_one_conflict_with_sources_and_dates():
    """AC: BSA-AC-413"""
    a = _osv("PYSEC-2020-1", "2.20.0", modified="2020-01-02T00:00:00Z")
    b = _osv("GHSA-req1-aaaa-aaaa", "2.31.0", modified="2020-02-03T00:00:00Z")
    out = engine.detect_conflicts([a, b], "requests", "PyPI", "2.19.1")
    assert len(out) == 1
    cf = out[0]
    assert cf["field"] == "fixed_version" and len(cf["values"]) == 2
    assert cf["values"][0] == {"value": "2.20.0", "source": "PYSEC-2020-1", "date": "2020-01-02"}
    assert cf["values"][1] == {"value": "2.31.0", "source": "GHSA-req1-aaaa-aaaa", "date": "2020-02-03"}
    assert cf["chosen"] == "2.31.0" and cf["resolution"] == "highest_version" and cf["material"] is True


def test_three_agreeing_records_add_no_conflicts_key():
    """AC: BSA-AC-414"""
    grp = [_osv("A", "2.20.0"), _osv("B", "2.20.0"), _osv("C", "2.20.0")]
    ana = engine.normalize(_native(grp, "requests==2.19.1"), ".")
    assert all("conflicts" not in v for v in ana["vulns"])
    assert ana["adjustments"]["advisory_conflicts"] == 0


def test_a_missing_fix_is_not_a_disagreement():
    """AC: BSA-AC-415"""
    a = _osv("PYSEC-2020-1", "2.20.0")
    b = _osv("GHSA-req1-aaaa-aaaa", None)
    assert engine.detect_conflicts([a, b], "requests", "PyPI", "2.19.1") == []


def test_two_different_v3_scores_are_a_material_conflict():
    """AC: BSA-AC-416"""
    a = _osv("PYSEC-2020-1", "2.20.0", vec=V3_98)
    b = _osv("GHSA-req1-aaaa-aaaa", "2.20.0", vec=V3_75)
    out = engine.detect_conflicts([a, b], "requests", "PyPI", "2.19.1")
    c3 = [c for c in out if c["field"] == "cvss_v3"]
    assert len(c3) == 1 and c3[0]["material"] is True
    assert c3[0]["resolution"] == "highest_score" and c3[0]["chosen"] == 9.8


def _native(records: list, req: str = "requests==2.19.1") -> dict:
    """A minimal native OSV-Scanner shaped result carrying the given advisory records for one requirements.txt."""
    return {"results": [{"source": {"path": "requirements.txt", "type": "lockfile"},
                         "packages": [{"package": {"name": "requests", "version": "2.19.1", "ecosystem": "PyPI"},
                                       "identity": {"name": "requests", "ecosystem": "PyPI", "version": "2.19.1",
                                                    "relationship": "direct", "depth": 0},
                                       "query_status": "queried_online", "vulnerabilities": records}]}],
            "scan_status": {"sources": 1, "packages": 1, "mode": "online"},
            "completeness": {"data_status": "complete", "vulnerability_presence": "found"}, "notes": []}


def test_dates_only_differ_is_not_a_conflict():
    a = _osv("PYSEC-2020-1", "2.20.0", modified="2020-01-02T00:00:00Z")
    b = _osv("GHSA-req1-aaaa-aaaa", "2.20.0", modified="2020-03-04T00:00:00Z")
    assert engine.detect_conflicts([a, b], "requests", "PyPI", "2.19.1") == []


def test_lookup_answer_states_both_values_and_both_sources_and_verifies():
    """AC: BSA-AC-417, BSA-AC-419"""
    rec = {"name": "proj", "components": [], "plans": [], "vulns": [
        {"id": "GHSA-req1-aaaa-aaaa", "aliases": ["CVE-2020-1111"], "osv_ids": ["GHSA-req1-aaaa-aaaa"], "package": "requests",
         "version": "2.19.1", "ecosystem": "PyPI", "severity": "HIGH", "cvss": 7.5, "fixed_version": "2.31.0",
         "published": "2020-01-01T00:00:00Z", "files": [], "summary": "x",
         "conflicts": [{"field": "fixed_version", "values": [{"value": "2.20.0", "source": "PYSEC-2020-1", "date": "2020-01-02"},
                                                             {"value": "2.31.0", "source": "GHSA-req1-aaaa-aaaa", "date": "2020-02-03"}],
                        "chosen": "2.31.0", "resolution": "highest_version", "material": True}]}]}
    res = chat.run_tool(rec, "vuln_lookup", {"id": "CVE-2020-1111"})
    lines = "\n".join(res[0]["lines"])
    assert "2.20.0 (PYSEC-2020-1, 2020-01-02)" in lines
    assert "2.31.0 (GHSA-req1-aaaa-aaaa, 2020-02-03)" in lines
    docs = {res[0]["source"]: "\n".join(res[0]["lines"])}
    claims = [{"text": ln, "quote": ln, "source": res[0]["source"], "trust": "tool"} for ln in res[0]["lines"]]
    assert chat.verify_claims(claims, docs)["accuracy"] == 1.0


def test_a_dated_advisory_stamps_its_claims_and_an_undated_one_does_not():
    """AC: BSA-AC-418"""
    rec = {"name": "proj", "components": [], "plans": [], "vulns": [
        {"id": "GHSA-dated", "aliases": [], "osv_ids": [], "package": "requests", "version": "2.19.1", "ecosystem": "PyPI",
         "severity": "HIGH", "cvss": 7.5, "fixed_version": "2.20.0", "published": "2020-01-01T00:00:00Z", "files": [], "summary": ""},
        {"id": "GHSA-undated", "aliases": [], "osv_ids": [], "package": "flask", "version": "0.12", "ecosystem": "PyPI",
         "severity": "MEDIUM", "cvss": 5.0, "fixed_version": "1.0", "files": [], "summary": ""}]}
    dated = chat.run_tool(rec, "vuln_lookup", {"id": "GHSA-dated"})[0]
    assert dated.get("date") == "2020-01-01T00:00:00Z"
    undated = chat.run_tool(rec, "vuln_lookup", {"id": "GHSA-undated"})[0]
    assert "date" not in undated


def test_a_malformed_record_is_counted_and_the_analysis_still_finishes():
    """AC: BSA-AC-420"""
    bad = {"id": "MAL-1", "aliases": [], "published": "2020-01-01T00:00:00Z", "severity": "not-a-list",
           "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
    good = _osv("PYSEC-2020-1", "2.20.0")
    ana = engine.normalize(_native([bad, good]), ".")
    assert ana["adjustments"]["advisory_conflict_errors"] == 1
    assert ana["adjustments"]["advisory_conflicts"] == 0
    assert len(ana["vulns"]) == 2 and all("conflicts" not in v for v in ana["vulns"])


def test_one_conflict_is_counted_once_in_the_adjustments():
    """AC: BSA-AC-421"""
    a = _osv("PYSEC-2020-1", "2.20.0")
    b = _osv("GHSA-req1-aaaa-aaaa", "2.31.0")
    ana = engine.normalize(_native([a, b]), ".")
    assert ana["adjustments"]["advisory_conflicts"] == 1
    assert ana["vulns"][0]["fixed_version"] == "2.31.0"


def test_the_same_finding_across_2_manifests_lists_its_conflicts_once():
    """AC: BSA-AC-423"""
    a = _osv("PYSEC-2020-1", "2.20.0")
    b = _osv("GHSA-req1-aaaa-aaaa", "2.31.0")
    native = _native([a, b])
    native["results"].append(json.loads(json.dumps(native["results"][0])))
    native["results"][1]["source"]["path"] = "sub/requirements.txt"
    native["scan_status"]["sources"] = 2
    ana = engine.normalize(native, ".")
    with_conflicts = [v for v in ana["vulns"] if v.get("conflicts")]
    assert len(with_conflicts) == 1
    assert ana["adjustments"]["advisory_conflicts"] == 1


def test_a_record_without_conflicts_gains_no_new_keys():
    a = _osv("PYSEC-2020-1", "2.20.0")
    ana_before = engine.normalize(_native([a]), ".")
    v = ana_before["vulns"][0]
    assert "conflicts" not in v


def test_conflicts_survive_a_record_round_trip():
    """AC: BSA-AC-424"""
    a = _osv("PYSEC-2020-1", "2.20.0")
    b = _osv("GHSA-req1-aaaa-aaaa", "2.31.0")
    ana = engine.normalize(_native([a, b]), ".")
    v = json.loads(json.dumps(ana["vulns"][0]))
    assert v["conflicts"] == ana["vulns"][0]["conflicts"]
    b_nodate = _osv("GHSA-req1-aaaa-aaaa", "2.31.0", modified="")     # a record with neither modified nor a usable published prefix
    ana2 = engine.normalize(_native([_osv("PYSEC-2020-1", "2.20.0"), b_nodate]), ".")
    v2 = json.loads(json.dumps(ana2["vulns"][0]))
    assert v2["conflicts"][0]["values"][1]["date"] == "2020-01-01"     # falls back to published, never fabricated


def test_world_analysed_records_stay_conflict_free_and_the_metrics_hold(world):
    """AC: BSA-AC-422"""
    import os
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "requirements.txt"), "w", newline="\n").write("requests==2.19.1\n")
    ana = engine.analyze(d, scanner=FakeScanner())
    assert ana["adjustments"]["advisory_conflicts"] == 0
