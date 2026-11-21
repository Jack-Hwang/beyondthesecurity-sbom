"""Frozen handover baseline, post-handover findings and the assumption register (task 33, TR 4.7/4.8, AC 749-758)."""
from __future__ import annotations

import json
import os

from bts_sbom_app import handover
from conftest import FakeScanner


def _rec(name="proj", comps=None, vulns=None):
    return {"name": name, "components": comps or [{"name": "requests", "version": "2.19.1"}],
            "vulns": vulns or [], "lineage": {"commit": "a" * 40},
            "artifacts": {}}


def test_freeze_writes_the_baseline_once(tmp_path):
    """AC: BSA-AC-749"""
    out = str(tmp_path / "handover")
    rec = _rec(vulns=[{"id": "CVE-1"}])
    m1 = handover.freeze(rec, out)
    assert m1["component_hash"] and m1["finding_ids"] == ["CVE-1"] and m1["target"] == "proj"
    path = os.path.join(out, "handover-baseline.json")
    assert os.path.exists(path)
    # a second freeze must NOT overwrite the frozen baseline
    rec2 = _rec(vulns=[{"id": "CVE-2"}])
    m2 = handover.freeze(rec2, out)
    assert m2.get("already_frozen") is True
    on_disk = json.load(open(path, encoding="utf-8"))
    assert on_disk["finding_ids"] == ["CVE-1"]                       # still the original frozen content


def test_post_handover_flags_new_advisories_on_baseline_components(tmp_path):
    """AC: BSA-AC-750"""
    out = str(tmp_path / "handover")
    handover.freeze(_rec(vulns=[{"id": "CVE-1"}]), out)
    later = _rec(vulns=[{"id": "CVE-1"}, {"id": "CVE-2"}])
    res = handover.post_handover(later, handover.load(out))
    flagged = {r["id"] for r in res["post_handover"]}
    assert flagged == {"CVE-2"} and res["counts"]["post_handover"] == 1
    assert all("인수 후 발견" in r["note"] for r in res["post_handover"])


def test_component_hash_change_is_reported(tmp_path):
    """AC: BSA-AC-751"""
    out = str(tmp_path / "handover")
    handover.freeze(_rec(), out)
    changed = _rec(comps=[{"name": "requests", "version": "2.20.0"}], vulns=[{"id": "CVE-1"}])
    res = handover.post_handover(changed, handover.load(out))
    assert res["component_hash_matches"] is False


def test_the_assumption_register_fails_closed_on_unverified_assumptions():
    """AC: BSA-AC-752"""
    entries = {
        "CVE-1": {"status": "false-positive", "note": "see tests/test_evidence.py::test_x for the proof", "justification": "vulnerable_code_not_present"},
        "CVE-2": {"status": "false-positive", "note": "we believe it is fine", "justification": "vulnerable_code_not_in_execute_path"},
    }
    reg = handover.evaluate(entries)
    by_key = {r["key"]: r for r in reg["register"]}
    assert by_key["CVE-1"]["verified"] is True and by_key["CVE-1"]["state"] == "verified"
    assert by_key["CVE-2"]["verified"] is False and by_key["CVE-2"]["state"] == "unverified"
    assert reg["counts"] == {"assumptions": 2, "verified": 1, "unverified": 1}
    assert "fail-closed" in reg["note"]


def test_non_false_positive_entries_are_not_assumptions():
    entries = {"CVE-9": {"status": "accepted", "note": "accepted risk with a long reason text"}}
    reg = handover.evaluate(entries)
    assert reg["register"] == [] and reg["counts"]["assumptions"] == 0


def test_the_baseline_files_are_listed_with_hashes(tmp_path, make_repo, world):
    """AC: BSA-AC-753"""
    from bts_sbom_app import pipeline
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    m = handover.freeze(rec, str(tmp_path / "handover"))
    kinds = {f["kind"] for f in m["files"]}
    assert {"cdx", "spdx", "vex"} <= kinds
    assert all(len(f["sha256"]) == 64 for f in m["files"])


def test_vex_stays_fail_closed_for_unverified_assumptions(tmp_path, make_repo, world):
    """AC: BSA-AC-754"""
    from bts_sbom_app import sbom
    rec = _rec(vulns=[{"id": "CVE-1", "package": "requests", "version": "2.19.1", "severity": "HIGH"}])
    entries = {"CVE-1": {"status": "false-positive", "note": "we believe it is fine", "justification": "vulnerable_code_not_present"}}
    vex = sbom.openvex("proj", rec["vulns"], triage=entries)
    stmts = vex.get("statements") or []
    assert stmts and stmts[0]["status"] == "not_affected"                # the VEX gate itself still passes (justification+reason)
    # the assumption register must keep the assumption unverified (no evidence reference in the note)
    reg = handover.evaluate(entries)
    assert reg["register"][0]["verified"] is False


def test_deterministic_bytes():
    """AC: BSA-AC-755"""
    entries = {"CVE-1": {"status": "false-positive", "note": "evidence at docs/report.md", "justification": "vulnerable_code_not_present"}}
    a = json.dumps(handover.evaluate(entries), sort_keys=True, ensure_ascii=False)
    b = json.dumps(handover.evaluate(entries), sort_keys=True, ensure_ascii=False)
    assert a == b


def test_disclaimer_on_all_three_surfaces(tmp_path):
    """AC: BSA-AC-756"""
    out = str(tmp_path / "handover")
    m = handover.freeze(_rec(), out)
    p = handover.post_handover(_rec(vulns=[{"id": "CVE-2"}]), handover.load(out))
    a = handover.evaluate({"CVE-1": {"status": "false-positive", "note": "docs/report.md says", "justification": "vulnerable_code_not_present"}})
    blob = json.dumps([m, p, a], ensure_ascii=False)
    assert blob.count(handover.DISCLAIMER) == 3
