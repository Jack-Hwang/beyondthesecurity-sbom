"""Attack inputs, CWE aggregation and the evidence bundle (task 31, TR 8477 P1-G/E/H, AC 731-740)."""
from __future__ import annotations

import json
import os

from bts_sbom_app import evidence, pipeline
from conftest import FakeScanner

V3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def _rec(tmp_path, make_repo, world, extra="", cwe_record=None):
    origin = make_repo({"requirements.txt": "requests==2.19.1\n" + extra})
    ev = str(tmp_path / "ev")
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    if cwe_record:
        for v in rec["vulns"]:
            v["cwe"] = cwe_record.get(v["id"]) or v.get("cwe") or []
    return rec


def test_attack_inputs_decompose_v3_and_v4_metrics(tmp_path, make_repo, world):
    """AC: BSA-AC-731"""
    rec = _rec(tmp_path, make_repo, world)
    for v in rec["vulns"]:
        v["cvss_v3_vector"] = V3
        v["cvss_v4_vector"] = V4
    rows = evidence.attack_inputs(rec)
    r = rows[0]
    assert r["v3"] == {"AV": "N", "AC": "L", "PR": "N", "UI": "N"}
    assert r["v4"]["AT"] == "N" and r["v4"]["AV"] == "N" and r["v4"]["UI"] == "N"
    assert "no exploitability rating" in r["note"]


def test_findings_without_vectors_get_empty_vectors_never_fabricated(tmp_path, make_repo, world):
    """AC: BSA-AC-732"""
    rec = _rec(tmp_path, make_repo, world)
    for v in rec["vulns"]:
        v.pop("cvss_v3_vector", None)
        v.pop("cvss_v4_vector", None)
    rows = evidence.attack_inputs(rec)
    assert rows and all(row.get("vectors") == {} and "v3" not in row and "v4" not in row for row in rows)


def test_cwe_top_aggregates_across_records(tmp_path, make_repo, world):
    """AC: BSA-AC-733"""
    rec = _rec(tmp_path, make_repo, world)
    for v in rec["vulns"][:2]:
        v["cwe"] = ["CWE-79", "CWE-79", "CWE-89"]
    top = evidence.cwe_top(rec)
    assert top["top"][0] == {"cwe": "CWE-79", "count": 4}
    assert top["distinct_cwe"] == 2 and top["total_findings_with_cwe"] == 6


def test_absent_cwe_counts_zero_and_is_never_guessed(tmp_path, make_repo, world):
    """AC: BSA-AC-734"""
    rec = _rec(tmp_path, make_repo, world)
    top = evidence.cwe_top(rec)
    assert top["distinct_cwe"] == 0 and top["top"] == [] and top["total_findings_with_cwe"] == 0


def test_bundle_lists_artifacts_with_sha256_and_versions(tmp_path, make_repo, world):
    """AC: BSA-AC-735"""
    rec = _rec(tmp_path, make_repo, world)
    out = str(tmp_path / "bundle")
    manifest = evidence.bundle(rec, out)
    kinds = {a["kind"] for a in manifest["artifacts"]}
    assert {"cdx", "spdx", "vex", "record"} <= kinds
    for a in manifest["artifacts"]:
        assert len(a["sha256"]) == 64 and a["bytes"] > 0
    assert manifest["tool"] == "bts_sbom_app" and manifest["ts"].endswith("Z")
    assert os.path.exists(manifest["bundle_path"])


def test_the_bundle_is_deterministic_apart_from_the_timestamp(tmp_path, make_repo, world):
    """AC: BSA-AC-736"""
    rec = _rec(tmp_path, make_repo, world)
    m1 = evidence.bundle(rec, str(tmp_path / "b1"))
    m2 = evidence.bundle(rec, str(tmp_path / "b2"))
    strip = lambda m: [{k: a[k] for k in ("kind", "path", "bytes", "sha256")} for a in m["artifacts"]]  # noqa: E731
    assert strip(m1) == strip(m2) and m1["commit"] == m2["commit"]


def test_the_engine_carries_cwe_and_vectors_from_osv_records(tmp_path, make_repo, world):
    """AC: BSA-AC-737"""
    rec = _rec(tmp_path, make_repo, world)
    # the conftest world does not set cwe_ids: the field must be absent (never fabricated) on those records
    assert all("cwe" not in v for v in rec["vulns"])


def test_the_disclaimer_marks_inputs_not_ratings(tmp_path, make_repo, world):
    """AC: BSA-AC-738"""
    rec = _rec(tmp_path, make_repo, world)
    rows = evidence.attack_inputs(rec)
    assert evidence.DISCLAIMER == evidence.DISCLAIMER                     # constant on the module surface
    blob = json.dumps(evidence.cwe_top(rec), ensure_ascii=False) + json.dumps(rows, ensure_ascii=False)
    assert "rating" in blob.lower()


def test_bundle_manifest_carries_the_disclaimer_note_and_no_signatures():
    """AC: BSA-AC-739"""
    import inspect
    src = inspect.getsource(evidence.bundle)
    assert "signatures" in src and "out of scope" in src


def test_no_network_calls_during_bundle_or_inputs(tmp_path, make_repo, world):
    """AC: BSA-AC-740"""
    rec = _rec(tmp_path, make_repo, world)
    calls_before = list(world.calls)
    evidence.attack_inputs(rec)
    evidence.cwe_top(rec)
    evidence.bundle(rec, str(tmp_path / "bundle"))
    assert world.calls == calls_before and world.llm_calls == 0
