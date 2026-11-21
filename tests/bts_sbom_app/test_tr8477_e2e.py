"""End-to-end: pipeline -> V&V report -> evidence bundle -> provider reconcile -> freeze/post-handover.

TR 8477 5.2 pipeline shape (BOM in -> known vulns -> scan -> cross-check) on one analysed git repo,
plus a security sweep of the new modules' honesty guarantees (fail-closed, no secrets, no network).
"""
from __future__ import annotations

import json
import os

from bts_sbom_app import evidence, handover, pipeline, reconcile, vnv
from bts_sbom_app.util import tree_hash
from conftest import FakeScanner

PROVIDER_CDX = {
    "bomFormat": "CycloneDX",
    "components": [
        {"name": "requests", "version": "2.99.0", "purl": "pkg:pypi/requests@2.99.0"},
        {"name": "pyyaml", "version": "3.12", "purl": "pkg:pypi/pyyaml@3.12"},
    ],
    "vulnerabilities": [
        {"id": "CVE-2020-1111", "affects": [{"ref": "pkg:pypi/requests@2.19.1"}]},
    ],
}


def test_e2e_tr8477_pipeline(tmp_path, make_repo, world):
    """AC: BSA-AC-757"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\npyyaml==3.12\n"})
    ev = str(tmp_path / "ev")
    before = tree_hash(origin)
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "work"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "cache"), plan_ref="PLAN-7")
    assert rec["error"] is None
    assert tree_hash(origin) == before                                  # the origin is untouched throughout

    # 1) V&V evidence report (TR 8.1)
    rep = rec["vnv"]
    assert rep["traceability"]["plan_ref"] == "PLAN-7" and rep["results"]["grade"] in ("pass", "pass with restrictions")

    # 2) attack inputs + CWE + evidence bundle
    inputs = evidence.attack_inputs(rec)
    assert inputs and all("note" in i for i in inputs)
    bundle = evidence.bundle(rec, os.path.join(ev, rec["name"], "bundle"))
    kinds = {a["kind"] for a in bundle["artifacts"]}
    assert {"cdx", "spdx", "vex", "record"} <= kinds

    # 3) provider SBOM cross-check (TR 5.2)
    x = reconcile.reconcile(PROVIDER_CDX, rec)
    assert x["declared_components"] == 2
    mm = {m["name"]: m for m in x["missing_from_artifacts"] if m.get("evidence") == "version mismatch"}
    assert "requests" in mm and mm["requests"]["declared_version"] == "2.99.0"  # provider says 2.99, scan says 2.19.1

    # 4) frozen baseline + post-handover
    frozen = handover.freeze(rec, os.path.join(ev, rec["name"], "handover"))
    assert frozen["finding_ids"], "the freeze records the advisories known at handover"

    # 5) a later analysis picks up a new advisory on the same baseline components -> flagged
    origin2 = make_repo({"requirements.txt": "requests==2.19.1\npyyaml==3.12\n"}, name="proj-later")
    rec2 = pipeline.run_project(origin2, work_root=str(tmp_path / "work2"), out_dir=str(tmp_path / "ev2"), use_llm=False,
                                scanner=FakeScanner(), run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "cache2"),
                                plan_ref="PLAN-7")
    for v in rec2["vulns"]:
        if v["package"] == "requests":
            v["id"] = "CVE-NEW-9999"                                    # simulate a NEW advisory attached to a baseline package
            break
    post = handover.post_handover(rec2, frozen)
    assert post["counts"]["post_handover"] >= 1                         # the new advisory is flagged, not silently folded in
    assert all("인수 후 발견" in r["note"] for r in post["post_handover"])


def test_e2e_offline_report_is_never_a_bare_pass(tmp_path, make_repo, world):
    """AC: BSA-AC-758 (security/honesty sweep)"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\nLicenseRef-mystery==1.0\n"})
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(tmp_path / "ev"), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"),
                               offline=True)
    rep = vnv.report(rec)
    assert rep["results"]["grade"] == "pass with restrictions"
    reasons = " ".join(x["reason"] for x in rep["scope"]["exclusions"])
    assert "오프라인" in reasons and "라이선스" in reasons
    blob = json.dumps(rep, ensure_ascii=False)
    assert "grade\": \"pass\"" not in blob                              # never a bare pass


def test_e2e_no_secrets_in_any_new_output(tmp_path, make_repo, world):
    """AC: BSA-AC-759 — security sweep: the new modules must never echo credentials, tokens or approval digests."""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(tmp_path / "ev"), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"),
                               offline=True)
    planted = "SECRET-TOKEN-ab12cd34ef56"
    rec["source"] = "https://user:" + planted + "@github.com/o/r.git"
    rec["approval_token"] = planted
    blob = json.dumps({
        "vnv": vnv.report(rec),
        "inputs": evidence.attack_inputs(rec),
        "cwe": evidence.cwe_top(rec),
        "reconcile": reconcile.reconcile(PROVIDER_CDX, rec),
        "handover": handover.evaluate({"CVE-1": {"status": "false-positive", "note": "docs/report.md",
                                                 "justification": "vulnerable_code_not_present"}}),
    }, ensure_ascii=False)
    assert planted not in blob
    assert "user:" not in blob and "@github.com/o/r.git" not in blob
