"""Patch regression impact (four quadrants) + independent review (course package B, lecture 3-3 p.54,56).

Mostly pure-function unit tests over bts_sbom_app.impact.classify()/bts_sbom_app.review.review(); one
end-to-end test drives pipeline._patch_loop itself, reusing the make_repo/world fixtures and FakeScanner
already used by tests/bts_sbom_app/test_patch_delivery.py.
"""
from __future__ import annotations

import inspect
from typing import Any, Dict, List, Optional

from bts_sbom_app import engine, impact, pipeline, remediate, review

from conftest import FakeScanner

REQ3 = "requests==2.19.1\nflask==0.12\npyyaml==3.12\n"


def _comp(name: str, version: str, *, ecosystem: str = "PyPI", relationship: str = "direct",
          files: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"name": name, "version": version, "ecosystem": ecosystem, "relationship": relationship,
            "files": list(files or []), "purl": "", "vulns": 0}


def _vuln(vid: str, package: str, version: str, *, ecosystem: str = "PyPI", files: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"id": vid, "package": package, "version": version, "ecosystem": ecosystem, "files": list(files or [package])}


def _plan(component: str, current_version: str, safe_version: str, *, ecosystem: str = "PyPI",
          status: str = "upgrade") -> Dict[str, Any]:
    return {"component": component, "ecosystem": ecosystem, "current_version": current_version,
            "safe_version": safe_version, "status": status}


# --------------------------------------------------------------------------------- pipeline._patch_loop integration
def test_patch_loop_adds_impact_and_review_without_breaking_existing_fields(make_repo, world):
    """AC: BSA-AC-316"""
    repo = make_repo({"requirements.txt": REQ3})
    ana = engine.analyze(repo, scanner=FakeScanner())
    plans = remediate.plan(ana["components"], ana["vulns"])
    remediate.verify(plans)
    rec = {"components": ana["components"], "vulns": ana["vulns"], "plans": plans}
    out = pipeline._patch_loop(rec, repo, approved=True, token=None, rounds=2, offline=True, scanner=FakeScanner(), verify_rounds=1)
    assert out["status"] == "applied"                               # pre-existing field/value untouched
    assert out["rescan_fixed_total"] == 4                           # pre-existing behaviour untouched
    assert "impact" in out and "error" not in out["impact"]
    assert "review" in out and "error" not in out["review"]
    assert out["impact"]["verdict"] in ("clean", "incomplete", "regression")
    assert out["review"]["reviewer"] == "deterministic-v1" and out["review"]["independent"] is True


# --------------------------------------------------------------------------------------------- impact.classify(): direct
def test_direct_quadrant_resolved_remaining_introduced():
    """AC: BSA-AC-317"""
    before_vulns = [_vuln("CVE-1", "flask", "0.12"), _vuln("CVE-2", "flask", "0.12"), _vuln("CVE-3", "flask", "0.12")]
    after_vulns = [_vuln("CVE-2", "flask", "1.0.1"), _vuln("CVE-4", "flask", "1.0.1")]
    plans = [_plan("flask", "0.12", "1.0.1")]
    res = impact.classify([], before_vulns, [], after_vulns, ["requirements.txt"], plans)
    d = res["direct"]
    assert d["status"] == "regression" and d["counts"] == {"resolved": 2, "remaining": 1, "introduced": 1}


def test_direct_na_without_upgrades_and_unverified_without_a_rescan():
    """AC: BSA-AC-318"""
    res_na = impact.classify([], [], [], [], [], [])
    assert res_na["direct"] == {"status": "n/a", "checked": True,
                                "counts": {"resolved": 0, "remaining": 0, "introduced": 0}, "evidence": []}
    plans = [_plan("flask", "0.12", "1.0.1")]
    res_unverified = impact.classify([], [_vuln("CVE-1", "flask", "0.12")], None, None, [], plans)
    assert res_unverified["direct"]["status"] == "unverified" and res_unverified["direct"]["checked"] is False


# -------------------------------------------------------------------------------------------- impact.classify(): upstream
def test_upstream_regression_and_blocked_count():
    """AC: BSA-AC-319"""
    before_components = [_comp("flask", "0.12", files=["requirements.txt"]), _comp("six", "1.10.0", files=["requirements.txt"])]
    after_components = [_comp("flask", "1.0.1", files=["requirements.txt"]), _comp("six", "1.10.0", files=["requirements.txt"])]
    before_vulns = [_vuln("CVE-F", "flask", "0.12"), _vuln("CVE-S", "six", "1.10.0")]
    after_vulns = [_vuln("CVE-S", "six", "1.10.0"), _vuln("CVE-S2", "six", "1.10.0")]
    plans = [_plan("flask", "0.12", "1.0.1"), dict(_plan("pyyaml", "3.12", "3.13"), apply_status="blocked")]
    res = impact.classify(before_components, before_vulns, after_components, after_vulns, ["requirements.txt"], plans)
    u = res["upstream"]
    assert u["status"] == "regression" and u["counts"]["new_findings"] == 1 and u["counts"]["blocked"] == 1


def test_upstream_na_without_changed_files_or_without_other_declared_components():
    """AC: BSA-AC-320"""
    plans = [_plan("flask", "0.12", "1.0.1")]
    res1 = impact.classify([], [], [], [], [], plans)
    assert res1["upstream"]["status"] == "n/a"
    before_components = [_comp("flask", "0.12", files=["requirements.txt"])]
    after_components = [_comp("flask", "1.0.1", files=["requirements.txt"])]
    res2 = impact.classify(before_components, [], after_components, [], ["requirements.txt"], plans)
    assert res2["upstream"]["status"] == "n/a"              # only the upgraded component itself is declared there


# --------------------------------------------------------------------------------------------------- verdict aggregation
def test_verdict_never_clean_while_a_quadrant_is_unverified():
    """AC: BSA-AC-321 (State)"""
    plans = [_plan("flask", "0.12", "1.0.1")]
    res = impact.classify([], [_vuln("CVE-1", "flask", "0.12")], [], [], ["requirements.txt"], plans, fleet=None)
    assert res["shared"]["status"] == "unverified"
    assert res["verdict"] != "clean"
    assert any(q["status"] == "unverified" for q in (res["direct"], res["upstream"], res["downstream"], res["shared"]))


# ----------------------------------------------------------------------------------------------- impact.classify(): shared
def test_shared_regression_same_component_two_manifests_one_patched():
    """AC: BSA-AC-322"""
    before_components = [_comp("flask", "0.12", files=["requirements.txt"]), _comp("flask", "0.12", files=["other/requirements.txt"])]
    after_components = [_comp("flask", "1.0.1", files=["requirements.txt"]), _comp("flask", "0.12", files=["other/requirements.txt"])]
    plans = [_plan("flask", "0.12", "1.0.1")]
    res = impact.classify(before_components, [], after_components, [], ["requirements.txt"], plans)
    s = res["shared"]
    assert s["status"] == "regression" and s["counts"]["other_manifests_unfixed"] == 1
    assert res["verdict"] == "regression"


def test_shared_fleet_counts_two_other_projects_on_the_vulnerable_version():
    """AC: BSA-AC-323"""
    before_components = [_comp("flask", "0.12", files=["requirements.txt"])]
    after_components = [_comp("flask", "1.0.1", files=["requirements.txt"])]
    plans = [_plan("flask", "0.12", "1.0.1")]
    fleet_data = {
        "proj-a": {"components": [_comp("flask", "0.12", files=["requirements.txt"])], "vulns": []},
        "proj-b": {"components": [_comp("flask", "0.12", files=["requirements.txt"])], "vulns": []},
        "proj-c": {"components": [_comp("flask", "1.0.1", files=["requirements.txt"])], "vulns": []},
    }
    res = impact.classify(before_components, [], after_components, [], ["requirements.txt"], plans, fleet=fleet_data)
    s = res["shared"]
    assert s["status"] == "regression" and s["counts"]["fleet_projects_affected"] == 2


def test_shared_unverified_without_fleet_even_when_locally_clean():
    """AC: BSA-AC-324"""
    before_components = [_comp("flask", "0.12", files=["requirements.txt"])]
    after_components = [_comp("flask", "1.0.1", files=["requirements.txt"])]
    plans = [_plan("flask", "0.12", "1.0.1")]
    res = impact.classify(before_components, [], after_components, [], ["requirements.txt"], plans, fleet=None)
    assert res["shared"]["status"] == "unverified" and res["shared"]["checked"] is False


# ------------------------------------------------------------------------------------------- impact.classify(): downstream
def test_downstream_regression_on_a_transitive_dependency():
    """AC: BSA-AC-325"""
    before_components = [_comp("flask", "0.12", files=["requirements.txt"], relationship="direct"),
                         _comp("six", "1.10.0", files=["requirements.txt"], relationship="indirect")]
    after_components = [_comp("flask", "1.0.1", files=["requirements.txt"], relationship="direct"),
                        _comp("six", "1.10.0", files=["requirements.txt"], relationship="indirect")]
    before_vulns = [_vuln("CVE-F", "flask", "0.12")]
    after_vulns = [_vuln("CVE-SIX", "six", "1.10.0")]
    plans = [_plan("flask", "0.12", "1.0.1")]
    res = impact.classify(before_components, before_vulns, after_components, after_vulns, ["requirements.txt"], plans)
    assert res["downstream"]["status"] == "regression" and res["downstream"]["counts"]["new_transitive_findings"] == 1


def test_downstream_unverified_when_regeneration_is_pending_without_a_new_finding():
    """AC: BSA-AC-326"""
    before_components = [_comp("flask", "0.12", files=["requirements.txt"])]
    after_components = [_comp("flask", "1.0.1", files=["requirements.txt"])]
    plans = [_plan("flask", "0.12", "1.0.1")]
    res = impact.classify(before_components, [], after_components, [], ["requirements.txt"], plans,
                          regenerate=["package-lock.json: npm install --package-lock-only"])
    assert res["downstream"]["status"] == "unverified" and res["downstream"]["counts"]["regenerate_pending"] == 1


# --------------------------------------------------------------------------------------- verdict aggregation (continued)
def test_all_quadrants_na_and_verdict_clean_when_nothing_was_upgraded():
    """AC: BSA-AC-327"""
    res = impact.classify([], [], [], [], [], [])
    assert res["verdict"] == "clean"
    assert all(q["status"] == "n/a" for q in (res["direct"], res["upstream"], res["downstream"], res["shared"]))


def test_verdict_regression_wins_over_ok_quadrants():
    """AC: BSA-AC-328"""
    before_components = [_comp("flask", "0.12", files=["requirements.txt"]), _comp("flask", "0.12", files=["other/requirements.txt"])]
    after_components = [_comp("flask", "1.0.1", files=["requirements.txt"]), _comp("flask", "0.12", files=["other/requirements.txt"])]
    before_vulns = [_vuln("CVE-F", "flask", "0.12")]
    after_vulns: List[Dict[str, Any]] = []                            # direct: fully resolved -> ok
    plans = [_plan("flask", "0.12", "1.0.1")]
    res = impact.classify(before_components, before_vulns, after_components, after_vulns, ["requirements.txt"], plans)
    assert res["direct"]["status"] == "ok"
    assert res["shared"]["status"] == "regression"
    assert res["verdict"] == "regression"


def test_verdict_incomplete_when_no_regression_but_something_is_unverified():
    """AC: BSA-AC-329"""
    before_components = [_comp("flask", "0.12", files=["requirements.txt"])]
    after_components = [_comp("flask", "1.0.1", files=["requirements.txt"])]
    before_vulns = [_vuln("CVE-F", "flask", "0.12")]
    after_vulns: List[Dict[str, Any]] = []
    plans = [_plan("flask", "0.12", "1.0.1")]
    res = impact.classify(before_components, before_vulns, after_components, after_vulns, ["requirements.txt"], plans, fleet=None)
    assert res["direct"]["status"] == "ok" and res["upstream"]["status"] == "n/a" and res["downstream"]["status"] == "ok"
    assert res["shared"]["status"] == "unverified"
    assert res["verdict"] == "incomplete"


# --------------------------------------------------------------------------------------------------------- review.review()
def test_review_rejects_file_changes_outside_planned_manifests():
    """AC: BSA-AC-330"""
    res = review.review(plan_digest="abc123", changed_files=["requirements.txt", "unexpected.txt"],
                        planned_manifests=["requirements.txt"], diff_stats={"lines_changed": 5},
                        impact={"verdict": "clean"}, plan_summary={"major_bumps": 0})
    assert res["verdict"] == "reject"
    assert any(f["rule"] == "RV-SCOPE" for f in res["findings"])


def test_review_rejects_direct_lockfile_edits():
    """AC: BSA-AC-331"""
    res = review.review(plan_digest="abc123", changed_files=["package-lock.json"],
                        planned_manifests=["package-lock.json"], diff_stats={"lines_changed": 5},
                        impact={"verdict": "clean"}, plan_summary={"major_bumps": 0})
    assert res["verdict"] == "reject" and any(f["rule"] == "RV-LOCKFILE" for f in res["findings"])


def test_review_major_bump_needs_explicit_confirmation():
    """AC: BSA-AC-332"""
    base = dict(plan_digest="abc", changed_files=["requirements.txt"], planned_manifests=["requirements.txt"],
               diff_stats={"lines_changed": 5}, impact={"verdict": "clean"}, plan_summary={"major_bumps": 1})
    unconfirmed = review.review(**base)
    assert unconfirmed["verdict"] == "changes_requested"
    assert any(f["rule"] == "RV-MAJOR-BUMP" for f in unconfirmed["findings"])
    confirmed = review.review(major_bump_confirmed=True, **base)
    assert not any(f["rule"] == "RV-MAJOR-BUMP" for f in confirmed["findings"])
    assert confirmed["verdict"] == "approve"


def test_review_maps_impact_verdict_to_reject_changes_requested_or_approve():
    """AC: BSA-AC-333"""
    base = dict(plan_digest="abc", changed_files=["requirements.txt"], planned_manifests=["requirements.txt"],
               diff_stats={"lines_changed": 5}, plan_summary={"major_bumps": 0})
    rej = review.review(impact={"verdict": "regression", "summary": "x"}, **base)
    chg = review.review(impact={"verdict": "incomplete", "summary": "y"}, **base)
    ok = review.review(impact={"verdict": "clean", "summary": "z"}, **base)
    assert rej["verdict"] == "reject" and chg["verdict"] == "changes_requested" and ok["verdict"] == "approve"


def test_review_diff_size_cap():
    """AC: BSA-AC-334"""
    base = dict(plan_digest="abc", changed_files=["requirements.txt"], planned_manifests=["requirements.txt"],
               impact={"verdict": "clean"}, plan_summary={"major_bumps": 0})
    small = review.review(diff_stats={"lines_changed": 10}, max_diff_lines=400, **base)
    big = review.review(diff_stats={"lines_changed": 500}, max_diff_lines=400, **base)
    assert small["verdict"] == "approve"
    assert big["verdict"] == "changes_requested" and any(f["rule"] == "RV-DIFF-SIZE" for f in big["findings"])


def test_review_signature_has_no_rec_parameter():
    """AC: BSA-AC-335"""
    params = inspect.signature(review.review).parameters
    assert "rec" not in params
    res = review.review(plan_digest="", changed_files=[], planned_manifests=[], diff_stats={}, impact={}, plan_summary={})
    assert res["reviewer"] == "deterministic-v1" and res["independent"] is True
