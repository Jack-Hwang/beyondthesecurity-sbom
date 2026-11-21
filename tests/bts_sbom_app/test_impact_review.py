"""Four-quadrant patch impact + the independent advisory review (task 1, AC 316-333)."""
from __future__ import annotations

import inspect

from bts_sbom_app import impact, pipeline, review
from conftest import FakeScanner


def comp(name: str, version: str, files: list, rel: str = "direct") -> dict:
    return {"name": name, "version": version, "ecosystem": "PyPI", "files": files, "relationship": rel,
            "depth": 0 if rel == "direct" else 1, "vulns": 0}


def vul(vid: str, pkg: str, ver: str, files: list) -> dict:
    return {"id": vid, "package": pkg, "version": ver, "ecosystem": "PyPI", "files": files}


RES = [{"component": "requests", "from": "2.19.1", "to": "2.31.0", "status": "applied", "file": "requirements.txt"}]
EDITED = {"requirements.txt"}


def test_shared_quadrant_catches_the_same_component_in_a_second_manifest():
    """AC: BSA-AC-316"""
    before = [comp("requests", "2.19.1", ["requirements.txt", "sub/requirements.txt"])]
    out = impact.classify(before_components=before, before_vulns=[], after_components=[], after_vulns=[],
                          edited_files=EDITED, results=RES)
    assert out["shared"]["status"] == "regression"
    assert out["shared"]["counts"]["unpatched_manifests"] == 1
    assert "sub/requirements.txt" in out["shared"]["evidence"][0]
    assert out["verdict"] == "regression"


def test_direct_ok_when_all_advisories_cleared():
    """AC: BSA-AC-317"""
    out = impact.classify(before_components=[comp("requests", "2.19.1", ["requirements.txt"])],
                          before_vulns=[vul("CVE-1", "requests", "2.19.1", ["requirements.txt"]), vul("CVE-2", "requests", "2.19.1", ["requirements.txt"])],
                          after_components=[comp("requests", "2.31.0", ["requirements.txt"])], after_vulns=[],
                          edited_files=EDITED, results=RES)
    assert out["direct"]["status"] == "ok"
    assert out["direct"]["counts"] == {"cleared": 2, "remaining": 0, "introduced": 0}


def test_direct_regression_when_the_upgrade_introduces_one_advisory():
    """AC: BSA-AC-318"""
    out = impact.classify(before_components=[comp("requests", "2.19.1", ["requirements.txt"])],
                          before_vulns=[vul("CVE-1", "requests", "2.19.1", ["requirements.txt"])],
                          after_components=[comp("requests", "2.31.0", ["requirements.txt"])],
                          after_vulns=[vul("CVE-NEW", "requests", "2.31.0", ["requirements.txt"])],
                          edited_files=EDITED, results=RES)
    assert out["direct"]["status"] == "regression"
    assert out["direct"]["counts"]["introduced"] == 1


def test_upstream_regression_when_an_untouched_sibling_gains_one_advisory():
    """AC: BSA-AC-319"""
    before = [comp("requests", "2.19.1", ["requirements.txt"]), comp("flask", "0.12", ["requirements.txt"])]
    after = [comp("requests", "2.31.0", ["requirements.txt"]), comp("flask", "0.12", ["requirements.txt"])]
    out = impact.classify(before_components=before, before_vulns=[vul("CVE-1", "requests", "2.19.1", ["requirements.txt"])],
                          after_components=after,
                          after_vulns=[vul("CVE-SIB", "flask", "0.12", ["requirements.txt"])],
                          edited_files=EDITED, results=RES)
    assert out["upstream"]["status"] == "regression"
    assert out["upstream"]["counts"]["new"] == 1


def test_downstream_regression_when_a_transitive_gains_one_advisory():
    """AC: BSA-AC-320"""
    before = [comp("requests", "2.19.1", ["requirements.txt"]), comp("urllib3", "1.25", ["requirements.txt"], rel="transitive")]
    after = [comp("requests", "2.31.0", ["requirements.txt"]), comp("urllib3", "1.25", ["requirements.txt"], rel="transitive")]
    out = impact.classify(before_components=before, before_vulns=[vul("CVE-1", "requests", "2.19.1", ["requirements.txt"])],
                          after_components=after,
                          after_vulns=[vul("CVE-TRANS", "urllib3", "1.25", ["requirements.txt"])],
                          edited_files=EDITED, results=RES)
    assert out["downstream"]["status"] == "regression"
    assert out["downstream"]["counts"]["new"] == 1


def test_downstream_unverified_while_an_unedited_lockfile_still_pins_the_upgrade():
    """AC: BSA-AC-321"""
    before = [comp("requests", "2.19.1", ["requirements.txt", "package-lock.json"])]
    out = impact.classify(before_components=before, before_vulns=[vul("CVE-1", "requests", "2.19.1", ["requirements.txt"])],
                          after_components=[comp("requests", "2.31.0", ["requirements.txt"])], after_vulns=[],
                          edited_files=EDITED, results=RES)
    assert out["downstream"]["status"] == "unverified"
    assert out["downstream"]["counts"]["regenerate"] == ["package-lock.json"]
    assert out["verdict"] == "incomplete"


def test_any_unverified_quadrant_never_yields_clean():
    """AC: BSA-AC-322"""
    out = impact.classify(before_components=[comp("requests", "2.19.1", ["requirements.txt"])], before_vulns=[],
                          after_components=[], after_vulns=None, edited_files=EDITED, results=RES)
    assert out["verdict"] == "incomplete"
    assert all(out[q]["status"] == "unverified" for q in ("direct", "upstream", "downstream"))


def test_all_four_quadrants_ok_gives_clean():
    """AC: BSA-AC-323"""
    before = [comp("requests", "2.19.1", ["requirements.txt"])]
    out = impact.classify(before_components=before, before_vulns=[vul("CVE-1", "requests", "2.19.1", ["requirements.txt"])],
                          after_components=[comp("requests", "2.31.0", ["requirements.txt"])], after_vulns=[],
                          edited_files=EDITED, results=RES)
    assert all(out[q]["status"] == "ok" for q in ("direct", "upstream", "downstream", "shared"))
    assert out["verdict"] == "clean"


def test_other_projects_are_counted_when_fleet_records_are_given():
    """AC: BSA-AC-324"""
    fleet_projects = {
        "proj-a": {"vulns": [], "components": [comp("requests", "2.19.1", ["requirements.txt"])]},
        "proj-b": {"vulns": [], "components": [comp("requests", "2.19.1", ["requirements.txt"])]},
        "this-project": {"vulns": [], "components": [comp("requests", "2.31.0", ["requirements.txt"])]},
    }
    out = impact.classify(before_components=[comp("requests", "2.19.1", ["requirements.txt"])], before_vulns=[],
                          after_components=[], after_vulns=[], edited_files=EDITED, results=RES,
                          fleet_projects=fleet_projects, project_name="this-project")
    op = out["shared"]["counts"]["other_projects"]
    assert op["checked"] is True and op["count"] == 2


def test_without_fleet_records_other_projects_stay_unchecked_and_shared_status_is_untouched():
    """AC: BSA-AC-325"""
    out = impact.classify(before_components=[comp("requests", "2.19.1", ["requirements.txt"])], before_vulns=[],
                          after_components=[], after_vulns=[], edited_files=EDITED, results=RES, fleet_projects=None)
    op = out["shared"]["counts"]["other_projects"]
    assert op["checked"] is False and op["count"] == 0
    assert out["shared"]["status"] == "ok"


def _review(impact_verdict: str | None, **kw) -> dict:
    imp = None if impact_verdict is None else {"verdict": impact_verdict}
    base = dict(planned_files=["requirements.txt"], changed_files=["requirements.txt"], diff_lines=4,
                impact=imp, upgrades=[{"component": "requests", "from": "2.19.1", "to": "2.20.0", "breaking_risk": "low"}])
    base.update(kw)
    return review.review(**base)


def test_review_rejects_on_an_impact_regression():
    """AC: BSA-AC-326"""
    r = _review("regression")
    assert r["verdict"] == "reject" and r["findings"][0]["rule"] == "R4"


def test_review_requests_changes_on_an_incomplete_impact():
    """AC: BSA-AC-327"""
    r = _review("incomplete")
    assert r["verdict"] == "changes_requested" and any(f["rule"] == "R5" for f in r["findings"])


def test_review_requests_changes_when_a_lockfile_was_edited():
    """AC: BSA-AC-328"""
    r = _review("clean", changed_files=["package-lock.json"], planned_files=["requirements.txt", "package-lock.json"])
    assert r["verdict"] == "changes_requested" and r["findings"][0]["rule"] == "R2"


def test_review_requests_changes_on_an_unacknowledged_breaking_upgrade():
    """AC: BSA-AC-329"""
    r = _review("clean", upgrades=[{"component": "flask", "from": "0.12", "to": "1.0", "breaking_risk": "high"}])
    assert r["verdict"] == "changes_requested" and any(f["rule"] == "R3" for f in r["findings"])
    ok = _review("clean", ack_breaking=True, upgrades=[{"component": "flask", "from": "0.12", "to": "1.0", "breaking_risk": "high"}])
    assert ok["verdict"] == "approve"


def test_review_approves_when_every_rule_passes():
    """AC: BSA-AC-330"""
    r = _review("clean")
    assert r["verdict"] == "approve" and r["findings"] == []
    assert r["reviewer"] == "deterministic-v1" and r["independent"] is True


def test_review_takes_only_artefacts_never_the_planners_state():
    """AC: BSA-AC-331"""
    params = set(inspect.signature(review.review).parameters)
    assert not (params & {"rec", "record", "plans"})


def test_pipeline_patch_result_carries_impact_and_review_and_keeps_every_earlier_key(make_repo, world, tmp_path):
    """AC: BSA-AC-332"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "work"), out_dir=str(tmp_path / "out"), patch=True, approved=True,
                               use_llm=False, scanner=FakeScanner(), run_arch=False, cache_dir=str(tmp_path / "cache"))
    p = rec["patch"]
    assert p["status"] == "applied"
    assert p["impact"]["verdict"] == "clean" and p["review"]["independent"] is True
    for key in ("approved", "rounds", "status", "before", "applied_components", "base_commit", "last",
                "regenerate", "estimated_fixed_by_plan", "after"):
        assert key in p, key


def test_an_impact_failure_is_recorded_and_never_changes_the_patch_status(make_repo, world, tmp_path, monkeypatch):
    """AC: BSA-AC-333"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    monkeypatch.setattr(impact, "classify", lambda **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "work"), out_dir=str(tmp_path / "out"), patch=True, approved=True,
                               use_llm=False, scanner=FakeScanner(), run_arch=False, cache_dir=str(tmp_path / "cache"))
    p = rec["patch"]
    assert p["status"] == "applied"
    assert "error" in p["impact"] and "RuntimeError" in p["impact"]["error"]
