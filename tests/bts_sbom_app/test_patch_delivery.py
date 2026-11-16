"""Workspace safety, approval-gated patching, regression revert and delivery targets."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from bts_sbom_app import deliver, engine, patch, pipeline, remediate, workspace
from bts_sbom_app.util import tree_hash
from conftest import FakeScanner, run_git

REQ3 = "requests==2.19.1\nflask==0.12\npyyaml==3.12\n"


def _plans(path: str):
    ana = engine.analyze(path, scanner=FakeScanner())
    plans = remediate.plan(ana["components"], ana["vulns"])
    remediate.verify(plans)
    return ana, plans


def test_unsafe_sources_are_refused():
    """AC: BSA-AC-2"""
    bad = ["ext::sh -c touch /tmp/pwned", "--upload-pack=evil", "http://example.com/x.git"]
    refused = 0
    for b in bad:
        with pytest.raises(ValueError):
            workspace.normalize_source(b)
            refused -= 1
        refused += 1
    assert refused == 3
    assert workspace.prepare("ext::sh -c id", os.getcwd() + "/_nowhere")["ok"] is False


def test_clone_command_carries_three_safety_settings(monkeypatch, tmp_path):
    """AC: BSA-AC-3"""
    seen = {}

    def fake_run(cmd, cwd=None, timeout=0, env=None):
        seen["cmd"] = list(cmd)
        return 1, "", "stop here"

    monkeypatch.setattr(workspace, "run", fake_run)
    res = workspace.prepare("https://github.com/o/r.git", str(tmp_path / "w"))
    assert res["ok"] is False
    cmd = " ".join(seen["cmd"])
    flags = ["core.hooksPath=", "--no-recurse-submodules", "protocol.ext.allow=never"]
    assert sum(1 for f in flags if f in cmd) == 3


def test_no_approval_changes_nothing(make_repo, world):
    """AC: BSA-AC-14"""
    repo = make_repo({"requirements.txt": REQ3})
    _, plans = _plans(repo)
    before = tree_hash(repo)
    res = patch.apply(repo, plans, approved=False)
    assert res["status"] == "not_approved" and tree_hash(repo) == before and res["changed_files"] == []


def test_digest_mismatch_applies_nothing(make_repo, world):
    """AC: BSA-AC-15"""
    repo = make_repo({"requirements.txt": REQ3})
    _, plans = _plans(repo)
    before = tree_hash(repo)
    res = patch.apply(repo, plans, approved=True, token="0000deadbeef0000")
    assert res["status"] == "digest_mismatch" and tree_hash(repo) == before


def test_upper_bound_is_blocked_not_forced(make_repo):
    """AC: BSA-AC-16"""
    repo = make_repo({"requirements.txt": "flask>=0.12,<1.0\n"})
    plan = {"component": "flask", "ecosystem": "PyPI", "current_version": "0.12", "safe_version": "3.1.3", "status": "upgrade",
            "files": ["requirements.txt"], "verification": {"clean": True}}
    before = Path(repo, "requirements.txt").read_text(encoding="utf-8")
    res = patch.apply(repo, [plan], approved=True)
    assert res["results"][0]["status"] == "blocked" and Path(repo, "requirements.txt").read_text(encoding="utf-8") == before


def test_requirements_patch_changes_three_pins_and_commits(make_repo, world):
    """AC: BSA-AC-17"""
    repo = make_repo({"requirements.txt": REQ3})
    _, plans = _plans(repo)
    res = patch.apply(repo, plans, approved=True)
    assert res["status"] == "applied" and res["branch"] == "bts-sbom/auto-fix"
    text = Path(repo, "requirements.txt").read_text(encoding="utf-8")
    assert "requests==2.31.0" in text and "flask==1.0.1" in text and "pyyaml==5.4" in text
    assert sum(1 for r in res["results"] if r["status"] == "applied") == 3
    assert run_git(repo, "rev-list", "--count", "main..bts-sbom/auto-fix").strip() == "1"


def test_regression_after_patch_is_reverted(make_repo, world):
    """AC: BSA-AC-18"""
    repo = make_repo({"requirements.txt": "requests==2.19.1\n"})
    base = workspace.head(repo)["commit"]
    original = Path(repo, "requirements.txt").read_text(encoding="utf-8")

    class Regressing(FakeScanner):
        def scan(self, path, **kw):
            r = super().scan(path, **kw)
            for res in r["results"]:
                for p in res["packages"]:
                    if p["package"]["version"] == "9.9":          # the patched version "introduces" 3 new findings
                        from conftest import FAMILIES
                        p["vulnerabilities"] = [FAMILIES[2][0], FAMILIES[4][0], FAMILIES[0][0]]
            return r

    sc = Regressing()
    ana = engine.analyze(repo, scanner=sc)
    plans = remediate.plan(ana["components"], ana["vulns"])
    plans[0]["safe_version"] = "9.9"
    rec = {"vulns": ana["vulns"], "plans": plans}
    out = pipeline._patch_loop(rec, repo, approved=True, token=None, rounds=2, offline=True, scanner=sc, verify_rounds=1)
    assert out["status"] == "regression_reverted"
    assert Path(repo, "requirements.txt").read_text(encoding="utf-8") == original
    assert workspace.head(repo)["commit"] == base


def test_lockfile_only_dependency_gets_manual_command_and_no_lock_edit(make_repo):
    """AC: BSA-AC-19"""
    lock = '{"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1.0.0"}}}\n'
    repo = make_repo({"package-lock.json": lock})
    plan = {"component": "x", "ecosystem": "npm", "current_version": "1.0.0", "safe_version": "1.0.1", "status": "upgrade",
            "files": ["package-lock.json"], "verification": {"clean": True}}
    res = patch.apply(repo, [plan], approved=True)
    r = res["results"][0]
    assert r["status"] == "manual" and r["manual_command"] and Path(repo, "package-lock.json").read_text(encoding="utf-8") == lock
    assert res["changed_files"] == []


@pytest.fixture
def applied(make_repo, world):
    repo = make_repo({"requirements.txt": REQ3})
    work = workspace.prepare(repo, os.path.join(os.path.dirname(repo), "work"))
    _, plans = _plans(work["path"])
    res = patch.apply(work["path"], plans, approved=True)
    return repo, work["path"], res


def test_inplace_and_github_need_explicit_flags(applied):
    """AC: BSA-AC-20"""
    origin, work, res = applied
    before = tree_hash(origin)
    a = deliver.deliver(work, res, target="inplace", origin=origin)
    b = deliver.deliver(work, res, target="github", remote_url="https://github.com/o/r.git")
    assert "refused" in a["error"] and "refused" in b["error"] and tree_hash(origin) == before


def test_github_delivery_pushes_exactly_one_branch(applied, tmp_path):
    """AC: BSA-AC-21"""
    origin, work, res = applied
    bare = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    out = deliver.deliver(work, res, target="github", remote_url=bare.as_uri(), allow_push=True)
    assert out["ok"], out
    refs = subprocess.run(["git", "-C", str(bare), "for-each-ref", "--format=%(refname)"], capture_output=True, text=True).stdout.split()
    assert refs == ["refs/heads/bts-sbom/auto-fix"]


def test_folder_delivery_writes_patch_report_and_files(applied, tmp_path):
    """AC: BSA-AC-22"""
    origin, work, res = applied
    dest = tmp_path / "out"
    out = deliver.deliver(work, res, target="folder", dest=str(dest))
    names = {p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()}
    assert out["ok"] and {"fix.patch", "PATCH_REPORT.md", "files/requirements.txt"} <= names and len(names) >= 3


def test_pipeline_patch_flow_origin_untouched_and_findings_to_zero(make_repo, world, tmp_path):
    """AC: BSA-AC-1, BSA-AC-45"""
    origin = make_repo({"requirements.txt": REQ3, "LICENSE": "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\n"})
    before = tree_hash(origin)
    sc = FakeScanner()
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "work"), out_dir=str(tmp_path / "out"), patch=True, approved=True, use_llm=False,
                               scanner=sc, run_arch=False, cache_dir=str(tmp_path / "cache"))
    assert rec["error"] is None and not rec["stage_errors"], rec["stage_errors"]
    assert len(rec["vulns"]) == 4
    assert rec["patch"]["status"] == "applied" and rec["patch"]["after"]["vulns_rescan"] == 0 and rec["patch"]["rescan_fixed_total"] == 4
    assert tree_hash(origin) == before and rec["origin_unchanged"] is True
    assert os.path.isfile(rec["artifacts"]["cdx"]) and os.path.isfile(rec["artifacts"]["record"])


def test_transitive_gem_is_manual_not_blocked(make_repo):
    """AC: BSA-AC-59"""
    lock = "\n".join(["GEM", "  specs:", "    activestorage (5.2.0)", ""])
    repo = make_repo({"Gemfile": "gem 'rails'\n", "Gemfile.lock": lock})
    plan = {"component": "activestorage", "ecosystem": "RubyGems", "current_version": "5.2.0", "safe_version": "5.2.8", "status": "upgrade",
            "files": ["Gemfile.lock"], "verification": {"clean": True}}
    res = patch.apply(repo, [plan], approved=True)
    r = res["results"][0]
    assert r["status"] == "manual" and "bundle update --conservative" in r["manual_command"]
    assert sum(1 for x in res["results"] if x["status"] == "blocked") == 0


def test_untouched_lockfile_findings_do_not_cause_a_revert(make_repo, world):
    """AC: BSA-AC-66"""
    repo = make_repo({"requirements.txt": "requests==2.19.1\n", "other/requirements.txt": "pyyaml==3.12\n"})

    class LockStyle(FakeScanner):
        def scan(self, path, **kw):
            r = super().scan(path, **kw)
            if "requests==2.31.0" in open(os.path.join(path, "requirements.txt"), encoding="utf-8").read():       # after the patch...
                for res in r["results"]:
                    if res["source"]["path"].replace("\\", "/").endswith("other/requirements.txt"):
                        from conftest import FAMILIES
                        res["packages"][0]["vulnerabilities"].extend([FAMILIES[2][0], FAMILIES[3][0], FAMILIES[5][0]])   # ...an UNRELATED file gains 3
            return r

    sc = LockStyle()
    ana = engine.analyze(repo, scanner=sc)
    plans = remediate.plan(ana["components"], ana["vulns"])
    remediate.verify(plans)
    rec = {"vulns": ana["vulns"], "plans": [p for p in plans if p["component"] == "requests"]}
    out = pipeline._patch_loop(rec, repo, approved=True, token=None, rounds=1, offline=True, scanner=sc, verify_rounds=1)
    assert out["status"] != "regression_reverted" and "requests==2.31.0" in Path(repo, "requirements.txt").read_text(encoding="utf-8")


def test_existing_workcopy_with_readonly_files_is_replaced_without_leaks(tmp_path):
    """AC: BSA-AC-68"""
    import stat
    root = tmp_path / "w"
    old = root / "proj" / ".git" / "objects"
    old.mkdir(parents=True)
    ro = old / "pack"
    ro.write_text("x", encoding="utf-8")
    os.chmod(ro, stat.S_IREAD)                                     # git writes objects read-only
    dest = workspace._unique_dest(str(root), "proj")
    assert dest == str(root / "proj") and not os.path.exists(dest)
    assert [p.name for p in root.iterdir()] == []
