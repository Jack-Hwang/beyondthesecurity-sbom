"""Defect cluster 'workspace-security' (report section 4): symlinks materialised in the work copy,
no path-containment check in patch.apply(), and an approval digest that ignores target files/verification.

Real-symlink cases are wrapped so they skip cleanly (with a clear reason) on a host/user that cannot create
symlinks (e.g. Windows without SeCreateSymbolicLinkPrivilege/Developer Mode); a monkeypatched variant next to
each proves the same filter/containment logic without needing a real symlink.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from bts_sbom_app import patch, workspace


def _try_symlink(src: str, dst: str, *, target_is_directory: bool = False) -> None:
    try:
        os.symlink(src, dst, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip("cannot create symlinks without privilege/support on this host: %s" % exc)


# ------------------------------------------------------------------ BSA-AC-202: workspace.prepare() symlink handling
def test_local_folder_symlink_is_skipped_not_copied(tmp_path):
    """AC: BSA-AC-202"""
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("TOP SECRET CONTENT", encoding="utf-8")
    outside_dir = outside / "secret_dir"
    outside_dir.mkdir()
    (outside_dir / "inner.txt").write_text("also secret", encoding="utf-8")

    src = tmp_path / "src"
    src.mkdir()
    (src / "normal.txt").write_text("fine", encoding="utf-8")
    _try_symlink(str(secret), str(src / "evil_link.txt"))
    _try_symlink(str(outside_dir), str(src / "evil_dir"), target_is_directory=True)

    res = workspace.prepare(str(src), str(tmp_path / "work"))
    assert res["ok"] is True
    dest = res["path"]

    # the symlinked entries are absent entirely - not copied, not dereferenced into a plain file/dir
    assert not os.path.lexists(os.path.join(dest, "evil_link.txt"))
    assert not os.path.lexists(os.path.join(dest, "evil_dir"))
    assert os.path.isfile(os.path.join(dest, "normal.txt"))

    # the loss is reported, not silent
    assert res["skipped_symlinks"] == 2
    assert res["lineage"]["skipped_symlinks"] == 2

    # the work copy contains 0 symlinks anywhere
    for dp, dns, fns in os.walk(dest):
        for n in dns + fns:
            assert not os.path.islink(os.path.join(dp, n))


def test_local_file_source_and_git_clone_report_zero_skipped_symlinks(tmp_path, monkeypatch):
    """AC: BSA-AC-202"""
    f = tmp_path / "single.txt"
    f.write_text("hello", encoding="utf-8")
    res = workspace.prepare(str(f), str(tmp_path / "work"))
    assert res["ok"] is True and res["skipped_symlinks"] == 0 and res["lineage"]["skipped_symlinks"] == 0

    def fake_run(cmd, cwd=None, timeout=0, env=None):
        return 1, "", "stop here"

    monkeypatch.setattr(workspace, "run", fake_run)
    res2 = workspace.prepare("https://example.invalid/o/r.git", str(tmp_path / "work2"))
    assert res2["ok"] is False  # clone refused (no network in tests) - nothing to assert on skipped_symlinks here


def test_copy_tree_no_symlinks_filters_without_a_real_symlink(monkeypatch, tmp_path):
    """AC: BSA-AC-202 - proves the copy-filter logic (skip + count) without creating any real symlink/junction."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "keep.txt").write_text("ok", encoding="utf-8")
    (src / "fake_link.txt").write_text("should not appear in the work copy", encoding="utf-8")
    sub = src / "sub"
    sub.mkdir()
    (sub / "nested.txt").write_text("nested", encoding="utf-8")

    def fake_is_link_like(path: str) -> bool:
        return os.path.basename(path) == "fake_link.txt"

    monkeypatch.setattr(workspace, "_is_link_like", fake_is_link_like)
    dst = tmp_path / "dst"
    skipped = workspace._copy_tree_no_symlinks(str(src), str(dst), workspace._IGNORE)

    assert skipped == 1
    assert not os.path.exists(dst / "fake_link.txt")
    assert (dst / "keep.txt").read_text(encoding="utf-8") == "ok"
    assert (dst / "sub" / "nested.txt").read_text(encoding="utf-8") == "nested"


class _FakeLStat:
    def __init__(self, attrs: int) -> None:
        self.st_file_attributes = attrs


def test_is_link_like_detects_a_reparse_point_flag_without_a_real_junction(monkeypatch, tmp_path):
    """AC: BSA-AC-202 - Windows junctions/reparse points are detected via the stat flag even when
    os.path.islink() itself says False (the case for some junction/reparse-point kinds)."""
    target = tmp_path / "looks_like_a_junction"
    target.mkdir()
    real_lstat = os.lstat

    def fake_lstat(path, *a, **k):
        if os.path.abspath(str(path)) == os.path.abspath(str(target)):
            return _FakeLStat(workspace._REPARSE_ATTR)
        return real_lstat(path, *a, **k)

    monkeypatch.setattr(os, "lstat", fake_lstat)
    assert os.path.islink(str(target)) is False
    assert workspace._is_link_like(str(target)) is True


# ------------------------------------------------------------------ BSA-AC-203: patch.apply() path containment
def _upgrade_plan(**overrides):
    plan = {"component": "requests", "ecosystem": "PyPI", "current_version": "2.19.1", "safe_version": "2.31.0",
            "status": "upgrade", "files": ["requirements.txt"], "verification": {"clean": True}}
    plan.update(overrides)
    return plan


def test_patch_apply_blocks_relative_traversal_outside_root(tmp_path):
    """AC: BSA-AC-203"""
    secret_file = tmp_path / "secret" / "requirements.txt"
    secret_file.parent.mkdir()
    secret_file.write_text("requests==2.19.1\n", encoding="utf-8")
    root = tmp_path / "work"
    root.mkdir()

    plan = _upgrade_plan(files=["../secret/requirements.txt"])
    res = patch.apply(str(root), [plan], approved=True)

    assert res["results"][0]["status"] == "blocked"
    assert "outside work copy" in res["results"][0]["detail"]
    assert res["changed_files"] == []
    assert secret_file.read_text(encoding="utf-8") == "requests==2.19.1\n"


def test_patch_apply_blocks_absolute_path_target(tmp_path):
    """AC: BSA-AC-203"""
    secret_file = tmp_path / "secret2" / "requirements.txt"
    secret_file.parent.mkdir()
    secret_file.write_text("requests==2.19.1\n", encoding="utf-8")
    root = tmp_path / "work2"
    root.mkdir()

    plan = _upgrade_plan(files=[str(secret_file)])
    res = patch.apply(str(root), [plan], approved=True)

    assert res["results"][0]["status"] == "blocked"
    assert "outside work copy" in res["results"][0]["detail"]
    assert secret_file.read_text(encoding="utf-8") == "requests==2.19.1\n"


def test_patch_apply_blocks_symlinked_target_without_a_real_symlink(monkeypatch, tmp_path):
    """AC: BSA-AC-203 - proves the symlink-containment check without creating a real symlink."""
    root = tmp_path / "work3"
    root.mkdir()
    target = root / "requirements.txt"
    target.write_text("requests==2.19.1\n", encoding="utf-8")
    real_islink = os.path.islink

    def fake_islink(path) -> bool:
        if os.path.abspath(str(path)) == os.path.abspath(str(target)):
            return True
        return real_islink(path)

    monkeypatch.setattr(os.path, "islink", fake_islink)
    plan = _upgrade_plan()
    res = patch.apply(str(root), [plan], approved=True)

    assert res["results"][0]["status"] == "blocked"
    assert "outside work copy" in res["results"][0]["detail"]
    assert target.read_text(encoding="utf-8") == "requests==2.19.1\n"


def test_patch_apply_blocks_write_through_a_real_symlinked_target(tmp_path):
    """AC: BSA-AC-203 - end-to-end repro from the analysis report: a symlinked manifest in the work copy
    must not let apply() write through it into the file it points at outside the work copy."""
    secret = tmp_path / "secret3.txt"
    secret.write_text("requests==2.19.1\n", encoding="utf-8")
    root = tmp_path / "work4"
    root.mkdir()
    link = root / "requirements.txt"
    _try_symlink(str(secret), str(link))

    plan = _upgrade_plan()
    res = patch.apply(str(root), [plan], approved=True)

    assert res["results"][0]["status"] == "blocked"
    assert "outside work copy" in res["results"][0]["detail"]
    assert secret.read_text(encoding="utf-8") == "requests==2.19.1\n"


def test_patch_apply_still_applies_a_legitimate_in_root_target(make_repo, world):
    """AC: BSA-AC-203 - the containment check must not block an ordinary, legitimate target."""
    repo = make_repo({"requirements.txt": "requests==2.19.1\n"})
    plan = _upgrade_plan()
    res = patch.apply(repo, [plan], approved=True)
    assert res["results"][0]["status"] == "applied"
    assert Path(repo, "requirements.txt").read_text(encoding="utf-8") == "requests==2.31.0\n"


# ------------------------------------------------------------------ BSA-AC-204: approval_digest binds files + verification
def test_approval_digest_changes_with_target_files():
    """AC: BSA-AC-204"""
    plan_a = _upgrade_plan()
    plan_b = _upgrade_plan(files=["unrelated/other_requirements.txt"])
    assert patch.approval_digest([plan_a]) != patch.approval_digest([plan_b])


def test_approval_digest_changes_with_verification_state():
    """AC: BSA-AC-204"""
    plan_a = _upgrade_plan()
    plan_c = _upgrade_plan(verification={"clean": False})
    assert patch.approval_digest([plan_a]) != patch.approval_digest([plan_c])


def test_old_token_is_rejected_when_targets_and_verification_later_differ(make_repo):
    """AC: BSA-AC-204 - TOCTOU replay from the analysis report: a token computed for one plan must not be
    accepted for a later plan that shares ecosystem/component/versions but targets different files with a
    different verification outcome."""
    repo = make_repo({"requirements.txt": "requests==2.19.1\n", "unrelated/other_requirements.txt": "requests==2.19.1\n"})
    plan_a = _upgrade_plan()
    plan_b = _upgrade_plan(files=["unrelated/other_requirements.txt"], verification={"clean": False})

    token = patch.approval_digest([plan_a])
    res = patch.apply(repo, [plan_b], approved=True, token=token)

    assert res["status"] == "digest_mismatch"
    assert Path(repo, "unrelated", "other_requirements.txt").read_text(encoding="utf-8") == "requests==2.19.1\n"
