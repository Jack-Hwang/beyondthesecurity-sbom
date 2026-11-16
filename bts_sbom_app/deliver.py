"""Patch delivery. The patch is produced on a work copy; delivery decides where it lands.

  branch   (default) leave the fix branch + commit in the work copy and return the diff - nothing outside the copy changes
  folder   export changed files (relative paths kept) + fix.patch + PATCH_REPORT.md into a destination folder
  inplace  apply fix.patch to the ORIGIN local folder (git apply, checked first) - needs allow_origin_write=True
  github   push the fix branch to a remote repository you name (https/ssh/file URL) - needs allow_push=True; optionally
           open a pull request with the ``gh`` CLI (open_pr=True)
Outward-facing steps (inplace, github, PR) are never taken implicitly: each requires its own explicit flag, every other
target is reversible by deleting the work copy / destination folder.
"""
from __future__ import annotations

import os
import re
import shutil
from typing import Any, Dict, Optional

from . import patch as patchmod
from . import workspace
from .util import run, tree_hash


def _report_md(res: Dict[str, Any]) -> str:
    lines = ["# BTS-SBOM dependency security update", "", "- approval digest: `%s`" % res.get("digest"), "- status: %s" % res.get("status"), ""]
    lines.append("| component | from | to | status | file / note |")
    lines.append("|---|---|---|---|---|")
    for r in res.get("results", []):
        lines.append("| %s | %s | %s | %s | %s |" % (r["component"], r["from"], r["to"], r["status"], (r.get("file") or r.get("manual_command") or r.get("detail") or "").replace("|", "/")))
    if res.get("regenerate"):
        lines += ["", "Regenerate lockfiles (not edited by BTS-SBOM):", ""] + ["- `%s`" % x for x in res["regenerate"]]
    return "\n".join(lines) + "\n"


def deliver(work: str, res: Dict[str, Any], *, target: str = "branch", dest: Optional[str] = None, origin: Optional[str] = None,
            allow_origin_write: bool = False, remote_url: Optional[str] = None, allow_push: bool = False,
            open_pr: bool = False, pr_base: str = "main", branch: Optional[str] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"target": target, "ok": False}
    if res.get("status") != "applied" or not res.get("base_commit"):
        out["error"] = "nothing to deliver (patch status %s)" % res.get("status")
        return out
    df = patchmod.diff(work, res["base_commit"])
    out["diff_stat"] = df["stat"]
    if target == "branch":
        out.update(ok=True, branch=res.get("branch"), commit=res.get("commit"), where=work)
        return out
    if target == "folder":
        if not dest:
            out["error"] = "dest is required for target=folder"
            return out
        os.makedirs(dest, exist_ok=True)
        for rel in res.get("changed_files", []):
            dp = os.path.join(dest, "files", rel)
            os.makedirs(os.path.dirname(dp), exist_ok=True)
            shutil.copy2(os.path.join(work, rel), dp)
        with open(os.path.join(dest, "fix.patch"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(df["patch"])
        with open(os.path.join(dest, "PATCH_REPORT.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(_report_md(res))
        out.update(ok=True, dest=dest, files=len(res.get("changed_files", [])))
        return out
    if target == "inplace":
        if not allow_origin_write:
            out["error"] = "refused: inplace delivery modifies the origin folder and needs allow_origin_write=True"
            return out
        if not origin or not os.path.isdir(origin):
            out["error"] = "origin folder not found"
            return out
        tmp = os.path.join(work, ".bts_sbom_app_fix.patch")
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(df["patch"])
        rc, _, err = run(["git", "apply", "--check", "--unsafe-paths", "--directory=.", tmp], cwd=origin)
        if rc != 0:
            os.unlink(tmp)
            out["error"] = "patch does not apply cleanly to the origin (it changed since the copy was taken): " + err.strip()[-200:]
            return out
        before = tree_hash(origin)
        rc, _, err = run(["git", "apply", "--unsafe-paths", tmp], cwd=origin)
        os.unlink(tmp)
        out.update(ok=rc == 0, origin=origin, origin_changed=before != tree_hash(origin), error=None if rc == 0 else err.strip()[-200:])
        return out
    if target == "github":
        if not allow_push:
            out["error"] = "refused: pushing to a remote needs allow_push=True"
            return out
        if not remote_url or not re.match(r"^(https://|ssh://|git@|file://)", remote_url):
            out["error"] = "remote_url must be an https/ssh/file git URL"
            return out
        br = branch or res.get("branch") or "bts-sbom/auto-fix"
        rc, _, err = workspace.git(work, "push", "--", remote_url, "%s:refs/heads/%s" % (br, br), timeout=300)
        out.update(ok=rc == 0, pushed=rc == 0, remote=remote_url, branch=br, error=None if rc == 0 else err.strip()[-300:])
        if rc == 0 and open_pr:
            m = re.search(r"github\.com[/:]([\w.-]+/[\w.-]+?)(?:\.git)?$", remote_url)
            if not m:
                out["pr_error"] = "pull requests are only opened for github.com remotes"
            else:
                rc2, so, er2 = run(["gh", "pr", "create", "--repo", m.group(1), "--head", br, "--base", pr_base,
                                    "--title", "BTS-SBOM: dependency security update",
                                    "--body", _report_md(res)], cwd=work, timeout=120)
                out["pr_url"] = so.strip().splitlines()[-1] if rc2 == 0 and so.strip() else None
                if rc2 != 0:
                    out["pr_error"] = er2.strip()[-300:]
        return out
    out["error"] = "unknown target %r (branch|folder|inplace|github)" % target
    return out
