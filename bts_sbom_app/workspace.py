"""Source acquisition: git URL / GitHub shorthand / local folder -> an isolated WORK COPY.

Honesty + safety contract
  * The origin is never modified: everything happens in a copy under ``work_root``.
  * Cloned code is untrusted data: hooks are disabled, submodules are not fetched, symlinks are not
    materialised, ``ext::`` style transports are refused, and nothing in the clone is ever executed.
  * A local folder with uncommitted changes is analysed *with* those changes (the copy carries them as a
    baseline commit) and the fact is recorded in ``lineage``.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import tempfile
from typing import Any, Dict, Optional

from .util import run, safe_name

_IGNORE = shutil.ignore_patterns("node_modules", ".venv", "venv", "__pycache__", "target", "dist", "build",
                                 ".mypy_cache", ".pytest_cache", "*.pyc", ".tox", ".gradle")
_REPARSE_ATTR = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_GIT_ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="echo", GCM_INTERACTIVE="never")
_URL_RE = re.compile(r"^(https://|ssh://|git@|file://)")
_SHORTHAND_RE = re.compile(r"^(?:github:)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$")
_NOHOOKS = None


def _hooks_dir() -> str:
    global _NOHOOKS
    if _NOHOOKS is None:
        _NOHOOKS = tempfile.mkdtemp(prefix="bts_sbom_nohooks_")
    return _NOHOOKS


def normalize_source(src: str) -> Dict[str, str]:
    """Classify ``src`` -> {kind: git|local, url|path}. Refuses dangerous transports."""
    s = (src or "").strip()
    if not s:
        raise ValueError("empty source")
    if s.startswith("-") or "ext::" in s or s.lower().startswith(("fd::", "http://")):
        raise ValueError("refused source (unsafe transport or option-like value): %r" % s[:60])
    if _URL_RE.match(s):
        return {"kind": "git", "url": s}
    if not os.path.exists(os.path.expanduser(s)):
        m = _SHORTHAND_RE.match(s)
        if m and not re.match(r"^[A-Za-z]:[\\/]", s):
            return {"kind": "git", "url": "https://github.com/%s/%s.git" % (m.group(1), m.group(2))}
    return {"kind": "local", "path": os.path.abspath(os.path.expanduser(s))}


def git(path: str, *args: str, timeout: float = 180.0):
    return run(["git", "-C", path, "-c", "user.email=bts-sbom@local", "-c", "user.name=bts-sbom",
                "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + _hooks_dir(), *args],
               timeout=timeout, env=_GIT_ENV)


def head(path: str) -> Dict[str, str]:
    rc, out, _ = git(path, "rev-parse", "HEAD")
    rc2, rem, _ = git(path, "config", "--get", "remote.origin.url")
    rc3, br, _ = git(path, "rev-parse", "--abbrev-ref", "HEAD")
    return {"commit": out.strip() if rc == 0 else "", "remote": rem.strip() if rc2 == 0 else "",
            "branch": br.strip() if rc3 == 0 else ""}


def _force_remove(func, path, _exc) -> None:
    """git marks object files read-only; on Windows that makes plain rmtree fail silently (-> leaked, PID-suffixed copies)."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def _is_link_like(path: str) -> bool:
    """True for a real OS symlink, or (Windows) a junction/other reparse point - neither is ever materialised."""
    if os.path.islink(path):
        return True
    try:
        attrs = os.lstat(path).st_file_attributes  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False
    return bool(attrs & _REPARSE_ATTR)


def _copy_tree_no_symlinks(src: str, dst: str, ignore) -> int:
    """Like shutil.copytree(..., symlinks=False) but never materialises a symlink/junction in dst - it is skipped
    and counted instead of being dereferenced or copied. Returns the number of entries skipped."""
    os.makedirs(dst, exist_ok=True)
    names = os.listdir(src)
    ignored = ignore(src, names) if ignore else set()
    skipped = 0
    for name in names:
        if name in ignored:
            continue
        s = os.path.join(src, name)
        d = os.path.join(dst, name)
        if _is_link_like(s):
            skipped += 1
            continue
        if os.path.isdir(s):
            skipped += _copy_tree_no_symlinks(s, d, ignore)
        else:
            shutil.copy2(s, d)
    return skipped


def _unique_dest(work_root: str, name: str) -> str:
    dest = os.path.join(work_root, name)
    if os.path.exists(dest):
        shutil.rmtree(dest, onerror=_force_remove)
    if os.path.exists(dest):                       # locked leftovers (Windows) -> unique name
        dest = "%s_%d" % (dest, os.getpid())
    return dest


def prepare(src: str, work_root: str, *, ref: Optional[str] = None, depth: int = 200,
            name: Optional[str] = None) -> Dict[str, Any]:
    """Return {ok, path, kind, name, lineage, skipped_symlinks} or {ok: False, error}. Always a copy under work_root.

    ``skipped_symlinks`` counts symlinks/junctions found in a local-folder source: they are never materialised in
    the work copy (so the copy cannot be used to read or, via patch.apply(), write outside it) - the count is
    reported instead of being silently dropped."""
    try:
        spec = normalize_source(src)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    if shutil.which("git") is None and spec["kind"] == "git":
        return {"ok": False, "error": "git is not installed"}
    os.makedirs(work_root, exist_ok=True)
    base = spec.get("url") or spec["path"]
    nm = safe_name(name or os.path.basename(base.rstrip("/\\")).replace(".git", "") or "project")
    dest = _unique_dest(work_root, nm)

    if spec["kind"] == "git":
        cmd = ["git", "-c", "core.hooksPath=" + _hooks_dir(), "-c", "core.symlinks=false",
               "-c", "core.autocrlf=false", "-c", "protocol.ext.allow=never", "clone", "--no-tags",
               "--no-recurse-submodules", "--depth", str(depth)]
        if ref:
            cmd += ["--branch", ref]
        cmd += ["--", spec["url"], dest]
        rc, _, err = run(cmd, timeout=600, env=_GIT_ENV)
        if rc != 0:
            shutil.rmtree(dest, ignore_errors=True)
            return {"ok": False, "error": "git clone failed: " + err.strip()[-300:]}
        lin = head(dest)
        lin.update(source=spec["url"], ref=ref or "", skipped_symlinks=0)
        return {"ok": True, "path": dest, "kind": "git", "name": nm, "lineage": lin, "skipped_symlinks": 0}

    p = spec["path"]
    if not os.path.exists(p):
        return {"ok": False, "error": "path does not exist: %s" % p}
    skipped_symlinks = 0
    if os.path.isfile(p):
        os.makedirs(dest)
        shutil.copy2(p, dest)
        kind = "local-file"
    else:
        skipped_symlinks = _copy_tree_no_symlinks(p, dest, _IGNORE)
        kind = "local-copy"
    dirty = False
    if shutil.which("git"):
        if not os.path.isdir(os.path.join(dest, ".git")):
            git(dest, "init", "-q")
        else:
            rc, st, _ = git(dest, "status", "--porcelain")
            dirty = rc == 0 and bool(st.strip())
        git(dest, "add", "-A")
        git(dest, "commit", "-q", "--allow-empty", "-m", "bts-sbom: baseline snapshot of work copy")
    lin = head(dest)
    lin.update(source=p, uncommitted_changes_included=dirty, skipped_symlinks=skipped_symlinks)
    return {"ok": True, "path": dest, "kind": kind, "name": nm, "lineage": lin, "skipped_symlinks": skipped_symlinks}


__all__ = ["prepare", "normalize_source", "git", "head"]
