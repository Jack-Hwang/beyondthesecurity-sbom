"""Source acquisition: git URL / GitHub shorthand / local folder -> an isolated WORK COPY.

Honesty + safety contract
  * The origin is never modified: everything happens in a copy under ``work_root``.
  * Cloned code is untrusted data: hooks are disabled, submodules are not fetched, symlinks are not
    materialised, ``ext::`` style transports are refused, and nothing in the clone is ever executed.
  * A local folder with uncommitted changes is analysed *with* those changes (the copy carries them as a
    baseline commit) and the fact is recorded in ``lineage``.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import stat
import tempfile
import urllib.parse
from typing import Any, Dict, Optional

from .util import run, safe_name

_IGNORE = shutil.ignore_patterns("node_modules", ".venv", "venv", "__pycache__", "target", "dist", "build",
                                 ".mypy_cache", ".pytest_cache", "*.pyc", ".tox", ".gradle")
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


DEFAULT_SOURCE_HOSTS = "github.com,gitlab.com,bitbucket.org"


def _first_non_public(host: str, resolver) -> Optional[str]:
    """The core's SSRF rule (bts_sbom/ossscan.py::_non_public_address) over an injected resolver: the first address that
    is not global (loopback, link-local/cloud metadata, private, reserved, ...) as a string, else None."""
    try:
        infos = resolver(host, None)
    except (OSError, UnicodeError):
        return None
    for info in infos:
        raw = str(info[4][0]).split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped is not None:
            ip = mapped
        if ip.is_multicast or not ip.is_global:
            return str(ip)
    return None


def check_source_policy(spec: Dict[str, str], *, cloud: bool, resolver=None) -> Optional[str]:
    """Cloud-mode source policy: a refusal reason, or None to proceed. Cloud-off returns None for every input
    (the earlier behaviour). Strict checks, in order: no local paths, https:// only, host allow-list
    (BTS_SBOM_SOURCE_HOSTS, default github/gitlab/bitbucket), public addresses only (the core's SSRF rule),
    no embedded credentials. DNS is checked once here and git resolves again later - a TOCTOU window remains
    (see ADR-0018)."""
    if not cloud:
        return None
    if spec.get("kind") == "local":
        return "local paths are disabled in cloud mode"
    url = str(spec.get("url") or "")
    if not url.startswith("https://"):
        return "only https:// git URLs are allowed in cloud mode"
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ""
    except ValueError:
        return "not a usable URL"
    if not host:
        return "only https:// git URLs are allowed in cloud mode"
    if parsed.username or parsed.password:
        return "URLs carrying credentials are refused in cloud mode"
    allowed = [h.strip().lower() for h in os.environ.get("BTS_SBOM_SOURCE_HOSTS", DEFAULT_SOURCE_HOSTS).split(",") if h.strip()]
    if host.lower() not in allowed:
        return "host %s is not in the source allow-list" % host
    if resolver is None:
        from bts_sbom.ossscan import _non_public_address       # core is read-only: reuse its rule, never edit it
        bad = _non_public_address(host)
    else:
        bad = _first_non_public(host, resolver)
    if bad:
        return "host %s resolves to a non-public address (%s)" % (host, bad)
    return None


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


def _unique_dest(work_root: str, name: str) -> str:
    dest = os.path.join(work_root, name)
    if os.path.exists(dest):
        shutil.rmtree(dest, onerror=_force_remove)
    if os.path.exists(dest):                       # locked leftovers (Windows) -> unique name
        dest = "%s_%d" % (dest, os.getpid())
    return dest


def _dir_size(path: str) -> int:
    total = 0
    for dp, _dns, fns in os.walk(path):
        for fn in fns:
            try:
                total += os.path.getsize(os.path.join(dp, fn))
            except OSError:
                pass
    return total


def prepare(src: str, work_root: str, *, ref: Optional[str] = None, depth: int = 200,
            name: Optional[str] = None, max_copy_mb: int = 0) -> Dict[str, Any]:
    """Return {ok, path, kind, name, lineage} or {ok: False, error}. Always a copy under work_root."""
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
        lin.update(source=spec["url"], ref=ref or "")
        return {"ok": True, "path": dest, "kind": "git", "name": nm, "lineage": lin}

    p = spec["path"]
    if not os.path.exists(p):
        return {"ok": False, "error": "path does not exist: %s" % p}
    if os.path.isfile(p):
        os.makedirs(dest)
        shutil.copy2(p, dest)
        kind = "local-file"
    else:
        shutil.copytree(p, dest, ignore=_IGNORE, symlinks=True)
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
    if max_copy_mb and _dir_size(dest) > max_copy_mb * 1024 * 1024:
        shutil.rmtree(dest, onerror=_force_remove)      # abort and leave 0 bytes of it on disk
        return {"ok": False, "error": "workcopy_too_large: the work copy exceeds %d MB" % max_copy_mb}
    lin = head(dest)
    lin.update(source=p, uncommitted_changes_included=dirty)
    return {"ok": True, "path": dest, "kind": kind, "name": nm, "lineage": lin}


__all__ = ["prepare", "normalize_source", "git", "head"]
