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
import socket
import stat
import tempfile
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Mapping, Optional, Tuple

from . import netaddr
from .util import run, safe_name

_IGNORE = shutil.ignore_patterns("node_modules", ".venv", "venv", "__pycache__", "target", "dist", "build",
                                 ".mypy_cache", ".pytest_cache", "*.pyc", ".tox", ".gradle")
_GIT_ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="echo", GCM_INTERACTIVE="never")
_URL_RE = re.compile(r"^(https://|ssh://|git@|file://)")
_SHORTHAND_RE = re.compile(r"^(?:github:)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$")
_NOHOOKS = None
ROOTS_ENV = "BTS_SBOM_ALLOWED_ROOTS"                 # os.pathsep-joined folders: when set, a local source (or file:// URL) must live inside one of them
PRIVATE_ENV = "BTS_OSS_ALLOW_PRIVATE_HOSTS"          # =1 lets a git URL point at a non-public host (a private git server on purpose)
_LOCAL_NAMES = ("localhost", "metadata.google.internal", "metadata")


def allowed_roots(env: Optional[Mapping[str, str]] = None) -> List[str]:
    """The declared source roots as real paths ([] = unrestricted, the trusted-operator mode of a localhost service)."""
    raw = (env if env is not None else os.environ).get(ROOTS_ENV, "")
    return [os.path.realpath(os.path.expanduser(p)) for p in raw.split(os.pathsep) if p.strip()]


def _inside(path: str, roots: List[str]) -> bool:
    real = os.path.realpath(path)
    for r in roots:
        try:
            if os.path.commonpath([real, r]) == r:
                return True
        except ValueError:                           # different drives
            continue
    return False


def public_address(host: str) -> Optional[bool]:
    """True/False for an IP literal (False for loopback, private, link-local incl. cloud metadata, CGNAT, reserved), None for a name.
    Legacy IPv4 spellings (decimal 2130706433, hex 0x7f000001, octal 0177.0.0.1, short 127.1) are literals too: they are what git/curl connect to."""
    ip = netaddr.parse_literal(host)
    return None if ip is None else netaddr.is_public(ip)


def _url_host(url: str) -> str:
    if url.startswith("git@"):                       # scp-like: git@host:owner/repo
        return url[4:].split(":", 1)[0]
    return urllib.parse.urlsplit(url).hostname or ""


def _check_git_host(url: str, env: Optional[Mapping[str, str]] = None) -> None:
    """Refuse a git URL whose host is a non-public IP literal or a local/metadata name (no DNS here: this is pure classification)."""
    if (env if env is not None else os.environ).get(PRIVATE_ENV) == "1" or url.startswith("file://"):
        return
    host = netaddr.normalize_host(_url_host(url))
    if host in _LOCAL_NAMES or host.endswith((".localhost", ".internal")) or public_address(host) is False:
        raise ValueError("refused source: %r is not a public host (set %s=1 to allow a private git server)" % (host, PRIVATE_ENV))


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
    roots = allowed_roots()
    if _URL_RE.match(s):
        if s.startswith("file://"):                  # a file:// clone reads a local folder: the same boundary as a local path
            authority = urllib.parse.urlsplit(s).netloc
            if authority not in ("", "localhost"):    # the checked path and the executed URL must be the same thing: no remote authority
                raise ValueError("refused source: a file:// URL must not name a host (%r)" % authority[:40])
            local = urllib.request.url2pathname(urllib.parse.urlsplit(s).path)
            if roots and not _inside(local, roots):
                raise ValueError("refused source: file:// path is outside the declared roots (%s)" % ROOTS_ENV)
        else:
            _check_git_host(s)
        return {"kind": "git", "url": s}
    if not os.path.exists(os.path.expanduser(s)):
        m = _SHORTHAND_RE.match(s)
        if m and not re.match(r"^[A-Za-z]:[\\/]", s):
            return {"kind": "git", "url": "https://github.com/%s/%s.git" % (m.group(1), m.group(2))}
    path = os.path.abspath(os.path.expanduser(s))
    if roots and not _inside(path, roots):
        raise ValueError("refused source: local path is outside the declared roots (%s)" % ROOTS_ENV)
    return {"kind": "local", "path": path}


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


def _resolve_for_clone(url: str, env: Optional[Mapping[str, str]] = None) -> Tuple[str, str]:
    """(refused_address, pin_address) for a git host NAME. ``refused_address`` is the first non-public address it resolves to ('' = none);
    ``pin_address`` is the public address git must connect to (see the clone command: DNS rebinding between this check and git's own
    later resolution is closed by pinning). A resolver failure is not a refusal: git will fail on its own; only positive evidence of an
    internal target blocks the clone. IP literals were classified without DNS and need no pin."""
    if (env if env is not None else os.environ).get(PRIVATE_ENV) == "1" or url.startswith("file://"):
        return "", ""
    host = _url_host(url)
    if not host or public_address(host) is not None:
        return "", ""
    try:
        infos = socket.getaddrinfo(host, None)
    except (OSError, UnicodeError):
        return "", ""
    pin = ""
    for info in infos:
        addr = str(info[4][0])
        if public_address(addr) is False:
            return addr, ""
        if not pin or (":" in pin and ":" not in addr):          # prefer IPv4 for the pin
            pin = addr
    return "", pin


def _resolves_privately(url: str, env: Optional[Mapping[str, str]] = None) -> str:
    """The first non-public address a git host NAME resolves to ('' = fine or undecidable)."""
    return _resolve_for_clone(url, env)[0]


def _curl_pin(url: str, pin: str) -> List[str]:
    """``-c http.curloptResolve=host:port:ip`` for an https clone: git (libcurl) then connects to the address that was just checked."""
    if not pin or not url.startswith("https://"):
        return []
    parts = urllib.parse.urlsplit(url)
    return ["-c", "http.curloptResolve=%s:%d:%s" % (parts.hostname, parts.port or 443, pin)]


def prepare(src: str, work_root: str, *, ref: Optional[str] = None, depth: int = 200,
            name: Optional[str] = None) -> Dict[str, Any]:
    """Return {ok, path, kind, name, lineage} or {ok: False, error}. Always a copy under work_root."""
    try:
        spec = normalize_source(src)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    if shutil.which("git") is None and spec["kind"] == "git":
        return {"ok": False, "error": "git is not installed"}
    pin = ""
    if spec["kind"] == "git":
        resolved, pin = _resolve_for_clone(spec["url"])               # before anything is created under work_root
        if resolved:
            return {"ok": False, "error": "refused source: %r resolves to a non-public address (%s); set %s=1 to allow a private git server" % (_url_host(spec["url"]), resolved, PRIVATE_ENV)}
    os.makedirs(work_root, exist_ok=True)
    base = spec.get("url") or spec["path"]
    nm = safe_name(name or os.path.basename(base.rstrip("/\\")).replace(".git", "") or "project")
    dest = _unique_dest(work_root, nm)

    if spec["kind"] == "git":
        cmd = ["git"] + _curl_pin(spec["url"], pin) + ["-c", "core.hooksPath=" + _hooks_dir(), "-c", "core.symlinks=false",
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
    lin = head(dest)
    lin.update(source=p, uncommitted_changes_included=dirty)
    return {"ok": True, "path": dest, "kind": kind, "name": nm, "lineage": lin}


__all__ = ["prepare", "normalize_source", "git", "head"]
