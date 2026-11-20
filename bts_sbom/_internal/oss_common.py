"""Shared plumbing for the OSS scanners (source / dependency / binary / yocto / android / precheck).

Safety rules every scanner inherits from here (the analysed tree is UNTRUSTED DATA - read, never executed):
  * the walk never follows symlinks (a link is recorded as skipped, not dereferenced) and never leaves ``root``;
  * every read is size-bounded; every walk is count-bounded and reports ``truncated`` instead of silently stopping;
  * default exclusions are RECORDED (the scanner emits the item with ``exclude=True`` and the reason in ``comment``),
    never silently dropped - the same transparency FOSSLight's "Exclude" column gives.
"""
from __future__ import annotations

import contextlib
import hashlib
import os
import threading
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Sequence, Tuple

from bts_sbom.ossreport import path_matches

MAX_FILES = 200_000
MAX_READ = 2_000_000
_TEST_DIRS = {"test", "tests", "__tests__", "testing", "testdata", "spec", "specs"}
_DOC_DIRS = {"doc", "docs", "documentation"}
_BUILD_SCRIPTS = {"makefile", "gnumakefile", "cmakelists.txt", "configure", "configure.ac", "meson.build",
                  "build.gradle", "build.gradle.kts", "build.xml", "build.sbt", "rakefile", "gruntfile.js",
                  "gulpfile.js", "webpack.config.js", "sconstruct", "wscript"}
_BUILD_EXT = {".cmake", ".mk", ".gradle", ".bazel", ".bzl"}


# ------------------------------------------------------------------------------------------ cooperative cancellation
# A scan started from the web console runs in a worker thread and must stop when the user presses Cancel - also in the
# middle of a long walk, an extraction or a download, not only between stages.  The token is thread-local so the scanners
# need no extra parameter; the long loops (walk, archive members, downloads, git) call ``check_cancel``.
_tls = threading.local()


class Cancelled(BaseException):
    """Raised by :func:`check_cancel`.  A BaseException on purpose: the scanners' tolerant ``except Exception`` blocks
    (one unreadable file must not stop a scan) must not swallow a cancellation."""


@contextlib.contextmanager
def cancel_scope(event: "Optional[threading.Event]"):
    prev = getattr(_tls, "event", None)
    _tls.event = event
    try:
        yield
    finally:
        _tls.event = prev


def is_cancelled() -> bool:
    ev = getattr(_tls, "event", None)
    return bool(ev is not None and ev.is_set())


def check_cancel() -> None:
    if is_cancelled():
        raise Cancelled("cancelled")


def norm(path: str) -> str:
    return path.replace("\\", "/").lstrip("./") if path.startswith("./") else path.replace("\\", "/")


def default_exclude_reason(rel: str) -> Optional[str]:
    """Why a path is excluded by default (None = not excluded).  Mirrors the documented FOSSLight behaviour: hidden files
    and folders, test and doc directories, build scripts."""
    parts = norm(rel).split("/")
    for p in parts[:-1]:
        if p.startswith(".") and p not in (".", ".."):
            return "hidden directory"
        if p.lower() in _TEST_DIRS:
            return "test directory"
        if p.lower() in _DOC_DIRS:
            return "documentation directory"
    name = parts[-1]
    if name.lower() in ("sbom-info.yaml", "oss-pkg-info.yaml"):
        return "OSS correction file"          # input of the scan, not analysed material (its text would be misread as a notice)
    if name.startswith(".") and name.lower() not in (".reuse",):
        return "hidden file"
    if name.lower() in _BUILD_SCRIPTS or os.path.splitext(name)[1].lower() in _BUILD_EXT:
        return "build script"
    return None


@dataclass
class WalkStats:
    files: int = 0
    skipped_symlinks: List[str] = field(default_factory=list)
    skipped_excluded: int = 0
    truncated: bool = False
    unreadable_dirs: List[str] = field(default_factory=list)


def user_excluded(rel: str, patterns: Sequence[str]) -> bool:
    return any(path_matches(p, rel) or path_matches(p.rstrip("/") + "/", rel + "/") for p in patterns or ())


def walk(root: str, excludes: Sequence[str] = (), max_files: int = MAX_FILES,
         stats: Optional[WalkStats] = None, prune_hidden_dirs: bool = False) -> Iterator[Tuple[str, str]]:
    """Yield (absolute, relative-with-forward-slashes) for regular files under ``root``.

    User ``excludes`` (glob / directory patterns) are pruned.  Symlinks (files AND directories) are never followed.
    ``prune_hidden_dirs`` additionally skips hidden directories such as .git entirely (their files are not even listed)."""
    st = stats if stats is not None else WalkStats()
    root = os.path.abspath(root)
    if os.path.isfile(root):
        st.files += 1
        yield root, os.path.basename(root)
        return

    def onerror(err: OSError) -> None:
        st.unreadable_dirs.append(str(getattr(err, "filename", "")))

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
        check_cancel()
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        rel_dir = "" if rel_dir == "." else rel_dir
        keep: List[str] = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            rel = (rel_dir + "/" + d) if rel_dir else d
            if os.path.islink(full):
                st.skipped_symlinks.append(rel)
                continue
            if user_excluded(rel, excludes) or (prune_hidden_dirs and d.startswith(".")):
                st.skipped_excluded += 1
                continue
            keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            full = os.path.join(dirpath, f)
            rel = (rel_dir + "/" + f) if rel_dir else f
            if os.path.islink(full):
                st.skipped_symlinks.append(rel)
                continue
            if not os.path.isfile(full):
                continue                       # sockets, FIFOs, devices
            if user_excluded(rel, excludes):
                st.skipped_excluded += 1
                continue
            if st.files >= max_files:
                st.truncated = True
                return
            st.files += 1
            if not st.files & 0xFF:
                check_cancel()
            yield full, rel


def read_text(path: str, limit: int = MAX_READ) -> str:
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit)
    except OSError:
        return ""
    for enc in ("utf-8-sig", "utf-16"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def read_bytes(path: str, limit: int = MAX_READ) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""


def sha256_file(path: str, limit: Optional[int] = None) -> str:
    h = hashlib.sha256()
    n = 0
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                n += len(chunk)
                if limit is not None and n > limit:
                    return ""
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def safe_join(root: str, rel: str) -> Optional[str]:
    """``root``/``rel`` or None when it would escape ``root`` (.., absolute path, drive switch)."""
    rel = rel.replace("\\", "/")
    if os.path.isabs(rel) or (len(rel) > 1 and rel[1] == ":"):
        return None
    full = os.path.normpath(os.path.join(root, rel))
    r = os.path.abspath(root)
    if full != r and not full.startswith(r + os.sep):
        return None
    return full
