# round-2 X1 cross-platform hardening (REA 21 §7) — new shared helper.
"""Path normalization helpers shared by manifest parsers.

Windows-produced lockfiles travel (checked into a repo on Windows, scanned
on Linux CI and vice versa), so any RELATIVE path a parser matches on must
be normalized to one canonical form before comparison. `norm_rel_path`
converts backslashes to forward slashes, strips a leading "./", collapses
duplicate slashes and lower-cases — the same canonical form
manifests.parser_for matches its relpath suffixes against ("var/lib/dpkg/
status" style routes). Absolute paths keep their leading slash.
"""
from __future__ import annotations

import os
from typing import Optional


def norm_rel_path(p: Optional[str]) -> str:
    """Canonical form for relative-path matching (forward slashes, no "./",
    collapsed separators, lower-cased). Never touches the filesystem and is
    safe on absolute paths too (a leading "/" survives)."""
    s = str(p or "").replace("\\", "/")
    s = s.replace("//", "/")
    while s.startswith("./"):
        s = s[2:]
    return s.lower()


def rel_suffix_matches(path: str, suffix: str) -> bool:
    """True when `path` equals or ends with the slash-normalized `suffix`
    (both sides canonicalized — Windows backslashes in, POSIX or Windows
    lockfile provenance, same verdict on every OS)."""
    norm = norm_rel_path(path)
    suf = norm_rel_path(suffix)
    return norm == suf or norm.endswith("/" + suf)


def sibling(path: Optional[str], name: str) -> Optional[str]:
    """Absolute path of `name` next to `path`, or None when `path` names no
    existing sibling. os.path.join based — never string concatenation."""
    if not path:
        return None
    cand = os.path.join(os.path.dirname(path), name)
    return cand if os.path.isfile(cand) else None


__all__ = ["norm_rel_path", "rel_suffix_matches", "sibling"]
