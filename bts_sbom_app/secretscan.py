"""secretscan.py - stdlib regex sweep for secret-looking strings over an analysed source tree (course package C08).

Why: BTS-SBOM reads a lot of other people's trees (an uploaded archive, a cloned repo, an extracted package). None of
that is ever executed, but a tree can still contain a committed credential that should not be echoed back to a chat
transcript or a report. This module never does that either: every finding carries only ``file`` + ``line`` + ``rule``
(the rule NAME, e.g. ``"aws-access-key"``) - never the matched text, never even a prefix of it, so showing findings to
a user or writing them to the evidence file can never leak the secret it found.

Honesty contract: a binary file and a file over :data:`MAX_FILE_BYTES` are SKIPPED, not silently treated as clean -
the counts ride on the summary dict's ``coverage_limited`` flag (true the moment anything was skipped) so "0
findings" is never read as "nothing here" when part of the tree was never actually read. Stdlib only, no network,
deterministic (the walk is fully sorted).

Safety of the walk itself: ``.git`` and ``node_modules`` (by name, at any depth) are never descended into, and a
symlinked file or directory is never followed - a tree that symlinks outside itself (or into a cycle) cannot make
the scanner read something outside ``root`` or loop forever.

Public surface: :func:`scan_tree` (the one entry point most callers want) and :func:`scan_text` (the regex sweep
alone, over an in-memory string, handy for a unit test or a paste-box feature).

CLI/API wiring - this module owns neither; the integrator applies them in the files that DO own them:
  * ``cli_ext.py``: a ``bts-sbom secrets scan <root>`` subcommand - call :func:`scan_tree`, print the summary line
    and up to N findings as ``file:line [rule]`` (never the matched text), and exit non-zero both when
    ``findings`` is non-zero AND when ``summary["coverage_limited"]`` is true (an honest partial scan must not look
    like a clean pass to a CI gate either).
  * ``bts_sbom_app/oss_api.py`` (or ``server.py``): fold the same two values into the existing scan job - e.g. a
    ``secrets`` key on the job's overview dict (``{"findings": [...], "summary": {...}}``), reusing the job's own
    root/evidence directory as ``root`` - so the existing "OSS Scanner" screen can show a secrets tab without a new
    background-job type.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Tuple

#: Bytes sniffed from the start of a file to decide text vs binary before reading the rest.
_SNIFF_BYTES = 8192
#: A file at or above this size is skipped as "oversized" (named in the summary, never silently treated as clean).
MAX_FILE_BYTES = 2_000_000
#: Directory names that are never descended into, anywhere in the tree (exact name match, not a path/glob).
SKIP_DIR_NAMES = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})

#: The Windows FILE_ATTRIBUTE_REPARSE_POINT bit (0x400). Irrelevant off Windows - the getattr() guard below handles
#: that, so this constant is never even consulted on Linux/macOS.
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# 7 rule categories (course package C08). The pattern itself is intentionally simple/explainable; a real deployment
# would add a dedicated scanner (gitleaks, GitHub secret scanning) in CI as well - this is a conservative first line,
# not a complete one.
RULES: Dict[str, "re.Pattern[str]"] = {
    "aws-access-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private-key-block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "anthropic-api-key": re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    "openai-style-key": re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
    "azure-storage-account-key": re.compile(r"\bAccountKey=[A-Za-z0-9+/=]{30,}"),
    "password-in-url": re.compile(r"\b(?:postgres(?:ql)?|mysql|mssql|redis|mongodb(?:\+srv)?)://[^:\s/@\"']+:[^@\s\"']{3,}@"),
    "password-assignment": re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']"),
}
#: Stable iteration order (dict literals already preserve insertion order; named for readability at call sites).
RULE_NAMES: Tuple[str, ...] = tuple(RULES)


def scan_text(text: str) -> List[Tuple[int, str]]:
    """Every (1-based line number, rule name) hit in ``text``. Never returns the matched text itself."""
    hits: List[Tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for name in RULE_NAMES:
            if RULES[name].search(line):
                hits.append((lineno, name))
    return hits


def _looks_binary(sample: bytes, full: bytes) -> bool:
    if b"\x00" in sample:
        return True
    try:
        full.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _read_text_or_skip_reason(path: str) -> Tuple[str, str]:
    """-> (text, "") on a readable, in-limit, text file, else ("", reason) with reason one of
    "oversized" / "binary" / "unreadable". Never raises."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return "", "unreadable"
    if size > MAX_FILE_BYTES:
        return "", "oversized"
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return "", "unreadable"
    if _looks_binary(data[:_SNIFF_BYTES], data):
        return "", "binary"
    return data.decode("utf-8"), ""


def _is_reparse_point(path: str) -> bool:
    """True on Windows when ``path`` is a reparse point - this catches an NTFS directory JUNCTION
    (``mklink /J``), which ``os.path.islink()`` never reports: a junction uses the IO_REPARSE_TAG_MOUNT_POINT
    reparse tag, not the symlink tag ``islink()`` looks for, so it would otherwise walk the scanner straight
    through it. ``st_file_attributes`` only exists on Windows; the ``getattr`` below makes this always False
    (a no-op) on Linux/macOS, where ``os.path.islink()`` already covers every symlink."""
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    attrs = getattr(st, "st_file_attributes", None)
    if attrs is None:
        return False
    return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)


def _escapes_root(path: str, root_real: str) -> bool:
    """True when ``path``'s fully-resolved real path is not ``root_real`` itself or inside it. A belt-and-braces
    containment check (on top of :func:`_is_reparse_point`) so an escape is caught even via a reparse-point kind
    neither that attribute check nor ``os.path.islink()`` was written to recognise."""
    real = os.path.normcase(os.path.realpath(path))
    return real != root_real and not real.startswith(root_real + os.sep)


def _unsafe_entry(path: str, root_real: str) -> bool:
    return os.path.islink(path) or _is_reparse_point(path) or _escapes_root(path, root_real)


def _iter_files(root: str) -> List[str]:
    """Every regular file under ``root``, sorted (deterministic), skipping :data:`SKIP_DIR_NAMES` by name and never
    following a symlink OR a Windows directory junction/reparse point - either could otherwise walk the scanner
    outside ``root`` (or into a cycle), so both are checked, plus a resolved-realpath containment check as a
    second line of defence (see :func:`_escapes_root`)."""
    root_real = os.path.normcase(os.path.realpath(root))
    out: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIR_NAMES and not _unsafe_entry(os.path.join(dirpath, d), root_real)
        )
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if _unsafe_entry(full, root_real):
                continue
            out.append(full)
    return out


def scan_tree(root: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Walk ``root`` and return ``(findings, summary)``.

    ``findings`` is a list of ``{"file": <path relative to root, "/" separated>, "line": <1-based>, "rule": <name>}``
    dicts - file + line + rule only, never the matched text.

    ``summary`` always carries honest coverage::

        {"root": <abs path>, "files_scanned": N, "files_skipped_binary": N, "files_skipped_oversized": N,
         "files_skipped_unreadable": N, "files_skipped_total": N, "findings": len(findings),
         "coverage_limited": bool, "max_file_bytes": MAX_FILE_BYTES, "rules": [...RULE_NAMES]}

    ``coverage_limited`` is true the moment ANY file was skipped, so a caller must never report "0 findings" as a
    clean scan without also checking it.
    """
    root_abs = os.path.abspath(root)
    findings: List[Dict[str, Any]] = []
    scanned = 0
    skipped_binary = 0
    skipped_oversized = 0
    skipped_unreadable = 0
    for full in _iter_files(root_abs):
        text, reason = _read_text_or_skip_reason(full)
        if reason == "binary":
            skipped_binary += 1
            continue
        if reason == "oversized":
            skipped_oversized += 1
            continue
        if reason == "unreadable":
            skipped_unreadable += 1
            continue
        scanned += 1
        rel = os.path.relpath(full, root_abs).replace(os.sep, "/")
        for lineno, rule in scan_text(text):
            findings.append({"file": rel, "line": lineno, "rule": rule})
    total_skipped = skipped_binary + skipped_oversized + skipped_unreadable
    summary = {
        "root": root_abs,
        "files_scanned": scanned,
        "files_skipped_binary": skipped_binary,
        "files_skipped_oversized": skipped_oversized,
        "files_skipped_unreadable": skipped_unreadable,
        "files_skipped_total": total_skipped,
        "findings": len(findings),
        "coverage_limited": total_skipped > 0,
        "max_file_bytes": MAX_FILE_BYTES,
        "rules": list(RULE_NAMES),
    }
    return findings, summary


__all__ = ["scan_tree", "scan_text", "RULES", "RULE_NAMES", "MAX_FILE_BYTES", "SKIP_DIR_NAMES"]
