"""Source scan in the FOSSLight Source Scanner style, rebuilt on this package's rules: walk a LOCAL tree and collect, per text
file, the SPDX-License-Identifier tags and the copyright lines, plus every license-named file detected by text (``licenses.detect_text``).

Feature and output-shape inspiration: FOSSLight Scanner (github.com/fosslight/fosslight_scanner, Apache-2.0) - the per-scanner
"Scanner Info" header (tool, version, started, analyzed path, excluded paths, per-scanner stats), the per-file rows and the
exclusion conventions (hidden/hidden folders, skipped dependency trees). The code is ours: stdlib only, bounded, read-only, and
honest - a guessed license is never claimed, a file that could not be read is listed, and a binary is not parsed here
(``binscan`` is its own pass with its own bounds).

Honest bounds: SPDX tags and copyright lines are what the file SAYS, not a legal conclusion; detection names come from the same
detection table the rest of the package uses (``licenses.detect_text``), and files are capped - the overflow is counted and listed,
never hidden.
"""
from __future__ import annotations

import datetime
import os
import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import __version__, licenses
from .contextpack import SKIP_DIRS

SCHEMA = "bts-sbom.srcscan.v1"
MAX_FILES = 20_000
MAX_TEXT_FILES = 6_000
MAX_FILE_BYTES = 200_000
LICENSE_READ_BYTES = 40_000
_HEAD_BYTES = 4_000
_FILES_CAP = 300
HONESTY = ["SPDX tags and copyright lines are what a file SAYS, not a legal conclusion; detection names come from the shared detection table",
           "read-only and bounded: files over the cap are listed, never hidden; binaries are not parsed here (binscan is its own pass)"]
_COPYRIGHT = re.compile(r"(?:Copyright(?:\s*\(c\))?|©|\(c\))\s*((?:\d{4}\s*(?:[-,]\s*\d{4})?\s*){0,3})([^\n\r;*]{0,120})", re.I)


def _is_link(path: str) -> bool:
    """Symlink OR a Windows reparse point (a junction, which os.path.islink does not report). Same rule as contextpack."""
    if os.path.islink(path):
        return True
    try:
        return bool(getattr(os.lstat(path), "st_file_attributes", 0) & 0x400)
    except (OSError, ValueError):
        return True                                       # cannot tell: treat as unsafe


def walk(root: str, *, max_files: int = MAX_FILES) -> Iterator[Tuple[str, str, bool]]:
    """Yield (relative path, full path, binary-sniff) for every regular file under ``root``; skipped trees and links are the
    caller's business via the returned flags... they are recorded by ``build`` instead, so this yields nothing for them."""
    seen = 0
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS and not d.startswith("."))
        for fn in sorted(fns):
            fp = os.path.join(dp, fn)
            rel = os.path.relpath(fp, root).replace("\\", "/")
            if _is_link(fp):
                yield rel, fp, False
                continue
            seen += 1
            if seen > max_files:
                return
            yield rel, fp, False


def _sniff_binary(fp: str) -> bool:
    """A NUL byte in the head, or undecodable bytes, make a file binary for this pass."""
    try:
        with open(fp, "rb") as fh:
            head = fh.read(8_192)
        return b"\x00" in head
    except OSError:
        return True


def scanner_info(root: str, *, stats: Dict[str, Any], excluded: Dict[str, List[str]]) -> Dict[str, Any]:
    """The Scanner Info header the FOSSLight report leads with: tool, version, started, path, excluded, per-scanner stats."""
    return {"tool": "bts-sbom-app srcscan", "version": __version__, "started": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "path": os.path.abspath(root), "excluded": excluded, "stats": stats}


def build(root: str, *, max_text_files: int = MAX_TEXT_FILES) -> Dict[str, Any]:
    if not os.path.isdir(root):
        raise ValueError("not a folder: %s" % root)
    excluded: Dict[str, List[str]] = {"skipped_dirs": [], "links": [], "binaries": [], "oversized": [], "unreadable": []}
    stats = {"walked": 0, "text_scanned": 0, "license_files": 0, "detected": 0, "with_spdx": 0, "with_copyright": 0}
    files: List[Dict[str, Any]] = []
    for dp, dns, fns in os.walk(root):
        for d in list(dns):
            if d in SKIP_DIRS or d.startswith("."):
                excluded["skipped_dirs"].append(os.path.relpath(os.path.join(dp, d), root).replace("\\", "/"))
        dns[:] = sorted(d for d in dns if d not in SKIP_DIRS and not d.startswith("."))
        for fn in sorted(fns):
            fp = os.path.join(dp, fn)
            rel = os.path.relpath(fp, root).replace("\\", "/")
            stats["walked"] += 1
            if _is_link(fp):
                excluded["links"].append(rel)
                continue
            try:
                if os.path.getsize(fp) > MAX_FILE_BYTES:
                    excluded["oversized"].append(rel)
                    continue
                if _sniff_binary(fp):
                    excluded["binaries"].append(rel)
                    continue
            except OSError:
                excluded["unreadable"].append(rel)
                continue
            stem = os.path.splitext(fn)[0]
            named = bool(licenses._LICENSE_FILE.match(fn) or licenses._LICENSE_FILE.match(stem))
            try:
                with open(fp, "rb") as fh:
                    body_bytes = fh.read(LICENSE_READ_BYTES if named else _HEAD_BYTES)
                text = body_bytes.decode("utf-8", "ignore")
            except OSError:
                excluded["unreadable"].append(rel)
                continue
            item: Dict[str, Any] = {"file": rel, "license": "", "spdx": [], "copyrights": []}
            if named:
                stats["license_files"] += 1
                item["license"] = licenses.detect_text(text)
                if item["license"]:
                    stats["detected"] += 1
            else:
                if stats["text_scanned"] >= max_text_files:
                    excluded.setdefault("over_text_cap", []).append(rel)
                    continue
                stats["text_scanned"] += 1
                for m in licenses._SPDX_TAG.finditer(text):
                    expr, _ = licenses.normalize(m.group(1).strip())
                    if expr and expr not in item["spdx"]:
                        item["spdx"].append(expr)
            seen_c: List[str] = []                                # copyright lines are reported from license files too
            for m in _COPYRIGHT.finditer(text):
                years, holder = (m.group(1) or "").strip(), (m.group(2) or "").strip()
                line = ("Copyright %s%s" % (years + " " if years else "", holder)).strip()
                if len(line) >= 9 and line not in seen_c:
                    seen_c.append(line[:160])
                if len(seen_c) >= 5:
                    break
            item["copyrights"] = seen_c
            if item["license"] or item["spdx"] or item["copyrights"]:
                if item["spdx"]:
                    stats["with_spdx"] += 1
                if item["copyrights"]:
                    stats["with_copyright"] += 1
                files.append(item)
    files.sort(key=lambda f: f["file"])
    return {"schema": SCHEMA, "status": "OK", "root": os.path.abspath(root), "scanner_info": scanner_info(root, stats=stats, excluded=excluded),
            "files": files[:_FILES_CAP], "files_truncated": max(0, len(files) - _FILES_CAP), "honesty": HONESTY}


def to_csv(c: Dict[str, Any]) -> str:
    """The FOSSLight-report-shaped CSV (source sheet): one row per file with its SPDX identifiers and copyright lines."""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["File", "License (detected)", "SPDX identifiers", "Copyright lines"])
    for f in c.get("files") or []:
        w.writerow([f["file"], f.get("license") or "", "; ".join(f.get("spdx") or []), " | ".join(f.get("copyrights") or [])])
    return buf.getvalue()


def to_md(c: Dict[str, Any]) -> str:
    i = c.get("scanner_info") or {}
    st = i.get("stats") or {}
    ex = i.get("excluded") or {}
    out = ["# Source scan of %s" % c.get("root", ""), "",
           "Scanner: %s %s, started %s." % (i.get("tool"), i.get("version"), i.get("started")),
           "Walked %d file(s): %d text scanned, %d license-named, %d detected, %d with SPDX tags, %d with copyright lines." % (
               st.get("walked", 0), st.get("text_scanned", 0), st.get("license_files", 0), st.get("detected", 0), st.get("with_spdx", 0), st.get("with_copyright", 0)),
           "Excluded: %s." % ", ".join("%s %d" % (k, len(v)) for k, v in ex.items() if v) or "nothing excluded.", ""]
    if not (c.get("files") or []):
        out.append("No SPDX tag, copyright line or license file was found - that is a finding, not an absence of scanning.")
        return "\n".join(out) + "\n"
    out += ["| file | license (detected) | SPDX identifiers | copyright lines |", "|---|---|---|---|"]
    for f in (c.get("files") or [])[:50]:
        out.append("| %s | %s | %s | %s |" % (f["file"], f.get("license") or "-", "; ".join(f.get("spdx") or []) or "-",
                                              " | ".join(f.get("copyrights") or [])[:200] or "-"))
    if c.get("files_truncated"):
        out += ["", "%d more file(s) with findings beyond the %d listed." % (c["files_truncated"], _FILES_CAP)]
    out += ["", "> " + "; ".join(HONESTY) + "."]
    return "\n".join(out) + "\n"
