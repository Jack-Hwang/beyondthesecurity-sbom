"""Binary scan in the FOSSLight Binary Scanner style, bounded to what is honest without a binary DB: walk a LOCAL tree, collect the
binary list (NUL-byte sniff, same rule as srcscan), and extract bounded string evidence - license names, copyright lines and
notice-file names - from each binary's first ``READ_BYTES``.

FOSSLight Scanner (github.com/fosslight/fosslight_scanner, Apache-2.0) matches binaries against a binary DB and reports the
identified OSS; this package ships no such database, so this pass does something narrower and says so: it reports the strings a
binary carries as EVIDENCE for a human, never as identification. No reverse engineering, nothing executed, nothing unpacked - an
embedded ZIP or an installer payload is opaque bytes here and stays opaque on purpose.

Honest bounds: a license name found in strings does not mean the binary IS that component; absence of strings does not prove a
binary is clean; and the read window is bounded - the overflow is counted, not hidden.
"""
from __future__ import annotations

import datetime
import os
import re
from typing import Any, Dict, List

from . import __version__
from .srcscan import MAX_FILE_BYTES, _is_link
from .contextpack import SKIP_DIRS
from . import binary_rea

SCHEMA = "bts-sbom.binscan.v1"
MAX_BINARIES = 200
READ_BYTES = 262_144
MIN_RUN = 6
HONESTY = ["no binary database ships with this tool: string evidence is a lead for a human, never an identification",
           "a license name in the strings does not mean the binary is that component, and an absence proves nothing; the read window is bounded"]
_LICENSE_STRINGS = ("Apache License", "GNU General Public License", "GNU Lesser General Public License", "MIT License",
                    "Boost Software License", "Mozilla Public License", "OpenSSL License", "The Unlicense", "zlib License",
                    "ISC License", "BSD ", "Beerware", "Public Domain")
_COPYRIGHT = re.compile(r"(?:Copyright(?:\s*\(c\))?|©|\(c\))[^\n\r;*]{0,120}", re.I)
_PRINTABLE = re.compile(rb"[ -~]{%d,}" % MIN_RUN)


def _strings(body: bytes) -> List[str]:
    out: List[str] = []
    for m in _PRINTABLE.finditer(body):
        try:
            s = m.group(0).decode("ascii")
        except UnicodeDecodeError:
            continue
        out.append(s.strip())
        if len(out) >= 40_000:
            break
    return out


def build(root: str, *, max_binaries: int = MAX_BINARIES) -> Dict[str, Any]:
    if not os.path.isdir(root):
        raise ValueError("not a folder: %s" % root)
    excluded: Dict[str, List[str]] = {"skipped_dirs": [], "links": [], "oversized": [], "unreadable": [], "text": []}
    stats = {"walked": 0, "binaries": 0, "with_license_strings": 0, "with_copyright": 0, "read_truncated": 0}
    bins: List[Dict[str, Any]] = []
    evs: List[Dict[str, Any]] = []
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
                size = os.path.getsize(fp)
            except OSError:
                excluded["unreadable"].append(rel)
                continue
            if size > MAX_FILE_BYTES:
                excluded["oversized"].append(rel)
                continue
            try:
                with open(fp, "rb") as fh:
                    head = fh.read(8_192)
                    if b"\x00" not in head:
                        excluded["text"].append(rel)
                        continue
                    body = head + fh.read(READ_BYTES - len(head))
            except OSError:
                excluded["unreadable"].append(rel)
                continue
            if len(body) < size:
                stats["read_truncated"] += 1
            if stats["binaries"] >= max_binaries:
                excluded.setdefault("over_bin_cap", []).append(rel)
                continue
            stats["binaries"] += 1
            strings = _strings(body)
            found = [s for s in (_LICENSE_STRINGS) if any(s.casefold() in x.casefold() for x in strings)]
            copyrights: List[str] = []
            for x in strings:
                m = _COPYRIGHT.search(x)
                if m and m.group(0).strip() not in copyrights:
                    copyrights.append(m.group(0).strip()[:160])
                if len(copyrights) >= 5:
                    break
            # REA-style structural tier (engine-free): import tables / needed libs / ASAR manifests as
            # dependency evidence + SBOM components. Structural facts ride along per binary.
            struct_ev = binary_rea.inspect(fp)
            stats.setdefault("structural", Counter := __import__("collections").Counter())
            Counter[struct_ev["kind"]] += 1
            if found:
                stats["with_license_strings"] += 1
            if copyrights:
                stats["with_copyright"] += 1
            entry = {"file": rel, "bytes": size, "license_strings": found, "copyrights": copyrights}
            if struct_ev["kind"] != "unknown" and struct_ev["evidence"]:
                entry["structure"] = {k: v for k, v in struct_ev["evidence"].items()
                                      if k in ("format", "machine", "class", "imported_dlls", "imports",
                                               "needed", "package_name", "package_version", "dependencies",
                                               "electron", "files", "js_files", "classes", "manifest")}
                entry["structure_tier"] = struct_ev["tier"]
                if struct_ev["error"]:
                    entry["structure_error"] = struct_ev["error"]
            bins.append(entry)
            evs.append(struct_ev)
    bins.sort(key=lambda b: b["file"])
    info = {"tool": "bts-sbom-app binscan", "version": __version__,
            "started": datetime.datetime.now().astimezone().isoformat(timespec="seconds"), "path": os.path.abspath(root),
            "excluded": excluded, "stats": stats}
    components = binary_rea.components_from(evs)
    honesty = HONESTY + [binary_rea.TIER + "-tier structural evidence: import tables / ELF DT_NEEDED / "
                         "ASAR manifests are dependency evidence with stated limitations, not a decompilation"]
    return {"schema": SCHEMA, "status": "OK", "root": os.path.abspath(root), "scanner_info": info,
            "binaries": bins, "binaries_truncated": 0, "honesty": honesty,
            "components": components, "component_count": len(components)}


def to_csv(c: Dict[str, Any]) -> str:
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["Binary", "Bytes", "License strings", "Copyright lines"])
    for b in c.get("binaries") or []:
        w.writerow([b["file"], b["bytes"], "; ".join(b.get("license_strings") or []), " | ".join(b.get("copyrights") or [])])
    return buf.getvalue()


def to_md(c: Dict[str, Any]) -> str:
    i = c.get("scanner_info") or {}
    st = i.get("stats") or {}
    ex = i.get("excluded") or {}
    out = ["# Binary scan of %s" % c.get("root", ""), "",
           "Scanner: %s %s, started %s." % (i.get("tool"), i.get("version"), i.get("started")),
           "Walked %d file(s): %d binary, %d with license strings, %d with copyright lines; %d read window(s) truncated." % (
               st.get("walked", 0), st.get("binaries", 0), st.get("with_license_strings", 0), st.get("with_copyright", 0), st.get("read_truncated", 0)),
           "Excluded: %s." % (", ".join("%s %d" % (k, len(v)) for k, v in ex.items() if v) or "nothing excluded."), ""]
    if not (c.get("binaries") or []):
        out.append("No binary carried license or copyright strings - string evidence only, never an identification.")
        return "\n".join(out) + "\n"
    out += ["| binary | bytes | license strings | copyright lines |", "|---|---|---|---|"]
    for b in (c.get("binaries") or [])[:50]:
        out.append("| %s | %d | %s | %s |" % (b["file"], b["bytes"], "; ".join(b.get("license_strings") or []) or "-",
                                              " | ".join(b.get("copyrights") or [])[:200] or "-"))
    comps = c.get("components") or []
    if comps:
        out += ["", "## Structural components (%d) - engine-free REA-style tier" % len(comps), "",
                "| component | kind | via | from |", "|---|---|---|---|"]
        for cm in comps[:60]:
            out.append("| %s | %s | %s | %s |" % (cm["name"], cm["kind"], cm["via"], cm["from_file"]))
    out += ["", "> " + "; ".join(HONESTY) + "."]
    return "\n".join(out) + "\n"
