# vendored from common/license_scan.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
Source-file license detector — scans the ACTUAL bytes of a source tree for
license evidence, in the spirit of FOSSology's scanning agents
(github.com/fossology/fossology, src/): a clean-room re-implementation of the
ideas behind three of them — nothing is copied from FOSSology's GPL code.

  * ojo       -> `SPDX-License-Identifier:` tag scanner   (exact, top confidence)
  * nomos     -> distinctive license-phrase recognizer     (per SPDX license)
  * copyright -> copyright / (c) holder extractor

Why this is different from the deps.dev license lookup already in the report:
that reports the license a package *declares* in a registry; this reports the
license actually *present in the files on disk*, with file:line + the matched
snippet as evidence. The two together let us flag declared-vs-detected
mismatches.

Honesty: a file with no recognizable license text yields NO license finding —
it is counted as "no license detected", never guessed. Scanning is capped and
any truncation / skipped directory is reported, never hidden.
"""
import os
import re
from typing import Dict, Any, List, Optional, Tuple

from bts_sbom._internal.license_utils import classify_license, analyze_licenses

# ── scan bounds (honest caps; truncation is reported) ────────────────────────
MAX_FILES = 6000
MAX_BYTES_SOURCE = 64 * 1024
MAX_BYTES_LICENSE = 256 * 1024
_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".sca_workspace",
              ".venv", "venv", "dist", "build", ".mypy_cache", ".pytest_cache",
              ".tox", ".gradle", "target", ".idea", ".vscode"}
_BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg", ".pdf",
    ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".class",
    ".so", ".dll", ".dylib", ".a", ".o", ".obj", ".exe", ".bin", ".wasm",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".pyc", ".pyo", ".lock", ".min.js", ".map",
}
# files whose NAME marks them as a license/notice document (read in full)
_LICENSE_NAME_RE = re.compile(
    r"^(licen[sc]e|copying|copyright|notice|unlicense|patents|authors)"
    r"([._-].*)?$", re.IGNORECASE)

# ── ojo: SPDX-License-Identifier tag ─────────────────────────────────────────
_SPDX_TAG_RE = re.compile(r"SPDX-License-Identifier\s*:\s*([^\n\r]+)", re.IGNORECASE)
_TAG_TERMINATORS = ("*/", "-->", "#}", "}}", "*)", "--%>", '"""', "'''", "%}")


def _clean_spdx_expr(raw: str) -> str:
    expr = (raw or "").strip()
    for term in _TAG_TERMINATORS:
        if term in expr:
            expr = expr.split(term)[0]
    # keep only characters that can appear in an SPDX expression
    expr = re.sub(r"[^A-Za-z0-9.\-+()/ ]+", " ", expr).strip()
    # collapse internal whitespace
    return re.sub(r"\s{2,}", " ", expr)


# ── nomos: distinctive per-license phrase signatures ─────────────────────────
# (spdx_id, [required phrases], [excluded phrases]) — first signature whose
# required phrases are ALL present (and no excluded phrase present) wins.
# Order matters: more specific / narrower licenses come first.
_SIGNATURES: List[Tuple[str, List[str], List[str]]] = [
    # ── Apache ────────────────────────────────────────────────────────────────
    ("Apache-2.0", ["apache license", "version 2.0"], []),
    ("Apache-2.0", ["www.apache.org/licenses/license-2.0"], []),
    ("Apache-1.1", ["apache software license", "version 1.1"], []),
    # ── MIT / ISC ─────────────────────────────────────────────────────────────
    ("MIT", ["permission is hereby granted, free of charge, to any person obtaining a copy"], []),
    ("ISC", ["permission to use, copy, modify, and/or distribute this software for any purpose"], []),
    # ── BSD ───────────────────────────────────────────────────────────────────
    ("BSD-4-Clause", ["redistribution and use in source and binary forms",
                      "neither the name", "advertising materials"], []),
    ("BSD-3-Clause", ["redistribution and use in source and binary forms",
                      "neither the name"], ["advertising materials"]),
    ("BSD-2-Clause", ["redistribution and use in source and binary forms"], ["neither the name"]),
    # ── MPL ───────────────────────────────────────────────────────────────────
    ("MPL-2.0", ["mozilla public license", "version 2.0"], []),
    ("MPL-2.0", ["mozilla.org/mpl/2.0"], []),
    ("MPL-1.1", ["mozilla public license", "version 1.1"], []),
    # ── GPL family (order: AGPL > LGPL > GPL, most specific first) ───────────
    ("AGPL-3.0-only",   ["gnu affero general public license", "version 3"], []),
    ("AGPL-3.0-only",   ["gnu affero general public license"], []),
    ("LGPL-3.0-only",   ["gnu lesser general public license", "version 3"], []),
    ("LGPL-2.1-only",   ["gnu lesser general public license", "version 2.1"], []),
    ("LGPL-2.0-only",   ["gnu lesser general public license", "version 2"], []),
    ("LGPL-2.1-only",   ["gnu lesser general public license"], ["version 3", "version 2\n"]),
    ("GPL-3.0-or-later", ["gnu general public license", "version 3", "any later version"], ["lesser", "affero"]),
    ("GPL-2.0-or-later", ["gnu general public license", "version 2", "any later version"], ["lesser", "affero", "version 3"]),
    ("GPL-3.0-only",    ["gnu general public license", "version 3"], ["lesser", "affero", "any later"]),
    ("GPL-2.0-only",    ["gnu general public license", "version 2"], ["lesser", "affero", "any later"]),
    ("GPL-2.0-only",    ["gnu general public license"], ["lesser", "affero", "any later"]),
    # ── SSPL (MongoDB/Elasticsearch — stronger than AGPL) ────────────────────
    ("SSPL-1.0", ["server side public license"], []),
    ("SSPL-1.0", ["sspl", "section 13"], []),
    # ── Eclipse / EPL ─────────────────────────────────────────────────────────
    ("EPL-2.0", ["eclipse public license", "version 2.0"], []),
    ("EPL-1.0", ["eclipse public license", "version 1.0"], []),
    ("EPL-1.0", ["eclipse public license"], ["version 2"]),
    # ── EUPL (European Union Public Licence) ─────────────────────────────────
    ("EUPL-1.2", ["european union public licence", "v. 1.2"], []),
    ("EUPL-1.2", ["european union public licence", "version 1.2"], []),
    ("EUPL-1.1", ["european union public licence", "v. 1.1"], []),
    ("EUPL-1.1", ["european union public licence"], ["1.2"]),
    # ── CDDL (Sun/Oracle OpenSolaris) ────────────────────────────────────────
    ("CDDL-1.0", ["common development and distribution license", "version 1.0"], []),
    ("CDDL-1.0", ["common development and distribution license"], ["1.1"]),
    ("CDDL-1.1", ["common development and distribution license", "version 1.1"], []),
    # ── Creative Commons (ShareAlike = copyleft for content) ─────────────────
    # More-specific variants (NC, ND, SA) must come BEFORE the generic CC-BY-x.x
    # entries so the ordered first-match walk picks the narrower license.
    ("CC-BY-NC-4.0",   ["creative commons attribution-noncommercial 4.0"], []),
    ("CC-BY-NC-4.0",   ["creative commons", "noncommercial", "4.0"], ["sharealike"]),
    ("CC-BY-NC-3.0",   ["creative commons attribution-noncommercial 3.0"], []),
    ("CC-BY-NC-SA-4.0", ["creative commons", "noncommercial", "sharealike", "4.0"], []),
    ("CC-BY-NC-SA-3.0", ["creative commons", "noncommercial", "sharealike", "3.0"], []),
    ("CC-BY-ND-4.0",   ["creative commons attribution-noderivatives 4.0"], []),
    ("CC-BY-ND-4.0",   ["creative commons", "noderivatives", "4.0"], []),
    ("CC-BY-SA-4.0",   ["creative commons attribution-sharealike 4.0"], []),
    ("CC-BY-SA-4.0",   ["creative commons", "sharealike", "4.0"], ["noncommercial"]),
    ("CC-BY-SA-3.0",   ["creative commons attribution-sharealike 3.0"], []),
    # Generic CC-BY: exclude NC/ND/SA variants so they don't shadow the above.
    ("CC-BY-4.0",      ["creative commons attribution 4.0 international"], ["noncommercial", "noderivatives", "sharealike"]),
    ("CC-BY-4.0",      ["creative commons attribution", "4.0 international"], ["noncommercial", "noderivatives", "sharealike"]),
    ("CC-BY-3.0",      ["creative commons attribution 3.0"], ["sharealike", "noncommercial", "noderivatives"]),
    ("CC0-1.0",        ["cc0 1.0 universal"], []),
    ("CC0-1.0",        ["creative commons zero"], []),
    # ── CERN Open Hardware Licence (automotive ECU hardware components) ────────
    ("CERN-OHL-S-2.0", ["cern open hardware licence version 2", "strongly reciprocal"], []),
    ("CERN-OHL-S-2.0", ["cern-ohl-s"], []),
    ("CERN-OHL-W-2.0", ["cern open hardware licence version 2", "weakly reciprocal"], []),
    ("CERN-OHL-W-2.0", ["cern-ohl-w"], []),
    ("CERN-OHL-P-2.0", ["cern open hardware licence version 2", "permissive"], []),
    ("CERN-OHL-P-2.0", ["cern-ohl-p"], []),
    ("CERN-OHL-S-2.0", ["cern open hardware licence", "strongly reciprocal"], []),
    # ── TAPR Open Hardware License ────────────────────────────────────────────
    ("TAPR-OHL-1.0", ["tapr open hardware license"], []),
    ("TAPR-OHL-1.0", ["tapr-ohl"], []),
    # ── Open Software License (strong copyleft, rarely seen) ────────────────
    ("OSL-3.0", ["open software license", "version 3.0"], []),
    ("OSL-3.0", ["open software license 3.0"], []),
    ("OSL-2.1", ["open software license", "version 2.1"], []),
    ("OSL-2.0", ["open software license", "version 2.0"], []),
    # ── Educational Community License ─────────────────────────────────────────
    ("ECL-2.0", ["educational community license", "version 2.0"], []),
    ("ECL-1.0", ["educational community license", "version 1.0"], []),
    # ── EUPL ─────────────────────────────────────────────────────────────────
    # (also covered above; add phrase for plain text notices in European software)
    ("EUPL-1.2", ["licensed under the eupl, version 1.2"], []),
    ("EUPL-1.1", ["licensed under the eupl, version 1.1"], []),
    # ── Classpath-exception-2.0 WITH GPL-2.0 (common in Java) ────────────────
    ("GPL-2.0-only WITH Classpath-exception-2.0",
     ["gnu general public license", "classpath exception"], ["version 3", "lesser"]),
    # ── BSL-1.1 (MariaDB Business Source License) ────────────────────────────
    ("BSL-1.1", ["business source license", "1.1"], []),
    ("BSL-1.1", ["mariadb business source license"], []),
    # ── PolyForm ─────────────────────────────────────────────────────────────
    ("PolyForm-NonCommercial-1.0.0", ["polyform noncommercial license", "1.0.0"], []),
    ("PolyForm-Strict-1.0.0",        ["polyform strict license"], []),
    # ── Other common open-source ──────────────────────────────────────────────
    ("Unlicense",   ["this is free and unencumbered software released into the public domain"], []),
    ("BSL-1.0",     ["boost software license"], []),
    ("Zlib",        ["altered source versions must be plainly marked as such"], []),
    ("Artistic-2.0", ["artistic license, version 2.0"], []),
    ("Artistic-2.0", ["artistic license 2.0"], []),
    ("Python-2.0",  ["python software foundation license"], []),
    ("PSF-2.0",     ["psf license agreement"], []),
    ("ISC",         ["isc license", "permission to use, copy, modify"], []),
    ("OFL-1.1",     ["sil open font license", "version 1.1"], []),
    # ── Proprietary / All Rights Reserved ────────────────────────────────────
    ("LicenseRef-Proprietary", ["all rights reserved", "proprietary and confidential"], []),
    ("LicenseRef-Proprietary", ["confidential and proprietary"], []),
]


def _phrase_re(phrase: str) -> "re.Pattern":
    toks = phrase.split()
    return re.compile(r"\s+".join(re.escape(t) for t in toks), re.IGNORECASE)


# compile once
_SIG_COMPILED = [
    (spdx, [_phrase_re(p) for p in req], [_phrase_re(p) for p in exc])
    for spdx, req, exc in _SIGNATURES
]

# ── copyright: (c) holder extraction ─────────────────────────────────────────
_COPYRIGHT_RE = re.compile(
    r"copyright\s*(?:\(c\)|©|&copy;)?\s*"
    r"((?:\d{4}(?:\s*[-,]\s*\d{4})*)?\s*(?:\(c\)|©)?\s*[^\n\r]{0,120})",
    re.IGNORECASE)
_COPYRIGHT_NOISE = re.compile(r"copyright\s+(holder|owner|notice|law|and\b|\(c\)\s*$)", re.IGNORECASE)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _detect_notice(text: str) -> Optional[Tuple[str, int, str]]:
    """Return (spdx_id, line, snippet) for the first matching license signature."""
    for spdx, reqs, excs in _SIG_COMPILED:
        m0 = reqs[0].search(text)
        if not m0:
            continue
        if any(r.search(text) is None for r in reqs[1:]):
            continue
        if any(e.search(text) is not None for e in excs):
            continue
        snippet = re.sub(r"\s+", " ", m0.group(0)).strip()[:160]
        return spdx, _line_of(text, m0.start()), snippet
    return None


def _extract_copyrights(text: str, path: str, cap: int = 8) -> List[Dict[str, Any]]:
    out, seen = [], set()
    for m in _COPYRIGHT_RE.finditer(text):
        holder = re.sub(r"\s+", " ", m.group(1)).strip(" .,-\t")
        holder = re.sub(r"\s*(all rights reserved|<.*?>|\(.*?@.*?\)).*$", "", holder,
                        flags=re.IGNORECASE).strip(" .,-")
        if len(holder) < 3 or _COPYRIGHT_NOISE.search(m.group(0)):
            continue
        key = holder.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append({"holder": holder, "file": path, "line": _line_of(text, m.start()),
                    "text": re.sub(r"\s+", " ", m.group(0)).strip()[:160]})
        if len(out) >= cap:
            break
    return out


def scan_file(abspath: str, relpath: str) -> Dict[str, Any]:
    """Scan a single file. Returns {findings, copyrights} (possibly empty)."""
    findings: List[Dict[str, Any]] = []
    is_license_doc = bool(_LICENSE_NAME_RE.match(os.path.basename(relpath)))
    cap = MAX_BYTES_LICENSE if is_license_doc else MAX_BYTES_SOURCE
    try:
        with open(abspath, "rb") as f:
            raw = f.read(cap)
    except (OSError, IOError):
        return {"findings": [], "copyrights": []}
    if _is_binary(raw):
        return {"findings": [], "copyrights": []}
    text = raw.decode("utf-8", errors="replace")

    # 1) ojo — SPDX tags (may be several, e.g. multi-license file)
    seen_tags = set()
    for m in _SPDX_TAG_RE.finditer(text):
        expr = _clean_spdx_expr(m.group(1))
        if not expr or expr.lower() in seen_tags:
            continue
        seen_tags.add(expr.lower())
        findings.append({"file": relpath, "line": _line_of(text, m.start()),
                         "kind": "spdx-tag", "license": expr, "confidence": "exact",
                         "evidence": f"SPDX-License-Identifier: {expr}"})

    # 2) nomos — license notice text (only if no SPDX tag already nailed it,
    #    OR this is a LICENSE/COPYING document where the full text is expected)
    if is_license_doc or not seen_tags:
        notice = _detect_notice(text)
        if notice:
            spdx, line, snip = notice
            # don't double-report the same license the SPDX tag already gave
            if spdx.lower() not in seen_tags:
                findings.append({"file": relpath, "line": line,
                                 "kind": "license-file" if is_license_doc else "license-text",
                                 "license": spdx,
                                 "confidence": "high" if is_license_doc else "medium",
                                 "evidence": snip})

    copyrights = _extract_copyrights(text, relpath)
    return {"findings": findings, "copyrights": copyrights}


def scan_tree(root: str, max_files: int = MAX_FILES,
              skip_dirs: Optional[set] = None) -> Dict[str, Any]:
    """Walk `root`, scan every text file, and aggregate license evidence.

    Returns an evidence-grounded license picture: every reported license traces
    to at least one file:line. Returns honest counters (files scanned, skipped,
    truncated) — never a fabricated 'clean'.
    """
    skip = _SKIP_DIRS if skip_dirs is None else skip_dirs
    findings: List[Dict[str, Any]] = []
    copyrights: List[Dict[str, Any]] = []
    scanned = considered = 0
    skipped_dirs: set = set()
    truncated = False

    for dirpath, dirnames, filenames in os.walk(root):
        pruned = [d for d in dirnames if d in skip or d.startswith(".sca_workspace")]
        for d in pruned:
            skipped_dirs.add(d)
        dirnames[:] = [d for d in dirnames if d not in skip]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in _BINARY_EXT and not _LICENSE_NAME_RE.match(fn):
                continue
            considered += 1
            if scanned >= max_files:
                truncated = True
                continue
            ap = os.path.join(dirpath, fn)
            rp = os.path.relpath(ap, root).replace("\\", "/")
            res = scan_file(ap, rp)
            scanned += 1
            if res["findings"] or res["copyrights"]:
                findings.extend(res["findings"])
                copyrights.extend(res["copyrights"])

    return _aggregate(findings, copyrights, scanned, considered,
                      sorted(skipped_dirs), truncated)


def _aggregate(findings, copyrights, scanned, considered, skipped_dirs, truncated) -> Dict[str, Any]:
    # distinct SPDX ids -> occurrences + representative files
    licenses: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        lic = f["license"]
        e = licenses.setdefault(lic, {"license": lic, "category": classify_license(lic),
                                      "count": 0, "files": [], "best_confidence": "medium"})
        e["count"] += 1
        if len(e["files"]) < 12 and f["file"] not in e["files"]:
            e["files"].append(f["file"])
        if _CONF_RANK.get(f["confidence"], 0) > _CONF_RANK.get(e["best_confidence"], 0):
            e["best_confidence"] = f["confidence"]

    license_files = [
        {"file": f["file"], "license": f["license"], "line": f["line"]}
        for f in findings if f["kind"] == "license-file"
    ]

    # reuse the policy engine: treat each detected license as a pseudo-component
    pseudo = [{"name": f"{f['license']} @ {f['file']}", "version": "",
               "license": f["license"]} for f in findings if f["kind"] != "spdx-tag"] \
        or [{"name": lic, "version": "", "license": lic} for lic in licenses]
    policy = analyze_licenses(pseudo) if licenses else {
        "summary": {"category_counts": {}, "highest_severity": "NONE", "conflict_count": 0},
        "findings": [], "classified": []}

    # dedup copyright holders across the tree
    holders: Dict[str, Dict[str, Any]] = {}
    for c in copyrights:
        holders.setdefault(c["holder"], c)

    lic_list = sorted(licenses.values(),
                      key=lambda e: (-e["count"], e["license"]))
    return {
        "files_scanned": scanned,
        "files_considered": considered,
        "truncated": truncated,
        "skipped_dirs": skipped_dirs,
        "findings": findings,
        "licenses": lic_list,
        "distinct_licenses": [e["license"] for e in lic_list],
        "spdx_expression": " AND ".join(sorted(licenses.keys())) if licenses else "",
        "license_files": license_files,
        "copyrights": list(holders.values())[:50],
        "policy": policy["summary"],
        "policy_findings": policy["findings"],
        "notes": _notes(scanned, considered, truncated, skipped_dirs, bool(licenses)),
    }


_CONF_RANK = {"exact": 3, "high": 2, "medium": 1}


def _notes(scanned, considered, truncated, skipped_dirs, any_license) -> List[str]:
    notes = []
    if truncated:
        notes.append(f"Scan capped at {scanned} files ({considered} text files present) — "
                     f"license coverage is partial for this tree.")
    if skipped_dirs:
        notes.append("Skipped for performance (not scanned): " + ", ".join(skipped_dirs))
    if not any_license:
        notes.append("No license text or SPDX tag was detected in the scanned files "
                     "(this is reported honestly, not treated as 'no obligations').")
    return notes
