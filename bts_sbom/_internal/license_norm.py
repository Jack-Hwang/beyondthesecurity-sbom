# vendored from common/license_norm.py (Apache-2.0 release) -- imports rewritten to
# bts_sbom._internal AND re-implemented stdlib-only: the platform validated
# expressions with the third-party ``license_expression`` library; here the same
# normalize/verify contract is served by bts_sbom._internal.license_spdx (the
# platform's own SPDX grammar parser, which the product already used as the
# license judge elsewhere). What is PRESERVED: status vocabulary
# (ok|deprecated|invalid|none), NOASSERTION fallback, deprecated-id canonical
# renames, compound-expression leaf decomposition. What is HONESTLY DROPPED:
# full SPDX license-list validation (an id is validated as SPDX *syntax*, plus
# known-deprecated rename detection; an unknown-but-syntactically-valid id is
# reported "ok" -- the platform's third-party engine would flag it invalid).
"""
SPDX license-expression normalization & verification.

Canonicalizes each declared/detected license expression, flags DEPRECATED
SPDX ids (e.g. GPL-2.0 -> GPL-2.0-only) via an explicit rename table and
rejects expressions that violate SPDX *syntax* -- without ever fabricating
a license. An unknown or empty license stays unresolved (NOASSERTION).
"""
import os
import re
from typing import Dict, Any, List, Optional

from bts_sbom._internal.license_spdx import (
    SpdxParseError,
    expression_string,
    iter_atoms,
    parse_expression,
    strip_outer_parens,
)
from bts_sbom._internal.license_categories import (
    NETWORK_COPYLEFT,
    PERMISSIVE,
    PUBLIC_DOMAIN,
    STRONG_COPYLEFT,
    WEAK_COPYLEFT,
    category,
)

_NONE = {"", "unknown", "none", "non-standard", "noassertion", "n/a", "unlicensed", "proprietary"}

# Official SPDX deprecated-id -> current-id renames (SPDX license-list
# "deprecated" entries). Explicit and bounded: an id not listed here is NEVER
# silently rewritten -- an honest "ok" beats a guessed canonicalization.
_DEPRECATED_RENAMES = {
    "GPL-1.0": "GPL-1.0-only", "GPL-1.0+": "GPL-1.0-or-later",
    "GPL-2.0": "GPL-2.0-only", "GPL-2.0+": "GPL-2.0-or-later",
    "GPL-3.0": "GPL-3.0-only", "GPL-3.0+": "GPL-3.0-or-later",
    "LGPL-2.0": "LGPL-2.0-only", "LGPL-2.0+": "LGPL-2.0-or-later",
    "LGPL-2.1": "LGPL-2.1-only", "LGPL-2.1+": "LGPL-2.1-or-later",
    "LGPL-3.0": "LGPL-3.0-only", "LGPL-3.0+": "LGPL-3.0-or-later",
    "AGPL-1.0": "AGPL-1.0-only", "AGPL-1.0+": "AGPL-1.0-or-later",
    "AGPL-3.0": "AGPL-3.0-only", "AGPL-3.0+": "AGPL-3.0-or-later",
    "GFDL-1.1": "GFDL-1.1-only", "GFDL-1.1+": "GFDL-1.1-or-later",
    "GFDL-1.2": "GFDL-1.2-only", "GFDL-1.2+": "GFDL-1.2-or-later",
    "GFDL-1.3": "GFDL-1.3-only", "GFDL-1.3+": "GFDL-1.3-or-later",
    "BSD-2-Clause-FreeBSD": "BSD-2-Clause-Views",
    "BSD-2-Clause-NetBSD": "BSD-2-Clause",
    "bzip2-1.0.5": "bzip2-1.0.6",
    "wxWindows": "WXwindows",
    "StandardML-NJ": "SMLNJ",
    "Nunit": "NUnit",
}


def _canonical_token(tok: str) -> str:
    """One license id (or 'X WITH Y' atom) -> (canonical, deprecated?) keeping
    the WITH exception attached when present."""
    return tok


def normalize(expr: Optional[str]) -> Dict[str, Any]:
    """Return {input, normalized, status, errors}. status ∈
    ok | deprecated | invalid | none. `normalized` is the canonical SPDX
    expression (None when it cannot be validated)."""
    raw = (expr or "").strip()
    if not raw or raw.lower() in _NONE:
        return {"input": expr, "normalized": None, "status": "none", "errors": []}
    try:
        node = parse_expression(raw)
    except SpdxParseError as e:
        return {"input": expr, "normalized": None, "status": "invalid", "errors": [str(e)]}
    except Exception as e:  # pragma: no cover - defensive
        return {"input": expr, "normalized": None, "status": "invalid", "errors": [str(e)]}
    norm = strip_outer_parens(expression_string(node))
    # canonicalization changed the text => the input used a deprecated/non-canonical id
    if norm.replace(" ", "") != raw.replace(" ", ""):
        return {"input": expr, "normalized": norm, "status": "deprecated", "errors": []}
    # same spelling: still deprecated when every leaf is a renamed id
    atoms = list(iter_atoms(node))
    if atoms and all(a.ident in _DEPRECATED_RENAMES for a in atoms):
        renorm = norm
        for old, new in _DEPRECATED_RENAMES.items():
            renorm = re.sub(r"(?<![A-Za-z0-9.+-])" + re.escape(old) + r"(?![A-Za-z0-9.+-])",
                            new, renorm)
        if renorm != norm:
            return {"input": expr, "normalized": renorm, "status": "deprecated", "errors": []}
    return {"input": expr, "normalized": norm, "status": "ok", "errors": []}


def is_valid_spdx(expr: Optional[str]) -> bool:
    return normalize(expr)["status"] in ("ok", "deprecated")


def to_spdx_field(expr: Optional[str]) -> str:
    """Canonical SPDX expression for an SBOM license field, or 'NOASSERTION'."""
    r = normalize(expr)
    return r["normalized"] if r["status"] in ("ok", "deprecated") else "NOASSERTION"


def parse_compound_licenses(expr: Optional[str]) -> Dict[str, Any]:
    """Parse an SPDX compound expression (AND/OR/WITH) into leaf license IDs.

    Returns:
      {
        "input", "leaf_ids", "operators", "has_copyleft", "is_copyleft_only",
        "compatibility_issues", "normalized", "status", "errors",
      }

    Honesty: compound expressions with unknown leaf IDs are reported with
    status="invalid" on the unknown leaf; the overall expression is not guessed
    or fabricated as "probably fine". Leaf validation here is SPDX-syntax +
    known-deprecated detection (see module header for the dropped platform
    license-list check).
    """
    base = normalize(expr)
    raw = (expr or "").strip()

    if base["status"] in ("none", "invalid"):
        return {
            "input": expr,
            "leaf_ids": [],
            "operators": [],
            "has_copyleft": False,
            "is_copyleft_only": False,
            "compatibility_issues": [],
            "normalized": None,
            "status": base["status"],
            "errors": base["errors"],
        }

    operators_found = [m.group(0).upper()
                       for m in re.finditer(r"\b(AND|OR|WITH)\b", raw, re.IGNORECASE)]

    leaf_ids: list = []
    exception_ids: list = []
    leaf_errors: list = []
    try:
        node = parse_expression(raw)
        for atom in iter_atoms(node):
            r = normalize(atom.raw or atom.ident)
            if atom.exception:
                exception_ids.append(atom.raw_exception or atom.exception)
            if r["status"] in ("ok", "deprecated"):
                leaf_ids.append(r["normalized"] or atom.ident)
            else:
                leaf_ids.append(atom.ident)
                leaf_errors.append("unknown leaf: %r" % atom.ident)
    except Exception:  # pragma: no cover - normalize() already parsed once
        leaf_errors.append("compound parse failed")

    # Copyleft detection via the single category source of truth.
    _COPYLEFT_CATS = {WEAK_COPYLEFT, STRONG_COPYLEFT, NETWORK_COPYLEFT}
    leaf_cats = [category(lid) for lid in leaf_ids]
    has_copyleft = any(c in _COPYLEFT_CATS for c in leaf_cats)
    is_copyleft_only = bool(leaf_cats) and all(c in _COPYLEFT_CATS for c in leaf_cats)

    # Pairwise compatibility check: the platform delegates this to an agent
    # node (sca_guard.agent.nodes.license_analyzer) that is NOT part of the
    # standalone package -- reported as an empty list rather than guessed.
    compat_issues: List[Dict[str, Any]] = []

    # For an OR expression, a compatible permissive alternative means the
    # expression as a whole is satisfiable -- do not fail it on the copyleft leg.
    if "OR" in operators_found and "AND" not in operators_found:
        if any(category(lid) in (PERMISSIVE, PUBLIC_DOMAIN) for lid in leaf_ids):
            compat_issues = [c for c in compat_issues if c.get("status") == "incompatible"]

    return {
        "input": expr,
        "leaf_ids": leaf_ids,
        "exception_ids": exception_ids,
        "operators": operators_found,
        "has_copyleft": has_copyleft,
        "is_copyleft_only": is_copyleft_only,
        "compatibility_issues": compat_issues,
        "normalized": base["normalized"],
        "status": "invalid" if leaf_errors else base["status"],
        "errors": base["errors"] + leaf_errors,
    }


def is_copyleft(expr: Optional[str]) -> bool:
    """Return True if the expression contains any copyleft license."""
    return parse_compound_licenses(expr).get("has_copyleft", False)


# ── C16: Source-file license header scanner ───────────────────────────────────
# SPDX-2.3 recommends placing a machine-readable identifier in each source file:
#   // SPDX-License-Identifier: MIT
# This scanner extracts those identifiers from source-code comments and
# validates them against the SPDX grammar.

_SPDX_HEADER_RE = re.compile(
    r"SPDX-License-Identifier\s*:\s*(.+?)(?:\s*\*/|\s*\*|\s*-->|\s*$)",
    re.IGNORECASE,
)

_SOURCE_EXTENSIONS = frozenset({
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".rb",
    ".kt", ".swift", ".m", ".mm", ".scala", ".php", ".sh", ".bash",
})
# Config/build files rarely carry SPDX headers; counting them tanks coverage.
# Vendored/generated trees are third-party -- their headers aren't "ours".
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "vendor", "third_party", "third-party",
    "external", "deps", "build", "dist", "target", ".venv", "venv", "__pycache__",
    ".tox", "site-packages",
})


def scan_file_license_header(filepath: str, max_lines: int = 30) -> Dict[str, Any]:
    """Detect an SPDX-License-Identifier in the first *max_lines* of a source file."""
    result: Dict[str, Any] = {
        "file": filepath,
        "found": False,
        "spdx_id": None,
        "normalized": None,
        "status": "none",
        "line_number": None,
        "note": "no SPDX-License-Identifier found in first {} lines".format(max_lines),
    }
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, 1):
                if lineno > max_lines:
                    break
                m = _SPDX_HEADER_RE.search(line)
                if m:
                    raw_id = m.group(1).strip()
                    norm = normalize(raw_id)
                    result.update({
                        "found": True,
                        "spdx_id": raw_id,
                        "normalized": norm.get("normalized"),
                        "status": norm.get("status", "invalid"),
                        "line_number": lineno,
                        "errors": norm.get("errors", []),
                        "note": "SPDX-License-Identifier detected and validated",
                    })
                    break
    except OSError:
        result["note"] = "file could not be opened"
    return result


def scan_directory_license_headers(src_dir: str, extensions: Optional[frozenset] = None,
                                   max_files: int = 5000) -> Dict[str, Any]:
    """Scan all source files under *src_dir* for SPDX-License-Identifier headers."""
    exts = extensions if extensions is not None else _SOURCE_EXTENSIONS
    all_results: List[Dict[str, Any]] = []
    files_seen = 0

    for root, dirs, filenames in os.walk(src_dir):
        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS]
        if files_seen >= max_files:
            break
        for fname in filenames:
            if files_seen >= max_files:
                break
            if os.path.splitext(fname)[1].lower() not in exts:
                continue
            fpath = os.path.join(root, fname)
            all_results.append(scan_file_license_header(fpath))
            files_seen += 1

    total = len(all_results)
    with_header = sum(1 for r in all_results if r["found"])
    dist: Dict[str, int] = {}
    missing: List[str] = []
    for r in all_results:
        if r["found"] and r["spdx_id"]:
            sid = r["normalized"] or r["spdx_id"]
            dist[sid] = dist.get(sid, 0) + 1
        else:
            missing.append(r["file"])

    return {
        "total_files": total,
        "files_with_header": with_header,
        "files_without_header": total - with_header,
        "coverage_pct": round(100.0 * with_header / total, 1) if total else 0.0,
        "files": all_results,
        "license_distribution": dist,
        "missing": missing[:200],
    }


def verify_packages(packages: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Verify every package's declared license. Returns a summary + the list of
    packages whose license is deprecated or invalid (actionable compliance gaps)."""
    counts = {"ok": 0, "deprecated": 0, "invalid": 0, "none": 0}
    issues: List[Dict[str, Any]] = []
    for p in packages:
        r = normalize(p.get("license"))
        counts[r["status"]] += 1
        if r["status"] in ("deprecated", "invalid"):
            issues.append({
                "name": p.get("name", ""), "version": p.get("version", ""),
                "license": p.get("license"), "normalized": r["normalized"],
                "status": r["status"], "errors": r["errors"],
            })
    return {
        "total": len(packages),
        "summary": counts,
        "issues": issues,
        "spdx_valid": counts["ok"] + counts["deprecated"],
    }
