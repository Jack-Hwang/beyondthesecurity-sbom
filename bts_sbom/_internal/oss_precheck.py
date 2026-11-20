"""REUSE-style copyright/license declaration precheck (a clean-room re-implementation of the FOSSLight Prechecker's
publicly documented behaviour - lint / add / convert / download modes - NOT a port of its GPL-3.0 source, which was
never read, opened or searched; see the public REUSE Specification at https://reuse.software/spec/ and the Debian
machine-readable copyright format (DEP-5) for the file formats this module understands).

Four modes:
  lint     - checks that every (non-excluded) source file carries BOTH a copyright and a license declaration, either
             in the file's own header (``SPDX-FileCopyrightText`` / ``SPDX-License-Identifier``), in a sidecar
             ``<file>.license``, or via a covering ``.reuse/dep5`` (DEP-5) / ``REUSE.toml`` annotation; and that every
             license id used has its text under ``LICENSES/<id>.txt``.
  add      - inserts a standard SPDX header (in the right comment style for the file) into files that lack one.
  convert  - reads sbom-info.yaml / oss-pkg-info.yaml files below a path into an OssReport.
  download - fetches missing LICENSES/<id>.txt texts, only through an injected fetcher, only when ``online=True``.

Honesty contract (same as the rest of bts-sbom): a copyright or license this module cannot find in the file, a
sidecar, dep5 or REUSE.toml stays unreported - never guessed. Limits are recorded in the returned ``warnings``,
never silently applied. The analysed tree is UNTRUSTED DATA: files are only ever read (never executed), symlinks are
never followed, and every path built from file content (a license id read out of a tag, a path listed in
sbom-info.yaml) is re-validated against ``root`` before it is used for a filesystem read or write.
"""
from __future__ import annotations

import os
import stat
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from bts_sbom import ossreport
from bts_sbom._internal import oss_common
from bts_sbom.ossreport import OssItem, OssReport

try:
    import tomllib  # Python >= 3.11
except ImportError:  # pragma: no cover - exercised only on Python 3.10
    tomllib = None  # type: ignore[assignment]

MAX_HEADER_FILE_SIZE = 5_000_000       # add_headers: files larger than this are left untouched, not truncated
MAX_LICENSE_TEXT = 1_000_000           # download_licenses: a fetched text is capped, never allowed to grow unbounded

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,80}$")
_SPDX_TEXT_URL = "https://raw.githubusercontent.com/spdx/license-list-data/main/text/%s.txt"

_HDR_COPYRIGHT_RE = re.compile(r"SPDX-FileCopyrightText:\s*(.+)", re.IGNORECASE)
_HDR_LICENSE_RE = re.compile(r"SPDX-License-Identifier:\s*(.+)", re.IGNORECASE)
_COMMENT_TERMINATORS = ("*/", "-->", "#}", "}}", "*)", "--%>", '"""', "'''", "%}")

# lint: files excluded automatically (beyond user excludes / sbom-info.yaml exclude:True blocks)
_EXCLUDED_EXT = {".jar", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".exe", ".dll", ".so", ".dylib",
                 ".zip", ".tar", ".gz", ".json", ".lock"}
_VENV_DIR_NAMES = {"venv", ".venv"}
_NODE_MODULES_DIR = "node_modules"
_SBOM_INFO_NAMES = ("sbom-info.yaml", "oss-pkg-info.yaml")

# add_headers: comment style by extension / exact (case-insensitive) basename
_HASH_EXT = {".py", ".sh", ".rb", ".yaml", ".yml", ".toml", ".cmake"}
_HASH_BASENAMES = {"makefile", "gnumakefile", "cmakelists.txt"}
_SLASH_EXT = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".java", ".js", ".jsx", ".mjs", ".ts", ".tsx",
              ".go", ".rs", ".swift", ".kt", ".kts", ".cs", ".php"}
_BLOCKC_EXT = {".css", ".scss", ".less"}
_BLOCKXML_EXT = {".html", ".htm", ".xml", ".md", ".markdown", ".svg"}
_DASH_EXT = {".sql", ".lua"}
_SEMI_EXT = {".lisp", ".lsp", ".cl", ".el"}


# ===================================================================================================== path safety
def _resolve_in_root(root_abs: str, rel: str) -> Optional[str]:
    """``root_abs``/``rel`` when it stays inside ``root_abs``, is not (and is not reached through) a symlink;
    ``None`` otherwise.  Every path built from untrusted content (a tag value, an sbom-info.yaml path) goes through
    this before it touches the filesystem."""
    full = oss_common.safe_join(root_abs, rel)
    if full is None:
        return None
    if os.path.islink(full):
        return None
    real_root = os.path.realpath(root_abs)
    real_full = os.path.realpath(full)
    if real_full != real_root and not real_full.startswith(real_root + os.sep):
        return None
    return full


# ========================================================================================================== lint
def _clean_tag_value(raw: str) -> str:
    v = raw.strip()
    for term in _COMMENT_TERMINATORS:
        if term in v:
            v = v.split(term)[0].strip()
    return v


def _header_tags(text: str) -> Tuple[List[str], List[str]]:
    copyrights = [_clean_tag_value(m.group(1)) for m in _HDR_COPYRIGHT_RE.finditer(text)]
    licenses = [_clean_tag_value(m.group(1)) for m in _HDR_LICENSE_RE.finditer(text)]
    return [c for c in copyrights if c], [lic for lic in licenses if lic]


def _exclude_reason(rel: str, include_hidden: bool) -> Optional[str]:
    parts = rel.split("/")
    if parts and parts[0] == "LICENSES":
        return "license text file"
    if os.path.basename(rel) == "REUSE.toml":
        return "REUSE.toml metadata"
    if os.path.basename(rel).lower() in _SBOM_INFO_NAMES:
        return "sbom-info.yaml metadata"
    for p in parts[:-1]:
        if not include_hidden and p.startswith(".") and p not in (".", ".."):
            return "hidden directory"
        low = p.lower()
        if low == _NODE_MODULES_DIR:
            return "node_modules"
        if low in _VENV_DIR_NAMES:
            return "venv"
    name = parts[-1]
    if not include_hidden and name.startswith(".") and not name.lower().endswith(".license"):
        return "hidden file"
    if os.path.splitext(name)[1].lower() in _EXCLUDED_EXT:
        return "binary or generated file"
    return None


def _atoms(expr: str) -> List[str]:
    """Atomic SPDX license ids referenced by one license string (``A AND B`` -> ``[A, B]``); a string that is not a
    valid SPDX expression is returned as a single, literal atom - never silently dropped."""
    from bts_sbom._internal import license_spdx
    expr = (expr or "").strip()
    if not expr:
        return []
    try:
        node = license_spdx.parse_expression(expr)
    except Exception:
        return [expr]
    out: List[str] = []
    for a in license_spdx.iter_atoms(node):
        ident = a.display()          # keeps "X WITH exception": the exception is part of the atomic choice
        if ident and ident not in out:
            out.append(ident)
    return out


def _text_ids(atom: str) -> List[str]:
    """Ids whose ``LICENSES/<id>.txt`` must exist for one atom: the license and, for ``X WITH Y``, the exception
    too (REUSE requires a text for both)."""
    parts = re.split(r"\s+WITH\s+", atom.strip(), maxsplit=1, flags=re.IGNORECASE)
    return [p.strip() for p in parts if p.strip()]


# -------------------------------------------------------------------------------------------------- dep5 (DEP-5)
def _parse_dep5(text: str) -> List[Dict[str, Any]]:
    """Tolerant parser for the Debian machine-readable copyright format (DEP-5, a public spec).  Stanzas separated
    by a blank line; ``Files:``/``Copyright:``/``License:`` fields, with indented continuation lines folded in."""
    stanzas: List[Dict[str, str]] = []
    cur: Dict[str, str] = {}
    key: Optional[str] = None
    for raw_line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not raw_line.strip():
            if cur:
                stanzas.append(cur)
            cur, key = {}, None
            continue
        if raw_line[:1] in " \t" and key:
            cur[key] = cur.get(key, "") + "\n" + raw_line.strip()
            continue
        if ":" in raw_line:
            k, v = raw_line.split(":", 1)
            key = k.strip()
            cur[key] = v.strip()
        # a malformed line with no ':' and no leading whitespace is ignored (tolerant parser)
    if cur:
        stanzas.append(cur)
    out: List[Dict[str, Any]] = []
    for st in stanzas:
        if "Files" not in st:
            continue
        out.append({"files": st["Files"].split(),
                    "copyright": st.get("Copyright", "").strip(),
                    "license": st.get("License", "").split("\n", 1)[0].strip()})
    return out


def _load_dep5(root_abs: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    path = _resolve_in_root(root_abs, ".reuse/dep5")
    if path is None or not os.path.isfile(path):
        return [], None
    text = oss_common.read_text(path)
    try:
        return _parse_dep5(text), None
    except Exception as exc:
        return [], "could not parse .reuse/dep5: %s" % exc


# ----------------------------------------------------------------------------------------------------- REUSE.toml
def _toml_scalar_fallback(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return raw[1:-1].replace('\\"', '"')
    if len(raw) >= 2 and raw[0] == "'" and raw[-1] == "'":
        return raw[1:-1]
    return raw


def _toml_list_fallback(raw: str) -> List[str]:
    raw = raw.strip()
    if raw.startswith("["):
        inner = raw[1:raw.rfind("]")] if "]" in raw else raw[1:]
        items = re.findall(r'"((?:[^"\\]|\\.)*)"', inner)
        if not items:
            items = re.findall(r"'([^']*)'", inner)
        return [i.replace('\\"', '"') for i in items]
    v = _toml_scalar_fallback(raw)
    return [v] if v else []


def _parse_reuse_toml_fallback(text: str) -> List[Dict[str, Any]]:
    """Regex-based fallback for Python 3.10 (no ``tomllib``): extracts ``[[annotations]]`` blocks only - good enough
    for the simple ``path = "..."`` / ``SPDX-FileCopyrightText = "..."`` / ``SPDX-License-Identifier = "..."`` shape
    the REUSE spec documents; anything more exotic is not supported (reported as a limitation, never guessed)."""
    out: List[Dict[str, Any]] = []
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    blocks = re.split(r"(?m)^[ \t]*\[\[[ \t]*annotations[ \t]*\]\][ \t]*$", text)
    for block in blocks[1:]:
        m = re.search(r"(?m)^[ \t]*\[", block)
        body = block[:m.start()] if m else block
        path_m = re.search(r'(?m)^[ \t]*path[ \t]*=[ \t]*(.+)$', body)
        cr_m = re.search(r'(?m)^[ \t]*SPDX-FileCopyrightText[ \t]*=[ \t]*(.+)$', body)
        lic_m = re.search(r'(?m)^[ \t]*SPDX-License-Identifier[ \t]*=[ \t]*(.+)$', body)
        paths = _toml_list_fallback(path_m.group(1)) if path_m else []
        if not paths:
            continue
        out.append({"files": paths,
                    "copyright": _toml_scalar_fallback(cr_m.group(1)) if cr_m else "",
                    "license": _toml_scalar_fallback(lic_m.group(1)) if lic_m else ""})
    return out


def _parse_reuse_toml(text: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    warnings: List[str] = []
    data = None
    if tomllib is not None:
        try:
            data = tomllib.loads(text)
        except Exception as exc:
            warnings.append("REUSE.toml: tomllib could not parse it (%s); using the tolerant fallback scan" % exc)
    if data is not None:
        out: List[Dict[str, Any]] = []
        for a in data.get("annotations") or []:
            if not isinstance(a, dict):
                continue
            raw_path = a.get("path")
            paths = [str(p) for p in raw_path] if isinstance(raw_path, list) else (
                [str(raw_path)] if isinstance(raw_path, str) else [])
            if not paths:
                continue
            out.append({"files": paths, "copyright": str(a.get("SPDX-FileCopyrightText") or ""),
                        "license": str(a.get("SPDX-License-Identifier") or "")})
        return out, warnings
    return _parse_reuse_toml_fallback(text), warnings


def _load_reuse_toml(root_abs: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    path = _resolve_in_root(root_abs, "REUSE.toml")
    if path is None or not os.path.isfile(path):
        return [], []
    text = oss_common.read_text(path)
    try:
        return _parse_reuse_toml(text)
    except Exception as exc:
        return [], ["could not parse REUSE.toml: %s" % exc]


def _coverage_for(rel: str, entries: Sequence[Dict[str, Any]]) -> Tuple[str, str]:
    """(copyright, license) a dep5/REUSE.toml entry list declares for ``rel``; the LAST matching entry wins, per
    the DEP-5 precedence rule (REUSE.toml annotations are applied the same way here for simplicity)."""
    cr, lic = "", ""
    for e in entries:
        if any(ossreport.path_matches(p, rel) for p in e["files"]):
            if e.get("copyright"):
                cr = e["copyright"]
            if e.get("license"):
                lic = e["license"]
    return cr, lic


def _run_lint(root: str, excludes: Sequence[str], include_hidden: bool) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    root_abs = os.path.abspath(root)
    warnings: List[str] = []
    stats = oss_common.WalkStats()
    entries = list(oss_common.walk(root_abs, excludes=excludes, stats=stats))
    if stats.truncated:
        warnings.append("file walk truncated at %d files; lint results are partial" % oss_common.MAX_FILES)
    if stats.skipped_symlinks:
        warnings.append("%d symlink(s) were not followed" % len(stats.skipped_symlinks))
    if stats.unreadable_dirs:
        warnings.append("%d director(y/ies) could not be read" % len(stats.unreadable_dirs))

    sbom_info_files = sorted({rel for _, rel in entries if os.path.basename(rel).lower() in _SBOM_INFO_NAMES})
    exclude_patterns: List[str] = []
    for rel in sbom_info_files:
        abspath = _resolve_in_root(root_abs, rel)
        if abspath is None:
            continue
        try:
            blocks = ossreport.load_corrections(abspath)
        except ossreport.CorrectionError as exc:
            warnings.append("%s: %s" % (rel, exc))
            continue
        for b in blocks:
            if b["exclude"]:
                exclude_patterns.extend(b["paths"])

    dep5_entries, dep5_warn = _load_dep5(root_abs)
    if dep5_warn:
        warnings.append(dep5_warn)
    toml_entries, toml_warns = _load_reuse_toml(root_abs)
    warnings.extend(toml_warns)

    excluded_counts: Dict[str, int] = {}
    if stats.skipped_excluded:
        excluded_counts["user excludes"] = stats.skipped_excluded

    missing_copyright: List[str] = []
    missing_license: List[str] = []
    missing_both: List[str] = []
    licenses_count: Dict[str, int] = {}
    files_checked = 0
    details: List[Dict[str, Any]] = []

    for abspath, rel in entries:
        name = os.path.basename(rel)
        if name.lower().endswith(".license"):
            continue
        if exclude_patterns and any(ossreport.path_matches(p, rel) for p in exclude_patterns):
            excluded_counts["excluded by sbom-info.yaml"] = excluded_counts.get("excluded by sbom-info.yaml", 0) + 1
            continue
        reason = _exclude_reason(rel, include_hidden)
        if reason:
            excluded_counts[reason] = excluded_counts.get(reason, 0) + 1
            continue
        peek = oss_common.read_bytes(abspath, limit=8192)
        if b"\x00" in peek:
            excluded_counts["binary content"] = excluded_counts.get("binary content", 0) + 1
            continue

        files_checked += 1
        text = oss_common.read_text(abspath)
        hdr_cr, hdr_lic = _header_tags(text)
        side_cr: List[str] = []
        side_lic: List[str] = []
        side_full = abspath + ".license"
        if os.path.isfile(side_full) and not os.path.islink(side_full):
            side_cr, side_lic = _header_tags(oss_common.read_text(side_full))
        dep5_cr, dep5_lic = _coverage_for(rel, dep5_entries)
        toml_cr, toml_lic = _coverage_for(rel, toml_entries)

        copyrights = hdr_cr + side_cr + ([dep5_cr] if dep5_cr else []) + ([toml_cr] if toml_cr else [])
        lic_exprs = hdr_lic + side_lic + ([dep5_lic] if dep5_lic else []) + ([toml_lic] if toml_lic else [])
        has_copyright, has_license = bool(copyrights), bool(lic_exprs)

        if not has_copyright and not has_license:
            status = "missing_both"
            missing_both.append(rel)
        elif not has_copyright:
            status = "missing_copyright"
            missing_copyright.append(rel)
        elif not has_license:
            status = "missing_license"
            missing_license.append(rel)
        else:
            status = "ok"

        evidence = []
        if hdr_cr or hdr_lic:
            evidence.append("SPDX tag in file header")
        if side_cr or side_lic:
            evidence.append("sidecar .license file")
        if dep5_cr or dep5_lic:
            evidence.append(".reuse/dep5 coverage")
        if toml_cr or toml_lic:
            evidence.append("REUSE.toml coverage")

        atoms: List[str] = []
        for expr in lic_exprs:
            for a in _atoms(expr):
                licenses_count[a] = licenses_count.get(a, 0) + 1
                if a not in atoms:
                    atoms.append(a)

        details.append({"path": rel, "copyright": "; ".join(c for c in copyrights if c), "licenses": atoms,
                        "status": status, "evidence": evidence})

    license_texts_missing: List[str] = []
    needed_text_ids = sorted({tid for atom in licenses_count for tid in _text_ids(atom)})
    for lic_id in needed_text_ids:
        if lic_id.upper() in ("NOASSERTION", "NONE"):
            continue
        p = _resolve_in_root(root_abs, "LICENSES/%s.txt" % lic_id)
        if p is None:
            warnings.append("ignored a license identifier that is not a safe file name: %r" % lic_id)
            continue
        if not os.path.isfile(p):
            license_texts_missing.append(lic_id)

    compliant = not (missing_copyright or missing_license or missing_both or license_texts_missing)
    summary = {
        "compliant": compliant,
        "missing_copyright": sorted(missing_copyright),
        "missing_license": sorted(missing_license),
        "missing_both": sorted(missing_both),
        "licenses": dict(sorted(licenses_count.items())),
        "license_texts_missing": sorted(license_texts_missing),
        "files_checked": files_checked,
        "excluded": excluded_counts,
        "sbom_info_files": sbom_info_files,
        "warnings": warnings,
    }
    return summary, details


def lint(root: str, *, excludes: Sequence[str] = (), include_hidden: bool = False) -> Dict[str, Any]:
    summary, _details = _run_lint(root, excludes, include_hidden)
    return summary


# ========================================================================================================= scan
def scan(root: str, *, excludes: Sequence[str] = ()) -> OssReport:
    root_abs = os.path.abspath(root)
    summary, details = _run_lint(root_abs, excludes, include_hidden=False)
    report = OssReport(info=ossreport.new_info(analyzed_path=root_abs, excluded=list(excludes)))
    for d in details:
        it = OssItem(kind="src", source_path=d["path"], licenses=list(d["licenses"]), copyright=d["copyright"],
                     evidence=list(d["evidence"]) or ["REUSE precheck: no declaration found"])
        if d["status"] != "ok":
            it.comment = "REUSE precheck: %s" % d["status"].replace("_", " ")
            report.warnings.append("%s: %s" % (d["path"], d["status"].replace("_", " ")))
        report.items.append(it)
    report.info["scanners"]["precheck"] = {
        "files_checked": summary["files_checked"],
        "compliant": summary["compliant"],
        "missing_copyright": len(summary["missing_copyright"]),
        "missing_license": len(summary["missing_license"]),
        "missing_both": len(summary["missing_both"]),
        "license_texts_missing": summary["license_texts_missing"],
        "excluded": summary["excluded"],
        "sbom_info_files": summary["sbom_info_files"],
    }
    report.warnings.extend(summary["warnings"])
    return report


# ====================================================================================================== add_headers
def _comment_style_for(rel: str) -> Optional[str]:
    base = os.path.basename(rel)
    if base.lower() in _HASH_BASENAMES:
        return "hash"
    ext = os.path.splitext(base)[1].lower()
    if ext in _HASH_EXT:
        return "hash"
    if ext in _SLASH_EXT:
        return "slash"
    if ext in _BLOCKC_EXT:
        return "block_c"
    if ext in _BLOCKXML_EXT:
        return "block_xml"
    if ext in _DASH_EXT:
        return "dash"
    if ext in _SEMI_EXT:
        return "semi"
    return None


def _newline_style(data: bytes) -> bytes:
    if b"\r\n" in data:
        return b"\r\n"
    if b"\r" in data and b"\n" not in data:
        return b"\r"
    return b"\n"


def _header_block_bytes(style: str, copyright_text: str, license_id: str, download_location: str, nl: bytes) -> bytes:
    tag_lines = ["SPDX-FileCopyrightText: %s" % copyright_text, "SPDX-License-Identifier: %s" % license_id]
    if download_location:
        tag_lines.append("SPDX-PackageDownloadLocation: %s" % download_location)
    if style == "hash":
        body = ["# " + t for t in tag_lines]
    elif style == "slash":
        body = ["// " + t for t in tag_lines]
    elif style == "dash":
        body = ["-- " + t for t in tag_lines]
    elif style == "semi":
        body = [";; " + t for t in tag_lines]
    elif style == "block_c":
        body = ["/*"] + [" * " + t for t in tag_lines] + [" */"]
    elif style == "block_xml":
        body = ["<!--"] + tag_lines + ["-->"]
    else:
        raise ValueError("unknown comment style %r" % style)
    body.append("")
    nl_s = nl.decode("ascii")
    return (nl_s.join(body) + nl_s).encode("utf-8")


class _UnsafePath(Exception):
    pass


def _open_checked(root_abs: str, rel: str, *, write: bool):
    """Open ``root_abs``/``rel`` once, after proving the descriptor really is a regular file inside the root.

    The path check alone is a time-of-check/time-of-use race against an attacker-controlled tree: between the check
    and the open a component can be swapped for a symlink.  So: refuse symlinks at open time where the platform can
    (``O_NOFOLLOW``), then confirm *the opened descriptor* is the very file the path resolves to inside the root
    (``samestat`` on the descriptor vs. the re-resolved path), is a regular file and - for a write - has a single link
    (a hard link could alias a file outside the tree)."""
    full = _resolve_in_root(root_abs, rel)
    if full is None:
        raise _UnsafePath("path escapes root, or is (or is reached through) a symlink")
    flags = (os.O_RDWR if write else os.O_RDONLY) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(full, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise _UnsafePath("not a regular file")
        if write and st.st_nlink > 1:
            raise _UnsafePath("hard-linked file - left untouched")
        again = _resolve_in_root(root_abs, rel)
        if again is None:
            raise _UnsafePath("path changed while it was being opened (symlink or escape)")
        if not os.path.samestat(st, os.stat(again)):
            raise _UnsafePath("path changed while it was being opened")
        return os.fdopen(fd, "r+b" if write else "rb")
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def add_headers(root: str, paths: Sequence[str], *, license: str, copyright: str, download_location: str = "",
                dry_run: bool = True) -> List[Dict[str, Any]]:
    root_abs = os.path.abspath(root)
    results: List[Dict[str, Any]] = []
    for raw_path in paths:
        rel = str(raw_path).replace("\\", "/")
        entry: Dict[str, Any] = {"path": rel, "action": "skipped", "reason": "", "written": False}

        full = _resolve_in_root(root_abs, rel)
        if full is None:
            entry["reason"] = "path escapes root, or is (or is reached through) a symlink"
            results.append(entry)
            continue
        if not os.path.isfile(full):
            entry["reason"] = "not a regular file"
            results.append(entry)
            continue
        try:
            fh = _open_checked(root_abs, rel, write=not dry_run)
        except _UnsafePath as exc:
            entry["reason"] = str(exc)
            results.append(entry)
            continue
        except OSError:
            entry["reason"] = "could not open the file"
            results.append(entry)
            continue
        # From here on every read and the write go through this one descriptor, so a path swapped for a symlink
        # (or a directory swapped for one) between the check and the write cannot redirect the write.
        try:
            size = os.fstat(fh.fileno()).st_size
            if size > MAX_HEADER_FILE_SIZE:
                fh.close()
                entry["reason"] = "file larger than %d bytes - left untouched" % MAX_HEADER_FILE_SIZE
                results.append(entry)
                continue
            raw = fh.read(MAX_HEADER_FILE_SIZE + 1)
        except OSError:
            fh.close()
            entry["reason"] = "could not read the file"
            results.append(entry)
            continue
        if len(raw) > MAX_HEADER_FILE_SIZE or b"\x00" in raw[:8192]:
            fh.close()
            entry["reason"] = "binary file" if len(raw) <= MAX_HEADER_FILE_SIZE else \
                "file larger than %d bytes - left untouched" % MAX_HEADER_FILE_SIZE
            results.append(entry)
            continue

        probe = raw.decode("utf-8", "replace")
        if _HDR_COPYRIGHT_RE.search(probe) and _HDR_LICENSE_RE.search(probe):
            fh.close()
            entry["reason"] = "already declares SPDX tags"
            results.append(entry)
            continue
        sidecar = full + ".license"
        if os.path.isfile(sidecar) and not os.path.islink(sidecar):
            side_probe = oss_common.read_text(sidecar)
            if _HDR_COPYRIGHT_RE.search(side_probe) and _HDR_LICENSE_RE.search(side_probe):
                fh.close()
                entry["reason"] = "already declared via a sidecar .license file"
                results.append(entry)
                continue

        style = _comment_style_for(rel)
        if style is None:
            fh.close()
            entry["reason"] = "no known comment style for this file type"
            results.append(entry)
            continue

        bom, body = (raw[:3], raw[3:]) if raw.startswith(b"\xef\xbb\xbf") else (b"", raw)
        nl = _newline_style(body)
        idx = body.find(nl)
        first_line, remainder = (body, b"") if idx == -1 else (body[:idx + len(nl)], body[idx + len(nl):])
        first_text = first_line.decode("utf-8", "replace")
        if first_text.startswith("#!") or first_text.lstrip().startswith("<?xml"):
            keep, rest = first_line, remainder
        else:
            keep, rest = b"", body

        header_bytes = _header_block_bytes(style, copyright, license, download_location, nl)
        new_bytes = bom + keep + header_bytes + rest

        entry["action"] = "would add" if dry_run else "added"
        entry["style"] = style
        entry["reason"] = ""
        entry["header_preview"] = header_bytes.decode("utf-8", "replace")
        try:
            if not dry_run:
                try:
                    fh.seek(0)
                    fh.write(new_bytes)
                    fh.truncate()
                    fh.flush()
                except OSError:
                    entry["action"] = "skipped"
                    entry["reason"] = "could not write the file"
                    entry.pop("header_preview", None)
                    results.append(entry)
                    continue
                entry["written"] = True
        finally:
            fh.close()
        results.append(entry)
    return results


# ========================================================================================================= convert
def convert(root: str) -> OssReport:
    root_abs = os.path.abspath(root)
    report = OssReport(info=ossreport.new_info(analyzed_path=root_abs))
    stats = oss_common.WalkStats()
    found = [(a, r) for a, r in oss_common.walk(root_abs, stats=stats)
             if os.path.basename(r).lower() in _SBOM_INFO_NAMES]
    if stats.truncated:
        report.warnings.append("file walk truncated at %d files while looking for sbom-info.yaml" % oss_common.MAX_FILES)

    version_blocks = 0
    items_built = 0
    for abspath, rel in found:
        try:
            blocks = ossreport.load_corrections(abspath)
        except ossreport.CorrectionError as exc:
            report.warnings.append("%s: %s" % (rel, exc))
            continue
        for b in blocks:
            version_blocks += 1
            for p in (b["paths"] or [""]):
                report.items.append(OssItem(
                    kind="src", oss_name=b["package"], version=b["version"], licenses=list(b["licenses"]),
                    download_location=b["download"], homepage=b["homepage"], copyright=b["copyright"],
                    source_path=p, exclude=b["exclude"], comment=b["comment"],
                    evidence=["sbom-info.yaml: %s" % rel]))
                items_built += 1

    if not found:
        report.warnings.append("no sbom-info.yaml or oss-pkg-info.yaml file found under %s" % root_abs)
    report.info["scanners"]["precheck_convert"] = {
        "sbom_info_files_found": sorted(r for _, r in found),
        "version_blocks": version_blocks,
        "items": items_built,
    }
    return report


# =================================================================================================== download_licenses
def _default_fetcher(url: str) -> Optional[str]:
    import urllib.request
    if not url.startswith("https://"):
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bts-sbom-oss-precheck"})
        with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 - fixed https host, opt-in only
            return resp.read(MAX_LICENSE_TEXT + 1).decode("utf-8", "replace")
    except Exception:
        return None


def download_licenses(root: str, ids: Sequence[str], *, online: bool = False, fetcher: Any = None) -> Dict[str, List[str]]:
    root_abs = os.path.abspath(root)
    result: Dict[str, List[str]] = {"written": [], "skipped_existing": [], "skipped_offline": [],
                                    "invalid_id": [], "failed": []}
    for raw_id in ids:
        rid = str(raw_id).strip()
        if not _ID_RE.match(rid):
            result["invalid_id"].append(str(raw_id))
            continue
        dest = _resolve_in_root(root_abs, "LICENSES/%s.txt" % rid)
        if dest is None:
            result["invalid_id"].append(rid)
            continue
        if os.path.exists(dest):
            result["skipped_existing"].append(rid)
            continue
        if not online:
            result["skipped_offline"].append(rid)
            continue
        fn = fetcher or _default_fetcher
        try:
            text = fn(_SPDX_TEXT_URL % rid)
        except Exception:
            text = None
        if not text or not str(text).strip():
            result["failed"].append(rid)
            continue
        text = str(text)
        if len(text) > MAX_LICENSE_TEXT:
            text = text[:MAX_LICENSE_TEXT]
        if not text.endswith("\n"):
            text += "\n"
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        result["written"].append(rid)
    return result
