"""Android scanner: reimplements, from the publicly documented AOSP build-output formats (module-info.json,
MODULE_LICENSE_* marker files, .meta_lic license-metadata, the generated NOTICE file) what the FOSSLight Android
Scanner user guide describes - it needs an EXISTING Android build output (``out/`` + optionally a build log) and
never builds or executes anything itself.

Sources, in the order evidence is taken from them:
  * ``module-info.json``        - produced by the Android build system (``m module-info``): module name -> {path
                                   (source dirs), installed (output paths), class, ...}.  Static JSON, never trusted
                                   blindly: every path inside it is resolved with ``oss_common.safe_join`` and a path
                                   that would escape ``root`` is rejected, not followed.
  * ``MODULE_LICENSE_<NAME>``    - an (often empty) marker file placed directly in the module's own source
                                   directory; the suffix is mapped to an SPDX id only when the mapping is
                                   unambiguous (e.g. ``APACHE2`` -> ``Apache-2.0``); a bare, versionless suffix such
                                   as ``BSD`` or ``GPL`` is kept as raw text - never guessed.
  * ``<module>.meta_lic``        - the module's license-metadata file (protobuf TEXT format); read with a tolerant
                                   line parser that never raises.  ``license_kinds`` values of the form
                                   ``SPDX-license-identifier-<ID>`` are a structural fact (not a guess) and are
                                   decoded directly; anything else is kept as raw text.
  * a binary DB                  - NOT AVAILABLE to this offline reimplementation; "OSS Name" therefore falls back
                                   to the Android module name, which is recorded as such (never invented further).
  * the final NOTICE             - ``NOTICE.html`` / ``NOTICE.xml.gz`` / ``NOTICE.txt`` (checked in that order,
                                   bounded; a ``.gz`` is decompressed with an explicit output-size cap so a gzip bomb
                                   cannot exhaust memory) - used only to decide the four Notice states the FOSSLight
                                   guide documents (ok / ok(NA) / nok / nok(NA)).
"""
from __future__ import annotations

import json
import os
import re
import zlib
from typing import Any, Dict, List, Optional, Sequence, Tuple

from bts_sbom import ossreport
from bts_sbom._internal import oss_common

MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_META_LIC_BYTES = 2 * 1024 * 1024
MAX_NOTICE_COMPRESSED_BYTES = 32 * 1024 * 1024
MAX_NOTICE_DECOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_MODULES = 200_000
MAX_CHECKSUM_BYTES = 200 * 1024 * 1024

# AOSP MODULE_LICENSE_<suffix> -> SPDX id: only the unambiguous (versioned) ones; a bare BSD/GPL/LGPL/MPL/CDDL/
# PUBLIC_DOMAIN/PERMISSIVE/CUSTOM/UNENCUMBERED/NOTICE suffix names a *category*, not one specific license text, so it
# is deliberately left unmapped (kept as raw text in the comment, per the honesty contract).
_MODULE_LICENSE_MAP = {
    "APACHE2": "Apache-2.0", "APACHE_2_0": "Apache-2.0", "APACHE": "Apache-2.0",
    "MIT": "MIT",
    "GPL2": "GPL-2.0-only", "GPL_V2": "GPL-2.0-only", "GPLV2": "GPL-2.0-only",
    "GPL3": "GPL-3.0-only", "GPL_V3": "GPL-3.0-only", "GPLV3": "GPL-3.0-only",
    "LGPL2": "LGPL-2.0-only", "LGPL21": "LGPL-2.1-only", "LGPL2_1": "LGPL-2.1-only", "LGPLV2_1": "LGPL-2.1-only",
    "LGPL3": "LGPL-3.0-only", "LGPLV3": "LGPL-3.0-only",
    "MPL2": "MPL-2.0", "MPL_2_0": "MPL-2.0",
}
_MODULE_LICENSE_RE = re.compile(r"^MODULE_LICENSE_([A-Za-z0-9_.]+)$")
_NOTICE_NAME_RE = re.compile(r"^NOTICE(\.[A-Za-z0-9]+)?$", re.IGNORECASE)
_META_LIC_LINE_RE = re.compile(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(?:"((?:[^"\\]|\\.)*)"|(\S+))')
_SPDX_KIND_PREFIX = "SPDX-license-identifier-"


# ============================================================================================ module-info.json
def _as_list(v: Any) -> List[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if isinstance(x, (str, int, float))]
    if isinstance(v, (str, int, float)):
        return [str(v)]
    return []


def _load_module_info(path: str) -> Dict[str, Any]:
    text = oss_common.read_text(path, limit=MAX_JSON_BYTES)
    try:
        doc = json.loads(text)
    except ValueError:
        return {}
    return doc if isinstance(doc, dict) else {}


# ============================================================================================ .meta_lic (tolerant)
def _parse_meta_lic(text: str) -> Dict[str, List[str]]:
    """Best-effort line parser for the protobuf-TEXT ``.meta_lic`` license-metadata file. Never raises: a line that
    does not match ``key: "value"`` / ``key: value`` is simply ignored."""
    out: Dict[str, List[str]] = {}
    for line in text.splitlines():
        m = _META_LIC_LINE_RE.match(line)
        if not m:
            continue
        key = m.group(1)
        val = m.group(2)
        if val is None:
            val = m.group(3) or ""
        else:
            val = val.replace('\\"', '"').replace("\\\\", "\\")
        out.setdefault(key, []).append(val)
    return out


def _license_from_meta_lic(kv: Dict[str, List[str]]) -> Tuple[str, List[str]]:
    spdx_ids: List[str] = []
    raw_kinds: List[str] = []
    for v in kv.get("license_kinds", []):
        if v.startswith(_SPDX_KIND_PREFIX):
            ident = v[len(_SPDX_KIND_PREFIX):]
            if ident not in spdx_ids:
                spdx_ids.append(ident)
        elif v not in raw_kinds:
            raw_kinds.append(v)
    comments = []
    if len(spdx_ids) > 1:
        comments.append("multiple license_kinds combined with AND from .meta_lic; verify this is not an OR choice")
    if raw_kinds:
        comments.append("non-SPDX license_kinds in .meta_lic kept as found: %s" % ", ".join(sorted(raw_kinds)))
    return (" AND ".join(spdx_ids), comments)


# ============================================================================================ MODULE_LICENSE_* / NOTICE-in-source
def _listdir_no_symlinks(d: str) -> List[str]:
    try:
        names = os.listdir(d)
    except OSError:
        return []
    return [n for n in names if not os.path.islink(os.path.join(d, n))]


def _find_module_license_marker(src_abs: str) -> Optional[str]:
    if not os.path.isdir(src_abs) or os.path.islink(src_abs):
        return None
    for n in sorted(_listdir_no_symlinks(src_abs)):
        m = _MODULE_LICENSE_RE.match(n)
        if m:
            return m.group(1)
    return None


def _has_source_notice_file(src_abs: str) -> bool:
    if not os.path.isdir(src_abs) or os.path.islink(src_abs):
        return False
    return any(_NOTICE_NAME_RE.match(n) for n in _listdir_no_symlinks(src_abs))


# ============================================================================================ final NOTICE (bounded, gzip-bomb safe)
def _gunzip_bounded(path: str, max_compressed: int = MAX_NOTICE_COMPRESSED_BYTES,
                    max_decompressed: int = MAX_NOTICE_DECOMPRESSED_BYTES) -> Tuple[str, bool]:
    raw = oss_common.read_bytes(path, limit=max_compressed + 1)
    truncated = len(raw) > max_compressed
    raw = raw[:max_compressed]
    if not raw:
        return "", truncated
    try:
        d = zlib.decompressobj(zlib.MAX_WBITS | 16)
    except Exception:
        return "", True
    out = bytearray()
    feed = raw
    guard = 0
    try:
        while True:
            remaining = max_decompressed - len(out)
            if remaining <= 0:
                truncated = True
                break
            piece = d.decompress(feed, remaining)
            out.extend(piece)
            feed = d.unconsumed_tail
            guard += 1
            if not feed or guard > 1_000_000:
                break
    except Exception:
        truncated = True
    return bytes(out).decode("utf-8", "replace"), truncated


def _load_final_notice(path: str) -> Tuple[str, bool]:
    low = path.lower()
    if low.endswith(".gz"):
        return _gunzip_bounded(path)
    text = oss_common.read_text(path, limit=MAX_NOTICE_DECOMPRESSED_BYTES)
    return text, len(text) >= MAX_NOTICE_DECOMPRESSED_BYTES


def _in_final_notice(notice_text: str, candidates: Sequence[str]) -> bool:
    if not notice_text:
        return False
    return any(c and c in notice_text for c in candidates)


# ============================================================================================ discovery
def _discover(scan_root: str, excludes: Sequence[str]) -> Dict[str, Any]:
    found: Dict[str, Any] = {"module_info": [], "meta_lic": {}, "notice": {"html": None, "gz": None, "txt": None}}
    stats = oss_common.WalkStats()
    for full, rel in oss_common.walk(scan_root, excludes, stats=stats):
        name = os.path.basename(rel)
        low = name.lower()
        if low == "module-info.json":
            found["module_info"].append(full)
        elif low.endswith(".meta_lic"):
            stem = name[: -len(".meta_lic")]
            found["meta_lic"].setdefault(stem, full)
        elif low == "notice.html" and found["notice"]["html"] is None:
            found["notice"]["html"] = full
        elif low == "notice.xml.gz" and found["notice"]["gz"] is None:
            found["notice"]["gz"] = full
        elif low == "notice.txt" and found["notice"]["txt"] is None:
            found["notice"]["txt"] = full
    return found


# ============================================================================================ packaging_config
def _load_packaging_config(cfg: Any) -> Dict[str, Any]:
    if isinstance(cfg, dict):
        return cfg
    if isinstance(cfg, str) and cfg:
        text = oss_common.read_text(cfg, limit=MAX_JSON_BYTES)
        try:
            doc = json.loads(text)
        except ValueError:
            return {}
        return doc if isinstance(doc, dict) else {}
    return {}


def _check_packaging(path_rel: str, config: Dict[str, Any]) -> List[str]:
    if not config:
        return []
    reasons: List[str] = []
    base = os.path.basename(path_rel)
    names = {str(x) for x in (config.get("prohibited_names") or config.get("names") or [])}
    exts = {str(x).lower().lstrip(".") for x in (config.get("prohibited_extensions") or config.get("extensions") or [])}
    paths = [str(x) for x in (config.get("prohibited_paths") or config.get("paths") or [])]
    if base in names:
        reasons.append("prohibited file name %r" % base)
    ext = os.path.splitext(base)[1].lower().lstrip(".")
    if ext and ext in exts:
        reasons.append("prohibited extension %r" % ext)
    for pat in paths:
        if ossreport.path_matches(pat, path_rel):
            reasons.append("matches prohibited path rule %r" % pat)
    return reasons


# ============================================================================================ dedupe
def _load_dedupe_keys(path: str) -> set:
    try:
        prior = ossreport.read_report(path)
    except Exception:
        return set()
    return {(os.path.basename(i.source_path), i.checksum) for i in prior.items if i.kind == "bin" and i.checksum}


# ============================================================================================ scan
def scan(root: str, *, build_log: Optional[str] = None, out_dir: Optional[str] = None,
         excludes: Sequence[str] = (), dedupe_against: Optional[str] = None,
         packaging_config: Any = None) -> ossreport.OssReport:
    """Scan an existing Android build output under ``root`` (never builds anything). Every path found inside
    ``module-info.json`` is resolved relative to ``root`` and rejected (not followed) when it would escape it.
    Returns one ``kind="bin"`` item per (module, installed file)."""
    root = os.path.abspath(root)
    report = ossreport.OssReport(info=ossreport.new_info(root, excludes))
    summary: Dict[str, Any] = {"modules": 0, "binaries": 0, "rejected_paths": 0, "module_info_files": 0,
                               "meta_lic_files": 0, "notice_source": None, "duplicates_marked": 0,
                               "improper_packaging": 0}

    scan_root = root
    if out_dir:
        j = oss_common.safe_join(root, out_dir)
        scan_root = j if j and os.path.isdir(j) else (os.path.abspath(out_dir) if os.path.isdir(os.path.abspath(out_dir)) else root)

    disc = _discover(scan_root, excludes)
    if scan_root != root and not disc["module_info"]:
        disc = _discover(root, excludes)   # fall back to a full scan if out_dir did not contain the artifacts
    summary["module_info_files"] = len(disc["module_info"])
    summary["meta_lic_files"] = len(disc["meta_lic"])

    if build_log:
        report.warnings.append("build_log=%r was accepted but is not parsed by this offline reimplementation "
                                "(no documented field list was in scope); no information was extracted from it" % build_log)

    notice_text, notice_truncated = "", False
    for kind in ("html", "gz", "txt"):
        p = disc["notice"].get(kind)
        if p:
            notice_text, notice_truncated = _load_final_notice(p)
            summary["notice_source"] = os.path.relpath(p, root).replace("\\", "/")
            break
    if summary["notice_source"] is None:
        report.warnings.append("no final NOTICE (NOTICE.html / NOTICE.xml.gz / NOTICE.txt) was found under %r; "
                                "every binary is reported notice_status='nok'" % scan_root)
    if notice_truncated:
        report.warnings.append("the final NOTICE file was truncated at the configured size bound")

    modules: Dict[str, Dict[str, Any]] = {}
    for mi_path in disc["module_info"]:
        doc = _load_module_info(mi_path)
        for name, info in list(doc.items())[:MAX_MODULES]:
            if isinstance(info, dict):
                modules[name] = info
    summary["modules"] = len(modules)

    pkg_config = _load_packaging_config(packaging_config)
    dedupe_keys = _load_dedupe_keys(dedupe_against) if dedupe_against else set()

    items: List[ossreport.OssItem] = []
    rejected = 0

    for name, info in list(modules.items())[:MAX_MODULES]:
        raw_paths = _as_list(info.get("path"))
        raw_installed = _as_list(info.get("installed"))
        classes = _as_list(info.get("class"))
        resolved_paths: List[Tuple[str, str]] = []
        for p in raw_paths:
            ap = oss_common.safe_join(root, p)
            if ap:
                resolved_paths.append((p.replace("\\", "/"), ap))
            else:
                rejected += 1
        resolved_installed: List[Tuple[str, str]] = []
        for p in raw_installed:
            ap = oss_common.safe_join(root, p)
            if ap:
                resolved_installed.append((p.replace("\\", "/"), ap))
            else:
                rejected += 1
        if not resolved_installed:
            continue

        license_expr, comments, has_source_notice = "", [], False
        meta_path = disc["meta_lic"].get(name)
        if meta_path:
            kv = _parse_meta_lic(oss_common.read_text(meta_path, limit=MAX_META_LIC_BYTES))
            license_expr, comments = _license_from_meta_lic(kv)
        if not license_expr:
            for _rel, src_abs in resolved_paths:
                suffix = _find_module_license_marker(src_abs)
                if suffix:
                    mapped = _MODULE_LICENSE_MAP.get(suffix.upper())
                    if mapped:
                        license_expr = mapped
                    else:
                        comments.append("MODULE_LICENSE_%s marker found; not a confirmed SPDX id, kept as found" % suffix)
                    break
        has_source_notice = any(_has_source_notice_file(src_abs) for _rel, src_abs in resolved_paths)

        for inst_rel, inst_abs in resolved_installed:
            binary_name = os.path.basename(inst_rel)
            included = _in_final_notice(notice_text, [binary_name, inst_rel, name])
            if has_source_notice and included:
                status = "ok"
            elif not has_source_notice and included:
                status = "ok(NA)"
            elif has_source_notice and not included:
                status = "nok(NA)"
            else:
                status = "nok"
            checksum = ""
            if os.path.isfile(inst_abs) and not os.path.islink(inst_abs):
                checksum = oss_common.sha256_file(inst_abs, limit=MAX_CHECKSUM_BYTES)
            needs_check = (not license_expr) or (not resolved_paths)
            it = ossreport.OssItem(kind="bin", oss_name=name, licenses=[license_expr] if license_expr else [],
                                   source_path=inst_rel, checksum=checksum, needs_check=needs_check,
                                   comment="; ".join(comments))
            it.notice_status = status
            it.extra["binary_name"] = binary_name
            it.extra["source_code_path"] = resolved_paths[0][0] if resolved_paths else ""
            it.extra["module_classes"] = classes
            it.evidence.append("module-info.json module=%s" % name)
            if meta_path:
                it.evidence.append("%s.meta_lic" % name)

            reasons = _check_packaging(inst_rel, pkg_config)
            if reasons:
                it.needs_check = True
                it.comment = ossreport._join(it.comment, "improper packaging: " + "; ".join(reasons))
                report.warnings.append("improper packaging: %s (%s)" % (inst_rel, "; ".join(reasons)))
                summary["improper_packaging"] += 1

            if checksum and (binary_name, checksum) in dedupe_keys:
                it.exclude = True
                it.comment = ossreport._join(it.comment, "duplicate of a previous scan result (dedupe_against): "
                                                         "same binary name and checksum")
                summary["duplicates_marked"] += 1

            items.append(it)

    summary["rejected_paths"] = rejected
    if rejected:
        report.warnings.append("%d path(s) inside module-info.json were rejected (would have left root) and skipped"
                                % rejected)
    summary["binaries"] = len(items)
    if not items:
        report.warnings.append("no installed binaries with a resolvable path were found under %r" % scan_root)

    report.items.extend(items)
    report.info["scanners"]["android"] = summary
    return report
