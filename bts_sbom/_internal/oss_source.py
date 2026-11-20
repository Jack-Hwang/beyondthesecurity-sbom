"""SOURCE scanner: FOSSLight Source Scanner's reporting behaviour, reimplemented natively and offline.

What this module does (from FOSSLight's public user guide, not from its code): walk a source tree and emit one
``OssItem`` (kind ``src``) per file that has a license/copyright finding OR that the default-exclusion rules flag
(build script, binary, hidden path, test/doc directory) - excluded files stay in the report with the reason in
``comment`` (``exclude=True``), never silently dropped.  A ``sbom-info.yaml`` at the project root (or any file the
caller names) then corrects/excludes rows by path, exactly as ``bts_sbom.ossreport`` already does for every scanner.

Detection is built ON TOP of ``bts_sbom._internal.license_scan`` (SPDX-License-Identifier tags, per-license header/
notice phrase signatures, license-file recognition, "(c)"/"(C)" copyright extraction) - that module is reused
as-is, never edited.  This file adds only what it does not already cover: a bare "(C) year holder" copyright
marker, REUSE-style "SPDX-FileCopyrightText:" tags, package-identity inference from the nearest enclosing
manifest (package.json, pyproject.toml, static setup.py, PKG-INFO/METADATA, pom.xml, Cargo.toml, go.mod,
composer.json, *.gemspec, bower.json, pubspec.yaml), and collection of each component's own license/NOTICE text
for the notice generator.

Honesty contract: a field this scanner cannot establish from the file or its metadata stays empty - nothing is
guessed.  Every item's ``evidence`` says how each license/copyright/identity fact was found (file:line or the
manifest file used).  Limits (file count, read size, truncation) are recorded in ``report.warnings`` and in
``report.info["scanners"]["source"]`` rather than failing or silently stopping.

Safety: the analysed tree is untrusted data.  Nothing here executes, imports or ``eval``s repository content;
``setup.py`` is read with ``ast.parse`` + ``ast.literal_eval`` on literal keyword values only (never executed),
XML (``pom.xml``) is parsed with ``xml.etree.ElementTree`` after rejecting any ``<!DOCTYPE`` (blocks both XXE and
entity-expansion attacks), and TOML/JSON/YAML manifests are parsed with ast/json/the project's own bounded
``miniyaml``.  Every walk goes through ``oss_common.walk`` (never follows symlinks); every extra directory or file
this module peeks at beyond what the walk yielded (a ``LICENSES/`` folder, a ``NOTICE`` file, a manifest in an
ancestor directory) is re-checked with ``os.path.islink`` before it is listed or opened, and every path is built
through ``oss_common.safe_join``.  Every read is bounded.  ``engine="scancode"`` is opt-in only and never runs a
real subprocess unless the caller asked for that engine, no ``runner`` was injected, and ``scancode`` is actually
on PATH; scancode itself only reads files, it does not execute the analysed code.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from bts_sbom import ossreport
from bts_sbom.ossreport import OssItem, OssReport
from bts_sbom._internal import license_scan, miniyaml, oss_common

try:
    import tomllib  # Python >= 3.11
except ImportError:  # pragma: no cover - exercised on the Python 3.10 floor
    tomllib = None  # type: ignore[assignment]

DEFAULT_MAX_FILES = 200_000
_SNIFF_BYTES = 64 * 1024          # header-only read for binary sniffing + the extra SPDX-FileCopyrightText scan
MAX_METADATA_BYTES = 2_000_000    # bound on reading a package-manifest file
MAX_LICENSE_TEXT = 200_000        # "bounded to 200 KB per text"
MAX_NOTICE_TEXT = 200_000
ENGINES = ("builtin", "scancode")

_LICENSE_FILE_RE = re.compile(r"^(licen[sc]e|copying|unlicense)(\..+)?$", re.IGNORECASE)
_NOTICE_FILE_RE = re.compile(r"^notice(\..+)?$", re.IGNORECASE)
_SPDX_FC_RE = re.compile(r"SPDX-FileCopyrightText:\s*([^\n\r]+)", re.IGNORECASE)
# a bare "(C) 2021 Holder" marker with no preceding word "copyright" (license_scan's own copyright regex requires
# that word first, so this one catches the variant it does not)
_BARE_C_RE = re.compile(r"\(c\)\s*([^\n\r]{0,120})", re.IGNORECASE)


# ======================================================================================= tiny local helpers
def _decode(data: bytes) -> str:
    """Same bounded decode fallback as ``oss_common.read_text``, for bytes already in hand."""
    for enc in ("utf-8-sig", "utf-16"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def _ancestors(rel_dir: str) -> List[str]:
    """``rel_dir`` then each parent up to ``""`` (the scan root), nearest first."""
    parts = rel_dir.split("/") if rel_dir else []
    return ["/".join(parts[:i]) for i in range(len(parts), -1, -1)]


def _dirname(rel: str) -> str:
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data


def _dir_entries(root: str, rel_dir: str, cache: Dict[str, Dict[str, str]]) -> Dict[str, str]:
    """{lowercase name: actual name} for the immediate, non-symlink children of ``rel_dir``.  Memoised; a
    symlinked child is simply left out (never followed), and ``rel_dir`` itself is never a symlink."""
    if rel_dir in cache:
        return cache[rel_dir]
    full = oss_common.safe_join(root, rel_dir) if rel_dir else os.path.abspath(root)
    entries: Dict[str, str] = {}
    if full and os.path.isdir(full) and not os.path.islink(full):
        try:
            for name in os.listdir(full):
                if os.path.islink(os.path.join(full, name)):
                    continue
                entries[name.lower()] = name
        except OSError:
            pass
    cache[rel_dir] = entries
    return entries


def _read_bounded(root: str, rel_file: str, limit: int) -> Optional[str]:
    full = oss_common.safe_join(root, rel_file)
    if not full or os.path.islink(full) or not os.path.isfile(full):
        return None
    text = oss_common.read_text(full, limit=limit)
    return text if text.strip() else None


# ============================================================================= package-manifest parsers
def _load_toml(text: str) -> Dict[str, Any]:
    if tomllib is not None:
        try:
            return tomllib.loads(text)
        except Exception:
            return {}
    return _mini_toml(text)


_TOML_SECTION_RE = re.compile(r"^\[(?!\[)([^\]]+)\]\s*$")
_TOML_KV_RE = re.compile(r"^([A-Za-z0-9_-]+)\s*=\s*(.+?)\s*$")


def _mini_toml_value(raw: str) -> Optional[str]:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        return raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    if len(raw) >= 2 and raw[0] == raw[-1] == "'":
        return raw[1:-1]
    return None  # numbers / bools / arrays / inline tables: not needed here, never guessed


def _mini_toml(text: str, max_lines: int = 20_000) -> Dict[str, Any]:
    """Minimal fallback for when ``tomllib`` is unavailable (Python 3.10): only plain ``[section]`` headers and
    quoted-string ``key = "value"`` lines are understood; anything else is skipped, never guessed at."""
    doc: Dict[str, Any] = {}
    section = doc
    for lineno, line in enumerate(text.splitlines()):
        if lineno > max_lines:
            break
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _TOML_SECTION_RE.match(s)
        if m:
            node: Any = doc
            for part in (p.strip().strip("\"'") for p in m.group(1).split(".")):
                if not isinstance(node, dict):
                    node = doc
                    break
                node = node.setdefault(part, {})
            section = node if isinstance(node, dict) else doc
            continue
        m = _TOML_KV_RE.match(s)
        if m and isinstance(section, dict):
            val = _mini_toml_value(m.group(2))
            if val is not None:
                section[m.group(1)] = val
    return doc


def _clean_repo_url(url: str) -> str:
    url = (url or "").strip()
    if url.startswith("git+"):
        url = url[4:]
    return url


def _parse_package_json(text: str) -> Dict[str, str]:
    try:
        data = json.loads(text)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out: Dict[str, str] = {}
    if isinstance(data.get("name"), str):
        out["name"] = data["name"]
    if isinstance(data.get("version"), str):
        out["version"] = data["version"]
    if isinstance(data.get("homepage"), str):
        out["homepage"] = data["homepage"]
    repo = data.get("repository")
    url = repo if isinstance(repo, str) else (repo.get("url") if isinstance(repo, dict) else None)
    if isinstance(url, str) and url:
        out["download_location"] = _clean_repo_url(url)
    return out


def _parse_pyproject_toml(text: str) -> Dict[str, str]:
    doc = _load_toml(text)
    out: Dict[str, str] = {}
    proj = doc.get("project") if isinstance(doc, dict) else None
    if isinstance(proj, dict):
        if isinstance(proj.get("name"), str):
            out["name"] = proj["name"]
        if isinstance(proj.get("version"), str):
            out["version"] = proj["version"]
        urls = proj.get("urls")
        if isinstance(urls, dict):
            for key in ("Homepage", "homepage", "Home", "home"):
                if isinstance(urls.get(key), str):
                    out["homepage"] = urls[key]
                    break
    tool = doc.get("tool") if isinstance(doc, dict) else None
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        out.setdefault("name", poetry.get("name") if isinstance(poetry.get("name"), str) else "")
        out.setdefault("version", poetry.get("version") if isinstance(poetry.get("version"), str) else "")
        out.setdefault("homepage", poetry.get("homepage") if isinstance(poetry.get("homepage"), str) else "")
        repo = poetry.get("repository")
        if isinstance(repo, str) and "download_location" not in out:
            out["download_location"] = repo
    return {k: v for k, v in out.items() if v}


def _parse_setup_py(text: str) -> Dict[str, str]:
    """Static only: ``ast.parse`` builds a syntax tree (nothing runs); only literal keyword values are read via
    ``ast.literal_eval``.  A ``name=my_var`` computed at import time is left empty - never guessed."""
    try:
        tree = ast.parse(text)
    except Exception:
        return {}
    out: Dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else None)
        if name != "setup":
            continue
        for kw in node.keywords:
            if kw.arg not in ("name", "version", "url", "homepage", "download_url") or kw.value is None:
                continue
            try:
                val = ast.literal_eval(kw.value)
            except Exception:
                continue
            if not isinstance(val, str):
                continue
            if kw.arg == "name":
                out["name"] = val
            elif kw.arg == "version":
                out["version"] = val
            elif kw.arg in ("url", "homepage"):
                out.setdefault("homepage", val)
            elif kw.arg == "download_url":
                out["download_location"] = val
        break  # the first setup(...) call in the file wins
    return out


def _parse_pkginfo(text: str) -> Dict[str, str]:
    """PKG-INFO / wheel METADATA: RFC-822-style headers until the first blank line."""
    out: Dict[str, str] = {}
    for line in text.splitlines():
        if line == "":
            break
        if line[:1] in (" ", "\t"):
            continue
        m = re.match(r"^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$", line)
        if not m:
            continue
        key, val = m.group(1).lower(), m.group(2).strip()
        if not val or val.upper() == "UNKNOWN":
            continue
        if key == "name":
            out["name"] = val
        elif key == "version":
            out["version"] = val
        elif key == "home-page":
            out["homepage"] = val
        elif key == "download-url":
            out["download_location"] = val
    return out


def _parse_pom_xml(text: str) -> Dict[str, str]:
    from bts_sbom._internal import safe_xml
    try:
        root_el = safe_xml.fromstring(text)        # a DOCTYPE/ENTITY is refused (XXE / entity expansion): never parsed
    except Exception:
        return {}

    def local(tag: str) -> str:
        return tag.split("}", 1)[-1] if "}" in tag else tag

    out: Dict[str, str] = {}
    for child in root_el:
        tag = local(child.tag)
        if tag == "name" and child.text and child.text.strip():
            out["name"] = child.text.strip()
        elif tag == "artifactId" and child.text and "name" not in out:
            out["name"] = child.text.strip()
        elif tag == "version" and child.text and child.text.strip():
            out["version"] = child.text.strip()
        elif tag == "url" and child.text and child.text.strip():
            out["homepage"] = child.text.strip()
        elif tag == "scm":
            for sub in child:
                if local(sub.tag) == "url" and sub.text and sub.text.strip():
                    out["download_location"] = sub.text.strip()
    return out


def _parse_cargo_toml(text: str) -> Dict[str, str]:
    doc = _load_toml(text)
    pkg = doc.get("package") if isinstance(doc, dict) else None
    out: Dict[str, str] = {}
    if isinstance(pkg, dict):
        for src, dst in (("name", "name"), ("version", "version"), ("homepage", "homepage"),
                         ("repository", "download_location")):
            if isinstance(pkg.get(src), str) and pkg[src]:
                out[dst] = pkg[src]
    return out


def _parse_go_mod(text: str) -> Dict[str, str]:
    m = re.search(r"^\s*module\s+(\S+)", text, re.MULTILINE)
    return {"name": m.group(1).strip('"')} if m else {}


def _parse_composer_json(text: str) -> Dict[str, str]:
    try:
        data = json.loads(text)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out: Dict[str, str] = {}
    if isinstance(data.get("name"), str):
        out["name"] = data["name"]
    if isinstance(data.get("version"), str):
        out["version"] = data["version"]
    if isinstance(data.get("homepage"), str):
        out["homepage"] = data["homepage"]
    src = data.get("source")
    if isinstance(src, dict) and isinstance(src.get("url"), str):
        out["download_location"] = src["url"]
    return out


def _parse_bower_json(text: str) -> Dict[str, str]:
    try:
        data = json.loads(text)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: data[k] for k in ("name", "version", "homepage") if isinstance(data.get(k), str) and data[k]}


def _parse_pubspec_yaml(text: str) -> Dict[str, str]:
    try:
        doc = miniyaml.loads(text)
    except miniyaml.YamlError:
        return {}
    if not isinstance(doc, dict):
        return {}
    out: Dict[str, str] = {}
    for k in ("name", "version", "homepage"):
        if isinstance(doc.get(k), str) and doc[k]:
            out[k] = doc[k]
    if isinstance(doc.get("repository"), str) and doc["repository"]:
        out["download_location"] = doc["repository"]
    return out


_GEM_FIELD_RE = {
    "name": re.compile(r"\.name\s*=\s*(['\"])(.*?)\1"),
    "version": re.compile(r"\.version\s*=\s*(['\"])(.*?)\1"),
    "homepage": re.compile(r"\.homepage\s*=\s*(['\"])(.*?)\1"),
}


def _parse_gemspec(text: str) -> Dict[str, str]:
    return {k: m.group(2) for k, rx in _GEM_FIELD_RE.items() if (m := rx.search(text))}


# nearest-enclosing-wins priority order, as documented for the FOSSLight source scanner's package identification
_META_PARSERS: List[Tuple[str, Callable[[str], Dict[str, str]]]] = [
    ("package.json", _parse_package_json),
    ("pyproject.toml", _parse_pyproject_toml),
    ("setup.py", _parse_setup_py),
    ("pkg-info", _parse_pkginfo),
    ("metadata", _parse_pkginfo),
    ("pom.xml", _parse_pom_xml),
    ("cargo.toml", _parse_cargo_toml),
    ("go.mod", _parse_go_mod),
    ("composer.json", _parse_composer_json),
    ("bower.json", _parse_bower_json),
    ("pubspec.yaml", _parse_pubspec_yaml),
]
_META_PARSER_MAP: Dict[str, Callable[[str], Dict[str, str]]] = dict(_META_PARSERS)
_META_PARSER_MAP["*.gemspec"] = _parse_gemspec


def _pick_metadata_file(entries: Dict[str, str]) -> Optional[Tuple[str, str]]:
    for key, _ in _META_PARSERS:
        if key in entries:
            return key, entries[key]
    gems = sorted(actual for lower, actual in entries.items() if lower.endswith(".gemspec"))
    if gems:
        return "*.gemspec", gems[0]
    return None


def _find_package_meta(root: str, rel_dir: str, dir_cache: Dict[str, Dict[str, str]],
                       meta_cache: Dict[str, Optional[Dict[str, str]]]) -> Optional[Dict[str, str]]:
    """Nearest enclosing directory (``rel_dir`` or an ancestor) that holds recognised package metadata."""
    if rel_dir in meta_cache:
        return meta_cache[rel_dir]
    result: Optional[Dict[str, str]] = None
    for d in _ancestors(rel_dir):
        entries = _dir_entries(root, d, dir_cache)
        picked = _pick_metadata_file(entries)
        if not picked:
            continue
        key, actual_name = picked
        rel_file = (d + "/" + actual_name) if d else actual_name
        text = _read_bounded(root, rel_file, MAX_METADATA_BYTES)
        fields: Dict[str, str] = {}
        if text:
            try:
                fields = _META_PARSER_MAP[key](text) or {}
            except Exception:
                fields = {}
        if any(fields.values()):
            result = {**fields, "evidence": "%s at %s" % (actual_name, rel_file), "dir": d}
        break
    meta_cache[rel_dir] = result
    return result


# ==================================================================================== license / notice text
def _nearest_license_dir(root: str, rel_dir: str, dir_cache: Dict[str, Dict[str, str]]) -> Optional[str]:
    """Nearest directory (``rel_dir`` or an ancestor) that holds a license file or a REUSE LICENSES/ directory."""
    for d in _ancestors(rel_dir):
        entries = _dir_entries(root, d, dir_cache)
        if "licenses" in entries or any(_LICENSE_FILE_RE.match(lower) for lower in entries):
            return d
    return None


def _is_deeper(inner: str, outer: str) -> bool:
    return inner != outer and (outer == "" or inner.startswith(outer + "/"))


def _find_license_text(root: str, rel_dir: str, lic: str,
                       dir_cache: Dict[str, Dict[str, str]]) -> Tuple[Optional[str], Optional[str]]:
    """Nearest enclosing license text for ``lic``: REUSE ``LICENSES/<id>.txt`` first, else a plain LICENSE /
    COPYING / UNLICENSE file - whichever is found closest wins.  Returns (text, evidence) or (None, None)."""
    want = (lic + ".txt").lower()
    for d in _ancestors(rel_dir):
        entries = _dir_entries(root, d, dir_cache)
        if "licenses" in entries:
            lic_dir = (d + "/" + entries["licenses"]) if d else entries["licenses"]
            lic_entries = _dir_entries(root, lic_dir, dir_cache)
            if want in lic_entries:
                rel_file = lic_dir + "/" + lic_entries[want]
                text = _read_bounded(root, rel_file, MAX_LICENSE_TEXT)
                if text:
                    return text, "REUSE license file at %s" % rel_file
        for lower, actual in sorted(entries.items()):
            if _LICENSE_FILE_RE.match(lower):
                rel_file = (d + "/" + actual) if d else actual
                text = _read_bounded(root, rel_file, MAX_LICENSE_TEXT)
                if text:
                    return text, "license file at %s" % rel_file
    return None, None


def _find_notice_text(root: str, pkg_dir: Optional[str], dir_cache: Dict[str, Dict[str, str]],
                      notice_cache: Dict[str, Optional[str]]) -> Optional[str]:
    if pkg_dir is None:
        return None
    if pkg_dir in notice_cache:
        return notice_cache[pkg_dir]
    text = None
    entries = _dir_entries(root, pkg_dir, dir_cache)
    for lower, actual in sorted(entries.items()):
        if _NOTICE_FILE_RE.match(lower):
            rel_file = (pkg_dir + "/" + actual) if pkg_dir else actual
            text = _read_bounded(root, rel_file, MAX_NOTICE_TEXT)
            if text:
                break
    notice_cache[pkg_dir] = text
    return text


# ========================================================================================= finding -> evidence
def _finding_evidence(f: Dict[str, Any]) -> str:
    loc = "%s:%d" % (f.get("file", ""), f.get("line", 0))
    kind, lic = f.get("kind"), f.get("license", "")
    if kind == "spdx-tag":
        return "SPDX-License-Identifier tag (%s) at %s" % (lic, loc)
    if kind == "license-file":
        return "license text in license file (%s) at %s" % (lic, loc)
    if kind == "license-text":
        return "license header/notice text signature (%s) at %s" % (lic, loc)
    return "%s (%s) at %s" % (kind or "license finding", lic, loc)


def _extra_filecopyright(text: str, relpath: str) -> List[Dict[str, Any]]:
    """REUSE ``SPDX-FileCopyrightText:`` tags - not recognised by ``license_scan`` (no literal word 'copyright')."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for m in _SPDX_FC_RE.finditer(text):
        val = m.group(1).strip()
        key = val.lower()
        if not val or key in seen:
            continue
        seen.add(key)
        out.append({"holder": val, "file": relpath, "line": text.count("\n", 0, m.start()) + 1,
                    "text": "SPDX-FileCopyrightText: %s" % val})
    return out


def _extra_bare_copyright(text: str, relpath: str) -> List[Dict[str, Any]]:
    """A bare ``(C) 2021 Holder`` marker - ``license_scan``'s own regex only fires after the literal word
    'copyright', so it misses this common variant."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for m in _BARE_C_RE.finditer(text):
        start = m.start()
        if "copyright" in text[max(0, start - 15):start].lower():
            continue  # already covered by license_scan's own "Copyright (c) ..." match
        holder = re.sub(r"\s+", " ", m.group(1)).strip(" .,-\t")
        holder = re.sub(r"\s*(all rights reserved|<.*?>).*$", "", holder, flags=re.IGNORECASE).strip(" .,-\t")
        if len(holder) < 3:
            continue
        key = holder.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append({"holder": holder, "file": relpath, "line": text.count("\n", 0, start) + 1,
                    "text": re.sub(r"\s+", " ", m.group(0)).strip()[:160]})
    return out


# =============================================================================================== builtin engine
def _scan_builtin(root: str, excludes: Sequence[str], max_files: int, report: OssReport) -> None:
    stats = oss_common.WalkStats()
    dir_cache: Dict[str, Dict[str, str]] = {}
    meta_cache: Dict[str, Optional[Dict[str, str]]] = {}
    notice_cache: Dict[str, Optional[str]] = {}

    files_scanned = files_binary_skipped = files_with_findings = packages_identified = 0
    excluded_by_default: Dict[str, int] = {}

    for abspath, rel in oss_common.walk(root, excludes=excludes, max_files=max_files, stats=stats):
        raw = oss_common.read_bytes(abspath, limit=_SNIFF_BYTES)
        is_bin = _is_binary(raw)
        reason = oss_common.default_exclude_reason(rel)
        if is_bin and not reason:
            reason = "binary file"

        findings: List[Dict[str, Any]] = []
        copyrights: List[Dict[str, Any]] = []
        if is_bin:
            files_binary_skipped += 1
        else:
            files_scanned += 1
            res = license_scan.scan_file(abspath, rel)
            findings = list(res["findings"])
            copyrights = list(res["copyrights"])
            extra_text = _decode(raw)
            copyrights.extend(_extra_filecopyright(extra_text, rel))
            copyrights.extend(_extra_bare_copyright(extra_text, rel))

        if not findings and not copyrights and not reason:
            continue  # nothing to report for this file

        if reason:
            excluded_by_default[reason] = excluded_by_default.get(reason, 0) + 1
        if findings or copyrights:
            files_with_findings += 1

        licenses: List[str] = []
        evidence: List[str] = []
        for f in findings:
            if f["license"] not in licenses:
                licenses.append(f["license"])
            evidence.append(_finding_evidence(f))
        copy_texts: List[str] = []
        seen_copy = set()
        for c in copyrights:
            t = c["text"]
            if t not in seen_copy:
                seen_copy.add(t)
                copy_texts.append(t)
            evidence.append("copyright statement at %s:%d" % (c["file"], c["line"]))

        rel_dir = _dirname(rel)
        meta = _find_package_meta(root, rel_dir, dir_cache, meta_cache)
        oss_name = version = homepage = download_location = ""
        pkg_dir: Optional[str] = None
        if meta:
            lic_dir = _nearest_license_dir(root, rel_dir, dir_cache)
            if lic_dir is not None and _is_deeper(lic_dir, meta.get("dir", "")):
                # a license file closer to the file than the package metadata marks separate (vendored) code: attributing it
                # to the enclosing package would be a guess, so identity stays empty
                evidence.append("package identity from %s NOT inherited: nested license at %s marks separate code" % (
                    meta["evidence"], lic_dir or "."))
                meta = None
        if meta:
            oss_name = meta.get("name", "")
            version = meta.get("version", "")
            homepage = meta.get("homepage", "")
            download_location = meta.get("download_location", "")
            pkg_dir = meta.get("dir")
            if oss_name or version or homepage or download_location:
                packages_identified += 1
                evidence.append("package identity from %s" % meta["evidence"])

        item = OssItem(kind="src", oss_name=oss_name, version=version, licenses=licenses,
                       download_location=download_location, homepage=homepage,
                       copyright="\n".join(copy_texts), source_path=rel, evidence=evidence)
        if reason:
            item.exclude = True
            item.comment = "Excluded: %s" % reason

        license_texts: Dict[str, str] = {}
        for lic in licenses:
            text, lic_evidence = _find_license_text(root, rel_dir, lic, dir_cache)
            if text:
                license_texts[lic] = text
                item.evidence.append("license text for %s from %s" % (lic, lic_evidence))
        if license_texts:
            item.extra["license_texts"] = license_texts
        notice_text = _find_notice_text(root, pkg_dir, dir_cache, notice_cache)
        if notice_text:
            item.extra["notice_file"] = notice_text

        report.items.append(item)

    if stats.truncated:
        report.warnings.append("file walk truncated at max_files=%d; some files were not scanned" % max_files)
    if stats.skipped_symlinks:
        report.warnings.append("%d symlink(s) were skipped (never followed)" % len(stats.skipped_symlinks))
    if stats.unreadable_dirs:
        report.warnings.append("%d director%s could not be read" %
                               (len(stats.unreadable_dirs), "y" if len(stats.unreadable_dirs) == 1 else "ies"))

    report.info.setdefault("scanners", {})["source"] = {
        "engine": "builtin",
        "files_seen": stats.files,
        "files_scanned": files_scanned,
        "files_binary_skipped": files_binary_skipped,
        "files_with_findings": files_with_findings,
        "excluded_by_default": excluded_by_default,
        "symlinks_skipped": len(stats.skipped_symlinks),
        "user_excluded": stats.skipped_excluded,
        "unreadable_dirs": len(stats.unreadable_dirs),
        "truncated": stats.truncated,
        "packages_identified": packages_identified,
        "not_supported": [
            "binary file content is never scanned (binaries are flagged Exclude, not content-scanned)",
            "the legacy .reuse/dep5 format (only the LICENSES/<id>.txt REUSE layout is read)",
            "choosing between OR alternatives in an SPDX expression (every alternative is kept as written)",
        ],
    }


# =============================================================================================== scancode engine
def _default_scancode_runner(cmd: List[str]) -> Tuple[int, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)  # nosec - opt-in, explicit tool call
    return proc.returncode, proc.stdout


def _scan_scancode(root: str, report: OssReport,
                   runner: Optional[Callable[[List[str]], Tuple[int, str]]]) -> None:
    info: Dict[str, Any] = {"engine": "scancode", "available": False, "files_with_findings": 0}
    if runner is None and shutil.which("scancode") is None:
        report.warnings.append("engine='scancode' requested but the 'scancode' executable was not found on "
                               "PATH; no scan was performed (never silently falling back to the builtin engine).")
        report.info.setdefault("scanners", {})["source"] = info
        return
    run = runner or _default_scancode_runner
    cmd = ["scancode", "--license", "--copyright", "--json-pp", "-", root]
    try:
        rc, out = run(cmd)
    except Exception as exc:
        report.warnings.append("scancode invocation failed: %s" % exc)
        report.info.setdefault("scanners", {})["source"] = info
        return
    if rc != 0:
        report.warnings.append("scancode exited with code %d" % rc)
    try:
        data = json.loads(out)
    except Exception as exc:
        report.warnings.append("scancode output could not be parsed as JSON: %s" % exc)
        report.info.setdefault("scanners", {})["source"] = info
        return

    info["available"] = True
    files = data.get("files") if isinstance(data, dict) else None
    for f in files or []:
        if not isinstance(f, dict) or f.get("type") not in (None, "file"):
            continue
        path = f.get("path") or ""
        licenses: List[str] = []
        for lic in f.get("licenses") or []:
            if not isinstance(lic, dict):
                continue
            spdx = lic.get("spdx_license_key") or lic.get("license_expression_spdx")
            if spdx and spdx not in licenses:
                licenses.append(spdx)
        copy_texts: List[str] = []
        for c in f.get("copyrights") or []:
            t = c.get("copyright") if isinstance(c, dict) else None
            if t and t not in copy_texts:
                copy_texts.append(t)
        if not licenses and not copy_texts:
            continue
        report.items.append(OssItem(kind="src", licenses=licenses, copyright="\n".join(copy_texts),
                                    source_path=path, evidence=["scancode"]))
    info["files_with_findings"] = len(report.items)
    report.info.setdefault("scanners", {})["source"] = info


# ===================================================================================== sbom-info.yaml corrections
def _apply_sbom_info(root: str, correction: Any, report: OssReport) -> None:
    if correction is False:
        return
    if correction is None:
        path = os.path.join(root, "sbom-info.yaml")
        if not os.path.isfile(path):
            return
    else:
        path = correction
    blocks = ossreport.load_corrections(path)  # raises ossreport.CorrectionError on a missing/malformed file
    stats = ossreport.apply_corrections(report, blocks, source=os.path.basename(str(path)))
    report.info.setdefault("scanners", {}).setdefault("source", {})["corrections"] = stats


# ============================================================================================== public API
def scan(root: str, *, excludes: Sequence[str] = (), correction: Any = None,
         max_files: int = DEFAULT_MAX_FILES, engine: str = "builtin",
         runner: Optional[Callable[[List[str]], Tuple[int, str]]] = None) -> OssReport:
    """Scan ``root`` as FOSSLight's Source Scanner would (reimplemented, offline): one ``OssItem`` (kind
    ``src``) per file with a license/copyright finding, plus every file the default-exclusion rules flag
    (build script, binary, hidden path, test/doc directory) - those stay in the report with ``exclude=True``
    and the reason in ``comment``.

    ``correction``: ``None`` (default) applies ``<root>/sbom-info.yaml`` when it exists; ``False`` disables
    corrections entirely; any other value is a path to a correction file to use instead.

    ``engine="scancode"`` is opt-in only: it shells out to the real ``scancode`` tool (via ``runner``, or the
    default subprocess runner when ``scancode`` is on PATH) instead of the builtin detectors; when scancode is
    unavailable and no ``runner`` was injected, a warning is recorded and no scan is performed - never a silent
    fallback to the builtin engine.
    """
    if engine not in ENGINES:
        raise ValueError("engine must be one of %s, got %r" % (ENGINES, engine))
    root_abs = os.path.abspath(root)
    report = OssReport(info=ossreport.new_info(analyzed_path=root_abs, excluded=excludes))
    if engine == "scancode":
        _scan_scancode(root_abs, report, runner)
    else:
        _scan_builtin(root_abs, excludes, max_files, report)
    _apply_sbom_info(root_abs, correction, report)
    return report
