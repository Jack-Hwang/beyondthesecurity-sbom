"""Yocto scanner: reimplements, from the publicly documented artifact formats (not from FOSSLight's code), what the
FOSSLight Yocto Scanner user guide describes - reading the artifacts of an EXISTING Yocto/OpenEmbedded build (it never
runs bitbake, never executes anything):

  * ``bom.json``                         - written by a ``bom.bbclass``-style recipe-info collector: one record per
                                            recipe (list-of-dicts or dict-of-dicts; this module accepts either).
  * ``installed-package-names.txt``      - one installed package name per line (the rootfs image manifest).
  * ``installed-packages.txt``           - one ``name_version-release_arch.ipk`` per line (used only as supporting
                                            evidence; the recipe/license/version of record always comes from bom.json
                                            or buildhistory - never guessed from the filename alone).
  * ``buildhistory/packages/<machine>/<recipe>[/<package>]/latest`` - Yocto's own documented build-history artifact:
                                            ``KEY = value`` lines (PN, PV, PR, LICENSE, PKGSIZE, RDEPENDS, ...).
  * ``tmp/deploy/licenses/<image>/license.manifest`` - blocks of "PACKAGE NAME: / PACKAGE VERSION: / RECIPE NAME: /
                                            LICENSE:" (a standard Yocto build artifact, independent of any scanner).
  * SPDX JSON (``create-spdx``)          - a standard SPDX-2.x document with a ``packages`` array; used as a last
                                            resort alternative source when neither bom.json nor license.manifest is
                                            available.
  * ``sbom-info.yaml`` / ``oss-pkg-info.yaml`` - optional override blocks matching on ``yocto_recipe:`` /
                                            ``yocto_package:`` (NOT the generic path-based ``ossreport`` corrections,
                                            which this format does not use); a matching block REPLACES the
                                            recipe-derived OSS info, as FOSSLight's guide documents.

Honesty: a LICENSE string that uses Yocto's ``&``/``|`` operators is converted into an SPDX ``AND``/``OR`` expression
structurally; an individual token is only rewritten to a canonical SPDX id when the rewrite is an unambiguous
punctuation-only correspondence (e.g. ``GPLv2+`` -> ``GPL-2.0-or-later``) - never a guess at WHICH license a bare,
versionless name such as ``BSD`` or ``PD`` means. Unrecognised tokens are kept exactly as found and the item's
comment says so. This module does not output OSS information for kernel or bootloader images, matching the
documented scope of the FOSSLight Yocto Scanner; a warning says so on every run.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from bts_sbom import ossreport
from bts_sbom._internal import miniyaml, oss_common

MAX_BOM_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_RECIPES = 100_000

_KERNEL_WARNING = ("the Yocto scanner does not produce OSS information for kernel or bootloader images "
                   "(same documented scope limitation as the FOSSLight Yocto Scanner)")

# ---- Yocto shorthand -> canonical SPDX id: UNAMBIGUOUS punctuation-only renames only (never a version guess) ----
_YOCTO_SPDX_RENAMES = {
    "GPLV1": "GPL-1.0-only", "GPLV1+": "GPL-1.0-or-later", "GPL-1.0+": "GPL-1.0-or-later",
    "GPLV2": "GPL-2.0-only", "GPLV2+": "GPL-2.0-or-later", "GPLV2.0+": "GPL-2.0-or-later",
    "GPL-2.0+": "GPL-2.0-or-later",
    "GPLV3": "GPL-3.0-only", "GPLV3+": "GPL-3.0-or-later", "GPL-3.0+": "GPL-3.0-or-later",
    "LGPLV2": "LGPL-2.0-only", "LGPLV2+": "LGPL-2.0-or-later", "LGPLV2.0+": "LGPL-2.0-or-later",
    "LGPL-2.0+": "LGPL-2.0-or-later",
    "LGPLV2.1": "LGPL-2.1-only", "LGPLV2.1+": "LGPL-2.1-or-later", "LGPL2.1": "LGPL-2.1-only",
    "LGPL-2.1+": "LGPL-2.1-or-later",
    "LGPLV3": "LGPL-3.0-only", "LGPLV3+": "LGPL-3.0-or-later", "LGPL-3.0+": "LGPL-3.0-or-later",
    "AGPLV3": "AGPL-3.0-only", "AGPLV3+": "AGPL-3.0-or-later", "AGPL-3.0+": "AGPL-3.0-or-later",
}
# ids already written exactly as SPDX spells them, common enough in Yocto LICENSE strings to list explicitly
_KNOWN_SPDX_EXACT = frozenset({
    "MIT", "ISC", "APACHE-2.0", "APACHE-1.1", "ZLIB", "BSL-1.0", "PYTHON-2.0", "CC0-1.0",
    "BSD-1-CLAUSE", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "BSD-4-CLAUSE", "ARTISTIC-1.0", "ARTISTIC-2.0",
    "GPL-1.0-ONLY", "GPL-1.0-OR-LATER", "GPL-2.0-ONLY", "GPL-2.0-OR-LATER", "GPL-3.0-ONLY", "GPL-3.0-OR-LATER",
    "LGPL-2.0-ONLY", "LGPL-2.0-OR-LATER", "LGPL-2.1-ONLY", "LGPL-2.1-OR-LATER", "LGPL-3.0-ONLY", "LGPL-3.0-OR-LATER",
    "AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER", "MPL-1.1", "MPL-2.0", "NTP", "VIM", "ICU", "SLEEPYCAT", "OFL-1.1",
})
_LIC_TOKEN_RE = re.compile(r"\(|\)|&|\||[^\s&|()]+")


def _convert_yocto_license(raw: str) -> Tuple[str, List[str]]:
    """Yocto ``LICENSE`` string (``&``/``|`` operators, optional parens) -> (SPDX AND/OR expression, unknown tokens).

    Structural conversion only: ``&`` -> ``AND``, ``|`` -> ``OR``; an id token is rewritten ONLY via the explicit,
    unambiguous rename table above.  Anything else is kept verbatim and reported as "unknown" (never guessed)."""
    raw = (raw or "").strip()
    if not raw:
        return "", []
    out: List[str] = []
    unknown: List[str] = []
    for tok in _LIC_TOKEN_RE.findall(raw):
        if tok in ("(", ")"):
            out.append(tok)
        elif tok == "&":
            out.append("AND")
        elif tok == "|":
            out.append("OR")
        else:
            up = tok.upper()
            if up in _YOCTO_SPDX_RENAMES:
                out.append(_YOCTO_SPDX_RENAMES[up])
            else:
                out.append(tok)
                if up not in _KNOWN_SPDX_EXACT:
                    unknown.append(tok)
    expr = " ".join(out)
    expr = re.sub(r"\(\s+", "(", expr)
    expr = re.sub(r"\s+\)", ")", expr)
    return expr, unknown


# ============================================================================================ bom.json
def _decode_bom_json(text: str) -> Tuple[List[Dict[str, Any]], bool]:
    """Accept a proper JSON list/dict, OR the "sequence of JSON objects" shape some bom.bbclass variants write
    (records concatenated by ','  with no enclosing brackets).  Returns (records, had_parse_trouble)."""
    text = text.strip()
    if not text:
        return [], False
    try:
        obj = json.loads(text)
    except ValueError:
        wrapped = "[" + text.rstrip().rstrip(",") + "]"
        try:
            obj = json.loads(wrapped)
        except ValueError:
            obj, trouble = _decode_concatenated_objects(text)
            return obj, trouble
    return _flatten_bom(obj), False


def _decode_concatenated_objects(text: str) -> Tuple[List[Dict[str, Any]], bool]:
    dec = json.JSONDecoder()
    out: List[Dict[str, Any]] = []
    i, n = 0, len(text)
    trouble = False
    count = 0
    while i < n and count < MAX_RECIPES:
        while i < n and text[i] in " \t\r\n,":
            i += 1
        if i >= n:
            break
        try:
            item, end = dec.raw_decode(text, i)
        except ValueError:
            trouble = True
            break
        if isinstance(item, dict):
            out.append(item)
        i = end
        count += 1
    return out, trouble


def _flatten_bom(obj: Any) -> List[Dict[str, Any]]:
    if isinstance(obj, list):
        return [x for x in obj[:MAX_RECIPES] if isinstance(x, dict)]
    if isinstance(obj, dict):
        recs = []
        for k, v in list(obj.items())[:MAX_RECIPES]:
            if isinstance(v, dict):
                v = dict(v)
                v.setdefault("recipe", k)
                v.setdefault("name", k)
                recs.append(v)
        return recs
    return []


def _bom_download_location(src_uri: Any) -> str:
    if isinstance(src_uri, list):
        tokens: List[str] = []
        for s in src_uri:
            tokens.extend(str(s).split())
    else:
        tokens = str(src_uri or "").split()
    for t in tokens:
        if t.startswith(("http://", "https://", "git://", "ftp://", "git+https://", "svn://")):
            return t
    return ""


def _bom_recipe_name(rec: Dict[str, Any]) -> str:
    for k in ("recipe", "name", "pn", "PN"):
        v = rec.get(k)
        if v:
            return str(v)
    return ""


# ============================================================================================ buildhistory "latest"
_KV_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def _parse_latest_kv(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        m = _KV_RE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _collect_buildhistory(buildhistory_dir: str, excludes: Sequence[str]) -> Tuple[Dict[str, Dict[str, str]],
                                                                                    Dict[str, List[Dict[str, Any]]],
                                                                                    int, bool]:
    """-> (recipe_level_kv_by_recipe, per_package_info_by_recipe, files_read, truncated)."""
    recipe_kv: Dict[str, Dict[str, str]] = {}
    pkg_info: Dict[str, List[Dict[str, Any]]] = {}
    stats = oss_common.WalkStats()
    read = 0
    for full, rel in oss_common.walk(buildhistory_dir, excludes, stats=stats):
        if os.path.basename(rel) != "latest":
            continue
        parts = rel.split("/")
        kv = _parse_latest_kv(oss_common.read_text(full, limit=MAX_MANIFEST_BYTES))
        read += 1
        if len(parts) >= 3 and parts[-1] == "latest":
            # .../<machine>/<recipe>/latest            (recipe level)
            # .../<machine>/<recipe>/<package>/latest   (sub-package level)
            if len(parts) == 3:
                recipe = parts[-2]
                recipe_kv[recipe] = kv
            else:
                recipe = parts[-3]
                pkg_name = parts[-2]
                entry = dict(kv)
                entry["_package"] = pkg_name
                pkg_info.setdefault(recipe, []).append(entry)
    return recipe_kv, pkg_info, read, stats.truncated


# ============================================================================================ license.manifest
_LM_FIELD_RE = re.compile(r"^(PACKAGE NAME|PACKAGE VERSION|RECIPE NAME|LICENSE)\s*:\s*(.*)$", re.IGNORECASE)


def _parse_license_manifest(text: str) -> List[Dict[str, str]]:
    blocks: List[Dict[str, str]] = []
    cur: Dict[str, str] = {}
    for line in text.splitlines():
        m = _LM_FIELD_RE.match(line.strip())
        if not m:
            if not line.strip() and cur:
                blocks.append(cur)
                cur = {}
            continue
        key = m.group(1).upper()
        if key == "PACKAGE NAME" and cur:
            blocks.append(cur)
            cur = {}
        cur[key] = m.group(2).strip()
    if cur:
        blocks.append(cur)
    return blocks


# ============================================================================================ SPDX JSON (create-spdx)
def _parse_spdx_packages(doc: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for p in (doc.get("packages") or [])[:MAX_RECIPES]:
        if not isinstance(p, dict):
            continue
        lic = p.get("licenseConcluded") or ""
        if not lic or lic in ("NOASSERTION", "NONE"):
            lic = p.get("licenseDeclared") or ""
        if lic in ("NOASSERTION", "NONE"):
            lic = ""
        dl = p.get("downloadLocation") or ""
        if dl in ("NOASSERTION", "NONE"):
            dl = ""
        cr = p.get("copyrightText") or ""
        if cr in ("NOASSERTION", "NONE"):
            cr = ""
        out.append({"name": str(p.get("name") or ""), "version": str(p.get("versionInfo") or ""),
                    "license": str(lic), "download": str(dl), "copyright": str(cr),
                    "spdxid": str(p.get("SPDXID") or "")})
    return out


# ============================================================================================ sbom-info / oss-pkg-info
def _load_yocto_overrides(path: str) -> List[Dict[str, Any]]:
    """Flatten FOSSLight's yocto-specific override YAML: package -> [ {version, license, 'source name or path',
    'download location', homepage, 'copyright text', exclude, comment, yocto_recipe, yocto_package}, ... ].
    Matching is on ``yocto_recipe`` / ``yocto_package`` (one or many), NOT on path - this format is specific to the
    Yocto/Android scanners and deliberately NOT parsed with ``ossreport.load_corrections``."""
    try:
        doc = miniyaml.load_file(path)
    except (miniyaml.YamlError, OSError) as exc:
        raise ValueError("cannot read %s: %s" % (path, exc))
    if doc is None:
        return []
    if not isinstance(doc, dict):
        raise ValueError("%s: top level must be a mapping of package name -> list of version blocks" % path)

    def as_list(v: Any) -> List[str]:
        if v is None:
            return []
        return [str(x) for x in v] if isinstance(v, list) else [str(v)]

    blocks: List[Dict[str, Any]] = []
    for pkg, vers in doc.items():
        if not isinstance(vers, list):
            continue
        for b in vers:
            if not isinstance(b, dict):
                continue
            blocks.append({
                "package": str(pkg), "version": "" if b.get("version") is None else str(b["version"]),
                "licenses": as_list(b.get("license")),
                "download": "" if b.get("download location") is None else str(b["download location"]),
                "homepage": "" if b.get("homepage") is None else str(b["homepage"]),
                "copyright": "" if b.get("copyright text") is None else "\n".join(as_list(b.get("copyright text"))),
                "exclude": bool(b.get("exclude")) if not isinstance(b.get("exclude"), str) else
                           b.get("exclude", "").strip().lower() in ("1", "true", "yes", "y"),
                "comment": "" if b.get("comment") is None else str(b["comment"]),
                "yocto_recipe": as_list(b.get("yocto_recipe")),
                "yocto_package": as_list(b.get("yocto_package")),
            })
    return blocks


def _apply_yocto_overrides(items: List[ossreport.OssItem], blocks: Sequence[Dict[str, Any]], source: str) -> int:
    applied = 0
    for b in blocks:
        wanted_recipes = {r.lower() for r in b["yocto_recipe"]}
        wanted_pkgs = {p.lower() for p in b["yocto_package"]}
        if not wanted_recipes and not wanted_pkgs:
            continue
        for it in items:
            recipe = str((it.extra or {}).get("recipe_name") or it.oss_name or "").lower()
            packages = {p.lower() for p in (it.extra or {}).get("packages") or []}
            if recipe not in wanted_recipes and not (wanted_pkgs & packages) and recipe not in wanted_pkgs:
                continue
            if b["exclude"]:
                it.exclude = True
                it.comment = ossreport._join(it.comment, "Excluded by %s" % source)
                applied += 1
                continue
            it.oss_name = b["package"]
            if b["version"]:
                it.version = b["version"]
            if b["licenses"]:
                it.licenses = list(b["licenses"])
            if b["download"]:
                it.download_location = b["download"]
            if b["homepage"]:
                it.homepage = b["homepage"]
            if b["copyright"]:
                it.copyright = b["copyright"]
            it.comment = ossreport._join(it.comment, b["comment"] or "Corrected by %s" % source)
            it.evidence.append("overridden by %s (yocto_recipe/yocto_package match)" % source)
            it.needs_check = False
            applied += 1
    return applied


# ============================================================================================ discovery
def _discover(root: str, excludes: Sequence[str]) -> Dict[str, Any]:
    found: Dict[str, Any] = {"bom_json": None, "installed_names": None, "installed_packages": None,
                             "license_manifest": None, "sbom_info": [], "spdx_json": [], "buildhistory": None}
    stats = oss_common.WalkStats()
    for full, rel in oss_common.walk(root, excludes, stats=stats):
        name = os.path.basename(rel).lower()
        if name == "bom.json" and found["bom_json"] is None:
            found["bom_json"] = full
        elif name == "installed-package-names.txt" and found["installed_names"] is None:
            found["installed_names"] = full
        elif name == "installed-packages.txt" and found["installed_packages"] is None:
            found["installed_packages"] = full
        elif name == "license.manifest" and found["license_manifest"] is None:
            found["license_manifest"] = full
        elif name in ("sbom-info.yaml", "oss-pkg-info.yaml"):
            found["sbom_info"].append(full)
        elif name.endswith(".spdx.json"):
            found["spdx_json"].append(full)
        elif name == "latest" and found["buildhistory"] is None and "/packages/" in oss_common.norm(rel):
            # .../buildhistory/packages/<machine>/<recipe>[/<package>]/latest
            idx = oss_common.norm(rel).find("/packages/")
            found["buildhistory"] = os.path.join(root, oss_common.norm(rel)[: idx + len("/packages")].lstrip("/"))
    return found


# ============================================================================================ scan
def scan(root: str, *, buildhistory: Optional[str] = None, bom_json: Optional[str] = None,
         installed_names: Optional[str] = None, installed_packages: Optional[str] = None,
         license_manifest: Optional[str] = None, sbom_info: Sequence[str] = (), binary_root: Optional[str] = None,
         excludes: Sequence[str] = ()) -> ossreport.OssReport:
    """Scan existing Yocto build artifacts under ``root`` (never runs bitbake). Any explicit path argument that is
    not given is auto-discovered under ``root``. Returns an :class:`ossreport.OssReport` with SRC items (one per
    installed recipe) and, when ``binary_root`` resolves and ``oss_binary`` is importable, BIN items."""
    root = os.path.abspath(root)
    report = ossreport.OssReport(info=ossreport.new_info(root, excludes))
    summary: Dict[str, Any] = {"recipes": 0, "source": None, "installed_names": 0, "buildhistory_files": 0,
                                "overrides_applied": 0, "unknown_license_tokens": 0, "bin_items": 0}
    report.warnings.append(_KERNEL_WARNING)

    disc = _discover(root, excludes)
    bom_json = bom_json or disc["bom_json"]
    installed_names = installed_names or disc["installed_names"]
    installed_packages = installed_packages or disc["installed_packages"]
    license_manifest = license_manifest or disc["license_manifest"]
    buildhistory = buildhistory or disc["buildhistory"]
    sbom_info = list(sbom_info) or disc["sbom_info"]

    names: List[str] = []
    if installed_names:
        text = oss_common.read_text(installed_names, limit=MAX_MANIFEST_BYTES)
        names = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    summary["installed_names"] = len(names)
    name_set = set(names)

    ipk_versions: Dict[str, str] = {}
    if installed_packages:
        text = oss_common.read_text(installed_packages, limit=MAX_MANIFEST_BYTES)
        for ln in text.splitlines():
            ln = ln.strip()
            # Yocto package names never contain '_' (OE convention uses '-'); version/release sits between the
            # first and the (arch-bearing) last underscore-delimited segment: name_version-release_arch.ipk
            m = re.match(r"^(?P<name>[^_]+)_(?P<ver>[^_]+)_(?P<arch>.+)\.ipk$", ln)
            if m:
                ipk_versions[m.group("name")] = m.group("ver")

    buildhistory_recipe_kv: Dict[str, Dict[str, str]] = {}
    buildhistory_pkg_info: Dict[str, List[Dict[str, Any]]] = {}
    if buildhistory and os.path.isdir(buildhistory):
        buildhistory_recipe_kv, buildhistory_pkg_info, nfiles, trunc = _collect_buildhistory(buildhistory, excludes)
        summary["buildhistory_files"] = nfiles
        if trunc:
            report.warnings.append("buildhistory scan truncated (too many files) under %r" % buildhistory)

    items: List[ossreport.OssItem] = []

    if bom_json and os.path.isfile(bom_json):
        text = oss_common.read_text(bom_json, limit=MAX_BOM_BYTES)
        if len(text) >= MAX_BOM_BYTES:
            report.warnings.append("bom.json truncated at %d bytes" % MAX_BOM_BYTES)
        recs, trouble = _decode_bom_json(text)
        if trouble:
            report.warnings.append("bom.json: some records near the end could not be parsed and were skipped")
        bom_rel = os.path.relpath(bom_json, root).replace("\\", "/")
        recipes: Dict[str, Dict[str, Any]] = {}
        pkg_to_recipe: Dict[str, str] = {}
        for rec in recs:
            rname = _bom_recipe_name(rec)
            if not rname:
                continue
            recipes[rname] = rec
            pkgs = str(rec.get("packages") or "").split()
            for p in pkgs:
                pkg_to_recipe.setdefault(p, rname)
            pkg_to_recipe.setdefault(rname, rname)
        wanted_recipes = set()
        if name_set:
            for pkg in name_set:
                r = pkg_to_recipe.get(pkg)
                if r:
                    wanted_recipes.add(r)
        else:
            wanted_recipes = set(recipes)
        for rname in sorted(wanted_recipes):
            rec = recipes.get(rname)
            if rec is None:
                continue
            version = str(rec.get("pv") or rec.get("PV") or rec.get("version") or "")
            packages = str(rec.get("packages") or "").split()
            version_source = "bom.json"
            if not version:
                for p in packages:
                    if p in ipk_versions:
                        version = ipk_versions[p]
                        version_source = "installed-packages.txt"
                        break
            lic_raw = str(rec.get("license") or rec.get("LICENSE") or "")
            expr, unknown = _convert_yocto_license(lic_raw)
            if unknown:
                summary["unknown_license_tokens"] += len(unknown)
            download = _bom_download_location(rec.get("src_uri") or rec.get("SRC_URI"))
            pkg_lic = rec.get("pkg_lic") if isinstance(rec.get("pkg_lic"), dict) else {}
            comment = ""
            if unknown:
                comment = "LICENSE token(s) not a recognised SPDX id (kept as found): %s" % ", ".join(sorted(set(unknown)))
            it = ossreport.OssItem(kind="src", oss_name=rname, version=version,
                                   licenses=[expr] if expr else [],
                                   download_location=download, source_path=bom_rel, comment=comment,
                                   needs_check=not bool(expr))
            it.evidence.append("bom.json entry (recipe=%s)" % rname)
            if version_source != "bom.json":
                it.evidence.append("version from %s" % version_source)
            it.extra["recipe_name"] = rname
            it.extra["packages"] = packages
            if rec.get("file"):
                it.extra["recipe_file"] = str(rec.get("file"))
            if pkg_lic:
                it.extra["pkg_lic"] = pkg_lic
            bh = buildhistory_pkg_info.get(rname)
            if bh:
                it.extra["buildhistory_packages"] = bh
            items.append(it)
        summary["source"] = "bom.json"

    # buildhistory-only recipes (bom.json absent, or a recipe missing from it)
    have = {it.extra.get("recipe_name") for it in items}
    for rname, kv in buildhistory_recipe_kv.items():
        if rname in have:
            continue
        version = kv.get("PV", "")
        lic_raw = kv.get("LICENSE", "")
        expr, unknown = _convert_yocto_license(lic_raw) if lic_raw else ("", [])
        it = ossreport.OssItem(kind="src", oss_name=kv.get("PN", rname), version=version,
                               licenses=[expr] if expr else [], source_path=os.path.relpath(buildhistory, root).replace("\\", "/"),
                               needs_check=not bool(expr))
        it.evidence.append("buildhistory/packages/.../%s/latest" % rname)
        it.extra["recipe_name"] = rname
        items.append(it)
        have.add(rname)
    if buildhistory_recipe_kv:
        summary["source"] = summary["source"] or "buildhistory"

    if not items and license_manifest and os.path.isfile(license_manifest):
        text = oss_common.read_text(license_manifest, limit=MAX_MANIFEST_BYTES)
        blocks = _parse_license_manifest(text)
        rel = os.path.relpath(license_manifest, root).replace("\\", "/")
        for b in blocks:
            rname = b.get("RECIPE NAME") or b.get("PACKAGE NAME") or ""
            if not rname:
                continue
            expr, unknown = _convert_yocto_license(b.get("LICENSE", ""))
            comment = ("LICENSE token(s) not a recognised SPDX id (kept as found): %s" % ", ".join(sorted(set(unknown)))
                       if unknown else "")
            it = ossreport.OssItem(kind="src", oss_name=rname, version=b.get("PACKAGE VERSION", ""),
                                   licenses=[expr] if expr else [], source_path=rel, comment=comment,
                                   needs_check=not bool(expr))
            it.evidence.append("license.manifest block (recipe=%s)" % rname)
            it.extra["recipe_name"] = rname
            items.append(it)
        summary["source"] = "license.manifest"

    if not items and disc["spdx_json"]:
        for path in disc["spdx_json"][:5]:
            text = oss_common.read_text(path, limit=MAX_BOM_BYTES)
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            if not isinstance(doc, dict) or "packages" not in doc:
                continue
            rel = os.path.relpath(path, root).replace("\\", "/")
            for p in _parse_spdx_packages(doc):
                if not p["name"]:
                    continue
                it = ossreport.OssItem(kind="src", oss_name=p["name"], version=p["version"],
                                       licenses=[p["license"]] if p["license"] else [], download_location=p["download"],
                                       copyright=p["copyright"], source_path=rel, needs_check=not bool(p["license"]))
                it.evidence.append("SPDX JSON package %s" % (p["spdxid"] or p["name"]))
                it.extra["recipe_name"] = p["name"]
                items.append(it)
            summary["source"] = "spdx-json"
            break

    summary["recipes"] = len(items)
    if not items:
        report.warnings.append("no Yocto recipe information found (no bom.json, buildhistory, license.manifest or "
                                "SPDX JSON located under %r)" % root)

    report.items.extend(items)

    for path in sbom_info:
        try:
            blocks = _load_yocto_overrides(path)
        except ValueError as exc:
            report.warnings.append(str(exc))
            continue
        summary["overrides_applied"] += _apply_yocto_overrides(report.items, blocks, os.path.basename(path))

    if binary_root:
        binary_root_abs = os.path.abspath(binary_root)
        try:
            import importlib
            oss_binary = importlib.import_module("bts_sbom._internal.oss_binary")
        except ImportError:
            report.warnings.append("bts_sbom._internal.oss_binary is not available; BIN sheet was not generated "
                                    "for binary_root=%r" % binary_root)
        else:
            try:
                bin_report = oss_binary.scan(binary_root_abs)
            except Exception as exc:  # defensive: a sibling scanner's failure must not abort this one
                report.warnings.append("binary scan of %r failed: %s" % (binary_root, exc))
            else:
                report.merge(bin_report)
                summary["bin_items"] = len(bin_report.items)
    else:
        report.warnings.append("no binary_root given/discovered; BIN sheet (decompressed rootfs) was not generated")

    report.info["scanners"]["yocto"] = summary
    return report
