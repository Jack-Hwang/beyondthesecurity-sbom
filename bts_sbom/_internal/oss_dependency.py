"""The DEPENDENCY scanner: every manifest/lockfile in a tree -> one ``OssReport`` of ``kind="dep"`` items.

Re-implements, natively and offline, what the FOSSLight Dependency Scanner's public user guide describes
(auto-detect package-manager manifests; report each dependency's name/version/license/download
location/homepage, direct-vs-transitive, and which dependencies it itself depends on) - from the
documented file FORMATS only.  No FOSSLight source was read or copied for this module (hard rule: FOSSLight
Prechecker is GPL-3.0-only and was never opened at all).

Supported managers (``item.extra["manager"]``): npm, yarn, pnpm, pypi, gradle, maven, cocoapods, carthage,
swift, pub, go, nuget, helm, unity, cargo.  Formats already covered by ``bts_sbom._internal.manifests`` are
reused as-is for parsing coordinates (package.json/-lock.json, requirements.txt, pyproject.toml, go.mod,
Cargo.toml/.lock, pom.xml, yarn.lock, packages.lock.json, gradle.lockfile, build.gradle*); everything else
(pnpm-lock.yaml, Podfile.lock, Cartfile.resolved, Package.resolved, pubspec.yaml/.lock, Chart.yaml/.lock,
uv.lock, packages.config, *.csproj, Directory.Packages.props, setup.py, Unity manifests) is parsed by the
new, from-scratch parsers in ``oss_manifests_extra``.

Honesty contract (see ``oss_manifests_extra`` for the per-field rules): a field this scanner cannot
establish from the manifest/lockfile ITSELF stays empty; ``direct`` is only True/False when the file
genuinely proves it, otherwise None; an unparseable manifest is a WARNING naming the file, never a silent
empty result; a manifest this scanner does not implement is counted, not guessed at.

The analysed tree is untrusted data: it is only ever read (``oss_common.walk`` / ``oss_common.read_text``,
both bounded, symlinks never followed); ``setup.py`` is read with ``ast.parse`` and literal evaluation of
individual AST nodes ONLY - it is never imported, exec'd or run.  Network access (registry license/metadata
lookups) only happens when the caller passes ``online=True``, through the injectable ``fetcher``.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from bts_sbom import ossreport
from bts_sbom._internal import manifests as _manifests
from bts_sbom._internal import oss_common
from bts_sbom._internal import oss_manifests_extra as _extra
from bts_sbom.ossreport import OssItem, OssReport

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - this project's floor is 3.10
    tomllib = None  # type: ignore[assignment]

MAX_ONLINE_LOOKUPS = 200
_ONLINE_TIMEOUT = 8
_ONLINE_MAX_BYTES = 1_000_000

# -------------------------------------------------------------------------------------- filename -> manager/parser
# Formats bts_sbom._internal.manifests already parses: basename (lowercase) -> manager.  "pubspec.lock" is
# intentionally NOT routed there - that module's parser is a documented no-op stub (it predates miniyaml);
# routing it to our own YAML-based parser instead is an honest improvement, not a silent downgrade.
_REUSED_MANAGER: Dict[str, str] = {
    "package.json": "npm", "package-lock.json": "npm", "npm-shrinkwrap.json": "npm",
    "requirements.txt": "pypi", "pyproject.toml": "pypi",
    "go.mod": "go",
    "cargo.toml": "cargo", "cargo.lock": "cargo",
    "pom.xml": "maven",
    "yarn.lock": "yarn",
    "packages.lock.json": "nuget",
    "gradle.lockfile": "gradle", "build.gradle": "gradle", "build.gradle.kts": "gradle",
}
_REQ_NAME_RE = re.compile(r"^(?:.+[-_.])?requirements(?:[-_.].+)?\.txt$")

# Formats this module parses itself (oss_manifests_extra): basename (lowercase) -> (manager, parse_fn).
_EXTRA_PARSERS: Dict[str, Tuple[str, Callable[[str, str], List[Dict[str, Any]]]]] = {
    "pnpm-lock.yaml": ("pnpm", _extra.parse_pnpm_lock),
    "podfile.lock": ("cocoapods", _extra.parse_podfile_lock),
    "cartfile.resolved": ("carthage", _extra.parse_cartfile_resolved),
    "package.resolved": ("swift", _extra.parse_package_resolved),
    "pubspec.yaml": ("pub", _extra.parse_pubspec_yaml),
    "pubspec.lock": ("pub", _extra.parse_pubspec_lock),
    "setup.py": ("pypi", _extra.parse_setup_py),
    "uv.lock": ("pypi", _extra.parse_uv_lock),
    "packages.config": ("nuget", _extra.parse_packages_config),
    "directory.packages.props": ("nuget", _extra.parse_directory_packages_props),
    "chart.yaml": ("helm", _extra.parse_chart_yaml),
    "chart.lock": ("helm", _extra.parse_chart_lock),
}

# Python files that uv.lock supersedes, in the SAME directory, when uv.lock is present there.
_PYTHON_MANIFEST_BASENAMES = {"pyproject.toml", "setup.py"}

_UNITY_MANIFEST_SUFFIX = "packages/manifest.json"
_UNITY_LOCK_SUFFIX = "packages/packages-lock.json"

# Manifest formats a WIDER library already recognises (bts_sbom._internal.manifests) that are simply not
# in this scanner's assigned ecosystem list (Ruby, PHP, Elixir, Conan, vcpkg, plain Pipfile/poetry locks).
# Seeing one is reported, honestly, as "not supported by this scanner" - never silently ignored.
_OUT_OF_SCOPE_HINT = {
    "gemfile.lock", "composer.lock", "pipfile.lock", "poetry.lock", "mix.lock",
    "conanfile.txt", "conanfile.py", "vcpkg.json", "go.sum",
}


def _norm(p: str) -> str:
    return p.replace("\\", "/")


def _classify(rel: str) -> Optional[Tuple[str, str, str]]:
    """(manager, origin, routing_key) for a recognised manifest, else None.  ``origin`` is 'reused' when
    bts_sbom._internal.manifests parses it, 'extra' when oss_manifests_extra does."""
    base = os.path.basename(rel)
    low = base.lower()
    if low in _REUSED_MANAGER:
        return (_REUSED_MANAGER[low], "reused", low)
    if _REQ_NAME_RE.match(low):
        return ("pypi", "reused", "requirements.txt")
    if low in _EXTRA_PARSERS:
        return (_EXTRA_PARSERS[low][0], "extra", low)
    if low.endswith(".csproj"):
        return ("nuget", "extra", "*.csproj")
    norm = _norm(rel).lower()
    if norm.endswith(_UNITY_MANIFEST_SUFFIX):
        return ("unity", "extra", _UNITY_MANIFEST_SUFFIX)
    if norm.endswith(_UNITY_LOCK_SUFFIX):
        return ("unity", "extra", _UNITY_LOCK_SUFFIX)
    return None


def _dirname(rel: str) -> str:
    d = os.path.dirname(_norm(rel))
    return d


def _is_descendant(child_dir: str, ancestor_dir: str) -> bool:
    if ancestor_dir == "":
        return True
    return child_dir == ancestor_dir or child_dir.startswith(ancestor_dir + "/")


# ---------------------------------------------------------------------------------------- reused-parser adapters
_NOFORCE = object()


def _relationship_to_direct(rel: str) -> Optional[bool]:
    if rel == "direct":
        return True
    if rel == "transitive":
        return False
    return None


# Reused basenames whose DetectedPackage.relationship default is NOT actually proven by the file itself
# (the underlying parser just defaults every row to "direct" because the format gives it nothing better).
# Trusting that default here would be a guess, not a finding - so every row is forced to direct=None.
_FORCE_NONE_BASENAMES = {"gradle.lockfile"}


def _detected_to_dict(dp: Any, manager: str, rel: str, direct_names: Optional[set] = None) -> Dict[str, Any]:
    base = os.path.basename(rel).lower()
    if base in _FORCE_NONE_BASENAMES:
        direct: Optional[bool] = None
    elif base == "yarn.lock":
        # yarn.lock's own DetectedPackage.relationship defaults to "direct" for every row (the format
        # itself does not distinguish direct from transitive) - that default would be a guess, so yarn.lock
        # is ONLY ever trusted via the sibling package.json cross-reference computed by the caller.
        direct = None if direct_names is None else (dp.name in direct_names or dp.name.lower() in direct_names)
    else:
        direct = _relationship_to_direct(getattr(dp, "relationship", "unknown"))
    purl = getattr(dp, "purl", "") or _extra.purl_for(manager, dp.name, dp.version)
    licenses = [str(dp.license)] if getattr(dp, "license", None) else []
    return {"name": dp.name, "version": dp.version or "", "manager": manager, "purl": purl, "direct": direct,
            "depends_on": [], "licenses": licenses, "download_location": "", "homepage": "",
            "evidence": ["parsed by bts_sbom._internal.manifests from %s" % rel]}


def _npm_declared_names(text: str) -> set:
    """Every name package.json declares, in ANY section, regardless of whether the version is a literal
    or a range - used only to decide direct-vs-transitive for the entries of a sibling lock file."""
    try:
        data = json.loads(text)
    except Exception:
        return set()
    names: set = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section) if isinstance(data, dict) else None
        if isinstance(deps, dict):
            names |= set(deps)
    return names


def _check_structurally_parseable(low: str, text: str, rel: str) -> Optional[str]:
    """None when ``text`` is at least structurally valid for its format; otherwise an error message.
    Only checked for strictly-grammared formats (JSON/TOML/XML) - line-oriented formats (requirements.txt,
    go.mod, yarn.lock, gradle build files) have no notion of "malformed" beyond "no line matched", which is
    already an honest (non-guessing) empty result, not a parser failure."""
    if low in ("package.json", "package-lock.json", "npm-shrinkwrap.json", "packages.lock.json"):
        try:
            json.loads(text)
        except Exception as exc:
            return "invalid JSON (%s)" % exc
        return None
    if low in ("pyproject.toml", "cargo.toml", "cargo.lock"):
        if tomllib is None:
            return None  # cannot validate without a TOML reader; not claimed malformed
        try:
            tomllib.loads(text)
        except Exception as exc:
            return "invalid TOML (%s)" % exc
        return None
    if low == "pom.xml":
        try:
            _extra._xml_root(text, rel)
        except ValueError as exc:
            return str(exc)
        return None
    return None


def _parse_reused(manager: str, low: str, text: str, rel: str, ap: str,
                   sibling_reader: Callable[[str], Optional[str]]) -> List[Dict[str, Any]]:
    fn = _manifests.parser_for(rel)   # parser_for already matches the requirements*.txt pattern itself
    if fn is None:
        return []
    # the ABSOLUTE path is passed to the parser (some, e.g. Cargo.lock, resolve a sibling manifest via
    # os.path.dirname(path) - that only works against a real filesystem path, not a walk-relative one);
    # the relative path is kept separately for source_path / evidence in the report.
    detected = fn(text, path=ap) or []
    direct_names = None
    if low == "yarn.lock":
        sibling = sibling_reader("package.json")
        if sibling is not None:
            direct_names = _npm_declared_names(sibling)
    return [_detected_to_dict(dp, manager, rel, direct_names) for dp in detected]


# ---------------------------------------------------------------------------------------------- main scan
def scan(root: str, *, excludes: Tuple[str, ...] = (), recursive: bool = True, online: bool = False,
         fetcher: Optional[Callable[[str], Optional[str]]] = None) -> OssReport:
    """Scan ``root`` for package-manager manifests/lockfiles and return an ``OssReport`` of ``kind="dep"``
    items.  ``recursive=False`` mirrors the documented FOSSLight default: once a directory has yielded a
    manifest, its subdirectories are not scanned for MORE manifests (siblings still are)."""
    report = OssReport(info=ossreport.new_info(analyzed_path=root, excludes=excludes))
    stats = oss_common.WalkStats()
    all_files: List[Tuple[str, str]] = list(oss_common.walk(root, excludes=excludes, stats=stats))

    by_dir: Dict[str, List[Tuple[str, str, str, str]]] = {}   # rel_dir -> [(rel, manager, origin, key)]
    out_of_scope: List[str] = []
    podspecs: Dict[str, str] = {}   # lowercase pod root name -> absolute path of a vendored *.podspec
    for abspath, rel in all_files:
        rel = _norm(rel)
        base = os.path.basename(rel).lower()
        if base.endswith(".podspec"):
            podspecs.setdefault(os.path.splitext(base)[0], abspath)
            continue
        hit = _classify(rel)
        if hit is None:
            if base in _OUT_OF_SCOPE_HINT or _manifests.is_supported_path(rel):
                out_of_scope.append(rel)
            continue
        manager, origin, key = hit
        by_dir.setdefault(_dirname(rel), []).append((rel, manager, origin, key))

    manifest_dirs = sorted(by_dir, key=lambda d: (d.count("/"), d))
    kept_dirs: List[str] = []
    pruned_dirs: List[str] = []
    if recursive:
        kept_dirs = manifest_dirs
    else:
        for d in manifest_dirs:
            if any(_is_descendant(d, k) and d != k for k in kept_dirs):
                pruned_dirs.append(d)
            else:
                kept_dirs.append(d)

    # uv.lock priority: within a single directory, uv.lock supersedes the other python manifests there.
    for d in kept_dirs:
        entries = by_dir[d]
        if any(key == "uv.lock" for _, _, _, key in entries):
            by_dir[d] = [e for e in entries if not (e[1] == "pypi" and os.path.basename(e[0]).lower() in
                                                     _PYTHON_MANIFEST_BASENAMES) and
                                              not (_REQ_NAME_RE.match(os.path.basename(e[0]).lower()))]

    abspath_of = {_norm(rel): ap for ap, rel in all_files}
    items: List[OssItem] = []
    by_manager: Dict[str, int] = {}
    files_processed = 0
    warn_count = 0

    def _sibling_reader_for(rel_dir: str) -> Callable[[str], Optional[str]]:
        def _read(basename: str) -> Optional[str]:
            cand = (rel_dir + "/" + basename) if rel_dir else basename
            ap = abspath_of.get(cand)
            return oss_common.read_text(ap) if ap else None
        return _read

    pkg_lock_licenses_cache: Dict[str, Dict[Tuple[str, str], List[str]]] = {}

    for d in kept_dirs:
        for rel, manager, origin, key in by_dir[d]:
            ap = abspath_of.get(rel)
            if ap is None:
                continue
            text = oss_common.read_text(ap)
            files_processed += 1
            try:
                if origin == "reused":
                    low = os.path.basename(rel).lower()
                    problem = _check_structurally_parseable(low, text, rel)
                    if problem:
                        report.warnings.append("dependency scan: could not parse %s: %s" % (rel, problem))
                        warn_count += 1
                        continue
                    rows = _parse_reused(manager, low, text, rel, ap, _sibling_reader_for(d))
                else:
                    parse_fn = (_extra.parse_csproj if key == "*.csproj" else
                               _extra.parse_unity_manifest if key == _UNITY_MANIFEST_SUFFIX else
                               _extra.parse_unity_packages_lock if key == _UNITY_LOCK_SUFFIX else
                               _EXTRA_PARSERS[key][1])
                    rows = parse_fn(text, rel)
            except ValueError as exc:
                report.warnings.append("dependency scan: could not parse %s: %s" % (rel, exc))
                warn_count += 1
                continue

            if manager == "npm" and os.path.basename(rel).lower() in ("package-lock.json", "npm-shrinkwrap.json"):
                lic_map = pkg_lock_licenses_cache.setdefault(rel, _extra.package_lock_licenses(text))
            else:
                lic_map = {}

            for row in rows:
                name = (row.get("name") or "").strip()
                if not name:
                    continue
                version = row.get("version") or ""
                licenses = list(row.get("licenses") or [])
                if not licenses and (name, version) in lic_map:
                    licenses = list(lic_map[(name, version)])
                    row = dict(row, evidence=list(row.get("evidence") or []) + [
                        "license field copied from %s's own package-lock.json entry" % name])
                download_location = row.get("download_location") or ""
                homepage = row.get("homepage") or ""
                if not download_location and not homepage:
                    dl, hp, note = _extra.derived_links(manager, name, version)
                    download_location, homepage = dl, hp
                    if note:
                        row = dict(row, evidence=list(row.get("evidence") or []) + [note])
                if manager == "cocoapods" and not licenses:
                    pod_path = podspecs.get(name.split("/", 1)[0].lower())
                    if pod_path:
                        lic = _extra.podspec_license(oss_common.read_text(pod_path))
                        if lic:
                            licenses = lic
                            row = dict(row, evidence=list(row.get("evidence") or []) +
                                      ["license read from vendored %s.podspec" % name.split("/", 1)[0]])
                it = OssItem(kind="dep", oss_name=name, version=version, licenses=licenses,
                            download_location=download_location, homepage=homepage, source_path=rel,
                            purl=row.get("purl") or "", direct=row.get("direct"),
                            depends_on=list(row.get("depends_on") or []), evidence=list(row.get("evidence") or []))
                it.extra["manager"] = manager
                items.append(it)
                by_manager[manager] = by_manager.get(manager, 0) + 1

    merged = _merge_duplicates(items)

    online_info: Dict[str, Any] = {"note": "offline - no registry lookups"}
    if online:
        online_info = _online_enrich(merged, fetcher)

    report.items = merged
    scanner_info: Dict[str, Any] = {
        "files_scanned": files_processed,
        "items": len(merged),
        "by_manager": dict(sorted(by_manager.items())),
        "recursive": recursive,
        "online": online,
        "pruned_by_recursive_false": sorted(pruned_dirs),
        "out_of_scope_manifests_seen": sorted(set(out_of_scope))[:100],
        "parse_warnings": warn_count,
        "truncated": stats.truncated,
        "skipped_symlinks": len(stats.skipped_symlinks),
        "unreadable_dirs": len(stats.unreadable_dirs),
        "online_enrichment": online_info,
        "not_implemented": ["Ruby (Gemfile.lock), PHP (composer.lock), Elixir (mix.lock), Conan, vcpkg, "
                            "Python Pipfile.lock/poetry.lock - out of this scanner's assigned ecosystem list"],
    }
    report.info.setdefault("scanners", {})["dependency"] = scanner_info
    if stats.truncated:
        report.warnings.append("dependency scan: file walk truncated at the file-count limit; some manifests "
                               "may not have been seen")
    return report


def _merge_duplicates(items: List[OssItem]) -> List[OssItem]:
    merged: Dict[Tuple[str, str, str, str], OssItem] = {}
    order: List[Tuple[str, str, str, str]] = []
    for it in items:
        manager = it.extra.get("manager", "")
        key = (manager, (it.oss_name or "").lower(), it.version, it.source_path)
        if key not in merged:
            merged[key] = it
            order.append(key)
            continue
        base = merged[key]
        for lic in it.licenses:
            if lic not in base.licenses:
                base.licenses.append(lic)
        for dep in it.depends_on:
            if dep not in base.depends_on:
                base.depends_on.append(dep)
        if base.direct is None and it.direct is not None:
            base.direct = it.direct
        base.download_location = base.download_location or it.download_location
        base.homepage = base.homepage or it.homepage
        base.purl = base.purl or it.purl
        for ev in it.evidence:
            if ev not in base.evidence:
                base.evidence.append(ev)
    return [merged[k] for k in order]


# ------------------------------------------------------------------------------------------- online enrichment
def _default_fetcher(url: str) -> Optional[str]:
    if not url.startswith("https://"):
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bts-sbom-oss-dependency/1"})
        with urllib.request.urlopen(req, timeout=_ONLINE_TIMEOUT) as resp:
            return resp.read(_ONLINE_MAX_BYTES + 1).decode("utf-8", "replace")
    except Exception:
        return None


def _maven_pom_url(name: str, version: str) -> str:
    g, _, a = name.partition(":")
    gp = g.replace(".", "/")
    return "https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.pom" % (gp, a, version, a, version)


def _online_enrich(items: List[OssItem], fetcher: Optional[Callable[[str], Optional[str]]]) -> Dict[str, Any]:
    do = fetcher or _default_fetcher
    info = {"source": "npm registry / PyPI JSON / crates.io / Maven Central POM", "attempted": 0, "resolved": 0,
            "failed": 0, "skipped": 0}
    todo = [it for it in items if not it.licenses and it.oss_name and it.version
            and it.extra.get("manager") in ("npm", "yarn", "pnpm", "pypi", "cargo", "maven", "gradle")]
    if len(todo) > MAX_ONLINE_LOOKUPS:
        info["skipped"] = len(todo) - MAX_ONLINE_LOOKUPS
        todo = todo[:MAX_ONLINE_LOOKUPS]
    for it in todo:
        manager = it.extra.get("manager")
        name, version = it.oss_name, it.version
        info["attempted"] += 1
        lic = None
        try:
            if manager in ("npm", "yarn", "pnpm"):
                url = "https://registry.npmjs.org/%s/%s" % (urllib.parse.quote(name, safe="@"),
                                                              urllib.parse.quote(version, safe=""))
                data = json.loads(do(url) or "null")
                if isinstance(data, dict):
                    lic = data.get("license")
                    if not lic and isinstance(data.get("licenses"), list) and data["licenses"]:
                        first = data["licenses"][0]
                        lic = first.get("type") if isinstance(first, dict) else first
            elif manager == "pypi":
                url = "https://pypi.org/pypi/%s/%s/json" % (urllib.parse.quote(name, safe=""),
                                                             urllib.parse.quote(version, safe=""))
                data = json.loads(do(url) or "null")
                if isinstance(data, dict):
                    lic = ((data.get("info") or {}).get("license") or "").strip() or None
            elif manager == "cargo":
                url = "https://crates.io/api/v1/crates/%s/%s" % (urllib.parse.quote(name, safe=""), version)
                data = json.loads(do(url) or "null")
                if isinstance(data, dict):
                    lic = (data.get("version") or {}).get("license")
            elif manager in ("maven", "gradle") and ":" in name:
                text = do(_maven_pom_url(name, version))
                if text:
                    m = re.search(r"<licenses>.*?<name>\s*([^<]+?)\s*</name>", text, re.DOTALL)
                    lic = m.group(1) if m else None
        except Exception:
            lic = None
        if lic:
            it.licenses.append(str(lic).strip())
            it.evidence.append("license resolved online from %s" % info["source"])
            info["resolved"] += 1
        else:
            info["failed"] += 1
    return info
