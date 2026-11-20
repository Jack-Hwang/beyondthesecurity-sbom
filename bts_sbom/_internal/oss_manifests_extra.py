"""New, from-scratch, static manifest/lockfile parsers for the OSS dependency scanner.

Covers the ecosystems the existing ``bts_sbom._internal.manifests`` package does not parse at all
(pnpm, CocoaPods, Carthage, Swift PM, Dart/Flutter pub, Helm, uv, .NET packages.config / csproj /
central package management, Unity) plus a static (never-exec) reader for ``setup.py``.

Written from the public, documented file formats only - no FOSSLight code was read or copied (see
the licensing note in the module docstring of ``oss_dependency``).

Every parser here returns a list of plain dicts, already in the shape ``oss_dependency.scan`` wants:

    {
        "name": str,                  # required; "" entries are dropped by the caller
        "version": str,               # "" when not resolvable - never guessed
        "manager": str,               # "npm" | "pnpm" | "pypi" | "nuget" | "cocoapods" | "carthage" |
                                       # "swift" | "pub" | "helm" | "unity" | ...
        "purl": str,                  # "" when a purl cannot be built (no usable name/version)
        "direct": True | False | None,  # None only when the file genuinely does not say
        "depends_on": [str, ...],     # names/purls the lock file itself records as this one's deps
        "licenses": [str, ...],       # only ever taken from THIS file - never guessed
        "download_location": str,
        "homepage": str,
        "evidence": [str, ...],       # how each (name, version, direct, license, link) was found
    }

A parser RAISES ``ValueError`` when the file is present but could not be parsed at all (caller turns
that into a warning naming the file) and returns ``[]`` for a syntactically valid file that legitimately
lists zero dependencies.  Nothing here ever execs, imports or shells out to analysed content; XML is
parsed with ``xml.etree`` after an explicit DOCTYPE/ENTITY rejection, and TOML/YAML go through the
project's own bounded stdlib readers.
"""
from __future__ import annotations

import ast
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from bts_sbom._internal import miniyaml

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - this project's floor is 3.10
    tomllib = None  # type: ignore[assignment]

MAX_TOML_BYTES = 8 * 1024 * 1024
MAX_XML_BYTES = 8 * 1024 * 1024


def _entry(name: str, version: str = "", manager: str = "", purl: str = "", direct: Optional[bool] = None,
           depends_on: Optional[List[str]] = None, licenses: Optional[List[str]] = None,
           download_location: str = "", homepage: str = "", evidence: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"name": name, "version": version or "", "manager": manager, "purl": purl, "direct": direct,
            "depends_on": list(depends_on or []), "licenses": [lic for lic in (licenses or []) if lic],
            "download_location": download_location or "", "homepage": homepage or "",
            "evidence": list(evidence or [])}


# =============================================================================================== purl helper
def purl_for(manager: str, name: str, version: str = "") -> str:
    """Best-effort ``pkg:<type>/...`` for ``manager``.  Several of these managers (carthage, helm, unity,
    pnpm, swift) have no officially registered purl type; the manager name is used as the type, the same
    pragmatic convention already used elsewhere in this codebase (``pkg:vcpkg/...``, ``pkg:conan/...``)."""
    if not name:
        return ""
    ptype = {"yarn": "npm", "pnpm": "npm", "gradle": "maven"}.get(manager, manager)
    ns, nm = "", name
    if ptype in ("npm",) and name.startswith("@") and "/" in name:
        ns, nm = name[1:].split("/", 1)
    elif ptype == "maven" and ":" in name:
        ns, nm = name.split(":", 1)
    path = (urllib.parse.quote(ns, safe="") + "/" if ns else "") + urllib.parse.quote(nm, safe="")
    out = "pkg:%s/%s" % (ptype, path)
    if version:
        out += "@" + urllib.parse.quote(str(version), safe="")
    return out


def derived_links(manager: str, name: str, version: str) -> Tuple[str, str, str]:
    """(download_location, homepage, evidence) derived PURELY from a public registry-URL convention -
    never claimed to be verified.  Empty strings where no safe, well-known convention exists."""
    if not name:
        return "", "", ""
    note = "derived from %s registry-URL convention (not verified)"
    if manager in ("npm", "yarn", "pnpm") and version:
        base = name.rsplit("/", 1)[-1]
        return ("https://registry.npmjs.org/%s/-/%s-%s.tgz" % (urllib.parse.quote(name, safe="@/"), base, version),
                "https://www.npmjs.com/package/%s" % urllib.parse.quote(name, safe="@/"), note % "npm")
    if manager == "pypi":
        return ("https://pypi.org/project/%s/%s/#files" % (urllib.parse.quote(name, safe=""), version) if version
                else "", "https://pypi.org/project/%s/" % urllib.parse.quote(name, safe=""), note % "PyPI")
    if manager == "cargo" and version:
        return ("https://crates.io/api/v1/crates/%s/%s/download" % (urllib.parse.quote(name, safe=""), version),
                "https://crates.io/crates/%s" % urllib.parse.quote(name, safe=""), note % "crates.io")
    if manager in ("maven", "gradle") and ":" in name and version:
        g, a = name.split(":", 1)
        gp = g.replace(".", "/")
        return ("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.jar" % (gp, a, version, a, version),
                "", note % "Maven Central repository layout")
    if manager == "nuget" and version:
        return ("https://www.nuget.org/api/v2/package/%s/%s" % (name, version),
                "https://www.nuget.org/packages/%s/%s" % (name, version), note % "NuGet.org")
    if manager == "go":
        return ("https://proxy.golang.org/%s/@v/%s.zip" % (name.lower(), version) if version else "",
                "https://pkg.go.dev/%s" % name, note % "Go module proxy")
    if manager == "pub":
        return "", "https://pub.dev/packages/%s" % urllib.parse.quote(name, safe=""), note % "pub.dev"
    if manager == "cargo":
        return "", "https://crates.io/crates/%s" % urllib.parse.quote(name, safe=""), note % "crates.io"
    return "", "", ""


# =============================================================================================== JSON guard
def _loads_json(text: str, what: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("%s: invalid JSON (%s)" % (what, exc))


def _loads_yaml(text: str, what: str) -> Any:
    try:
        return miniyaml.loads(text)
    except miniyaml.YamlError as exc:
        raise ValueError("%s: invalid YAML (%s)" % (what, exc))


def _loads_toml(text: str, what: str) -> Any:
    if tomllib is None:
        raise ValueError("%s: no TOML reader available in this interpreter" % what)
    if len(text.encode("utf-8", "replace")) > MAX_TOML_BYTES:
        raise ValueError("%s: TOML input larger than %d bytes" % (what, MAX_TOML_BYTES))
    try:
        return tomllib.loads(text)
    except Exception as exc:  # tomllib.TOMLDecodeError
        raise ValueError("%s: invalid TOML (%s)" % (what, exc))


def _xml_root(text: str, what: str):
    import xml.etree.ElementTree as ET
    from bts_sbom._internal import safe_xml
    if len(text.encode("utf-8", "replace")) > MAX_XML_BYTES:
        raise ValueError("%s: XML input larger than %d bytes" % (what, MAX_XML_BYTES))
    try:
        return safe_xml.fromstring(text)           # DTD / ENTITY refused wherever it sits in the document
    except safe_xml.DtdNotAllowed:
        raise ValueError("%s: DOCTYPE/ENTITY declarations are not allowed" % what)
    except ET.ParseError as exc:
        raise ValueError("%s: invalid XML (%s)" % (what, exc))


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


# =============================================================================================== pnpm-lock.yaml
_PNPM_KEY_RE = re.compile(r"^/?(?P<name>@[^/@]+/[^/@]+|[^/@]+)@(?P<version>[^(]+?)(?:\([^)]*\))*$")


def _pnpm_split(key: str) -> Optional[Tuple[str, str]]:
    m = _PNPM_KEY_RE.match(key.strip("'\""))
    if not m:
        return None
    return m.group("name"), m.group("version")


def parse_pnpm_lock(text: str, path: str = "") -> List[Dict[str, Any]]:
    """pnpm-lock.yaml, lockfileVersion 5.x/6.x ('packages' holds deps+dev flag) and 9.x ('importers' +
    'packages' + 'snapshots').  Direct = named under the root importer ('.') / top-level dependencies;
    everything else in 'packages' is, by construction, the rest of the resolved graph -> transitive."""
    doc = _loads_yaml(text, path or "pnpm-lock.yaml")
    if doc is None:
        return []
    if not isinstance(doc, dict):
        raise ValueError("%s: top level must be a mapping" % (path or "pnpm-lock.yaml"))
    direct_names: set = set()
    importers = doc.get("importers")
    if isinstance(importers, dict):
        root = importers.get(".") or next(iter(importers.values()), {}) if importers else {}
        for sect in ("dependencies", "devDependencies", "optionalDependencies"):
            direct_names |= set((root or {}).get(sect) or {})
    for sect in ("dependencies", "devDependencies", "optionalDependencies"):
        direct_names |= set(doc.get(sect) or {})
    packages = doc.get("packages")
    if not isinstance(packages, dict):
        return []
    snapshots = doc.get("snapshots") if isinstance(doc.get("snapshots"), dict) else {}
    # lockfileVersion 9: 'packages' keys are "name@version" but 'snapshots' keys carry the peer-dependency suffix
    # ("react-dom@18.2.0(react@18.2.0)"), so they are indexed by the key without it (the edges of every peer variant merge)
    snap_edges: Dict[str, Dict[str, Any]] = {}
    for sk, sv in snapshots.items():
        if isinstance(sv, dict) and isinstance(sv.get("dependencies"), dict):
            snap_edges.setdefault(re.sub(r"\(.*$", "", str(sk).strip("'\"")), {}).update(sv["dependencies"])
    out: List[Dict[str, Any]] = []
    for key, meta in packages.items():
        parsed = _pnpm_split(str(key))
        if not parsed:
            continue
        name, version = parsed
        meta = meta if isinstance(meta, dict) else {}
        edges = meta.get("dependencies") if isinstance(meta.get("dependencies"), dict) else None
        if edges is None:
            edges = snap_edges.get(re.sub(r"\(.*$", "", str(key).strip("'\"")), {})
        depends_on = [purl_for("npm", dn, str(dv).split("(", 1)[0]) for dn, dv in (edges or {}).items()]
        out.append(_entry(name, version, "pnpm", purl_for("pnpm", name, version),
                          direct=(name in direct_names), depends_on=depends_on,
                          evidence=["pnpm-lock.yaml packages entry %r" % key]))
    return out


# =================================================================================================== Podfile.lock
_POD_NAME_VER_RE = re.compile(r"^(?P<name>[^(]+?)\s*\((?P<version>[^)]+)\)\s*$")
_POD_DEP_RE = re.compile(r"^([^(\s]+)")


def _pod_root(name: str) -> str:
    return name.split("/", 1)[0].strip()


def parse_podfile_lock(text: str, path: str = "") -> List[Dict[str, Any]]:
    """Podfile.lock (CocoaPods): PODS is the FULL resolved graph (sub-items = that pod's own deps);
    DEPENDENCIES lists the Podfile's own direct pods, by name (no version)."""
    doc = _loads_yaml(text, path or "Podfile.lock")
    if doc is None:
        return []
    if not isinstance(doc, dict) or "PODS" not in doc:
        raise ValueError("%s: no PODS section" % (path or "Podfile.lock"))
    pods = doc.get("PODS") or []
    if not isinstance(pods, list):
        raise ValueError("%s: PODS must be a list" % (path or "Podfile.lock"))
    direct_section = doc.get("DEPENDENCIES")
    direct_names: Optional[set] = None
    if isinstance(direct_section, list):
        direct_names = set()
        for d in direct_section:
            spec = d if isinstance(d, str) else next(iter(d), "")
            m = _POD_NAME_VER_RE.match(spec) or None
            raw_name = m.group("name") if m else re.split(r"\s*\(", spec, 1)[0]
            # the FULL name: the Podfile asking for "Firebase/Analytics" does not make the "Firebase/Core" pod it pulls in
            # a direct dependency, so a subspec is never collapsed into its root here
            direct_names.add(raw_name.strip())
    checksums = doc.get("SPEC CHECKSUMS") if isinstance(doc.get("SPEC CHECKSUMS"), dict) else {}
    out: List[Dict[str, Any]] = []
    for item in pods:
        if isinstance(item, str):
            spec, subdeps = item, []
        elif isinstance(item, dict) and item:
            spec = next(iter(item))
            subdeps = item[spec] or []
        else:
            continue
        m = _POD_NAME_VER_RE.match(spec.strip())
        if not m:
            continue
        name, version = m.group("name").strip(), m.group("version").strip()
        depends_on = []
        for sd in subdeps if isinstance(subdeps, list) else []:
            sm = _POD_DEP_RE.match(str(sd).strip())
            if sm:
                depends_on.append(purl_for("cocoapods", _pod_root(sm.group(1))))
        direct = (name in direct_names) if direct_names is not None else None
        ev = ["Podfile.lock PODS entry %r" % spec]
        if name in checksums:
            ev.append("SPEC CHECKSUMS: " + checksums[name])
        out.append(_entry(name, version, "cocoapods", purl_for("cocoapods", name, version), direct=direct,
                          depends_on=depends_on, evidence=ev))
    return out


def podspec_license(text: str) -> List[str]:
    """Best-effort ``s.license`` / ``spec.license`` reader for a vendored *.podspec (Ruby DSL) - a single
    regex over a known, narrow pattern; never evaluates the file.  [] when nothing matches."""
    m = re.search(r"""(?:\bs|\bspec)\.license\s*=\s*(\{[^}]*\}|'[^']*'|"[^"]*")""", text)
    if not m:
        return []
    raw = m.group(1).strip()
    if raw[:1] in "'\"":
        return [raw[1:-1]] if len(raw) >= 2 else []
    tm = re.search(r"""[:'"]type[:'"]?\s*=>\s*['"]([^'"]+)['"]""", raw) or re.search(r"""type:\s*['"]([^'"]+)['"]""", raw)
    return [tm.group(1)] if tm else []


# =================================================================================================== Cartfile.resolved
_CARTFILE_RE = re.compile(r'^\s*(github|git|binary)\s+"([^"]+)"\s+"([^"]+)"\s*$')


def parse_cartfile_resolved(text: str, path: str = "") -> List[Dict[str, Any]]:
    """Cartfile.resolved (Carthage): one resolved spec+version per line.  Carthage records neither a
    dependency graph nor a direct/transitive bit in this file - every item is direct=None (honestly
    unknown), never guessed."""
    out: List[Dict[str, Any]] = []
    any_line = False
    for lineno, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _CARTFILE_RE.match(s)
        if not m:
            raise ValueError("%s: line %d is not a recognised Cartfile.resolved entry: %r"
                             % (path or "Cartfile.resolved", lineno, s[:80]))
        any_line = True
        kind, spec, version = m.groups()
        name = spec.rsplit("/", 1)[-1]
        home = ("https://github.com/%s" % spec) if kind == "github" else (spec if kind in ("git", "binary") else "")
        out.append(_entry(name, version, "carthage", purl_for("carthage", name, version), direct=None,
                          homepage=home if kind == "github" else "", download_location=home if kind != "github" else "",
                          evidence=["Cartfile.resolved: %s %r %r" % (kind, spec, version)]))
    if not any_line and text.strip():
        raise ValueError("%s: no recognised entries" % (path or "Cartfile.resolved"))
    return out


# =================================================================================================== Package.resolved
def parse_package_resolved(text: str, path: str = "") -> List[Dict[str, Any]]:
    """Swift Package Manager Package.resolved, format v1 (``object.pins``) or v2/v3 (top-level ``pins``).
    No dependency graph and no direct/transitive bit is recorded in this file -> direct=None."""
    doc = _loads_json(text, path or "Package.resolved")
    if not isinstance(doc, dict):
        raise ValueError("%s: top level must be an object" % (path or "Package.resolved"))
    pins = doc.get("pins")
    if pins is None and isinstance(doc.get("object"), dict):
        pins = doc["object"].get("pins")
    if pins is None:
        raise ValueError("%s: no 'pins' found (v1 'object.pins' or v2/v3 'pins')" % (path or "Package.resolved"))
    if not isinstance(pins, list):
        raise ValueError("%s: 'pins' must be a list" % (path or "Package.resolved"))
    out: List[Dict[str, Any]] = []
    for pin in pins:
        if not isinstance(pin, dict):
            continue
        name = str(pin.get("package") or pin.get("identity") or "").strip()
        if not name:
            continue
        state = pin.get("state") if isinstance(pin.get("state"), dict) else {}
        version = str(state.get("version") or "").strip()
        location = str(pin.get("location") or pin.get("repositoryURL") or "").strip()
        out.append(_entry(name, version, "swift", purl_for("swift", name, version), direct=None,
                          homepage=location, download_location=location,
                          evidence=["Package.resolved pin %r (%s)" % (name, "revision only" if not version and state.get("revision") else "version")]))
    return out


# =================================================================================================== pubspec.yaml / .lock
def parse_pubspec_yaml(text: str, path: str = "") -> List[Dict[str, Any]]:
    """pubspec.yaml: every declared dependency is direct by definition.  The version recorded is the
    RAW constraint as written (e.g. '^1.2.3') when the dependency is hosted/version-pinned; a git/path
    dependency has no version here and is recorded with version='' (never guessed)."""
    doc = _loads_yaml(text, path or "pubspec.yaml")
    if doc is None:
        return []
    if not isinstance(doc, dict):
        raise ValueError("%s: top level must be a mapping" % (path or "pubspec.yaml"))
    out: List[Dict[str, Any]] = []
    for section in ("dependencies", "dev_dependencies"):
        deps = doc.get(section)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            if name == "flutter" or name == "sdk":
                continue
            if isinstance(spec, dict):
                version, note = "", "git/path/sdk dependency (no version constraint in pubspec.yaml)"
            else:
                version = "" if spec in (None, "any") else str(spec).strip()
                note = "declared version constraint as written (may not be an exact/resolved version)"
            out.append(_entry(name, version, "pub", purl_for("pub", name, version) if version else "", direct=True,
                              evidence=["pubspec.yaml %s: %s" % (section, note)]))
    return out


def parse_pubspec_lock(text: str, path: str = "") -> List[Dict[str, Any]]:
    """pubspec.lock: the FULL resolved set, with an explicit 'dependency' field - 'direct main' / 'direct dev'
    / 'transitive' - so direct/transitive is proven by the file, never guessed."""
    doc = _loads_yaml(text, path or "pubspec.lock")
    if doc is None:
        return []
    packages = doc.get("packages") if isinstance(doc, dict) else None
    if not isinstance(packages, dict):
        raise ValueError("%s: no 'packages' mapping" % (path or "pubspec.lock"))
    out: List[Dict[str, Any]] = []
    for name, meta in packages.items():
        if not isinstance(meta, dict):
            continue
        version = str(meta.get("version") or "").strip()
        dep_flag = str(meta.get("dependency") or "").strip().lower()
        direct = True if dep_flag.startswith("direct") else (False if dep_flag == "transitive" else None)
        desc = meta.get("description") if isinstance(meta.get("description"), dict) else {}
        source = str(meta.get("source") or "")
        download = ""
        if source == "hosted" and desc.get("url"):
            download = "%s/packages/%s/versions/%s.tar.gz" % (str(desc["url"]).rstrip("/"), name, version or "")
        out.append(_entry(str(name), version, "pub", purl_for("pub", str(name), version), direct=direct,
                          download_location=download, homepage="",
                          evidence=["pubspec.lock packages.%s.dependency=%r" % (name, dep_flag or "(absent)")]))
    return out


# =================================================================================================== Chart.yaml / Chart.lock
def _parse_helm_chart(doc: Any, what: str) -> List[Dict[str, Any]]:
    if doc is None:
        return []
    if not isinstance(doc, dict):
        raise ValueError("%s: top level must be a mapping" % what)
    deps = doc.get("dependencies")
    if deps is None:
        return []
    if not isinstance(deps, list):
        raise ValueError("%s: 'dependencies' must be a list" % what)
    out: List[Dict[str, Any]] = []
    for d in deps:
        if not isinstance(d, dict):
            continue
        name = str(d.get("name") or "").strip()
        if not name:
            continue
        version = str(d.get("version") or "").strip()
        repo = str(d.get("repository") or "").strip()
        ev = ["%s dependencies entry %r (direct subchart only; Helm does not record transitive subcharts here)" % (what, name)]
        out.append(_entry(name, version, "helm", purl_for("helm", name, version), direct=True,
                          download_location=repo, homepage="", evidence=ev))
    return out


def parse_chart_yaml(text: str, path: str = "") -> List[Dict[str, Any]]:
    return _parse_helm_chart(_loads_yaml(text, path or "Chart.yaml"), path or "Chart.yaml")


def parse_chart_lock(text: str, path: str = "") -> List[Dict[str, Any]]:
    return _parse_helm_chart(_loads_yaml(text, path or "Chart.lock"), path or "Chart.lock")


# =================================================================================================== uv.lock
_UV_PKG_RE = re.compile(r"\[\[package\]\](.*?)(?=\n\[\[package\]\]|\Z)", re.DOTALL)
_UV_FIELD_RE = re.compile(r'^(name|version)\s*=\s*"([^"]*)"', re.MULTILINE)
_UV_SOURCE_RE = re.compile(r"^source\s*=\s*\{([^}]*)\}", re.MULTILINE)
_UV_DEP_NAME_RE = re.compile(r'name\s*=\s*"([^"]+)"')
_UV_DEPS_BLOCK_RE = re.compile(r"^dependencies\s*=\s*\[\s*\n(.*?)^\]", re.DOTALL | re.MULTILINE)
_UV_DEPS_INLINE_RE = re.compile(r"^dependencies\s*=\s*\[(.*)\]\s*$", re.MULTILINE)      # the whole array on one line


def _uv_from_toml(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    packages = data.get("package")
    if not isinstance(packages, list):
        return []
    version_by_name: Dict[str, str] = {}
    for pkg in packages:
        if isinstance(pkg, dict) and pkg.get("name") and pkg.get("version"):
            version_by_name.setdefault(str(pkg["name"]), str(pkg["version"]))
    direct_names: set = set()
    root_names: set = set()
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        src = pkg.get("source")
        if isinstance(src, dict) and ("virtual" in src or "editable" in src):
            if pkg.get("name"):
                root_names.add(str(pkg["name"]))
            for dep in (pkg.get("dependencies") or []):
                if isinstance(dep, dict) and dep.get("name"):
                    direct_names.add(str(dep["name"]))
            for grp in (pkg.get("dev-dependencies") or {}).values() if isinstance(pkg.get("dev-dependencies"), dict) else []:
                for dep in (grp or []):
                    if isinstance(dep, dict) and dep.get("name"):
                        direct_names.add(str(dep["name"]))
    out: List[Dict[str, Any]] = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version or str(name) in root_names:
            continue   # the root project itself (source = virtual/editable) is not a "dependency"
        name = str(name)
        deps = []
        for dep in (pkg.get("dependencies") or []):
            if isinstance(dep, dict) and dep.get("name"):
                dn = str(dep["name"])
                deps.append(purl_for("pypi", dn, version_by_name.get(dn, "")))
        direct = (name in direct_names) if direct_names else None
        out.append(_entry(name.lower(), str(version), "pypi", purl_for("pypi", name.lower(), str(version)),
                          direct=direct, depends_on=deps, evidence=["uv.lock [[package]] name=%r" % name]))
    return out


def _uv_regex_fallback(text: str, path: str) -> List[Dict[str, Any]]:
    blocks = _UV_PKG_RE.findall(text)
    if not blocks and "[[package]]" in text:
        raise ValueError("%s: could not locate any complete [[package]] block" % path)
    version_by_name: Dict[str, str] = {}
    parsed_blocks = []
    for block in blocks:
        fields = dict(_UV_FIELD_RE.findall(block))
        name, version = fields.get("name"), fields.get("version")
        if name and version:
            version_by_name.setdefault(name, version)
        parsed_blocks.append((fields, block))
    out: List[Dict[str, Any]] = []
    for fields, block in parsed_blocks:
        name, version = fields.get("name"), fields.get("version")
        if not name or not version:
            continue
        src_m = _UV_SOURCE_RE.search(block)
        if src_m and ("virtual" in src_m.group(1) or "editable" in src_m.group(1)):
            continue   # the root project itself - not a "dependency"
        deps = []
        dm = _UV_DEPS_BLOCK_RE.search(block) or _UV_DEPS_INLINE_RE.search(block)
        if dm:
            for dn in _UV_DEP_NAME_RE.findall(dm.group(1)):
                deps.append(purl_for("pypi", dn, version_by_name.get(dn, "")))
        out.append(_entry(name.lower(), version, "pypi", purl_for("pypi", name.lower(), version), direct=None,
                          depends_on=deps, evidence=["uv.lock [[package]] name=%r (regex fallback parser)" % name]))
    return out


def parse_uv_lock(text: str, path: str = "") -> List[Dict[str, Any]]:
    """uv.lock (PEP 751-adjacent uv-specific TOML).  Prefers ``tomllib``; falls back to a bounded regex
    reader when no TOML reader is available (this project's 3.10 floor; 3.11+ always has ``tomllib``).
    The regex fallback cannot see the root project's own dependency list, so ``direct`` stays None there."""
    if tomllib is not None:
        try:
            data = tomllib.loads(text)
        except Exception as exc:
            raise ValueError("%s: invalid TOML (%s)" % (path or "uv.lock", exc))
        return _uv_from_toml(data)
    return _uv_regex_fallback(text, path or "uv.lock")


# =================================================================================================== NuGet (XML)
def parse_packages_config(text: str, path: str = "") -> List[Dict[str, Any]]:
    root = _xml_root(text, path or "packages.config")
    if _local(root.tag) != "packages":
        raise ValueError("%s: expected a <packages> root element" % (path or "packages.config"))
    out: List[Dict[str, Any]] = []
    for pkg in root:
        if _local(pkg.tag) != "package":
            continue
        name = (pkg.get("id") or "").strip()
        version = (pkg.get("version") or "").strip()
        if not name:
            continue
        out.append(_entry(name, version, "nuget", purl_for("nuget", name, version), direct=True,
                          evidence=["packages.config <package id=%r version=%r>" % (name, version)]))
    return out


def parse_csproj(text: str, path: str = "") -> List[Dict[str, Any]]:
    """.csproj (SDK-style) <PackageReference Include=... Version=...>.  When Central Package Management
    is used the Version attribute is often absent from the csproj itself; version stays '' (never guessed
    from Directory.Packages.props without that file's own entry, which the caller may provide separately)."""
    root = _xml_root(text, path or "*.csproj")
    out: List[Dict[str, Any]] = []
    for el in root.iter():
        if _local(el.tag) != "PackageReference":
            continue
        name = (el.get("Include") or el.get("Update") or "").strip()
        if not name:
            continue
        version = (el.get("Version") or "").strip()
        if not version:
            for child in el:
                if _local(child.tag) == "Version" and (child.text or "").strip():
                    version = child.text.strip()
        ev = ["*.csproj <PackageReference Include=%r Version=%r>" % (name, version)]
        if not version:
            ev.append("version omitted - likely resolved via central package management (Directory.Packages.props)")
        out.append(_entry(name, version, "nuget", purl_for("nuget", name, version) if version else "",
                          direct=True, evidence=ev))
    return out


def parse_directory_packages_props(text: str, path: str = "") -> List[Dict[str, Any]]:
    root = _xml_root(text, path or "Directory.Packages.props")
    out: List[Dict[str, Any]] = []
    for el in root.iter():
        if _local(el.tag) != "PackageVersion":
            continue
        name = (el.get("Include") or "").strip()
        version = (el.get("Version") or "").strip()
        if not name:
            continue
        out.append(_entry(name, version, "nuget", purl_for("nuget", name, version), direct=True,
                          evidence=["Directory.Packages.props <PackageVersion Include=%r Version=%r> "
                                    "(central package management pin)" % (name, version)]))
    return out


# =================================================================================================== setup.py (static AST)
def _literal_strings(node: ast.AST) -> List[str]:
    """Flatten a literal list/tuple of string constants (optionally built with '+').  Anything that is
    not a plain literal is simply skipped - never executed, never guessed."""
    try:
        val = ast.literal_eval(node)
    except Exception:
        return []
    if isinstance(val, str):
        return [val]
    if isinstance(val, (list, tuple)):
        return [str(x) for x in val if isinstance(x, str)]
    return []


_PEP508_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(==\s*([^\s,;]+))?")


def parse_setup_py(text: str, path: str = "") -> List[Dict[str, Any]]:
    """setup.py: find install_requires=[...] / requires=[...] keyword literals inside a top-level call
    (conventionally setup(...)) via ``ast.parse`` + ``ast.literal_eval`` of just that sub-node.  The file
    is NEVER executed or imported.  Only an exact '==' pin yields a version; anything else keeps version=''
    (the name is still reported - never silently dropped)."""
    try:
        tree = ast.parse(text, filename=path or "setup.py")
    except SyntaxError as exc:
        raise ValueError("%s: could not parse as Python source (%s)" % (path or "setup.py", exc))
    found: List[ast.AST] = []

    class _Visitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            for kw in node.keywords or []:
                if kw.arg in ("install_requires", "requires", "setup_requires", "tests_require") and kw.value is not None:
                    found.append(kw.value)
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign) -> None:
            names = {t.id for t in node.targets if isinstance(t, ast.Name)}
            if names & {"install_requires", "requires"}:
                found.append(node.value)
            self.generic_visit(node)

    _Visitor().visit(tree)
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for node in found:
        for spec in _literal_strings(node):
            m = _PEP508_RE.match(spec)
            if not m:
                continue
            name = m.group(1)
            version = (m.group(3) or "").strip()
            key = (name.lower(), version)
            if key in seen:
                continue
            seen.add(key)
            out.append(_entry(name.lower(), version, "pypi", purl_for("pypi", name.lower(), version) if version else "",
                              direct=True, evidence=["setup.py literal dependency spec %r (static AST read, not executed)" % spec]))
    return out


# =================================================================================================== Unity
def parse_unity_manifest(text: str, path: str = "") -> List[Dict[str, Any]]:
    doc = _loads_json(text, path or "Packages/manifest.json")
    if not isinstance(doc, dict):
        raise ValueError("%s: top level must be an object" % (path or "Packages/manifest.json"))
    deps = doc.get("dependencies")
    if not isinstance(deps, dict):
        return []
    out: List[Dict[str, Any]] = []
    for name, version in deps.items():
        version = str(version).strip()
        out.append(_entry(str(name), version, "unity", purl_for("unity", str(name), version), direct=True,
                          evidence=["Packages/manifest.json dependencies.%s" % name]))
    return out


def parse_unity_packages_lock(text: str, path: str = "") -> List[Dict[str, Any]]:
    doc = _loads_json(text, path or "Packages/packages-lock.json")
    if not isinstance(doc, dict):
        raise ValueError("%s: top level must be an object" % (path or "Packages/packages-lock.json"))
    deps = doc.get("dependencies")
    if not isinstance(deps, dict):
        return []
    out: List[Dict[str, Any]] = []
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        version = str(meta.get("version") or "").strip()
        depth = meta.get("depth")
        direct = (depth == 0) if isinstance(depth, int) else None
        sub = meta.get("dependencies") if isinstance(meta.get("dependencies"), dict) else {}
        depends_on = [purl_for("unity", dn, str(dv)) for dn, dv in sub.items()]
        url = str(meta.get("url") or "")
        out.append(_entry(str(name), version, "unity", purl_for("unity", str(name), version), direct=direct,
                          depends_on=depends_on, download_location=url if url.startswith("http") else "",
                          evidence=["Packages/packages-lock.json dependencies.%s (depth=%r)" % (name, depth)]))
    return out


# =================================================================================================== package-lock.json license
def package_lock_licenses(text: str) -> Dict[Tuple[str, str], List[str]]:
    """Per-(name, version) "license"/"licenses" field already embedded by npm in a v2/v3 package-lock.json
    'packages' map (copied there from the dependency's own package.json).  Returns {} on anything that is
    not a parseable package-lock.json - the caller already parsed it once for coordinates and only calls
    this as a second, independent, best-effort pass."""
    try:
        data = json.loads(text)
    except Exception:
        return {}
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict):
        return {}
    out: Dict[Tuple[str, str], List[str]] = {}
    for pkg_path, meta in packages.items():
        if pkg_path == "" or not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if not version:
            continue
        segs = [s for s in str(pkg_path).split("node_modules/") if s]
        name = segs[-1].strip("/") if segs else pkg_path
        lic = meta.get("license")
        lics = meta.get("licenses")
        found: List[str] = []
        if isinstance(lic, str) and lic.strip():
            found = [lic.strip()]
        elif isinstance(lics, list):
            for entry in lics:
                if isinstance(entry, dict) and entry.get("type"):
                    found.append(str(entry["type"]))
                elif isinstance(entry, str):
                    found.append(entry)
        if found:
            out[(name, str(version))] = found
    return out
