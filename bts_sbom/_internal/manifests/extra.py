# vendored from common/manifests/extra.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
Additional ecosystem lockfile/manifest parsers — Rust (Cargo.lock), Ruby
(Gemfile.lock), PHP (composer.lock), Python (Pipfile.lock), Maven (pom.xml),
and Python project declarations (pyproject.toml with [tool.poetry] section).

Each returns DetectedPackage objects with an ecosystem tag that OsvScanner maps to
the OSV.dev ecosystem name (cargo→crates.io, rubygems→RubyGems, composer→Packagist,
pypi→PyPI, maven→Maven), so adding a parser here directly widens how many of a
project's real dependencies get an authoritative OSV vulnerability query.

HONESTY: only pinned/resolved versions are emitted. A pom.xml dependency whose
version is a `${property}` (not a literal) is skipped — never guessed — so the SBOM
never carries a fabricated coordinate.

pyproject.toml: Poetry version specs are typically version ranges (``^2.28``), not
pinned versions.  We strip leading range operators to obtain the floor version
(e.g. ``^2.28.0`` → ``2.28.0``) and mark those entries with confidence="medium".
Exact pins (no leading operator) get confidence="high".  These entries are most
useful when no poetry.lock is present; when a lockfile IS present its exact versions
take priority through the package_extractor source-priority merge.
"""
import json
import re
from typing import List, Any

from bts_sbom._internal.models import DetectedPackage
from bts_sbom._internal.manifests import cargo as raw_manifests

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


def _mk(name, version, ecosystem, purl, relationship="direct"):
    return DetectedPackage(
        name=name, version=version, ecosystem=ecosystem, purl=purl,
        source=f"manifest:{ecosystem}", provenance=[f"manifest:{ecosystem}"],
        relationship=relationship, depth=0, confidence="high")


# ── Rust: Cargo.lock (TOML) ───────────────────────────────────────────────────
def _cargo_root_direct(path: str):
    """Names declared by the sibling Cargo.toml, or None when no sibling
    manifest can be read. Cargo.lock itself does not mark which entries are
    the project's own declarations, so the sibling manifest is the only
    honest source for the direct set. [dependencies], [dev-dependencies],
    [build-dependencies] and [workspace.dependencies] all count (all are
    declared by this project rather than pulled in by another crate)."""
    if not path:
        return None
    import os
    ct = os.path.join(os.path.dirname(path), "Cargo.toml")
    if not os.path.isfile(ct):
        return None
    if tomllib is None:
        return None
    try:
        with open(ct, "rb") as fh:                 # tomllib requires binary
            data = tomllib.load(fh)
    except Exception:
        return None
    names = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        block = data.get(section)
        if isinstance(block, dict):
            names |= {str(n).lower() for n in block}
    for section in ("workspace", "target"):
        block = data.get(section)
        if isinstance(block, dict):
            deps = block.get("dependencies")
            if isinstance(deps, dict):
                names |= {str(n).lower() for n in deps}
    return names


def parse_cargo_lock(text: str, path: str = "") -> List[Any]:
    """Parse Cargo.lock (the resolved transitive closure) — round-2 E1.

    Transitive status: EVERY entry in the lockfile is returned, classified as
    `direct` when the sibling Cargo.toml declares it, `transitive` otherwise.
    When no sibling Cargo.toml can be read the relationship is honestly
    `unknown` — it used to default to `direct` for every entry, which
    mislabeled a resolved graph of hundreds of crates as first-level
    dependencies. For workspace projects the later lockfile-facts pass
    (BFS from the workspace members) overrides this with graph-derived
    depths when it can resolve the roots."""
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except Exception:
        return []
    direct = _cargo_root_direct(path)
    out = []
    for pkg in data.get("package", []) or []:
        name, ver = pkg.get("name"), pkg.get("version")
        if name and ver:
            if direct is None:
                rel = "unknown"
            elif str(name).lower() in direct:
                rel = "direct"
            else:
                rel = "transitive"
            dp = _mk(name, ver, "cargo", f"pkg:cargo/{name}@{ver}")
            dp.relationship = rel
            dp.depth = 1 if rel == "transitive" else 0
            out.append(dp)
    return out


def parse_cargo_toml(text: str, path: str = "") -> List[Any]:
    """Parse only explicitly pinned Cargo manifest dependencies.

    In Cargo, ``serde = "1.0"`` is a compatible range rather than an installed
    version. Only ``=1.2.3`` pins are safe to send to OSV without running Cargo's
    resolver. Normal projects should be scanned from Cargo.lock.
    """
    out = []
    for dep in raw_manifests.parse_cargo_toml(text):
        spec = str(dep.get("version") or "").strip()
        if not spec.startswith("="):
            continue
        version = spec[1:].strip()
        if not re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", version):
            continue
        name = dep.get("name")
        if name:
            out.append(_mk(name, version, "cargo", f"pkg:cargo/{name}@{version}"))
    return out


def parse_gradle_build(text: str, path: str = "") -> List[Any]:
    """Parse literal direct Maven coordinates from Groovy/Kotlin Gradle files.

    Dynamic versions and property references are deliberately skipped. A
    ``gradle.lockfile`` remains the authoritative source for the resolved graph.
    """
    out = []
    for dep in raw_manifests.parse_gradle_build(text):
        group = str(dep.get("group") or "").strip()
        artifact = str(dep.get("name") or "").strip()
        version = str(dep.get("version") or "").strip()
        if not group or not artifact or not version:
            continue
        if any(token in version for token in ("$", "{", "}", "+", "[", "]", "(")):
            continue
        name = f"{group}:{artifact}"
        out.append(_mk(name, version, "maven",
                       f"pkg:maven/{group}/{artifact}@{version}"))
    return out


# ── Ruby: Gemfile.lock (custom text; GEM/specs section) ───────────────────────
# a spec line is indented exactly 4 spaces: `    name (version)`; deeper (6-space)
# lines are dependency CONSTRAINTS (no exact version) and are skipped.
_GEM_SPEC_RE = re.compile(r"^    ([A-Za-z0-9_.\-]+) \(([0-9][^)]*)\)\s*$")


def parse_gemfile_lock(text: str, path: str = "") -> List[Any]:
    out, in_specs = [], False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs and stripped and not line.startswith(" "):
            in_specs = False        # left the GEM block
        if in_specs:
            m = _GEM_SPEC_RE.match(line)
            if m:
                name, ver = m.group(1), m.group(2).strip()
                out.append(_mk(name, ver, "rubygems", f"pkg:gem/{name}@{ver}"))
    return out


# ── PHP: composer.lock (JSON) ─────────────────────────────────────────────────
def parse_composer_lock(text: str, path: str = "") -> List[Any]:
    try:
        data = json.loads(text)
    except Exception:
        return []
    out = []
    for key, rel in (("packages", "direct"), ("packages-dev", "transitive")):
        for pkg in data.get(key, []) or []:
            name, ver = pkg.get("name"), pkg.get("version")
            if not name or not ver:
                continue
            ver = ver[1:] if re.match(r"^v\d", ver) else ver   # strip a leading 'v'
            out.append(_mk(name, ver, "composer", f"pkg:composer/{name}@{ver}", rel))
    return out


# ── Python: Pipfile.lock (JSON) ───────────────────────────────────────────────
def parse_pipfile_lock(text: str, path: str = "") -> List[Any]:
    try:
        data = json.loads(text)
    except Exception:
        return []
    out = []
    for key, rel in (("default", "direct"), ("develop", "transitive")):
        for name, spec in (data.get(key, {}) or {}).items():
            ver = (spec or {}).get("version", "") if isinstance(spec, dict) else ""
            ver = ver.lstrip("=") if ver else ""
            if name and ver:
                low = name.lower()
                out.append(_mk(low, ver, "pypi", f"pkg:pypi/{low}@{ver}", rel))
    return out


# ── Maven: pom.xml (XML; only literal versions) ───────────────────────────────
def parse_pom_xml(text: str, path: str = "") -> List[Any]:
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
    except Exception:
        return []

    def _local(tag):   # strip the {namespace}
        return tag.rsplit("}", 1)[-1]

    out = []
    for dep in root.iter():
        if _local(dep.tag) != "dependency":
            continue
        g = a = v = None
        for child in dep:
            lt = _local(child.tag)
            if lt == "groupId":
                g = (child.text or "").strip()
            elif lt == "artifactId":
                a = (child.text or "").strip()
            elif lt == "version":
                v = (child.text or "").strip()
        # skip unresolved (property/parent-managed) versions — never fabricate one
        if g and a and v and not v.startswith("${"):
            name = f"{g}:{a}"
            out.append(_mk(name, v, "maven", f"pkg:maven/{g}/{a}@{v}"))
    return out


# ── JavaScript: yarn.lock (custom text) ───────────────────────────────────────
_YARN_VER_RE = re.compile(r'^\s+version:?\s+"?([^"\s]+)"?\s*$')


def parse_yarn_lock(text: str, path: str = "") -> List[Any]:
    """Each block starts with an unindented `spec, spec:` header (name@range) and
    carries an indented `version "x"` line. The package name is everything before
    the LAST '@' in the first spec (keeps a leading '@' for scoped packages)."""
    out, current = [], None
    for line in text.splitlines():
        if line and not line[0].isspace() and not line.lstrip().startswith("#") \
                and line.rstrip().endswith(":"):
            header = line.rstrip()[:-1]
            first = header.split(",")[0].strip().strip('"')
            at = first.rfind("@")
            current = first[:at] if at > 0 else first
        elif current:
            m = _YARN_VER_RE.match(line)
            if m:
                out.append(_mk(current, m.group(1), "npm", f"pkg:npm/{current}@{m.group(1)}"))
                current = None
    return out


# ── .NET: packages.lock.json (NuGet) ──────────────────────────────────────────
def parse_nuget_lock(text: str, path: str = "") -> List[Any]:
    try:
        data = json.loads(text)
    except Exception:
        return []
    out, seen = [], set()
    for _fw, deps in (data.get("dependencies", {}) or {}).items():
        if not isinstance(deps, dict):
            continue
        for name, info in deps.items():
            ver = (info or {}).get("resolved") if isinstance(info, dict) else None
            if not name or not ver or (name, ver) in seen:
                continue
            seen.add((name, ver))
            rel = "direct" if (info.get("type") == "Direct") else "transitive"
            out.append(_mk(name, ver, "nuget", f"pkg:nuget/{name}@{ver}", rel))
    return out


# ── Go: go.sum (full transitive set, exact versions) ──────────────────────────
def parse_go_sum(text: str, path: str = "") -> List[Any]:
    out, seen = [], set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2 or not parts[1].startswith("v"):
            continue
        name = parts[0]
        ver = parts[1].split("/go.mod")[0]
        if (name, ver) in seen:
            continue
        seen.add((name, ver))
        out.append(_mk(name, ver, "go", f"pkg:golang/{name}@{ver}"))
    return out


# ── Gradle: gradle.lockfile (group:artifact:version=...) ──────────────────────
def parse_gradle_lock(text: str, path: str = "") -> List[Any]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coord = line.split("=", 1)[0]
        parts = coord.split(":")
        if len(parts) == 3:
            g, a, v = parts
            out.append(_mk(f"{g}:{a}", v, "maven", f"pkg:maven/{g}/{a}@{v}"))
    return out


# ── Dart/Flutter: pubspec.lock (Pub, YAML) ────────────────────────────────────
# (vendored note: pubspec.lock is YAML; the platform parsed it through the
#  third-party pyyaml library, which bts-sbom does NOT vendor in order to stay
#  stdlib-only. This parser therefore yields [] here — an honest empty result,
#  the same answer the platform gave whenever pyyaml was absent.)
def parse_pubspec_lock(text: str, path: str = "") -> List[Any]:
    return []


# ── Elixir: mix.lock (Hex) ────────────────────────────────────────────────────
_MIX_RE = re.compile(r'"[^"]+"\s*:\s*\{\s*:hex\s*,\s*:(\w+)\s*,\s*"([^"]+)"')


def parse_mix_lock(text: str, path: str = "") -> List[Any]:
    out = []
    for m in _MIX_RE.finditer(text):
        name, ver = m.group(1), m.group(2)
        out.append(_mk(name, ver, "hex", f"pkg:hex/{name}@{ver}"))
    return out


# ── Python: pyproject.toml — [tool.poetry] section ───────────────────────────
# Range-operator characters that Poetry uses before a version: ^, ~, >=, <=, >, <, !=
_POETRY_VER_STRIP_RE = re.compile(r"^[^0-9*]+")


def _poetry_spec_to_version(spec) -> tuple:
    """Return (version_str, confidence) from a Poetry dependency spec.

    Specs can be:
    - A plain string: ``"2.28.0"`` (exact, high) or ``"^2.28.0"`` (range, medium).
    - A dict with a ``"version"`` key (inline table): ``{version = "^2.28.0"}``.
    - A dict without ``"version"`` (e.g. git/path dep): skip entirely.

    We strip leading range operators to obtain the floor version and report
    confidence="medium" when we had to do so, confidence="high" when the spec
    was already an exact pin.
    """
    if isinstance(spec, dict):
        raw = spec.get("version", "")
        if not raw:
            return ("", "")          # git/path dep — no version available
    elif isinstance(spec, str):
        raw = spec.strip()
    else:
        return ("", "")

    if not raw or raw in ("*", ""):
        return ("", "")

    # Detect whether the spec starts with any range operator.
    has_operator = bool(_POETRY_VER_STRIP_RE.match(raw))
    ver = _POETRY_VER_STRIP_RE.sub("", raw).strip()
    if not ver:
        return ("", "")

    confidence = "medium" if has_operator else "high"
    return (ver, confidence)


def _mk_pypi(name, version, relationship, confidence="high"):
    low = name.lower()
    pkg = DetectedPackage(
        name=low, version=version, ecosystem="pypi",
        purl=f"pkg:pypi/{low}@{version}",
        source="manifest:pypi",
        provenance=["manifest:pypi"],
        relationship=relationship,
        depth=0,
        confidence=confidence,
    )
    return pkg


def parse_pyproject_toml(text: str, path: str = "") -> List[Any]:
    """Parse dependency declarations from pyproject.toml.

    Two backends are supported:

    **Poetry** (``[tool.poetry.*]``):
    - ``[tool.poetry.dependencies]``                  → direct
    - ``[tool.poetry.dev-dependencies]``              → transitive  (Poetry < 1.2)
    - ``[tool.poetry.group.<g>.dependencies]``        → direct if group=="main", else transitive
                                                        (Poetry 1.2+ groups)

    **PEP 621** (``[project.dependencies]``): used by hatch, flit, uv, setuptools
    and any build-backend that follows PEP 621.  Only ``==``-pinned entries produce
    a high-confidence record; range-specifier entries are skipped (no floor version
    is safe to infer for PEP 508 strings without a resolver).

    Only packages where a usable version string can be extracted are emitted.
    The ``python`` pseudo-dependency is always skipped.
    """
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except Exception:
        return []

    out: List[Any] = []
    seen: set = set()   # (name_lower, version) already added

    def _add(name: str, spec, relationship: str) -> None:
        if name.lower() == "python":
            return
        ver, conf = _poetry_spec_to_version(spec)
        if not ver:
            return
        key = (name.lower(), ver)
        if key in seen:
            return
        seen.add(key)
        out.append(_mk_pypi(name, ver, relationship, confidence=conf))

    # --- Poetry backend ---
    poetry = (data.get("tool") or {}).get("poetry") or {}
    if poetry:
        # Direct dependencies ([tool.poetry.dependencies])
        for name, spec in (poetry.get("dependencies") or {}).items():
            _add(name, spec, "direct")

        # Dev dependencies — legacy flat section ([tool.poetry.dev-dependencies])
        for name, spec in (poetry.get("dev-dependencies") or {}).items():
            _add(name, spec, "transitive")

        # Groups — Poetry 1.2+ ([tool.poetry.group.<group>.dependencies])
        for group_name, group_data in (poetry.get("group") or {}).items():
            if not isinstance(group_data, dict):
                continue
            rel = "direct" if group_name == "main" else "transitive"
            for name, spec in (group_data.get("dependencies") or {}).items():
                _add(name, spec, rel)

    # --- PEP 621 backend ([project.dependencies]) ---
    # PEP 508 dependency strings: "requests==2.28.0", "flask>=2.0,<3.0", etc.
    # We only emit entries with an exact ``==`` pin; range specifiers are skipped
    # because extracting a floor version from PEP 508 without a lock file is not
    # reliable and would produce false coordinates for CVE matching.
    project_deps = (data.get("project") or {}).get("dependencies") or []
    if isinstance(project_deps, list):
        # PEP 508 name: letters, digits, dashes, underscores, dots; no spaces.
        _pep508_pin = re.compile(
            r'^([A-Za-z0-9]([A-Za-z0-9._\-]*[A-Za-z0-9])?)'   # package name
            r'\s*==\s*'                                          # == operator only
            r'([^\s,;]+)',                                       # version string
            re.ASCII,
        )
        for dep_str in project_deps:
            if not isinstance(dep_str, str):
                continue
            m = _pep508_pin.match(dep_str.strip())
            if not m:
                continue
            name, ver = m.group(1), m.group(3).strip()
            if not name or not ver:
                continue
            key = (name.lower(), ver)
            if key in seen:
                continue
            seen.add(key)
            out.append(_mk_pypi(name, ver, "direct", confidence="high"))

    return out

# ── C/C++: conanfile.txt / conanfile.py / vcpkg.json (manifests only) ────────
# Automotive C/C++ package managers. Only EXACT pins are emitted (ranges are
# skipped for the same reason as Cargo: a floor version is not an installed
# version and would produce false CVE coordinates). Lockfiles (conan.lock)
# carry the resolved graph and are parsed separately.
_CONAN_REF = None


def _conan_ref_re():
    global _CONAN_REF
    if _CONAN_REF is None:
        import re as _re
        _CONAN_REF = _re.compile(
            r"^([A-Za-z0-9_+.-]+)/(\d[^\s#@]*)(?:@[^\s#]+)?(?:#[^\s#]+)?")
    return _CONAN_REF


def parse_conanfile_txt(text: str, path: str = "") -> List[Any]:
    """conanfile.txt [requires] section: name/version[@user/channel][#rrev]."""
    out = []
    in_requires = False
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("["):
            in_requires = s.lower().startswith("[requires")
            continue
        if not in_requires:
            continue
        m = _conan_ref_re().match(s)
        if m and re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", m.group(2)):
            name, ver = m.group(1), m.group(2)
            out.append(_mk(name, ver, "conan", f"pkg:conan/{name}@{ver}"))
    return out


def parse_conanfile_py(text: str, path: str = "") -> List[Any]:
    """conanfile.py: requires = "name/version@..." (single or tuple/list)."""
    out = []
    seen = set()
    for m in re.finditer(r'"([^"\n]+/\d[^"\n]*)"', text):
        ref = m.group(1).strip()
        hit = _conan_ref_re().match(ref)
        if hit and ref not in seen \
                and re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", hit.group(2)):
            seen.add(ref)
            name, ver = hit.group(1), hit.group(2)
            out.append(_mk(name, ver, "conan", f"pkg:conan/{name}@{ver}"))
    return out


def parse_vcpkg_json(text: str, path: str = "") -> List[Any]:
    """vcpkg.json manifest: "dependencies": {"name": "version" | {"version>=":}}.

    Only exact ``version-string`` / bare-string pins are emitted; ``version>=``
    minimums are ranges and are skipped (no lockfile = no resolved graph)."""
    try:
        import json as _json
        data = _json.loads(text)
    except Exception:
        return []
    out = []
    deps = data.get("dependencies") or []
    if isinstance(deps, list):                      # name-only list
        for d in deps:
            if isinstance(d, str):
                out.append(_mk(d, "", "vcpkg", f"pkg:vcpkg/{d}",
                               relationship="direct"))
        return out
    if isinstance(deps, dict):
        for name, spec in deps.items():
            if isinstance(spec, str) and spec:
                out.append(_mk(name, spec, "vcpkg", f"pkg:vcpkg/{name}@{spec}"))
            elif isinstance(spec, dict):
                ver = spec.get("version-string") or spec.get("version")
                if ver and re.fullmatch(r"[0-9][0-9A-Za-z.+-]*", str(ver)):
                    out.append(_mk(name, str(ver), "vcpkg",
                                   f"pkg:vcpkg/{name}@{ver}"))
    return out
