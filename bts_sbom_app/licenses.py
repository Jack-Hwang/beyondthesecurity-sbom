"""Open-source license discovery with provenance, SPDX normalisation, categories and policy checks.

Resolution chain per component (first hit wins, the winning source is recorded in ``license_source``):
  1. ``lockfile``   - license fields carried by package-lock.json (v2/v3) and composer.lock
  2. ``deps.dev``   - Google Open Source Insights (npm, PyPI, Go, Maven, Cargo, NuGet, RubyGems)
  3. ``registry:*`` - PyPI JSON / npm registry (only when deps.dev has no answer)
Honesty: a component without evidence stays unresolved (``license == ""``); nothing is guessed from the name.
Source-tree discovery (``scan_tree``) finds the project's own LICENSE files, SPDX headers and vendored licenses.
This module reports obligations and conflicts as engineering signals - it is not legal advice.
"""
from __future__ import annotations

import concurrent.futures as cf
import os
import re
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from . import audit, net, resilience
from .util import read_json, read_text, write_json

# --------------------------------------------------------------------------- SPDX normalisation
CATEGORY: Dict[str, str] = {}
for _c, _ids in {
    "permissive": "MIT MIT-0 Apache-2.0 BSD-2-Clause BSD-3-Clause BSD-3-Clause-Clear 0BSD ISC Zlib BSL-1.0 Python-2.0 "
                  "PSF-2.0 X11 Unicode-DFS-2016 Unicode-3.0 NCSA Artistic-2.0 WTFPL BlueOak-1.0.0 CC-BY-4.0 CC-BY-3.0 "
                  "OpenSSL libpng-2.0 Apache-1.1 JSON UPL-1.0 PostgreSQL MS-PL Ruby HPND curl BSD-4-Clause "
                  "AFL-2.1 AFL-3.0 Artistic-1.0 Artistic-1.0-Perl MIT-CMU BSD-1-Clause ZPL-2.1 OFL-1.1",
    "public-domain": "Unlicense CC0-1.0 SAX-PD",
    "weak-copyleft": "LGPL-2.0-only LGPL-2.0-or-later LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0-only LGPL-3.0-or-later "
                     "MPL-1.1 MPL-2.0 EPL-1.0 EPL-2.0 CDDL-1.0 CDDL-1.1 CPL-1.0 EUPL-1.1 EUPL-1.2 MS-RL OSL-3.0 "
                     "CC-BY-SA-4.0 CC-BY-SA-3.0",
    "strong-copyleft": "GPL-2.0-only GPL-2.0-or-later GPL-3.0-only GPL-3.0-or-later",
    "network-copyleft": "AGPL-3.0-only AGPL-3.0-or-later SSPL-1.0 OSL-3.0-network",
    "restricted": "BUSL-1.1 Elastic-2.0 CC-BY-NC-4.0 CC-BY-NC-SA-4.0 Commons-Clause",
}.items():
    for _i in _ids.split():
        CATEGORY[_i] = _c
CATEGORY["OSL-3.0"] = "weak-copyleft"
_LOWER_IDS = {k.lower(): k for k in CATEGORY}

_ALIASES = {
    "mit license": "MIT", "the mit license": "MIT", "mit/x11": "MIT", "expat": "MIT",
    "apache 2.0": "Apache-2.0", "apache-2": "Apache-2.0", "apache 2": "Apache-2.0", "apache2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0", "apache license, version 2.0": "Apache-2.0", "apache software license": "Apache-2.0",
    "apache license": "Apache-2.0", "the apache software license, version 2.0": "Apache-2.0", "asl 2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause", "bsd license": "BSD-3-Clause", "new bsd": "BSD-3-Clause", "new bsd license": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause", "bsd 3-clause": "BSD-3-Clause", "bsd-3-clause license": "BSD-3-Clause",
    "simplified bsd": "BSD-2-Clause", "bsd-2": "BSD-2-Clause", "bsd 2-clause": "BSD-2-Clause", "freebsd": "BSD-2-Clause",
    "isc license": "ISC", "isc license (iscl)": "ISC", "zlib license": "Zlib", "python software foundation license": "PSF-2.0",
    "psf": "PSF-2.0", "public domain": "Unlicense", "the unlicense": "Unlicense", "unlicense": "Unlicense",
    "cc0": "CC0-1.0", "cc0 1.0": "CC0-1.0", "mpl 2.0": "MPL-2.0", "mozilla public license 2.0": "MPL-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0", "mpl-2.0 license": "MPL-2.0",
    "gpl": "GPL-3.0-or-later", "gplv2": "GPL-2.0-only", "gplv2+": "GPL-2.0-or-later", "gplv3": "GPL-3.0-only",
    "gplv3+": "GPL-3.0-or-later", "gpl-2.0": "GPL-2.0-only", "gpl-2.0+": "GPL-2.0-or-later", "gpl-3.0": "GPL-3.0-only",
    "gpl-3.0+": "GPL-3.0-or-later", "gnu general public license v2": "GPL-2.0-only",
    "gnu general public license v3": "GPL-3.0-only", "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "lgpl": "LGPL-3.0-or-later", "lgpl-2.1": "LGPL-2.1-only", "lgpl-2.1+": "LGPL-2.1-or-later", "lgpl-3.0": "LGPL-3.0-only",
    "lgpl-3.0+": "LGPL-3.0-or-later", "lgplv2.1": "LGPL-2.1-only", "lgplv3": "LGPL-3.0-only",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    "gnu lesser general public license v2 or later (lgplv2+)": "LGPL-2.1-or-later",
    "agpl": "AGPL-3.0-or-later", "agpl-3.0": "AGPL-3.0-only", "agpl-3.0+": "AGPL-3.0-or-later", "agplv3": "AGPL-3.0-only",
    "epl-1.0": "EPL-1.0", "epl-2.0": "EPL-2.0", "eclipse public license 1.0": "EPL-1.0",
    "eclipse public license 2.0": "EPL-2.0", "eclipse public license - v 2.0": "EPL-2.0",
    "cddl": "CDDL-1.0", "common development and distribution license": "CDDL-1.0",
    "boost software license 1.0": "BSL-1.0", "boost": "BSL-1.0", "artistic-2.0": "Artistic-2.0",
    "unicode-dfs": "Unicode-DFS-2016", "bsd-3-clause-new": "BSD-3-Clause", "bsd-2-clause-freebsd": "BSD-2-Clause",
}
_DEPRECATED = {"gpl-2.0": "GPL-2.0-only", "gpl-3.0": "GPL-3.0-only", "lgpl-2.1": "LGPL-2.1-only",
               "lgpl-3.0": "LGPL-3.0-only", "agpl-3.0": "AGPL-3.0-only", "gpl-2.0+": "GPL-2.0-or-later",
               "gpl-3.0+": "GPL-3.0-or-later", "lgpl-2.1+": "LGPL-2.1-or-later", "lgpl-3.0+": "LGPL-3.0-or-later",
               "gpl-2.0-with-classpath-exception": "GPL-2.0-only WITH Classpath-exception-2.0"}
_NOISE = {"", "unknown", "noassertion", "none", "n/a", "unlicensed", "see license in license", "see license file",
          "custom", "other", "proprietary", "commercial", "nan", "null", "undefined"}
_EXPR_SPLIT = re.compile(r"(\(|\)|\s+(?:AND|OR|WITH)\s+|\s*/\s*|\s*;\s*|\s*\|\s*)", re.I)
_WELL_FORMED = re.compile(r"^(?:LicenseRef-[A-Za-z0-9.\-]+|[A-Za-z][A-Za-z0-9.+]*(?:-[A-Za-z0-9.+]+)+|[A-Za-z]+[0-9][A-Za-z0-9.+]*)$")
_NOT_AN_ID = {"like", "style", "ish", "derived", "compatible", "license", "licence", "custom", "other", "unknown", "see", "various",
              "proprietary", "commercial", "free", "open", "source", "public", "domain", "and", "or", "with", "file", "in"}
_EXTRA_ALIASES = {"lgplv2+": "LGPL-2.0-or-later", "lgplv2": "LGPL-2.0-only", "lgplv2.1+": "LGPL-2.1-or-later", "lgplv3+": "LGPL-3.0-or-later",
                  "psfl": "PSF-2.0", "python software foundation license": "PSF-2.0", "afl-2.1": "AFL-2.1", "afl-3.0": "AFL-3.0"}


def _one(tok: str) -> str:
    """One license name -> SPDX id, or '' when it is neither a known alias nor a well-formed SPDX identifier."""
    t = tok.strip()
    while t.startswith("(") and t.count("(") > t.count(")"):      # strip only UNBALANCED outer parens, so
        t = t[1:].strip()                                          # "GNU ... v3 (GPLv3)" keeps its own pair
    while t.endswith(")") and t.count(")") > t.count("("):
        t = t[:-1].strip()
    if not t:
        return ""
    low = t.lower()
    low = re.sub(r"\s+license$", "", low) if low not in _ALIASES and low.endswith(" license") else low
    for table in (_ALIASES, _EXTRA_ALIASES, _DEPRECATED):
        if low in table:
            return table[low]
    if low in _LOWER_IDS:
        return _LOWER_IDS[low]
    if t.endswith("+") and t[:-1].lower() in _LOWER_IDS:
        return _LOWER_IDS[t[:-1].lower()].replace("-only", "-or-later")
    # a well-formed SPDX identifier we simply have no category for (Artistic-1.0-Perl, AFL-2.1, MIT-CMU, LicenseRef-x):
    # it IS evidence of a specific license, so it is kept verbatim; its category stays "unknown" (-> policy review)
    if re.match(r"^[al]?gplv\d", low):            # "LGPLv2+" is a nickname, not an SPDX id: leave it unmapped instead of passing it through
        return ""
    if _WELL_FORMED.match(t) and not (set(re.split(r"[-.]", low)) & _NOT_AN_ID):
        return t
    return ""


def _strip_outer(expr: str) -> str:
    while expr.startswith("(") and expr.endswith(")"):
        depth = 0
        for i, ch in enumerate(expr):
            depth += ch == "("
            depth -= ch == ")"
            if depth == 0 and i < len(expr) - 1:
                return expr
        expr = expr[1:-1].strip()
    return expr


def normalize(raw: Any) -> Tuple[str, str]:
    """raw license value -> (SPDX expression or '', status: spdx|mapped|unmapped|empty).

    Accepts strings, lists (composer), dicts (npm legacy ``{type: ...}``). Compound expressions keep their structure -
    parentheses are preserved because ``A AND (B OR C)`` and ``A AND B OR C`` mean different things.
    """
    if raw is None:
        return "", "empty"
    if isinstance(raw, dict):
        raw = raw.get("type") or raw.get("name") or raw.get("license") or ""
    if isinstance(raw, (list, tuple)):
        parts = [normalize(x)[0] for x in raw]
        parts = [(("(%s)" % p) if " " in p else p) for p in parts if p]
        return (" OR ".join(parts), "mapped") if parts else ("", "unmapped" if raw else "empty")
    s = str(raw).strip()
    if s.lower() in _NOISE:
        return "", "empty"
    direct = _one(s)
    if direct:
        return direct, ("spdx" if direct.lower() == s.lower() else "mapped")
    out: List[str] = []
    depth = 0
    prev_atom = False
    exact = True
    for t in _EXPR_SPLIT.split(s):
        ts = (t or "").strip()
        if not ts:
            continue
        up = ts.upper()
        if ts == "(":
            if prev_atom:
                out.append("OR")
            out.append("(")
            depth += 1
            prev_atom = False
        elif ts == ")":
            depth -= 1
            if depth < 0:
                return "", "unmapped"
            out.append(")")
            prev_atom = True
        elif up in ("AND", "OR", "WITH"):
            out.append(up)
            prev_atom = False
        elif ts in ("/", ";", "|"):
            out.append("OR")
            prev_atom = False
        elif out and out[-1] == "WITH":                 # exception identifier is kept verbatim
            out.append(ts)
            prev_atom = True
        else:
            sp = _one(ts)
            if not sp:
                return "", "unmapped"
            exact = exact and sp.lower() == ts.strip("()").lower()
            if prev_atom:
                out.append("OR")
            out.append(sp)
            prev_atom = True
    if depth != 0 or not out or out[-1] in ("AND", "OR", "WITH"):
        return "", "unmapped"
    expr = _strip_outer(re.sub(r"\(\s+", "(", re.sub(r"\s+\)", ")", " ".join(out))))
    return expr, ("spdx" if exact else "mapped")


_RANK = ["public-domain", "permissive", "weak-copyleft", "strong-copyleft", "network-copyleft", "restricted"]


def _parse_tokens(toks: List[str]) -> Any:
    """expr := term (OR term)* ; term := factor (AND factor)* ; factor := '(' expr ')' | atom [WITH exception]"""
    pos = 0

    def peek() -> Optional[str]:
        return toks[pos] if pos < len(toks) else None

    def expr() -> Any:
        nonlocal pos
        kids = [term()]
        while peek() == "OR":
            pos += 1
            kids.append(term())
        return kids[0] if len(kids) == 1 else ("or", kids)

    def term() -> Any:
        nonlocal pos
        kids = [factor()]
        while peek() == "AND":
            pos += 1
            kids.append(factor())
        return kids[0] if len(kids) == 1 else ("and", kids)

    def factor() -> Any:
        nonlocal pos
        t = peek()
        if t == "(":
            pos += 1
            e = expr()
            if peek() == ")":
                pos += 1
            return e
        pos += 1
        exc = None
        if peek() == "WITH":
            pos += 1
            exc = peek()
            pos += 1
        return ("atom", t, exc)

    return expr()


def _cat_tree(node: Any) -> str:
    if node[0] == "atom":
        base = CATEGORY.get(node[1], "unknown")
        if node[2] and base == "strong-copyleft" and any(w in node[2].lower() for w in ("classpath", "linking")):
            return "weak-copyleft"
        return base
    kids = [_cat_tree(k) for k in node[1]]
    if node[0] == "and":                                  # all must be satisfied -> most restrictive (unknown poisons)
        return "unknown" if "unknown" in kids else max(kids, key=_RANK.index)
    known = [k for k in kids if k != "unknown"]           # OR: the licensee may pick the most permissive known branch
    return min(known, key=_RANK.index) if known else "unknown"


def category(expr: str) -> str:
    """Category of an SPDX expression: OR -> most permissive branch, AND -> most restrictive, WITH exception -> weak."""
    if not expr:
        return "unknown"
    toks = re.findall(r"\(|\)|\bAND\b|\bOR\b|\bWITH\b|[^\s()]+", expr)
    try:
        return _cat_tree(_parse_tokens(toks))
    except (IndexError, ValueError, TypeError):
        return "unknown"


OBLIGATIONS = {
    "public-domain": [], "permissive": ["keep copyright + license notice"],
    "weak-copyleft": ["keep notices", "share modifications to the library itself", "allow relinking (LGPL)"],
    "strong-copyleft": ["keep notices", "offer corresponding source of the combined work when distributed"],
    "network-copyleft": ["keep notices", "offer source to network users too (AGPL/SSPL)"],
    "restricted": ["commercial/field-of-use restrictions - legal review required"], "unknown": ["identify the license first"],
}

DEFAULT_POLICY = {"distribution": "binary",       # binary | saas | internal
                  "deny": ["network-copyleft", "restricted"], "review": ["strong-copyleft", "weak-copyleft", "unknown"]}


def policy_findings(components: List[Dict[str, Any]], policy: Optional[Dict[str, Any]] = None,
                    project_license: str = "") -> List[Dict[str, Any]]:
    pol = dict(DEFAULT_POLICY, **(policy or {}))
    dist = pol.get("distribution", "binary")
    deny = set(pol.get("deny") or [])
    review = set(pol.get("review") or [])
    if dist == "internal":                       # no distribution -> copyleft source-offer duties do not trigger
        review -= {"strong-copyleft", "weak-copyleft"}
    if dist == "saas":
        deny |= {"network-copyleft"}
    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for c in components:
        by_cat.setdefault(c.get("license_category") or "unknown", []).append(c)
    out: List[Dict[str, Any]] = []
    for cat, comps in sorted(by_cat.items()):
        if cat in deny:
            sev = "HIGH"
        elif cat in review:
            sev = "MEDIUM" if cat != "weak-copyleft" else "LOW"
        else:
            continue
        out.append({"category": cat, "severity": sev, "count": len(comps),
                    "components": sorted({c["name"] + "@" + c["version"] for c in comps})[:25],
                    "verdict": "deny" if cat in deny else "review", "obligations": OBLIGATIONS.get(cat, []),
                    "detail": "%d component(s) are %s for a %s distribution" % (len(comps), cat, dist)})
    pc = category(project_license) if project_license else ""
    if pc in ("permissive", "public-domain") and dist != "internal":
        gpl = [c for c in components if c.get("license_category") == "strong-copyleft"]
        if gpl:
            out.append({"category": "conflict", "severity": "HIGH", "count": len(gpl), "verdict": "conflict",
                        "components": sorted({c["name"] + "@" + c["version"] for c in gpl})[:25], "obligations": [],
                        "detail": "project license %s (%s) is combined with strong-copyleft dependencies; "
                                  "distribution would require the combined work to follow the copyleft terms" % (project_license, pc)})
    if pc == "strong-copyleft" and dist == "binary":
        # the PROJECT'S OWN duty (measured on u-boot: GPL-2.0-or-later project — the duty existed in law but was
        # invisible in every surface, because component findings dominate the loop)
        out.append({"category": "project-copyleft", "severity": "MEDIUM", "count": 1, "verdict": "review",
                    "components": [], "obligations": ["offer the corresponding source of the project itself",
                                                      "keep copyright and license notices"],
                    "detail": "the project itself is licensed %s (%s): distributing it in binary form requires "
                              "offering its corresponding source; this duty holds regardless of the dependency list"
                              % (project_license, pc)})
    return out


# --------------------------------------------------------------------------- lockfile licenses
def lockfile_licenses(root: str) -> Dict[Tuple[str, str], Any]:
    """{(canonical_name, version): raw license (str | list | dict)} from package-lock.json (v2/v3) and composer.lock files."""
    out: Dict[Tuple[str, str], Any] = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in ("node_modules", ".git", "vendor")]
        for fn in fns:
            fp = os.path.join(dp, fn)
            low = fn.lower()
            if low in ("package-lock.json", "npm-shrinkwrap.json"):
                doc = read_json(fp, {}) or {}
                for k, v in (doc.get("packages") or {}).items():
                    if not k or not isinstance(v, dict):
                        continue
                    name = v.get("name") or k.split("node_modules/")[-1]
                    if v.get("license") and v.get("version"):
                        out[(name.lower(), v["version"])] = v["license"]
            elif low == "composer.lock":
                doc = read_json(fp, {}) or {}
                for sec in ("packages", "packages-dev"):
                    for p in doc.get(sec) or []:
                        lic = p.get("license")
                        if lic and p.get("name") and p.get("version"):
                            out[(p["name"].lower(), str(p["version"]).lstrip("v"))] = lic
    return out


# --------------------------------------------------------------------------- remote lookups
_DEPSDEV = {"pypi": "pypi", "npm": "npm", "go": "go", "maven": "maven", "crates.io": "cargo", "nuget": "nuget",
            "rubygems": "rubygems"}


def _depsdev(eco: str, name: str, version: str, meta: Optional[Dict[str, Any]] = None) -> Optional[str]:
    sysname = _DEPSDEV.get(eco.lower())
    if not sysname:
        return None
    ver = version
    if sysname == "go" and not ver.startswith("v"):
        ver = "v" + ver
    url = "https://api.deps.dev/v3/systems/%s/packages/%s/versions/%s" % (
        sysname, urllib.parse.quote(name, safe=""), urllib.parse.quote(ver, safe=""))
    oc = net.http_json_oc(url)
    if meta is not None and oc.state != resilience.SUCCESS:
        meta["deps.dev"] = {"state": oc.state, "reason": oc.reason}          # C07: why we never asked / got nothing
    if not isinstance(oc.data, dict):
        return None
    lic = oc.data.get("licenses") or []
    lic = [x for x in lic if x and x.lower() not in ("non-standard", "noassertion")]
    return " OR ".join(lic) if lic else None


_POM_LICENSE = re.compile(r"<license>\s*<name>\s*([^<]+?)\s*</name>", re.I)
_POM_PARENT = re.compile(r"<parent>\s*<groupId>\s*([^<]+?)\s*</groupId>\s*<artifactId>\s*([^<]+?)\s*</artifactId>\s*<version>\s*([^<]+?)\s*</version>", re.I)


def _maven_pom(name: str, version: str, depth: int = 3) -> Optional[Any]:
    """License names from the artifact's POM on Maven Central; inherited from the parent POM when the artifact declares none."""
    if ":" not in name or depth <= 0:
        return None
    g, a = name.split(":", 1)
    txt = net.http_text("https://repo1.maven.org/maven2/%s/%s/%s/%s-%s.pom" % (g.replace(".", "/"), a, version, a, version))
    if not txt:
        return None
    names = _POM_LICENSE.findall(re.sub(r"<!--.*?-->", "", txt, flags=re.S))
    if names:
        return names
    m = _POM_PARENT.search(txt)
    return _maven_pom("%s:%s" % (m.group(1), m.group(2)), m.group(3), depth - 1) if m else None


def _registry(eco: str, name: str, version: str, extra: bool = True, meta: Optional[Dict[str, Any]] = None) -> Optional[Any]:
    """Registry-specific lookup. ``extra`` enables the wider fallbacks (npm legacy ``licenses`` array, Maven Central POM).
    ``meta`` (C07) collects {state, reason} per failed source so the caller can say WHY nothing was learned."""
    e = eco.lower()
    if e == "pypi":
        oc = net.http_json_oc("https://pypi.org/pypi/%s/%s/json" % (urllib.parse.quote(name), urllib.parse.quote(version)))
        if meta is not None and oc.state != resilience.SUCCESS:
            meta["registry:pypi"] = {"state": oc.state, "reason": oc.reason}
        doc = oc.data
        info = (doc or {}).get("info") or {}
        raw = info.get("license_expression") or info.get("license") or ""
        if raw and len(str(raw)) <= 120:
            return str(raw)
        for cl in info.get("classifiers") or []:
            if cl.startswith("License :: OSI Approved :: "):
                return cl.split("::")[-1].strip()
    elif e == "npm":
        oc = net.http_json_oc("https://registry.npmjs.org/%s/%s" % (urllib.parse.quote(name, safe="@"), urllib.parse.quote(version)))
        if meta is not None and oc.state != resilience.SUCCESS:
            meta["registry:npm"] = {"state": oc.state, "reason": oc.reason}
        doc = oc.data
        if extra:
            return (doc or {}).get("license") or (doc or {}).get("licenses") or None      # old packages: [{"type": "MIT", "url": ...}]
        return (doc or {}).get("license") or None
    elif e == "maven" and extra:
        return _maven_pom(name, version)
    return None


CACHE_FILE = "licenses_raw.json"


def resolve(components: List[Dict[str, Any]], root: str, *, online: bool = True, cache_dir: Optional[str] = None,
            workers: int = 8, ttl_s: float = 7 * 86400, max_remote: int = 4000, extra_registries: bool = True,
            sources: Tuple[str, ...] = ("lockfile", "deps.dev", "registry")) -> Dict[str, Any]:
    """Fill license fields of ``components`` in place; return stats {by_source, resolved, total, remote_lookups, ...}.

    The on-disk cache stores the RAW evidence a source returned ({raw, source, extra}); normalisation runs at read time, so an
    improved normaliser applies immediately and never hides behind a cached outcome. A cached MISS ("no evidence") is only
    trusted for ``ttl_s`` and only if it was recorded with at least the fallbacks that are enabled now.
    """
    stats: Dict[str, Any] = {"by_source": {}, "resolved": 0, "total": len(components), "unmapped_raw": {},
                             "remote_lookups": 0, "cache_hits": 0, "offline": not online, "extra_registries": extra_registries}
    cpath = os.path.join(cache_dir, CACHE_FILE) if cache_dir else None
    cache: Dict[str, Any] = read_json(cpath, {}) if cpath else {}
    lock = threading.Lock()
    lf = lockfile_licenses(root) if "lockfile" in sources else {}
    todo: List[Dict[str, Any]] = []

    def apply(c: Dict[str, Any], raw: Any, src: str) -> bool:
        if not raw:
            return False
        expr, _st = normalize(raw)
        if not expr:
            with lock:
                stats["unmapped_raw"][str(raw)[:60]] = stats["unmapped_raw"].get(str(raw)[:60], 0) + 1
            c["license_raw"] = str(raw)[:120]
            return False
        c["license"], c["license_source"], c["license_raw"] = expr, src, str(raw)[:120]
        c["license_category"] = category(expr)
        with lock:
            stats["by_source"][src] = stats["by_source"].get(src, 0) + 1
        return True

    def ckey(c: Dict[str, Any]) -> str:
        return "%s:%s@%s" % (c["ecosystem"].lower(), c["name"].lower(), c["version"])

    for c in components:
        raw = lf.get((c["name"].lower(), c["version"]))
        if raw and apply(c, raw, "lockfile"):
            continue
        hit = cache.get(ckey(c))
        if hit and hit.get("raw"):
            stats["cache_hits"] += 1
            if apply(c, hit["raw"], hit.get("source", "cache")):
                continue
            if not online:
                continue
            if hit.get("extra") or not extra_registries:      # raw evidence is unmappable and nothing wider to try
                continue
        elif hit and not hit.get("raw") and time.time() - hit.get("ts", 0) < ttl_s and (hit.get("extra") or not extra_registries):
            stats["cache_hits"] += 1
            continue
        todo.append(c)

    def look(c: Dict[str, Any]) -> Tuple[Dict[str, Any], Any, str, bool, Dict[str, Any]]:
        fails_before = net.thread_access_failures()
        first: Tuple[Any, str] = (None, "")
        blocked: Dict[str, Any] = {}                          # C07: {source: {state, reason}} for the asks that never happened
        for src, fn in (("deps.dev", _depsdev), ("registry", lambda e, n, v, meta=None: _registry(e, n, v, extra_registries, meta))):
            if src not in sources:
                continue
            raw = fn(c["ecosystem"], c["name"], c["version"], blocked)
            label = "deps.dev" if src == "deps.dev" else "registry:" + c["ecosystem"].lower()
            if raw and normalize(raw)[0]:
                return c, raw, label, False, {}
            if raw and first[0] is None:
                first = (raw, label)                          # keep unreadable evidence for the report, keep looking
        return c, first[0], first[1], net.thread_access_failures() > fails_before, blocked  # True: some lookup could not be made

    if online and todo:
        todo = todo[:max_remote]
        with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            for c, raw, src, unavailable, blocked in ex.map(look, todo):
                stats["remote_lookups"] += 1
                apply(c, raw, src)
                if unavailable and not raw:
                    # a source could not be reached (outage, or the circuit breaker was open): that is "could not check", not
                    # "no license" - caching it as a miss would hide the component from every run for the next ttl_s
                    stats["lookup_unavailable"] = stats.get("lookup_unavailable", 0) + 1
                    for label, why in (blocked or {}).items():     # C07: name WHY - circuit_open, http_500, ...
                        stats.setdefault("lookup_blocked_reasons", {}).setdefault(str(why.get("reason") or "unknown"), 0)
                        stats["lookup_blocked_reasons"][str(why.get("reason") or "unknown")] += 1
                        break                                     # one reason per component: the first blocked source
                    continue
                cache[ckey(c)] = {"raw": raw, "source": src, "extra": extra_registries, "ts": time.time()}
        if cpath:
            write_json(cpath, cache)
    for c in components:
        for k in ("license", "license_source", "license_raw"):
            c.setdefault(k, "")
        c.setdefault("license_category", category(c.get("license", "")))
        if c.get("license"):
            stats["resolved"] += 1
    stats["resolved_rate"] = round(stats["resolved"] / len(components), 3) if components else None
    stats["net"] = {k: net.STATS[k] for k in ("requests", "failures")}
    return stats


# --------------------------------------------------------------------------- source-tree discovery
_FILE_SIGS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("AGPL-3.0-only", re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE\s+Version 3", re.I)),
    ("LGPL-3.0-only", re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 3", re.I)),
    ("LGPL-2.1-only", re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 2\.1", re.I)),
    ("GPL-3.0-only", re.compile(r"GNU GENERAL PUBLIC LICENSE\s+Version 3", re.I)),
    ("GPL-2.0-only", re.compile(r"GNU GENERAL PUBLIC LICENSE\s+Version 2", re.I)),
    ("Apache-2.0", re.compile(r"Apache License\s+Version 2\.0", re.I)),
    ("MPL-2.0", re.compile(r"Mozilla Public License,? (?:Version |v\. ?)2\.0", re.I)),
    ("EPL-2.0", re.compile(r"Eclipse Public License\s*-?\s*v ?2\.0", re.I)),
    ("EPL-1.0", re.compile(r"Eclipse Public License\s*-?\s*v ?1\.0", re.I)),
    ("BSL-1.0", re.compile(r"Boost Software License", re.I)),
    ("Unlicense", re.compile(r"This is free and unencumbered software released into the public domain", re.I)),
    ("ISC", re.compile(r"Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee", re.I)),
    ("BSD-3-Clause", re.compile(r"Redistribution and use in source and binary forms.*?Neither the name", re.I | re.S)),
    ("BSD-2-Clause", re.compile(r"Redistribution and use in source and binary forms.*?THIS SOFTWARE IS PROVIDED", re.I | re.S)),
    ("MIT", re.compile(r"Permission is hereby granted, free of charge, to any person obtaining a copy", re.I)),
    ("Zlib", re.compile(r"This software is provided 'as-is', without any express or implied warranty", re.I)),
]
EXCERPT_CHARS = 3000
_LICENSE_FILE = re.compile(r"^(licen[cs]e|copying|copyright|notice|unlicense)([._-].*)?$", re.I)
_SPDX_TAG = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+\-() ]+?(?:\s+(?:AND|OR|WITH)\s+[A-Za-z0-9.+\-]+)*)\s*(?:\*/|-->|$)", re.M)
_SKIP = {"node_modules", ".git", "__pycache__", "dist", "build", ".venv", "venv", "target"}
_SRC_EXT = {".c", ".h", ".cc", ".cpp", ".hpp", ".py", ".js", ".ts", ".java", ".go", ".rs", ".rb", ".php", ".cs", ".kt", ".swift", ".sh"}


def detect_text(text: str) -> str:
    head = text[:12000]
    m = re.search(r"SPDX-License-Identifier:\s*(\S+)", head)
    if m:
        expr, _ = normalize(m.group(1))
        if expr:
            return expr
    for spdx, rx in _FILE_SIGS:
        if rx.search(head):
            if spdx == "GPL-3.0-only" and re.search(r"or \(at your option\) any later version", head, re.I):
                return "GPL-3.0-or-later"
            return spdx
    return ""


def scan_tree(root: str, *, max_files: int = 600) -> Dict[str, Any]:
    """Find the project's own license files, SPDX header tags and nested (vendored) license files."""
    files: List[Dict[str, Any]] = []
    tags: Dict[str, int] = {}
    scanned = 0
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in _SKIP]
        depth = os.path.relpath(dp, root).count(os.sep) + (0 if dp == root else 1)
        for fn in fns:
            fp = os.path.join(dp, fn)
            rel = os.path.relpath(fp, root).replace("\\", "/")
            stem = os.path.splitext(fn)[0]
            if _LICENSE_FILE.match(fn) or _LICENSE_FILE.match(stem):
                body = read_text(fp, 40000)
                det = detect_text(body)
                item = {"file": rel, "depth": depth, "license": det, "detected": bool(det)}
                if not det and body.strip():
                    item["excerpt"] = body.strip()[:EXCERPT_CHARS]      # evidence for a later council review (the work copy may be gone by then)
                files.append(item)
            elif scanned < max_files and os.path.splitext(fn)[1].lower() in _SRC_EXT:
                scanned += 1
                head = read_text(fp, 4000)
                for m in _SPDX_TAG.finditer(head):
                    expr, _ = normalize(m.group(1).strip())
                    if expr:
                        tags[expr] = tags.get(expr, 0) + 1
    root_files = [f for f in files if f["depth"] == 0]
    project = next((f["license"] for f in root_files if f["license"]), "")
    if not project and tags:
        project = max(tags, key=lambda k: tags[k])
    return {"project_license": project, "project_license_source": ("root license file" if any(f["license"] for f in root_files)
                                                                    else ("spdx header majority" if tags else "")),
            "license_files": files[:80], "vendored": [f for f in files if f["depth"] > 0][:40],
            "spdx_header_counts": tags, "source_files_scanned": scanned}


# --------------------------------------------------------------------------- audit sampling (BSA-AC-118x)
def audit_sample(components: List[Dict[str, Any]], *, frac: float = 0.1, seed: int = 0, min_per_source: int = 1) -> Dict[str, Any]:
    """A stratified review queue over RESOLVED components (``license`` truthy), grouped by the already-recorded
    ``license_source`` (``lockfile`` / ``deps.dev`` / ``registry:*`` / ``cache``). A source whose true error rate is
    higher than the others must not hide behind a good aggregate resolution rate: this samples at least ``frac``
    (default 10%, minimum ``min_per_source``) of EACH source's resolved components, deterministically (the same
    ``seed`` draws the same components from a source whose membership has not changed) - so a source with a 20%+
    true error rate has a good chance of surfacing a wrong entry even while the overall resolution rate looks fine.
    A source with 0 resolved components samples 0.

    Returns ``{frac, seed, min_per_source, sources, by_source: {source: resolved_count},
    sampled: {source: sampled_count}, queue: [component, ...]}`` - ``queue`` holds shallow copies of the sampled
    components themselves (plus ``audit_reason``), ready to hand to a reviewer; nothing is looked up again.
    """
    def _source_key(c: Dict[str, Any]) -> str:
        return str(c.get("license_source") or "unknown")

    resolved = [c for c in components if c.get("license")]
    by_source = {src: len(items) for src, items in audit.group_by(resolved, _source_key).items()}
    sample = audit.stratified_sample(resolved, _source_key, frac=frac, seed=seed, minimum=min_per_source)
    queue = [dict(c, audit_reason="stratified %s%% sample of resolution source %r (seed %s)" % (int(round(frac * 100)), src, seed))
             for src, items in sorted(sample.items()) for c in items]
    return {"frac": frac, "seed": seed, "min_per_source": min_per_source, "sources": sorted(by_source),
            "by_source": by_source, "sampled": {k: len(v) for k, v in sample.items()}, "queue": queue}
