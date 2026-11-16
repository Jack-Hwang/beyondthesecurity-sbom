"""SBOM/vulnerability engine adapter around the ``bts_sbom`` core (OSV.dev based).

All coupling to ``bts_sbom`` lives in this module so a core upgrade (another session is advancing it) only
needs this file re-verified (tests/test_engine_contract.py pins the contract).

What this layer adds on top of the core's native OSV-Scanner shaped result:
  * normalisation into flat component / vulnerability records with stable ids and relative file paths;
  * alias de-duplication (GHSA + CVE + PYSEC of one advisory become one finding);
  * fixed versions computed ONLY from ECOSYSTEM/SEMVER ranges that actually contain the installed version
    (the core's guided remediation mixes in git commit SHAs - measured: requests -> a 40-hex "version" -
    so it is deliberately not used);
  * CVSS v3 scoring from the vector, falling back to the advisory label, never guessing.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

from . import cvss, versions
from .util import clip, uniq

_PRIORITY = ("CVE-", "GHSA-", "PYSEC-", "RUSTSEC-", "GO-", "OSV-")


def _import_core():
    """Import the SBOM core. ``BTS_SBOM_PATH`` (a checkout or a pinned snapshot) takes precedence over whatever is installed,
    so a loop pass can run against an immutable core while the core itself is being developed elsewhere."""
    if "bts_sbom" in sys.modules:
        return sys.modules["bts_sbom"]
    extra = os.environ.get("BTS_SBOM_PATH", "")
    if extra and os.path.isdir(os.path.join(extra, "bts_sbom")):
        sys.path.insert(0, extra)
    try:
        import bts_sbom  # noqa: F401
        return sys.modules["bts_sbom"]
    except ImportError:
        raise ImportError("bts_sbom is required: pip install bts-sbom (or set BTS_SBOM_PATH to its checkout)")


def core_version() -> str:
    return str(getattr(_import_core(), "__version__", "unknown"))


def core_info() -> Dict[str, str]:
    m = _import_core()
    return {"version": str(getattr(m, "__version__", "unknown")), "path": os.path.dirname(os.path.dirname(os.path.abspath(m.__file__)))}


def scan(path: str, *, offline: bool = False, scanner: Any = None) -> Dict[str, Any]:
    """Run the core OSV scan on a file or directory and return its native result dict."""
    if scanner is None:
        core = _import_core()
        scanner = core.OsvScanner(offline=offline)
    return scanner.scan(path, with_licenses=False, guided_remediation=False)


def _canon(eco: str, name: str) -> str:
    n = str(name or "").strip()
    if str(eco).lower() == "pypi":
        return re.sub(r"[-_.]+", "-", n).lower()
    return n.lower()


def _same_pkg(pk: Dict[str, Any], name: str, eco: str) -> bool:
    pe = str(pk.get("ecosystem") or "").split(":", 1)[0].lower()
    return pe == str(eco).lower() and _canon(eco, pk.get("name", "")) == _canon(eco, name)


def fixed_versions(osv: Dict[str, Any], name: str, eco: str, version: str) -> Tuple[List[str], bool]:
    """(fixed_version_candidates, affects_this_version).

    Candidates are the ``fixed`` events of ECOSYSTEM/SEMVER ranges whose [introduced, fixed) interval contains
    ``version``. When the advisory only enumerates affected ``versions`` we fall back to the smallest fixed
    event above ``version``. GIT ranges (commit SHAs) are ignored.
    """
    fixes: List[str] = []
    affected = False
    all_fixed: List[str] = []
    listed = False
    for aff in osv.get("affected") or []:
        if not _same_pkg(aff.get("package") or {}, name, eco):
            continue
        if version in (aff.get("versions") or []):
            listed = True
        for rg in aff.get("ranges") or []:
            if rg.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            intro: Optional[str] = None
            intervals: List[Tuple[str, Optional[str], str]] = []
            for ev in rg.get("events") or []:
                if "introduced" in ev:
                    intro = ev["introduced"]
                elif "fixed" in ev:
                    intervals.append((intro or "0", ev["fixed"], "fixed"))
                    intro = None
                elif "last_affected" in ev:
                    intervals.append((intro or "0", ev["last_affected"], "last"))
                    intro = None
            if intro is not None:
                intervals.append((intro, None, "open"))
            for lo, hi, kind in intervals:
                if kind == "fixed" and versions.is_version(hi):
                    all_fixed.append(hi)  # type: ignore[arg-type]
                lo_ok = lo in ("0", "") or versions.compare(version, lo) >= 0
                if hi is None:
                    hi_ok = True
                elif kind == "fixed":
                    hi_ok = versions.compare(version, hi) < 0
                else:
                    hi_ok = versions.compare(version, hi) <= 0
                if lo_ok and hi_ok:
                    affected = True
                    if kind == "fixed" and versions.is_version(hi):
                        fixes.append(hi)  # type: ignore[arg-type]
    if not fixes and listed:
        affected = True
        nxt = versions.min_greater_or_equal(all_fixed, version)
        if nxt and versions.compare(nxt, version) > 0:
            fixes.append(nxt)
    return uniq(fixes), affected


def _primary_id(ids: List[str]) -> str:
    for pref in _PRIORITY:
        for i in ids:
            if i.startswith(pref):
                return i
    return ids[0] if ids else "?"


def _merge_vulns(raw: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    """Union-find over id+aliases: one group per real advisory."""
    parent: Dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for v in raw:
        ids = [v.get("id", "")] + list(v.get("aliases") or [])
        ids = [i for i in ids if i]
        for i in ids[1:]:
            parent[find(i)] = find(ids[0])
        if ids:
            find(ids[0])
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for v in raw:
        if v.get("id"):
            groups.setdefault(find(v["id"]), []).append(v)
    return list(groups.values())


_RUBY_PLATFORM = re.compile(r"^(\d[^-]*)-((?:x86|x64|arm|aarch64|java|jruby|mingw|mswin|universal|darwin|linux|ruby)\S*)$", re.I)
_GO_REQ = re.compile(r"^\s*(?:require\s+)?(\S+)\s+(v\d\S*)", re.M)


def _canonical_version(eco: str, ver: str) -> Tuple[str, str]:
    """(version, platform). Bundler lists one lock entry per platform (ffi 1.17.3-arm64-darwin); they are ONE package version."""
    if eco.lower() == "rubygems":
        m = _RUBY_PLATFORM.match(ver)
        if m:
            return m.group(1), m.group(2)
    return ver, ""


def _go_selected(source_path: str) -> Optional[set]:
    """(module, version) pairs selected by the sibling go.mod (Go's MVS result), or None when there is no go.mod."""
    gm = os.path.join(os.path.dirname(source_path), "go.mod")
    try:
        with open(gm, "r", encoding="utf-8", errors="replace") as fh:
            txt = fh.read()
    except OSError:
        return None
    return {(m.group(1), m.group(2)) for m in _GO_REQ.finditer(txt)}


def normalize(native: Dict[str, Any], root: str, *, dedupe: bool = True, merge_ruby_platforms: bool = True,
              go_mvs: bool = True) -> Dict[str, Any]:
    """Native OSV-Scanner shaped result -> {components, vulns, sources, status, notes, adjustments}.

    The three switches exist so each correction can be measured as one loop variable; every correction is counted in
    ``adjustments`` so nothing is removed silently:
      dedupe                same (advisory, package, version) reported by several manifests -> one finding listing all files
      merge_ruby_platforms  ``ffi 1.17.3-arm64-darwin`` and its siblings -> one package version
      go_mvs                go.sum-only module versions (never selected by the build) are not installed packages
    """
    root = os.path.abspath(root)

    def rel(p: str) -> str:
        try:
            r = os.path.relpath(p, root if os.path.isdir(root) else os.path.dirname(root))
        except ValueError:
            r = p
        return r.replace("\\", "/")

    adj = {"duplicate_findings_merged": 0, "ruby_platform_variants_merged": 0, "go_sum_only_dropped": 0}
    comps: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    vulns: List[Dict[str, Any]] = []
    seen_vuln: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    sources: List[Dict[str, Any]] = []
    for res in native.get("results") or []:
        src = res.get("source") or {}
        f = rel(src.get("path", ""))
        pkgs = res.get("packages") or []
        selected = _go_selected(src.get("path", "")) if go_mvs and os.path.basename(f).lower() == "go.sum" else None
        sources.append({"file": f, "type": src.get("type", ""), "components": len(pkgs)})
        for p in pkgs:
            pk = p.get("package") or {}
            ident = p.get("identity") or {}
            eco, name, raw_ver = str(pk.get("ecosystem") or ident.get("ecosystem") or ""), str(pk.get("name") or ""), \
                str(pk.get("version") or "")
            if selected is not None and eco.lower() == "go" and (name, raw_ver) not in selected:
                adj["go_sum_only_dropped"] += 1
                continue
            ver, platform = _canonical_version(eco, raw_ver) if merge_ruby_platforms else (raw_ver, "")
            key = (eco.lower(), _canon(eco, name), ver)
            c = comps.get(key)
            if c is None:
                c = comps[key] = {"name": name, "version": ver, "ecosystem": eco,
                                  "purl": ident.get("purl") or "", "scope": p.get("scope"),
                                  "relationship": ident.get("relationship") or "",
                                  "depth": ident.get("depth"), "files": [], "query_status": p.get("query_status", ""),
                                  "vulns": 0, "license": "", "license_source": "", "license_raw": ""}
                if platform:
                    c["purl"] = re.sub(r"@[^?#]*", "@" + ver, c["purl"]) if c["purl"] else ""
            elif platform:
                adj["ruby_platform_variants_merged"] += 1
            if platform:
                c.setdefault("platforms", [])
                if platform not in c["platforms"]:
                    c["platforms"].append(platform)
            if f not in c["files"]:
                c["files"].append(f)
            if c["relationship"] != "direct" and ident.get("relationship") == "direct":
                c["relationship"], c["depth"] = "direct", ident.get("depth")
            for grp in _merge_vulns(p.get("vulnerabilities") or []):
                ids = uniq([i for v in grp for i in [v.get("id", "")] + list(v.get("aliases") or []) if i])
                pid = _primary_id(ids)
                vkey = (pid, _canon(eco, name), ver)
                if dedupe and vkey in seen_vuln:
                    adj["duplicate_findings_merged"] += 1
                    prev = seen_vuln[vkey]
                    if f not in prev["files"]:
                        prev["files"].append(f)
                    continue
                best = max(grp, key=lambda v: (cvss.severity_of(v)[1] or -1))
                label, score, src_kind = cvss.severity_of(best)
                malicious = any(i.startswith("MAL-") for i in ids)       # OSV malicious-package advisory: not a bug, an attack
                if malicious:
                    label, src_kind = "CRITICAL", "malware-advisory"
                fx: List[str] = []
                hits = False
                for v in grp:
                    fv, hit = fixed_versions(v, name, eco, ver)
                    fx += fv
                    hits = hits or hit
                fx = uniq(fx)
                rec = {"id": pid, "aliases": [i for i in ids if i != pid],
                       "osv_ids": uniq([v.get("id", "") for v in grp]), "package": name, "version": ver,
                       "ecosystem": eco, "purl": c["purl"], "severity": label, "cvss": score,
                       "score_source": src_kind, "malicious": malicious, "fixed_version": versions.max_version(fx) or "",
                       "fixed_candidates": fx, "affects_confirmed": hits,
                       "summary": clip(best.get("summary") or best.get("details") or "", 240),
                       "published": best.get("published", ""), "files": [f],
                       "references": [r.get("url") for r in (best.get("references") or [])[:3] if r.get("url")]}
                vulns.append(rec)
                seen_vuln[vkey] = rec
                c["vulns"] += 1
    status = native.get("scan_status") or {}
    comp = native.get("completeness") or {}
    return {"components": sorted(comps.values(), key=lambda c: (c["ecosystem"], c["name"].lower(), c["version"])),
            "vulns": vulns, "sources": sources, "adjustments": adj,
            "unsupported": [rel(p) for p in (native.get("unsupported_files") or [])],
            "status": {k: status.get(k) for k in ("sources", "packages", "queried_online", "mode", "unqueried",
                                                   "version_unresolved", "network_fallback_offline")},
            "data_status": comp.get("data_status"), "vulnerability_presence": comp.get("vulnerability_presence"),
            "notes": [clip(n, 240) for n in (native.get("notes") or [])][:40]}


def severity_counts(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for v in vulns:
        out[v["severity"]] = out.get(v["severity"], 0) + 1
    return out


def analyze(path: str, *, offline: bool = False, scanner: Any = None, **opts: Any) -> Dict[str, Any]:
    return normalize(scan(path, offline=offline, scanner=scanner), path, **opts)
