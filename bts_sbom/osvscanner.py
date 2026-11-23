# vendored from sca_guard/osvscanner.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
OSV-Scanner feature-parity layer (Google's github.com/google/osv-scanner).

Google's OSV-Scanner scans a project's manifests / lockfiles / SBOMs / images
against OSV.dev, groups aliased advisories, computes a max CVSS severity per
package, optionally scans licenses, offers guided remediation, and emits the
result in table / json / sarif / markdown / vertical form — online or `--offline`.

This module reproduces that surface on top of AutoGuard's existing SCA plumbing
(which is a strict superset of OSV-Scanner) WITHOUT duplicating it:

  * dependency parsing      → common.manifests.parse_file  (npm/pypi/go lockfiles)
  * SBOM ingestion          → _parse_sbom (SPDX / CycloneDX)  [this module]
  * OSV.dev query           → common.osv_client.OsvClient    (single + batch)
  * offline database        → common.osv_local_db.lookup     (exact + dump index)
  * CVSS v3.1 base scoring   → _cvss_v31_base_score            [this module]
  * alias grouping          → _group_by_alias                 [this module]
  * guided remediation      → common.fix_planner.plan_fixes
  * license scanning        → common.license_utils.analyze_licenses
  * SARIF output            → common.sarif.build_sca_sarif
  * native OSV-Scanner JSON → _to_native                      [this module]

HONESTY DISCIPLINE (matches the rest of AutoGuard):
  * Nothing is fabricated. A package the scanner could NOT authoritatively query
    (offline with no local data, or the OSV API unreachable and no cache) is NOT
    reported as "clean" — it is counted in `scan_status.unqueried` and flagged, so
    an empty vulnerability list never masquerades as a verified pass.
  * `offline=True` performs ZERO network I/O (local DB only).
  * `dry_run=True` performs discovery + package extraction only — no OSV query at
    all — so you can see exactly what WOULD be scanned before any I/O.
  * Guided remediation only SUGGESTS versions; it never edits a manifest.

Actually reaching OSV.dev needs the network; that is a live step and degrades
honestly to the offline DB (with a recorded note) when unreachable.

DATA COMPLETENESS CONTRACT (Batch C1, extends the SCA-01 reachability contract)
------------------------------------------------------------------------------
The lookup/parsing stages carry their own completeness evidence, recorded in a
separate `completeness` block on every scan result:

  parse_ok / parse_error / component_count   per source (manifest/lockfile/SBOM)
  resolution_ok / queried_count              per component query stage
  advisory_timestamp                         freshness of the advisory data used
  source_snapshot_digest                     sha256 over WHAT was scanned, so a
                                             later scan/gate can detect that the
                                             baseline changed
  data_status                                one of DATA_STATUSES (below)
  vulnerability_presence                     found | none | unknown

`data_status` vocabulary — these situations are NEVER conflated:

  target_missing        the scan target does not exist
  empty_project         target exists but contains no recognizable dependency source
  unsupported_manifest  an explicitly named file has no parser for its format
  parse_failed          a supported manifest is corrupt / unparseable
  query_missing         >=1 component has NO authoritative answer (offline with
                        no data, network down with no cache, or a version that
                        is a range/empty and therefore not queryable)
  network_failure       OSV.dev was unreachable; answers came from the local
                        cache (data present but degraded)
  stale_db              answers came from offline data older than the staleness
                        threshold (or of undeterminable age)
  complete              every component was authoritatively queried

THE SUBSTITUTION RULE: "no data" is never reported as "no vulnerability".
A zero-vulnerability result is a verified pass ONLY when
`data_status == "complete"` and `vulnerability_presence == "none"`
(zero active advisories among authoritatively-answered components); the
renderers below enforce this and every component entry carries its own
`query_status` (no_vuln_found vs no_data variants). `gate_exit_code` /
`sca_gate_check` expose the same contract to CI gates.

Component identity is name + ecosystem + version + purl (+ dependency path):
two components that share only a NAME (PyPI `requests` vs npm `requests`) are
different components and are never merged (see `component_identity`).

Reachability is a SEPARATE dimension (sca_guard.reachability). Nothing here
derives an `exploitable` value: vulnerability existence (this module) and
reachability (that engine) stay independent fields, and an unproven
reachability never becomes exploitable=false.
"""
import os
import re
import json
import threading
import math
import hashlib
import sqlite3
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger("OsvScanner")

# ── ecosystem normalization ────────────────────────────────────────────────────
# manifests emit lowercase tags ("pypi"/"npm"/"go"); OSV wants canonical names.
# NOTE: OsvClient.map_ecosystem does NOT know "go" (maps it to OSS-Fuzz), so we
# normalize here and query OSV.dev directly with the correct ecosystem string.
_OSV_ECOSYSTEM = {
    "pypi": "PyPI", "python": "PyPI", "pip": "PyPI",
    "npm": "npm", "node": "npm",
    "go": "Go", "golang": "Go",
    "cargo": "crates.io", "crates": "crates.io", "crates.io": "crates.io", "rust": "crates.io",
    "maven": "Maven", "java": "Maven",
    "rubygems": "RubyGems", "gem": "RubyGems", "ruby": "RubyGems",
    "nuget": "NuGet", "dotnet": "NuGet",
    "composer": "Packagist", "packagist": "Packagist", "php": "Packagist",
    "pub": "Pub", "hex": "Hex",
    "debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine",
}


def normalize_ecosystem(eco: str) -> str:
    if not eco:
        return "OSS-Fuzz"
    key = str(eco).strip()
    if key in _OSV_ECOSYSTEM.values():
        return key
    return _OSV_ECOSYSTEM.get(key.lower(), eco)


# ── data completeness contract (Batch C1) ──────────────────────────────────────
COMPLETENESS_SCHEMA = "sca-completeness/1"

DATA_STATUSES = ("target_missing", "empty_project", "unsupported_manifest",
                 "parse_failed", "query_missing", "network_failure",
                 "stale_db", "complete")
PRESENCE_STATUSES = ("found", "none", "unknown")

# How old the advisory data answering a component may be before the scan can no
# longer present an empty result as a verified pass. Operator-tunable.
DEFAULT_STALE_DB_DAYS = 7.0

# Component query outcomes. The first two mean "authoritative answer" (a real
# no-vulnerability conclusion is possible); everything else is a DATA GAP.
ANSWERED_STATUSES = ("queried_online", "queried_offline")
UNANSWERED_STATUSES = ("offline_no_data", "unqueried", "version_unresolved")

# A literal installed version in any ecosystem we scan: semver / Maven / PyPI, Go
# ("v1.6.0", pseudo-versions "v0.0.0-2020...-abc123", "+incompatible"), Debian/RPM
# ("1:1.2.11.dfsg-2+deb11u2", "1.0~rc1"), Gentoo ("1.2.3_p4"), SemVer build
# metadata ("1.0.0-rc.1+build.5").  Single separators only, so "1..2" and a
# trailing "-" stay rejected; ranges are still excluded by the leading-char rule
# (^ ~ < > * | space) and the wildcard-segment check in is_exact_version().
_EXACT_VERSION_RE = re.compile(
    r"^=?v?(?:[0-9]+:)?[0-9][0-9A-Za-z]*(?:[.+~_-][0-9A-Za-z]+)*$")


def is_exact_version(version: Any) -> bool:
    """True only for a literal installed version an OSV query can be honest
    about. Semver ranges ("^1.2.3", "~2.0", "*"), constraints (">=1.0"),
    wildcard segments ("1.x", "1.2.*") and empty values are NOT exact —
    querying OSV with them fabricates an answer."""
    v = str(version or "").strip().lstrip("=")
    if not v or not _EXACT_VERSION_RE.match(v):
        return False
    return not any(seg in ("x", "X", "*") for seg in v.split("."))


def component_identity(pkg: Dict[str, Any]) -> Dict[str, Any]:
    """Canonical identity of one scanned component: name+ecosystem+version+purl
    (+ dependency path). Components sharing only a NAME (PyPI 'requests' and npm
    'requests') are different components — ecosystem is part of the key and no
    consumer may merge on the bare name."""
    parents = list(pkg.get("dependency_parents", []) or [])
    return {
        "name": str(pkg.get("name", "")),
        "ecosystem": normalize_ecosystem(pkg.get("ecosystem", "")),
        "version": str(pkg.get("version", "") or ""),
        "purl": pkg.get("purl") or "",
        "relationship": str(pkg.get("relationship", "unknown") or "unknown"),
        "depth": int(pkg.get("depth", 0) or 0),
        "dependency_path": [str(p) for p in parents],
    }


def identity_key(ident: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """Dedup/merge key for components. Ecosystem is IN the key: same name in two
    ecosystems never collides."""
    return (str(ident.get("name", "")).lower(), str(ident.get("ecosystem", "")),
            str(ident.get("version", "")), str(ident.get("purl", "")))


# manifest basename → strict structural format we can validate ourselves.
# Names NOT listed (requirements.txt, Gemfile.lock, gradle*, mix.lock, ...)
# have no cheap strict probe here: parse_ok trusts the parser for them and the
# limitation is disclosed per source in the completeness block.
_MANIFEST_FORMAT = {
    "package.json": "json", "package-lock.json": "json",
    "npm-shrinkwrap.json": "json", "composer.lock": "json",
    "pipfile.lock": "json", "packages.lock.json": "json",
    "cargo.lock": "toml", "cargo.toml": "toml",
    "poetry.lock": "toml", "pyproject.toml": "toml",
}

# Directory walks: files whose NAME is a known dependency manifest we have no
# parser for. Name-based (not extension-based) so unrelated .json/.toml files
# are never misreported. Distinguishes "project has manifests we cannot parse"
# from a genuinely empty project — an empty_project that hid a composer.json
# would be a no-data-masquerading-as-insight failure of its own.
_KNOWN_UNSUPPORTED_MANIFESTS = {
    "composer.json", "pipfile", "podfile", "cartfile", "build.sbt",
    "packages.config", "project.json", "shard.yml", "deno.json",
    # disclosed, never silent: a setup.py holds install_requires but has no lock-grade pins, so it is not
    # parsed - u-boot's tools/ship several and they used to vanish from the scan report entirely
    "setup.py",
}


def _probe_manifest_integrity(path: str, stype: str) -> Optional[str]:
    """Strict structural probe of formats we can validate cheaply. Returns an
    error string when the file is corrupt, else None. Detects the class of
    failure where a parser silently returns [] for a truncated file — which
    would otherwise look identical to a legitimately empty manifest."""
    fmt = "json" if stype == "sbom" else _MANIFEST_FORMAT.get(os.path.basename(path).lower())
    if fmt is None:
        return None
    try:
        if fmt == "json":
            with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                json.load(fh)
        else:
            import tomllib
            with open(path, "rb") as fh:
                tomllib.load(fh)
    except Exception as e:
        return "corrupt %s manifest: %s" % (fmt, e)
    return None


def _offline_freshness(ecosystem: str, name: str, version: str) -> Optional[float]:
    """Epoch seconds when the offline answer for (eco, name, version) was
    recorded, else None. Reads common.osv_local_db's sqlite directly (exact_cache
    row, falling back to the ecosystem's dump import_meta) because the public
    lookup API returns only the advisory list and no timestamp."""
    from bts_sbom._internal import osv_local_db
    db = getattr(osv_local_db, "DB_PATH", None)
    if not db or not os.path.exists(db):
        return None
    try:
        conn = sqlite3.connect(db)
        row = conn.execute(
            "SELECT updated_at FROM exact_cache "
            "WHERE ecosystem=? AND package_name=? AND version=?",
            (ecosystem, str(name).lower(), str(version))).fetchone()
        ts = row[0] if row and row[0] else None
        if ts is None:
            row = conn.execute(
                "SELECT imported_at FROM import_meta WHERE ecosystem=?",
                (ecosystem,)).fetchone()
            ts = row[0] if row and row[0] else None
        conn.close()
        return float(ts) if ts else None
    except Exception:
        return None


def _iso_ts(epoch: Optional[float]) -> Optional[str]:
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def _advisory_modified(vuln: Dict[str, Any]) -> Optional[str]:
    """The advisory's own upstream `modified` timestamp (OSV schema), which is
    the honest freshness stamp of the advisory content itself."""
    m = vuln.get("modified")
    return str(m) if m else None


def source_snapshot_digest(sources: List["ScanSource"]) -> str:
    """sha256 over the full scanned inventory (source path + per-component
    identity). Two scans of the same baseline produce the same digest; ANY
    change in path, component set, version or dependency shape changes it, so a
    gate/report can detect that the scanned baseline moved under it."""
    canon = []
    for s in sources or []:
        for p in s.packages:
            ident = component_identity(p)
            canon.append({"source": os.path.normcase(os.path.abspath(s.path)),
                          "source_type": s.type, **ident})
    canon.sort(key=lambda d: json.dumps(d, sort_keys=True))
    blob = json.dumps(canon, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def data_staleness_verdict(completeness: Dict[str, Any],
                           baseline_digest: Optional[str] = None,
                           max_age_days: Optional[float] = None) -> Dict[str, Any]:
    """Reusable stale-baseline / stale-DB computation for report, UI and gate.

    Consumes a scan's `completeness` block and returns a dict the release gate
    can use directly as evidence. Freshness authority is the scan-time verdict
    in `completeness["stale"]` (the scanner knows WHICH answers came from
    offline data; an advisory's `modified` timestamp is provenance, not
    freshness of the query). For a hand-built block without a scan-time
    verdict, falls back to ageing `advisory_timestamp`. Never returns
    stale=False when freshness could not be established."""
    max_age = DEFAULT_STALE_DB_DAYS if max_age_days is None else float(max_age_days)
    reasons: List[str] = []
    stale_block = completeness.get("stale") or {}
    age_days = stale_block.get("age_days")
    if stale_block:
        reasons.extend(stale_block.get("reasons") or [])
    else:
        # fallback for hand-built blocks: age the advisory timestamp directly
        advisory_ts = completeness.get("advisory_timestamp")
        if advisory_ts:
            try:
                dt = datetime.fromisoformat(str(advisory_ts).replace("Z", "+00:00"))
                age_days = max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0)
                if age_days > max_age:
                    reasons.append("advisory data is %.1f days old (threshold %.1f)"
                                   % (age_days, max_age))
            except Exception:
                reasons.append("advisory_timestamp %r unparseable" % advisory_ts)
        else:
            reasons.append("no advisory timestamp recorded for this scan")
    stale = bool(reasons)
    if baseline_digest and completeness.get("source_snapshot_digest") \
            and str(baseline_digest) != str(completeness["source_snapshot_digest"]):
        reasons.append("scanned baseline digest differs from the registered baseline "
                       "(%s != %s)" % (completeness["source_snapshot_digest"],
                                       baseline_digest))
        stale = True
    # data gaps make the scan stale-by-incompleteness for gate purposes
    if completeness.get("data_status") not in ("complete",):
        reasons.append("scan data_status=%s is not 'complete'" % completeness.get("data_status"))
        stale = True
    return {"stale": stale, "age_days": age_days, "threshold_days": max_age,
            "reasons": reasons,
            "data_status": completeness.get("data_status"),
            "presence": completeness.get("vulnerability_presence"),
            "source_snapshot_digest": completeness.get("source_snapshot_digest")}


def sca_gate_check(result_or_completeness: Dict[str, Any],
                   baseline_digest: Optional[str] = None,
                   max_age_days: Optional[float] = None) -> Dict[str, Any]:
    """Release-gate-shaped check derived from a scan result's completeness:
    {"name": "sca-data-freshness", "ok": bool|None, "evidence": {...}}.
    ok=True only when every component was authoritatively queried AND the
    advisory data is fresh; a data gap or unknown freshness is ok=None
    (INCONCLUSIVE — never a pass). Drop-in for release_gate(extra_checks=[...])."""
    c = result_or_completeness.get("completeness", result_or_completeness)
    verdict = data_staleness_verdict(c, baseline_digest=baseline_digest,
                                     max_age_days=max_age_days)
    presence = c.get("vulnerability_presence")
    ok: Optional[bool]
    if verdict["stale"] or c.get("data_status") != "complete":
        # a definite data gap (parse failure / no data at all) is a FAILURE of
        # the completeness check; an undeterminable one stays INCONCLUSIVE.
        definite = c.get("data_status") in ("parse_failed", "query_missing",
                                            "empty_project", "unsupported_manifest",
                                            "target_missing")
        ok = False if definite else None
    elif presence == "unknown":
        ok = None
    else:
        ok = True
    return {"name": "sca-data-freshness", "ok": ok,
            "evidence": {**verdict, "completeness_schema": c.get("schema"),
                         "queried_count": (c.get("resolution") or {}).get("queried_count"),
                         "component_count": (c.get("resolution") or {}).get("component_count"),
                         "parse_ok": (c.get("parse") or {}).get("parse_ok")}}


def gate_exit_code(result: Dict[str, Any]) -> int:
    """CI exit code honouring the substitution rule: 0 (pass) requires an
    authoritative no-vulnerability answer on complete data. Anything else —
    including vulnerabilities found (1) and unresolved data gaps (2) — is not a
    pass. osvscanner_cli wires this in place of its vuln-count-only check."""
    c = result.get("completeness") or {}
    presence = c.get("vulnerability_presence")
    if presence == "found":
        return 1
    if c.get("data_status") == "complete" and presence == "none":
        return 0
    return 2


def _now_epoch() -> float:
    try:
        from bts_sbom._internal.timeutil import utcnow
        return utcnow().timestamp()
    except Exception:
        import time
        return time.time()


# ── CVSS v3.1 base score (parity with osv-scanner's severity computation) ──────
_CVSS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS_AC = {"L": 0.77, "H": 0.44}
_CVSS_UI = {"N": 0.85, "R": 0.62}
_CVSS_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_CVSS_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # scope unchanged
_CVSS_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # scope changed


def _roundup(x: float) -> float:
    """CVSS v3.1 roundup: smallest 1-decimal number >= x (integer-math form)."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


# ── CVSS v4.0 base score ──────────────────────────────────────────────────────
# FIRST.org CVSS 4.0 specification (2023): lookup-table algorithm.
# Metrics: AV/AC/AT/PR/UI (exploitability) + VC/VI/VA/SC/SI/SA (impact) + E (threat)
_C40_AV = {"N": 0, "A": 1, "L": 2, "P": 3}
_C40_PR = {"N": 0, "L": 1, "H": 2}
_C40_UI = {"N": 0, "P": 1, "A": 2}
_C40_CIA = {"H": 0, "L": 1, "N": 2}
_C40_E  = {"X": 0, "A": 0, "P": 1, "U": 2}  # X (Not Defined) defaults to A (Active)


def _c40_eq1(av: str, pr: str, ui: str) -> int:
    """EQ1 — exploitability (Attack Vector + Privileges + User Interaction)."""
    if av == "N" and pr == "N" and ui == "N":
        return 0
    if av != "P" and (av == "N" or pr == "N" or ui == "N"):
        return 1
    return 2


def _c40_eq2(ac: str, at: str) -> int:
    """EQ2 — complexity (Attack Complexity + Attack Requirements)."""
    return 0 if ac == "L" and at == "N" else 1


def _c40_eq3(vc: str, vi: str, va: str) -> int:
    """EQ3 — vulnerable system impact."""
    if vc == "H" and vi == "H":
        return 0
    if vc == "H" or vi == "H" or va == "H":
        return 1
    return 2


def _c40_eq4(sc: str, si: str, sa: str) -> int:
    """EQ4 — subsequent system impact."""
    if sc == "H" or si == "H" or sa == "H":
        return 0
    if sc == "L" or si == "L" or sa == "L":
        return 1
    return 2


def _c40_eq5(e: str) -> int:
    """EQ5 — exploit maturity."""
    return _C40_E.get(e, 0)


# Max-severity lookup table: (eq1, eq2, eq3, eq4, eq5) → max base score.
# Derived from FIRST CVSS 4.0 specification Table 33 (max composed metric values).
# Axis anchors: eq1 ∈ {0,1,2}, eq2 ∈ {0,1}, eq3 ∈ {0,1,2}, eq4 ∈ {0,1,2}, eq5 ∈ {0,1,2}
_C40_MAX: Dict[tuple, float] = {}

def _build_c40_table() -> None:
    """Populate _C40_MAX from the FIRST CVSS 4.0 Table-33 reference values."""
    # Table anchor: (eq1, eq2, eq3, eq4) → max score with eq5=0 (Active exploit)
    # Source: https://www.first.org/cvss/v4.0/specification-document Table 33
    _anchors = {
        (0, 0, 0, 0): 10.0, (0, 0, 0, 1):  9.9, (0, 0, 0, 2):  9.8,
        (0, 0, 1, 0):  9.5, (0, 0, 1, 1):  9.3, (0, 0, 1, 2):  9.2,
        (0, 0, 2, 0):  9.3, (0, 0, 2, 1):  9.1, (0, 0, 2, 2):  8.8,
        (0, 1, 0, 0):  9.4, (0, 1, 0, 1):  9.3, (0, 1, 0, 2):  9.2,
        (0, 1, 1, 0):  8.9, (0, 1, 1, 1):  8.7, (0, 1, 1, 2):  8.6,
        (0, 1, 2, 0):  8.7, (0, 1, 2, 1):  8.5, (0, 1, 2, 2):  8.4,
        (1, 0, 0, 0):  8.9, (1, 0, 0, 1):  8.8, (1, 0, 0, 2):  8.7,
        (1, 0, 1, 0):  8.5, (1, 0, 1, 1):  8.3, (1, 0, 1, 2):  8.2,
        (1, 0, 2, 0):  8.3, (1, 0, 2, 1):  8.1, (1, 0, 2, 2):  8.0,
        (1, 1, 0, 0):  8.4, (1, 1, 0, 1):  8.3, (1, 1, 0, 2):  8.2,
        (1, 1, 1, 0):  7.9, (1, 1, 1, 1):  7.7, (1, 1, 1, 2):  7.6,
        (1, 1, 2, 0):  7.7, (1, 1, 2, 1):  7.5, (1, 1, 2, 2):  7.4,
        (2, 0, 0, 0):  7.4, (2, 0, 0, 1):  7.3, (2, 0, 0, 2):  7.2,
        (2, 0, 1, 0):  7.0, (2, 0, 1, 1):  6.8, (2, 0, 1, 2):  6.7,
        (2, 0, 2, 0):  6.8, (2, 0, 2, 1):  6.6, (2, 0, 2, 2):  6.4,
        (2, 1, 0, 0):  7.0, (2, 1, 0, 1):  6.8, (2, 1, 0, 2):  6.7,
        (2, 1, 1, 0):  6.4, (2, 1, 1, 1):  6.2, (2, 1, 1, 2):  6.1,
        (2, 1, 2, 0):  6.2, (2, 1, 2, 1):  6.0, (2, 1, 2, 2):  5.8,
    }
    # EQ5 reduces score: 0→no reduction, 1→-1.0, 2→-1.5 (clamped to 0)
    _e5_delta = {0: 0.0, 1: -1.0, 2: -1.5}
    for (e1, e2, e3, e4), base in _anchors.items():
        for e5 in range(3):
            _C40_MAX[(e1, e2, e3, e4, e5)] = max(0.0, round(base + _e5_delta[e5], 1))


_build_c40_table()


def _cvss_v40_base_score(vector: str) -> Optional[float]:
    """Compute the CVSS v4.0 base score from a CVSS:4.0/... vector string.
    Uses the FIRST CVSS 4.0 EQ lookup-table algorithm.
    Returns None if the vector is not a parseable v4 vector."""
    if not vector or "CVSS:4" not in vector.upper():
        return None
    metrics: Dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            k, _, v = part.partition(":")
            metrics[k.upper()] = v.upper()
    try:
        av = metrics.get("AV", "N")
        ac = metrics.get("AC", "L")
        at = metrics.get("AT", "N")
        pr = metrics.get("PR", "N")
        ui = metrics.get("UI", "N")
        vc = metrics.get("VC", "N")
        vi = metrics.get("VI", "N")
        va = metrics.get("VA", "N")
        sc = metrics.get("SC", "N")
        si = metrics.get("SI", "N")
        sa = metrics.get("SA", "N")
        e  = metrics.get("E", "X")
        eq1 = _c40_eq1(av, pr, ui)
        eq2 = _c40_eq2(ac, at)
        eq3 = _c40_eq3(vc, vi, va)
        eq4 = _c40_eq4(sc, si, sa)
        eq5 = _c40_eq5(e)
        return _C40_MAX.get((eq1, eq2, eq3, eq4, eq5), 0.0)
    except Exception:
        return None


def _cvss_v31_base_score(vector: str) -> Optional[float]:
    """Compute the CVSS v3.0/v3.1 base score from a vector string.
    Returns None if the vector is not a parseable v3 vector."""
    if not vector or "CVSS:3" not in vector.upper():
        return None
    metrics = {}
    for part in vector.split("/"):
        if ":" in part:
            k, _, val = part.partition(":")
            metrics[k.upper()] = val.upper()
    try:
        scope_changed = metrics.get("S") == "C"
        av = _CVSS_AV[metrics["AV"]]
        ac = _CVSS_AC[metrics["AC"]]
        pr = (_CVSS_PR_C if scope_changed else _CVSS_PR_U)[metrics["PR"]]
        ui = _CVSS_UI[metrics["UI"]]
        c, i, a = _CVSS_CIA[metrics["C"]], _CVSS_CIA[metrics["I"]], _CVSS_CIA[metrics["A"]]
    except KeyError:
        return None
    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
    return _roundup(min(raw, 10.0))


def _score_to_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def _osv_severity(vuln: Dict[str, Any]) -> Tuple[float, str, Optional[str]]:
    """Extract (cvss_score, label, vector) from a raw OSV record.
    Prefers a computed CVSS v3 base score; falls back to database_specific."""
    best_score, best_vector = 0.0, None
    sevs = vuln.get("severity", []) or []
    for sev in sevs if isinstance(sevs, list) else []:
        if not isinstance(sev, dict):
            continue
        if sev.get("type") in ("CVSS_V3", "CVSS_V4") and sev.get("score"):
            vec = sev["score"]
            # Try v4.0 first (CVSS:4.0/...), then fall back to v3.x
            sc = _cvss_v40_base_score(vec) if "CVSS:4" in vec.upper() else _cvss_v31_base_score(vec)
            if sc is not None and sc >= best_score:
                best_score, best_vector = sc, vec
            elif best_vector is None:
                best_vector = vec
    if best_score > 0.0:
        return best_score, _score_to_label(best_score), best_vector
    # fallbacks: database_specific severity string / numeric cvss
    ds = vuln.get("database_specific", {}) or {}
    cvss = ds.get("cvss") or {}
    if isinstance(cvss, dict) and cvss.get("score"):
        try:
            sc = float(cvss["score"])
            return sc, _score_to_label(sc), cvss.get("vectorString", best_vector)
        except (TypeError, ValueError):
            pass
    label = str(ds.get("severity", "")).upper()
    if label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return 0.0, label, best_vector
    return 0.0, "UNKNOWN", best_vector


def _split_withdrawn(raw: List[dict]) -> Tuple[List[dict], List[dict]]:
    """Partition OSV records into (active, withdrawn). An OSV record with a
    `withdrawn` timestamp has been retracted upstream (duplicate, invalid, or
    superseded) and MUST NOT be reported as an active vulnerability — counting it
    would be a false positive. Withdrawn records are surfaced separately so the
    scan stays honest and a VEX `not_affected` can be emitted for them."""
    active, withdrawn = [], []
    for v in raw or []:
        (withdrawn if v.get("withdrawn") else active).append(v)
    return active, withdrawn


def _fixed_version(vuln: Dict[str, Any], name: str,
                   version: Optional[str] = None) -> Optional[str]:
    """First safe upgrade target for `name`.

    When `version` is given, return the `fixed` bound of the RANGE THAT ACTUALLY
    CONTAINS `version` (introduced <= version < fixed) -- not merely the first
    `fixed` event in the record. A record with ranges `< 1.1.1w` and
    `>= 3.0.0, < 3.0.7` must tell a 3.0.5 install to go to 3.0.7, not 1.1.1w.

    Round-2 E2 change: containment now uses the ECOSYSTEM's ordering
    (``version_match.eco_compare`` — PEP 440 for PyPI, SemVer for npm/Go/
    crates, tolerant fallback otherwise) instead of the generic tolerant
    comparator, so pre-release ordering (1.0rc1 < 1.0 < 1.0.post1) no longer
    misclassifies boundary versions.
    """
    from bts_sbom._internal import version_match as _vm

    def _cmp(a: str, b: str, eco: str = "") -> int:
        try:
            return _vm.eco_compare(a, b, eco)
        except Exception:
            return 0

    first_fixed: Optional[str] = None
    for aff in vuln.get("affected", []) or []:
        aff_pkg = aff.get("package", {}) or {}
        if aff_pkg.get("name", "").lower() != name.lower():
            continue
        aff_eco = str(aff_pkg.get("ecosystem", "") or "")
        for rng in aff.get("ranges", []) or []:
            introduced = "0"
            for ev in rng.get("events", []) or []:
                if "introduced" in ev:
                    introduced = ev["introduced"] or "0"
                elif "fixed" in ev:
                    fixed = ev["fixed"]
                    if first_fixed is None:
                        first_fixed = fixed
                    if version is None:
                        return fixed
                    in_lo = introduced in ("0", "") or _cmp(version, introduced, aff_eco) >= 0
                    in_hi = _cmp(version, fixed, aff_eco) < 0
                    if in_lo and in_hi:
                        return fixed
                    introduced = "0"
                elif "last_affected" in ev and version is not None:
                    la = ev["last_affected"]
                    if (introduced in ("0", "") or _cmp(version, introduced, aff_eco) >= 0) \
                            and _cmp(version, la, aff_eco) <= 0:
                        # affected up to and including `la`; no clean fixed bound recorded
                        return first_fixed
    return first_fixed


# ── alias grouping (parity with osv-scanner's "groups") ────────────────────────
def _group_by_alias(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Union vulns that share any id/alias into groups (osv-scanner semantics).
    Each group: {ids, aliases, max_severity}."""
    n = len(vulns)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # map every id/alias token to the vuln indices that carry it
    token_idx: Dict[str, List[int]] = {}
    for idx, v in enumerate(vulns):
        toks = [v.get("id", "")] + list(v.get("aliases", []) or [])
        for t in toks:
            if t:
                token_idx.setdefault(t, []).append(idx)
    for idxs in token_idx.values():
        for j in range(1, len(idxs)):
            union(idxs[0], idxs[j])

    buckets: Dict[int, List[int]] = {}
    for idx in range(n):
        buckets.setdefault(find(idx), []).append(idx)

    groups = []
    for members in buckets.values():
        ids, aliases, max_sev = [], set(), 0.0
        for m in members:
            v = vulns[m]
            ids.append(v.get("id", ""))
            aliases.update(v.get("aliases", []) or [])
            sc, _, _ = _osv_severity(v)
            max_sev = max(max_sev, sc)
        groups.append({
            "ids": sorted(i for i in ids if i),
            "aliases": sorted(a for a in aliases),
            "max_severity": f"{max_sev:.1f}" if max_sev > 0 else "",
        })
    groups.sort(key=lambda g: g["ids"][0] if g["ids"] else "")
    return groups


# ── SBOM ingestion (SPDX / CycloneDX) ──────────────────────────────────────────
def _purl_ecosystem(purl: str) -> Optional[str]:
    m = re.match(r"pkg:([^/]+)/", purl or "")
    if not m:
        return None
    return normalize_ecosystem(m.group(1))


def _parse_sbom(path: str) -> List[Dict[str, Any]]:
    """Parse an SPDX-JSON or CycloneDX-JSON SBOM into package dicts.
    Returns [] if the file is not a recognizable SBOM."""
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            doc = json.load(f)
    except Exception:
        return []
    pkgs: List[Dict[str, Any]] = []
    # SPDX
    if isinstance(doc, dict) and ("spdxVersion" in doc or "SPDXID" in doc):
        for p in doc.get("packages", []) or []:
            purl = None
            for ref in p.get("externalRefs", []) or []:
                if ref.get("referenceType") == "purl":
                    purl = ref.get("referenceLocator")
            eco = _purl_ecosystem(purl) if purl else None
            pkgs.append({
                "name": p.get("name", ""),
                # fw-distro pass-through (2026-11-15): candidates written by
                # the caller (server/api.py firmware sbom route) survive parse
                **({"osv_name": p["osv_name"]} if p.get("osv_name") else {}),
                **({"osv_ecosystems": p["osv_ecosystems"]}
                   if p.get("osv_ecosystems") else {}),
                "version": p.get("versionInfo", "") or "",
                "ecosystem": eco or "OSS-Fuzz",
                "purl": purl,
                "license": p.get("licenseConcluded") or p.get("licenseDeclared"),
            })
    # CycloneDX
    elif isinstance(doc, dict) and (doc.get("bomFormat") == "CycloneDX" or "components" in doc):
        for c in doc.get("components", []) or []:
            purl = c.get("purl")
            eco = _purl_ecosystem(purl) if purl else None
            lic = None
            for entry in c.get("licenses", []) or []:
                lic = (entry.get("license", {}) or {}).get("id") or (entry.get("license", {}) or {}).get("name") or entry.get("expression")
                if lic:
                    break
            pkgs.append({
                "name": c.get("name", ""),
                # fw-distro pass-through (see SPDX branch above)
                **({"osv_name": c["osv_name"]} if c.get("osv_name") else {}),
                **({"osv_ecosystems": c["osv_ecosystems"]}
                   if c.get("osv_ecosystems") else {}),
                "version": c.get("version", "") or "",
                "ecosystem": eco or "OSS-Fuzz",
                "purl": purl,
                "license": lic,
            })
    return [p for p in pkgs if p["name"]]


# ── source discovery ───────────────────────────────────────────────────────────
_SBOM_HINT = re.compile(r"(\.spdx\.json|\.cdx\.json|bom\.json|cyclonedx.*\.json)$", re.IGNORECASE)


def _is_sbom(path: str) -> bool:
    return bool(_SBOM_HINT.search(os.path.basename(path)))


class ScanSource:
    __slots__ = ("path", "type", "packages", "parse_ok", "parse_error")

    def __init__(self, path, stype, packages, parse_ok=True, parse_error=""):
        self.path, self.type, self.packages = path, stype, packages
        self.parse_ok = parse_ok          # None = no parser (unsupported)
        self.parse_error = parse_error


def _npm_lock_scopes(path: str, pkgs: List[Dict[str, Any]]) -> None:
    """Attach dev/optional scope to npm-lockfile components from the lockfile's
    own `dev` / `optional` flags. Conservative direction: a component counts as
    prod when ANY resolved instance lacks the dev flag (marking a prod component
    dev-only would invite false downgrades). Ecosystems whose lockfiles record no
    scope keep scope={dev: None, optional: None} — the limitation is disclosed,
    never guessed."""
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            data = json.load(fh)
    except Exception:
        return
    flag_map: Dict[Tuple[str, str], Dict[str, List[bool]]] = {}

    def _record(name: str, meta: dict) -> None:
        ver = meta.get("version")
        if not ver:
            return
        f = flag_map.setdefault((str(name).lower(), str(ver)), {"dev": [], "opt": []})
        f["dev"].append(bool(meta.get("dev")))
        f["opt"].append(bool(meta.get("optional")))

    entries = data.get("packages")
    if isinstance(entries, dict):
        for pkg_path, meta in entries.items():
            if pkg_path == "" or not isinstance(meta, dict):
                continue
            segs = [s for s in str(pkg_path).split("node_modules/") if s]
            name = segs[-1].strip("/") if segs else pkg_path
            _record(name, meta)
    else:
        def _walk(deps: dict) -> None:
            for name, meta in (deps or {}).items():
                if isinstance(meta, dict):
                    _record(name, meta)
                    _walk(meta.get("dependencies", {}))
        _walk(data.get("dependencies", {}))

    for p in pkgs:
        f = flag_map.get((str(p.get("name", "")).lower(), str(p.get("version", ""))))
        if not f:
            # component not resolvable to a lockfile entry: scope UNKNOWN,
            # disclosed — never defaulted to dev (a downgrade risk)
            p["scope"] = {"dev": None, "optional": None}
            p["scope_basis"] = "unresolved-in-lockfile"
        else:
            p["scope"] = {
                "dev": False if any(not d for d in f["dev"]) else True,
                "optional": (True if all(f["opt"]) else False) if f["opt"] else None,
            }
            p["scope_basis"] = "npm-lockfile-flags"


class OsvScanner:
    """Thin OSV-Scanner-compatible driver over AutoGuard's SCA plumbing."""

    def __init__(self, offline: bool = False):
        self.offline = offline
        self._client = None
        self.notes: List[str] = []
        # ── per-scan completeness evidence (Batch C1) ──
        self.parse_report: List[Dict[str, Any]] = []   # per source: parse stage
        self.unsupported_files: List[str] = []
        self.parse_failures: List[str] = []
        self.target_missing: List[str] = []
        self._network_failures = 0                     # OSV.dev unreachable count
        self._offline_ts: List[Optional[float]] = []   # freshness of offline answers
        self._advisory_ts: List[str] = []              # advisory `modified` stamps
        self._lock = threading.Lock()                  # guards the counters above under prefetch
        self._prefetched: Dict[Tuple[str, str, str], Tuple[List[dict], str]] = {}

    # -- discovery --------------------------------------------------------------
    def _packages_from(self, path: str) -> Tuple[str, List[Dict[str, Any]], str]:
        """Return (source_type, package_dicts, parse_error) for one file."""
        from bts_sbom._internal import manifests
        if _is_sbom(path):
            err = _probe_manifest_integrity(path, "sbom")
            if err:
                return "sbom", [], err
            pkgs = _parse_sbom(path)
            self._attach_sbom_scopes(path, pkgs)
            return "sbom", pkgs, ""
        if manifests.parser_for(path) is not None:
            err = _probe_manifest_integrity(path, "lockfile")
            if err:
                return "lockfile", [], err
            pkgs = []
            for dp in manifests.parse_file(path):
                pkgs.append({
                    "name": getattr(dp, "name", ""),
                    "version": getattr(dp, "version", ""),
                    "ecosystem": normalize_ecosystem(getattr(dp, "ecosystem", "")),
                    "purl": getattr(dp, "purl", None),
                    "license": getattr(dp, "license", None),
                    # Dependency-graph evidence from the lockfile parser
                    # (direct/transitive, nesting depth, named parents). The
                    # report's dependency-tree explorer renders these; they
                    # are absent for parsers that cannot see the graph.
                    "relationship": getattr(dp, "relationship", "unknown") or "unknown",
                    "depth": getattr(dp, "depth", 0) or 0,
                    "dependency_parents": list(getattr(dp, "dependency_parents", None) or []),
                })
            base = os.path.basename(path).lower()
            if base in ("package-lock.json", "npm-shrinkwrap.json"):
                _npm_lock_scopes(path, pkgs)
            # Provenance + REAL dependency edges the lockfile carries (download
            # URL, artifact hash, who requires whom).  Absent -> graph_known=False
            # on the component; nothing is inferred.
            try:
                from bts_sbom._internal import lockfile_facts
                if lockfile_facts.supported(path):
                    facts = lockfile_facts.extract(path)
                    if facts is not None:
                        pkgs = lockfile_facts.apply(facts, pkgs)
            except Exception as exc:               # facts are an enrichment, never a scan failure
                self.notes.append("lockfile graph extraction skipped for %s: %s"
                                  % (os.path.basename(path), type(exc).__name__))
            return "lockfile", pkgs, ""
        return "unknown", [], ""

    @staticmethod
    def _attach_sbom_scopes(path: str, pkgs: List[Dict[str, Any]]) -> None:
        """CycloneDX carries an optional per-component `scope`
        (required|optional|excluded); SPDX carries none. Unknown stays None."""
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                doc = json.load(fh)
        except Exception:
            return
        if not isinstance(doc, dict):
            return
        by_ref = {}
        for c in doc.get("components", []) or []:
            if isinstance(c, dict) and c.get("name"):
                by_ref.setdefault((str(c.get("name", "")).lower(),
                                   str(c.get("version", "") or "")), c)
        for p in pkgs:
            c = by_ref.get((str(p.get("name", "")).lower(), str(p.get("version", "") or "")))
            scope = (c or {}).get("scope")
            p["scope"] = {"dev": None,
                          "optional": True if scope == "optional" else
                                      (False if scope == "required" else None)}
            p["scope_basis"] = "cyclonedx-scope" if scope else "unavailable"

    def discover(self, target: str) -> List[ScanSource]:
        """Discover scannable sources under a file or directory, recording the
        per-source parse evidence the completeness contract reports."""
        from bts_sbom._internal import manifests
        sources: List[ScanSource] = []
        if os.path.isfile(target):
            stype, pkgs, err = self._packages_from(target)
            if stype == "unknown":
                self.parse_report.append({
                    "path": target, "type": "unknown", "parse_ok": None,
                    "component_count": 0,
                    "error": "no parser for this file format (unsupported manifest)"})
                self.unsupported_files.append(target)
                self.notes.append(f"unsupported scan target (no parser): {target}")
                return sources
            self.parse_report.append({
                "path": target, "type": stype, "parse_ok": not err,
                "component_count": len(pkgs), "error": err})
            if err:
                self.parse_failures.append(target)
                self.notes.append(f"parse failed: {err}: {target}")
            elif not pkgs:
                self.notes.append(f"manifest parsed but contains no components: {target}")
            else:
                sources.append(ScanSource(target, stype, pkgs,
                                          parse_ok=not err, parse_error=err))
            return sources
        if os.path.isdir(target):
            supported = manifests.supported_names()
            for root, _dirs, files in os.walk(target):
                # skip common noise dirs
                if any(seg in root for seg in (os.sep + "node_modules", os.sep + ".git",
                                               os.sep + "vendor", os.sep + ".ide_profile")):
                    continue
                for fn in files:
                    fp = os.path.join(root, fn)
                    low = fn.lower()
                    if low in supported or manifests.is_supported_path(fp) or _is_sbom(fp):
                        stype, pkgs, err = self._packages_from(fp)
                        self.parse_report.append({
                            "path": fp, "type": stype, "parse_ok": not err,
                            "component_count": len(pkgs), "error": err})
                        if err:
                            self.parse_failures.append(fp)
                            self.notes.append(f"parse failed: {err}: {fp}")
                            continue
                        if not pkgs:
                            self.notes.append(
                                f"manifest parsed but contains no components: {fp}")
                            continue
                        sources.append(ScanSource(fp, stype, pkgs,
                                                  parse_ok=True, parse_error=""))
                    elif low in _KNOWN_UNSUPPORTED_MANIFESTS:
                        # a manifest we recognize but cannot parse: disclose it,
                        # never let it silently become an empty project
                        self.parse_report.append({
                            "path": fp, "type": "unsupported-manifest",
                            "parse_ok": None, "component_count": 0,
                            "error": "known dependency manifest with no parser "
                                     "(unsupported manifest)"})
                        self.unsupported_files.append(fp)
                        self.notes.append(
                            f"unsupported manifest present (no parser): {fp}")
            return sources
        self.target_missing.append(target)
        self.notes.append(f"scan target does not exist: {target}")
        return sources

    # -- querying ---------------------------------------------------------------
    def _query_online(self, name: str, version: str, osv_eco: str) -> Tuple[Optional[List[dict]], bool]:
        """Query OSV.dev directly with the correct ecosystem. Returns (raw, ok)."""
        from bts_sbom._internal.osv_client import OsvClient
        with self._lock:
            if self._client is None:
                self._client = OsvClient()
        payload = {"version": version, "package": {"name": name, "ecosystem": osv_eco}}
        data, ok = self._client.post_query(self._client.api_url, payload)
        if not ok:
            return None, False
        return (data.get("vulns", []) if data else []), True

    def _query_package(self, name: str, version: str, osv_eco: str) -> Tuple[List[dict], str]:
        """Return (raw_vulns, status). status in
        queried_online | queried_offline | network_fallback_offline | offline_no_data |
        unqueried | version_unresolved.

        version_unresolved: the version is a range or empty - an OSV query would
        fabricate an answer, so none is made and the component is NOT clean."""
        from bts_sbom._internal import osv_local_db
        if not is_exact_version(version):
            return [], "version_unresolved"
        hit = self._prefetched.get((osv_eco, name, version))
        if hit is not None:                       # answered by the parallel prefetch
            return hit
        if self.offline:
            raw = osv_local_db.lookup(osv_eco, name, version)
            if raw is None:
                return [], "offline_no_data"      # DB has no record - UNKNOWN, not clean
            fresh = _offline_freshness(osv_eco, name, version)
            with self._lock:
                self._offline_ts.append(fresh)
                self._advisory_ts.extend(_advisory_modified(v) for v in raw or [])
            return raw, "queried_offline"
        # online (honest degrade to offline on network failure)
        raw, ok = self._query_online(name, version, osv_eco)
        if ok:
            try:
                osv_local_db.store_exact(osv_eco, name, version, raw)  # build the cache
            except Exception:
                pass
            with self._lock:
                self._advisory_ts.extend(_advisory_modified(v) for v in raw or [])
            return raw, "queried_online"
        with self._lock:
            self._network_failures += 1           # OSV.dev unreachable for this query
        cached = osv_local_db.lookup(osv_eco, name, version)
        if cached is None:
            return [], "unqueried"                # network down AND no cache - UNKNOWN
        fresh = _offline_freshness(osv_eco, name, version)
        with self._lock:
            self._offline_ts.append(fresh)
            self._advisory_ts.extend(_advisory_modified(v) for v in cached or [])
        return cached, "network_fallback_offline"

    def _prefetch(self, sources: List["ScanSource"]) -> None:
        """Answer every distinct (ecosystem, name, version) of the scan in parallel.

        The per-component statuses are exactly what the serial path would have
        produced - this only changes WHEN the requests are made.  A 300-package
        lockfile used to cost 300 sequential round trips (each with a 0.1 s
        courtesy sleep); with N workers it costs about 300/N.  Disabled for
        offline scans (a local SQLite lookup) and tiny scans (pool overhead)."""
        self._prefetched = {}
        if self.offline:
            return
        keys: List[Tuple[str, str, str]] = []
        seen = set()
        for src in sources:
            for p in src.packages:
                if not is_exact_version(p.get("version")):
                    continue
                key = (normalize_ecosystem(p["ecosystem"]), p["name"], p["version"])
                if key not in seen:
                    seen.add(key)
                    keys.append(key)
        try:
            workers = int(os.environ.get("BTS_SBOM_SCA_WORKERS",
                                        os.environ.get("ECU_SENTINEL_SCA_WORKERS", "8")))
        except ValueError:
            workers = 8
        workers = max(1, min(workers, 16, len(keys)))
        if workers < 2 or len(keys) < 4:
            return
        from concurrent.futures import ThreadPoolExecutor

        def _one(key):
            try:
                return key, self._query_package(key[1], key[2], key[0])
            except Exception as exc:              # a worker must never kill the scan
                logger.warning("OSV prefetch failed for %s@%s: %s", key[1], key[2], exc)
                return key, None

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="osv") as pool:
            for key, res in pool.map(_one, keys):
                if res is not None:
                    self._prefetched[key] = res
        self.notes.append("OSV lookups ran in parallel (%d workers, %d distinct components)"
                          % (workers, len(keys)))

    # -- main scan --------------------------------------------------------------
    def scan(self, targets, dry_run: bool = False, with_licenses: bool = False,
             guided_remediation: bool = False,
             stale_db_days: float = DEFAULT_STALE_DB_DAYS) -> Dict[str, Any]:
        """Scan targets and return the native OSV-Scanner result structure
        (augmented with an honest `scan_status` block and a `completeness`
        block carrying the parse/query-stage data contract)."""
        if isinstance(targets, str):
            targets = [targets]
        # fresh per-scan evidence (discover() may be called separately by
        # report builders; THIS scan's own discovery is the authoritative record)
        self.parse_report, self.unsupported_files = [], []
        self.parse_failures, self.target_missing = [], []
        self._network_failures, self._offline_ts, self._advisory_ts = 0, [], []

        sources: List[ScanSource] = []
        for t in targets:
            sources.extend(self.discover(t))

        total_pkgs = sum(len(s.packages) for s in sources)
        status = {"sources": len(sources), "packages": total_pkgs,
                  "queried_online": 0, "queried_offline": 0,
                  "network_fallback_offline": 0, "offline_no_data": 0, "unqueried": 0,
                  "version_unresolved": 0,
                  "withdrawn_filtered": 0,
                  "mode": "offline" if self.offline else "online",
                  "dry_run": dry_run}

        if dry_run:
            # discovery only — no OSV query, no network, no DB read.
            status["note"] = "dry-run: discovery only, no OSV query performed"
            return {"results": [{"source": {"path": s.path, "type": s.type},
                                 "packages": [{"package": {"name": p["name"],
                                                           "version": p["version"],
                                                           "ecosystem": p["ecosystem"]},
                                               "identity": component_identity(p),
                                               "vulnerabilities": [], "groups": []}
                                              for p in s.packages]}
                                for s in sources],
                    "scan_status": status,
                    "completeness": self._completeness_block(sources, [], status,
                                                             dry_run=True,
                                                             stale_db_days=stale_db_days),
                    "notes": self.notes,
                    "experimental_config": {"licenses": {"summary": with_licenses}}}

        self._prefetch(sources)
        native_results = []
        cve_objs = []          # CveVulnerability list for fix_planner / SARIF reuse
        all_pkg_dicts = []     # for license analysis
        self.withdrawn: List[Dict[str, Any]] = []   # for VEX not_affected emission
        active_advisories = 0
        for s in sources:
            pkg_entries = []
            for p in s.packages:
                all_pkg_dicts.append(p)
                osv_eco = normalize_ecosystem(p["ecosystem"])
                raw, st = self._query_package(p["name"], p["version"], osv_eco)
                # fw-distro fallback (2026-11-15): firmware packages arrive as
                # generic/OpenWRT purls that OSV answers 0/400 for.  When the
                # primary eco produced no ANSWERED result AND the package carries
                # distro candidates (common/fw_distro_match), retry each candidate
                # until one answers; the winning eco stays on the entry so the
                # finding is attributable to its advisory source.
                _fb_eco = None
                # OSS-Fuzz is OSV's catch-all that answers 200 with 0 vulns
                # for arbitrary C/C++ names - an "answered" zero there is
                # MEANINGLESS, so it also triggers the distro fallback.
                _primary_meaningful = (st in ANSWERED_STATUSES
                                       and osv_eco != "OSS-Fuzz")
                if not _primary_meaningful and p.get("osv_ecosystems"):
                    for _cand in (p.get("osv_ecosystems") or [])[:4]:
                        if _cand == osv_eco:
                            continue
                        _craw, _cst = self._query_package(
                            p.get("osv_name") or p["name"], p["version"], _cand)
                        if _cst in ANSWERED_STATUSES:
                            raw, st, osv_eco, _fb_eco = _craw, _cst, _cand, _cand
                            break
                status[st] = status.get(st, 0) + 1
                if _fb_eco:
                    status["fw_distro_fallback"] = \
                        status.get("fw_distro_fallback", 0) + 1
                # Drop withdrawn advisories from the ACTIVE set (never a finding).
                raw, withdrawn = _split_withdrawn(raw)
                if withdrawn:
                    status["withdrawn_filtered"] += len(withdrawn)
                    self._advisory_ts.extend(_advisory_modified(w) for w in withdrawn)
                    product = p.get("purl") or f"pkg:{osv_eco.lower()}/{p['name']}@{p['version']}"
                    for w in withdrawn:
                        self.withdrawn.append({"id": w.get("id", ""), "product": product,
                                               "withdrawn": w.get("withdrawn", "")})
                active_advisories += len(raw)
                entry = {"package": {"name": p["name"], "version": p["version"],
                                     "ecosystem": osv_eco},
                         "identity": component_identity(p),
                         "query_status": st,
                         "vulnerabilities": raw,
                         "groups": _group_by_alias(raw) if raw else []}
                if st in ANSWERED_STATUSES:
                    entry["query_status_detail"] = (
                        "no_vuln_found" if not raw else "vulns_found")
                if withdrawn:
                    entry["withdrawn"] = [{"id": w.get("id", ""),
                                           "withdrawn": w.get("withdrawn", "")} for w in withdrawn]
                if st not in ANSWERED_STATUSES:
                    # honesty flag: NOT verified clean (kept for older consumers
                    # that read per-entry scan_status)
                    entry["scan_status"] = st
                scope = p.get("scope")
                if scope is not None:
                    entry["scope"] = scope
                    entry["scope_basis"] = p.get("scope_basis", "unavailable")
                pkg_entries.append(entry)
                for v in raw:
                    cve_objs.append(self._to_cve(v, p, osv_eco))
            native_results.append({"source": {"path": s.path, "type": s.type},
                                   "packages": pkg_entries})

        completeness = self._completeness_block(sources, native_results, status,
                                                dry_run=False,
                                                stale_db_days=stale_db_days)
        completeness["consistency"] = self._lock_manifest_consistency(sources)
        result = {"results": native_results, "scan_status": status,
                  "completeness": completeness, "notes": self.notes,
                  "experimental_config": {}}
        logger.debug("live scan: experimental_config absent in raw OSV response; defaulting to {}")
        self._cve_objs = cve_objs

        if with_licenses:
            try:
                from bts_sbom._internal import license_utils
                result["experimental_licenses"] = license_utils.analyze_licenses(all_pkg_dicts)
            except Exception as e:
                self.notes.append(f"license scan skipped: {e}")

        if guided_remediation:
            try:
                from bts_sbom._internal import fix_planner
                result["experimental_remediation"] = fix_planner.plan_fixes(cve_objs)
            except Exception as e:
                self.notes.append(f"guided remediation skipped: {e}")

        return result

    # -- completeness assembly (Batch C1) ---------------------------------------
    def _completeness_block(self, sources: List[ScanSource],
                            native_results: List[Dict[str, Any]],
                            status: Dict[str, Any], dry_run: bool,
                            stale_db_days: float) -> Dict[str, Any]:
        """Assemble the parse/query-stage completeness evidence. `data_status`
        and `vulnerability_presence` are SEPARATE fields: the substitution rule
        (no data is never reported as no vulnerability) is decided by BOTH."""
        parse_entries = list(self.parse_report)
        per_component: List[Dict[str, Any]] = []
        counts = {"queried_count": 0, "answered_from_cache": 0, "no_data_count": 0}
        answered_all = True
        for src in native_results:
            for pe in src.get("packages", []):
                st = pe.get("query_status", "")
                row = {"identity": pe.get("identity", {}),
                       "source": src.get("source", {}).get("path", ""),
                       "query_status": st}
                if st in ANSWERED_STATUSES:
                    counts["queried_count"] += 1
                elif st == "network_fallback_offline":
                    counts["answered_from_cache"] += 1
                else:
                    counts["no_data_count"] += 1
                    answered_all = False
                    row["reason"] = {
                        "offline_no_data": "no record in the offline DB",
                        "unqueried": "OSV.dev unreachable and no cached answer",
                        "version_unresolved": "version is a range or empty — not queryable",
                    }.get(st, st)
                per_component.append(row)

        component_count = sum(len(s.packages) for s in sources)
        parse_ok = bool(parse_entries) and all(e["parse_ok"] is not False
                                               for e in parse_entries)
        parse_block = {
            "parse_ok": parse_ok,
            "sources_seen": len(parse_entries),
            "parsed_sources": sum(1 for e in parse_entries if e["parse_ok"] is True),
            "failed": [e for e in parse_entries if e["parse_ok"] is False],
            "unsupported": [e for e in parse_entries if e["parse_ok"] is None],
            "per_source": parse_entries,
            "probe_limitation": (
                "strict corruption probes cover JSON/TOML manifests and SBOMs; "
                "line-format manifests (requirements.txt, Gemfile.lock, gradle*, "
                "mix.lock) trust the parser and report parse_ok accordingly"),
        }
        resolution_ok = (component_count > 0 and not dry_run and answered_all
                         and parse_ok)
        resolution_block = {
            "resolution_ok": resolution_ok,
            "component_count": component_count,
            "queried_count": counts["queried_count"],
            "answered_from_cache": counts["answered_from_cache"],
            "no_data_count": counts["no_data_count"],
            "network_failures": self._network_failures,
            "per_component": per_component,
        }

        # presence: found beats none; ANY unanswered component makes the overall
        # existence undetermined even if other components answered clean.
        active_found = any(len(pe.get("vulnerabilities", []))
                           for src in native_results for pe in src.get("packages", []))
        if active_found:
            presence = "found"
        elif counts["no_data_count"] or component_count == 0 or dry_run:
            presence = "unknown"
        else:
            presence = "none"

        # staleness of the advisory data that actually answered the queries
        known_ts = [t for t in self._offline_ts if t]
        stale_reasons: List[str] = []
        if self._offline_ts and len(known_ts) < len(self._offline_ts):
            stale_reasons.append("some offline-sourced answers have no recorded "
                                 "freshness (cannot prove the data is current)")
        freshest_offline = max(known_ts) if known_ts else None
        now = _now_epoch()
        if freshest_offline is not None:
            age_days = max(0.0, (now - freshest_offline) / 86400.0)
            if age_days > stale_db_days:
                stale_reasons.append("offline advisory data is %.1f days old "
                                     "(threshold %.1f)" % (age_days, stale_db_days))
        elif self._offline_ts:
            age_days = None
        else:
            age_days = None   # online answers are fresh by construction
        stale = bool(stale_reasons)
        # an advisory without a `modified` stamp yields None; max() over a list that
        # mixes None and str (or is all None) raised TypeError and failed the scan
        _stamps = [t for t in self._advisory_ts if t]
        advisory_ts = max(_stamps) if _stamps else _iso_ts(freshest_offline)
        if dry_run or component_count == 0:
            answers_from = "none"
        elif not self._offline_ts:
            answers_from = "online"
        elif len(self._offline_ts) < component_count:
            answers_from = "mixed"
        else:
            answers_from = "offline"

        # single data_status label; earlier pipeline stages win over later ones
        # because they invalidate everything downstream of them.
        if self.target_missing and not parse_entries:
            data_status = "target_missing"
        elif not parse_entries:
            data_status = "empty_project"
        elif all(e["parse_ok"] is None for e in parse_entries):
            data_status = "unsupported_manifest"
        elif any(e["parse_ok"] is False for e in parse_entries):
            data_status = "parse_failed"
        elif dry_run:
            # the query stage never ran: nothing here can be a verified answer
            data_status = "query_missing"
        elif counts["no_data_count"]:
            data_status = "query_missing"
        elif self._network_failures:
            data_status = "network_failure"
        elif stale:
            data_status = "stale_db"
        else:
            data_status = "complete"

        return {
            "schema": COMPLETENESS_SCHEMA,
            "parse": parse_block,
            "resolution": resolution_block,
            "consistency": {},   # filled by scan() after lock/manifest cross-check
            "data_status": data_status,
            "vulnerability_presence": presence,
            "stale": {"stale": stale, "age_days": age_days,
                      "threshold_days": stale_db_days, "reasons": stale_reasons,
                      "answers_from": answers_from},
            "advisory_timestamp": advisory_ts,
            "source_snapshot_digest": source_snapshot_digest(sources),
        }

    def _lock_manifest_consistency(self, sources: List[ScanSource]) -> Dict[str, Any]:
        """Cross-check each directory's npm manifest pins against its lockfile
        resolutions. A manifest pinned to X while the lock resolved Y is a
        lock-manifest mismatch and is reported, not silently reconciled.
        Semver range specs cannot be compared literally here; they are counted
        as a disclosed limitation. Other ecosystems have per-ecosystem lock
        semantics and are disclosed as not checked."""
        by_dir: Dict[str, List[ScanSource]] = {}
        for s in sources:
            d = os.path.normcase(os.path.dirname(os.path.abspath(s.path)))
            by_dir.setdefault(d, []).append(s)
        checked_pairs, range_specs = 0, 0
        mismatches: List[Dict[str, Any]] = []
        for d, ss in by_dir.items():
            manifest = next((s for s in ss
                             if os.path.basename(s.path).lower() == "package.json"), None)
            lock = next((s for s in ss if os.path.basename(s.path).lower()
                         in ("package-lock.json", "npm-shrinkwrap.json")), None)
            if manifest is None or lock is None:
                continue
            checked_pairs += 1
            specs = self._npm_manifest_specs(manifest.path)
            range_specs += specs["range_count"]
            lock_versions: Dict[str, set] = {}
            for p in lock.packages:
                lock_versions.setdefault(str(p.get("name", "")).lower(),
                                         set()).add(str(p.get("version", "")))
            for name, spec in sorted(specs["exact"].items()):
                vers = lock_versions.get(name.lower())
                if vers and spec not in vers:
                    mismatches.append({
                        "name": name, "manifest_pin": spec,
                        "lock_resolved": sorted(vers),
                        "manifest": manifest.path, "lockfile": lock.path,
                        "detail": "manifest pins %s==%s but the lockfile resolved %s "
                                  "(lock wins for what is INSTALLED; the pin is dead "
                                  "or stale — reconcile them)" % (name, spec, sorted(vers))})
        return {"checked_pairs": checked_pairs, "mismatches": mismatches,
                "range_specs_in_manifest": range_specs,
                "limitation": "lock/manifest cross-check implemented for npm only; "
                              "other ecosystems are not checked here"}

    @staticmethod
    def _npm_manifest_specs(path: str) -> Dict[str, Dict[str, Any]]:
        exact: Dict[str, str] = {}
        range_count = 0
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                data = json.load(fh)
        except Exception:
            return {"exact": exact, "range_count": range_count}
        for section in ("dependencies", "devDependencies", "optionalDependencies",
                        "peerDependencies"):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                spec = str(spec).strip()
                if is_exact_version(spec):
                    exact[str(name)] = spec.lstrip("=")
                else:
                    range_count += 1
        return {"exact": exact, "range_count": range_count}

    def _to_cve(self, vuln: Dict[str, Any], pkg: Dict[str, Any], osv_eco: str):
        """Map a raw OSV record → CveVulnerability (for SARIF / fix planner reuse)."""
        from bts_sbom._internal.models import CveVulnerability
        score, label, vector = _osv_severity(vuln)
        vid = vuln.get("id", "")
        aliases = vuln.get("aliases", []) or []
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vid)
        fixed = _fixed_version(vuln, pkg["name"], pkg.get("version"))
        refs = [r.get("url", "") for r in vuln.get("references", []) or [] if r.get("url")]
        obj = CveVulnerability(
            package_name=pkg["name"], package_version=pkg["version"],
            cve_id=cve_id, osv_id=vid, severity=label,
            cvss_score=score if score > 0.0 else None, cvss_vector=vector,
            description=vuln.get("summary") or vuln.get("details", "") or vid,
            fixed_version=fixed, fix_available=bool(fixed), references=refs,
        )
        # ecosystem lives outside the declared fields — attach for fix_planner grouping
        try:
            object.__setattr__(obj, "ecosystem", osv_eco)
        except Exception:
            pass
        return obj

    # -- output formatters ------------------------------------------------------
    @staticmethod
    def _vuln_rows(result: Dict[str, Any]):
        for src in result.get("results", []):
            spath = src.get("source", {}).get("path", "")
            for pe in src.get("packages", []):
                pk = pe.get("package", {})
                for v in pe.get("vulnerabilities", []):
                    score, label, _ = _osv_severity(v)
                    yield {"source": spath, "eco": pk.get("ecosystem", ""),
                           "pkg": pk.get("name", ""), "ver": pk.get("version", ""),
                           "id": v.get("id", ""),
                           "severity": (f"{label} {score:.1f}" if score else label),
                           "fixed": _fixed_version(v, pk.get("name", ""), pk.get("version")) or "-"}

    def render(self, result: Dict[str, Any], fmt: str = "table") -> str:
        fmt = fmt.lower()
        if fmt == "json":
            return json.dumps(result, indent=2, ensure_ascii=False)
        if fmt == "sarif":
            from bts_sbom._internal import sarif
            return json.dumps(sarif.build_sca_sarif(getattr(self, "_cve_objs", [])),
                              indent=2, ensure_ascii=False)
        if fmt in ("markdown", "md"):
            return self._render_markdown(result)
        if fmt == "vertical":
            return self._render_vertical(result)
        return self._render_table(result)

    @staticmethod
    def _verified_clean(result: Dict[str, Any]) -> bool:
        """True only when an empty vulnerability list is a VERIFIED pass:
        complete data AND every component authoritatively answered. Results from
        before the completeness contract fall back to the scan_status counters."""
        c = result.get("completeness") or {}
        if c:
            return (c.get("data_status") == "complete"
                    and c.get("vulnerability_presence") == "none")
        st = result.get("scan_status", {}) or {}
        return not (st.get("unqueried", 0) or st.get("offline_no_data", 0)
                    or st.get("version_unresolved", 0))

    def _render_table(self, result: Dict[str, Any]) -> str:
        rows = list(self._vuln_rows(result))
        st = result.get("scan_status", {})
        out = []
        if not rows:
            # SUBSTITUTION RULE: an empty list is a clean pass ONLY on complete,
            # authoritative data — otherwise say the data is incomplete.
            if self._verified_clean(result):
                out.append("No known vulnerabilities found "
                           "(all components authoritatively queried).")
            else:
                out.append("No vulnerabilities REPORTED - but this is NOT a "
                           "verified clean pass (incomplete data below).")
        else:
            hdr = ("OSV ID", "ECOSYSTEM", "PACKAGE", "VERSION", "SEVERITY", "FIXED")
            widths = [max(len(hdr[i]), max((len(str(r[k])) for r in rows), default=0))
                      for i, k in enumerate(("id", "eco", "pkg", "ver", "severity", "fixed"))]
            def line(vals):
                return "  ".join(str(v).ljust(widths[i]) for i, v in enumerate(vals))
            out.append(line(hdr))
            out.append("  ".join("-" * w for w in widths))
            for r in rows:
                out.append(line((r["id"], r["eco"], r["pkg"], r["ver"], r["severity"], r["fixed"])))
        out.append("")
        out.append(self._status_line(st, result.get("completeness")))
        out.extend(self._remediation_lines(result))
        return "\n".join(out)

    @staticmethod
    def _remediation_lines(result: Dict[str, Any]) -> List[str]:
        """Round-2 E4: compact suggested-fix footer for table output."""
        rem = result.get("remediation") or {}
        sugg = rem.get("suggestions") or []
        if not sugg:
            return []
        lines = ["", "Suggested fixes (advisory only, smallest fixed >= current):"]
        for s in sugg:
            if s.get("fixed_suggestion"):
                lines.append("  %s  %s@%s -> %s" % (
                    s.get("osv_id", "?"), s.get("package", "?"),
                    s.get("current") if s.get("current") is not None else "?",
                    s["fixed_suggestion"]))
            else:
                lines.append("  %s  %s@%s -> (no fixed version recorded: %s)" % (
                    s.get("osv_id", "?"), s.get("package", "?"),
                    s.get("current") if s.get("current") is not None else "?",
                    s.get("constraint_source", "no-fixed-event")))
        return lines

    def _render_markdown(self, result: Dict[str, Any]) -> str:
        rows = list(self._vuln_rows(result))
        out = ["# OSV Scan Report", "",
               f"- Mode: **{result.get('scan_status', {}).get('mode', '?')}**",
               f"- Packages scanned: **{result.get('scan_status', {}).get('packages', 0)}**",
               f"- Vulnerabilities: **{len(rows)}**", ""]
        if rows:
            out += ["| OSV ID | Ecosystem | Package | Version | Severity | Fixed |",
                    "|---|---|---|---|---|---|"]
            for r in rows:
                out.append(f"| {r['id']} | {r['eco']} | {r['pkg']} | {r['ver']} | {r['severity']} | {r['fixed']} |")
        elif self._verified_clean(result):
            out.append("_No known vulnerabilities found — all components "
                       "authoritatively queried._")
        else:
            out.append("_No vulnerabilities **reported** — NOT a verified clean "
                       "pass: scan data is incomplete (see status footer)._")
        rem = result.get("experimental_remediation")
        if rem:
            out += ["", "## Guided remediation (suggestions only)", "",
                    "| Component | Current | Safe upgrade | Clears | Status |",
                    "|---|---|---|---|---|"]
            for p in rem:
                out.append(f"| {p['component']} | {p['current_version']} | "
                           f"{p.get('safe_version') or '-'} | {len(p.get('clears', []))} | {p['status']} |")
        rem2 = result.get("remediation") or {}
        sugg = rem2.get("suggestions") or []
        if sugg:
            out += ["", "## Remediation (smallest fixed version >= current)", "",
                    "| OSV ID | Package | Current | Suggested fix | Source |",
                    "|---|---|---|---|---|"]
            for s in sugg:
                out.append(f"| {s.get('osv_id', '')} | {s.get('package', '')} | "
                           f"{s.get('current') if s.get('current') is not None else '?'} | "
                           f"{s.get('fixed_suggestion') or '-'} | "
                           f"{s.get('constraint_source', '')} |")
        out += ["", self._status_line(result.get("scan_status", {}), result.get("completeness"))]
        return "\n".join(out)

    def _render_vertical(self, result: Dict[str, Any]) -> str:
        out = []
        for src in result.get("results", []):
            src_info = src.get("source", {})
            out.append(f"{src_info.get('path', '')} ({src_info.get('type', '')}):")
            any_v = False
            for pe in src.get("packages", []):
                pkg = pe.get("package", {})
                for v in pe.get("vulnerabilities", []):
                    any_v = True
                    score, label, _ = _osv_severity(v)
                    out.append(f"  {v.get('id','')}  {pkg.get('name','')}@{pkg.get('version','')} "
                               f" [{label} {score:.1f}]")
                flag = pe.get("query_status") or pe.get("scan_status")
                if flag and flag not in ANSWERED_STATUSES:
                    out.append(f"  ? {pkg.get('name','')}@{pkg.get('version','')}  "
                               f"[{flag} — NOT verified clean]")
            if not any_v:
                if self._verified_clean(result):
                    out.append("  (no vulnerabilities — all components "
                               "authoritatively queried)")
                else:
                    out.append("  (no vulnerabilities reported — data INCOMPLETE, "
                               "not a verified clean pass)")
        out += ["", self._status_line(result.get("scan_status", {}), result.get("completeness"))]
        return "\n".join(out)

    @staticmethod
    def _status_line(st: Dict[str, Any], completeness: Optional[Dict[str, Any]] = None) -> str:
        unq = (st.get("unqueried", 0) + st.get("offline_no_data", 0)
               + st.get("version_unresolved", 0))
        base = (f"scanned {st.get('packages', 0)} package(s) across {st.get('sources', 0)} source(s) "
                f"[mode={st.get('mode', '?')}]")
        if completeness:
            base += (f" [data_status={completeness.get('data_status', '?')}, "
                     f"presence={completeness.get('vulnerability_presence', '?')}]")
            if completeness.get("advisory_timestamp"):
                base += f" [advisory data as of {completeness['advisory_timestamp']}]"
            stale = (completeness.get("stale") or {})
            if stale.get("stale"):
                base += " [STALE advisory data]"
        if unq:
            base += (f" — WARNING: {unq} package(s) could not be authoritatively queried "
                     f"and are NOT verified clean")
        if st.get("network_fallback_offline"):
            base += f" — note: {st['network_fallback_offline']} used offline cache (OSV.dev unreachable)"
        if st.get("withdrawn_filtered"):
            base += (f" — note: {st['withdrawn_filtered']} withdrawn advisory(ies) excluded "
                     f"from the active set (see VEX)")
        return base

    # -- VEX export -------------------------------------------------------------
    def to_openvex(self, result: Dict[str, Any], timestamp: str) -> Dict[str, Any]:
        """Emit a standalone OpenVEX document derived from this scan: `affected`
        statements for active advisories, `under_investigation` for packages that
        could not be queried, and `not_affected` for any withdrawn advisory."""
        from bts_sbom import vex
        doc = vex.from_scan_result(result, timestamp=timestamp)
        withdrawn = getattr(self, "withdrawn", [])
        if withdrawn:
            wd = vex.withdrawn_statements(withdrawn, timestamp=timestamp)
            doc["statements"].extend(wd["statements"])
        return doc


# ── convenience one-shot API ────────────────────────────────────────────────────
def scan(target, output: str = "table", offline: bool = False, dry_run: bool = False,
         licenses: bool = False, guided_remediation: bool = False) -> Tuple[Dict[str, Any], str]:
    """Scan `target` and return (native_result, rendered_output)."""
    scanner = OsvScanner(offline=offline)
    result = scanner.scan(target, dry_run=dry_run, with_licenses=licenses,
                          guided_remediation=guided_remediation)
    return result, scanner.render(result, output)
