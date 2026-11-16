# vendored from common/osv_local_db.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
Persistent local OSV vulnerability database (offline fallback).

Two layers:
  1. exact_cache  — durable (no TTL) store of live OSV query results keyed by
     (ecosystem, package, version). Accumulates a real local DB as the platform
     is used online; queried offline for exact (eco, name, version) hits.
  2. pkg_index    — package-level index built by importing OSV's public
     per-ecosystem `all.zip` dumps, enabling broader offline coverage with
     best-effort version matching.

When the OSV API is unreachable, cve_scanner falls back to lookup() here.

DB file: BTS_SBOM_OSV_DB_PATH env var  (default ./bts_sbom_osv_local.db)
Bulk data (per https://google.github.io/osv.dev/data/):
  bucket : gs://osv-vulnerabilities
  dumps  : https://storage.googleapis.com/osv-vulnerabilities/<ECOSYSTEM>/all.zip
  index  : https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt
  schema : OSV schema (https://ossf.github.io/osv-schema/)
NOTE: dump directories use the BASE ecosystem name ("Debian", "Alpine"),
not the version-qualified API form ("Debian:12").
"""
import io
from bts_sbom._version import __version__ as _BTS_VERSION
import os
import json
import time
import zipfile
import logging
import sqlite3
import urllib.parse
from typing import List, Dict, Any, Optional, Callable

import urllib.request
import urllib.error

from bts_sbom._internal import version_ranges

# (config.settings decoupled for the standalone package: the DB path and
# dump base URL come from env vars with the same defaults the platform used)
DB_PATH = os.environ.get("BTS_SBOM_OSV_DB_PATH") or os.path.join(os.getcwd(), "bts_sbom_osv_local.db")
OSV_DUMP_BASE_URL = os.environ.get("BTS_SBOM_OSV_DUMP_BASE_URL") or \
    "https://storage.googleapis.com/osv-vulnerabilities"


def _http_get(url: str, timeout: int = 20):
    """stdlib replacement for requests.get -> dict with status_code/text/content."""
    req = urllib.request.Request(url, headers={"User-Agent": "bts-sbom/" + _BTS_VERSION})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        return {"status_code": resp.status, "content": body,
                "text": body.decode("utf-8", "replace")}

logger = logging.getLogger("OsvLocalDB")


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    return conn


def init_db() -> None:
    conn = _connect()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS exact_cache (
            ecosystem TEXT, package_name TEXT, version TEXT,
            vulns_json TEXT, updated_at REAL,
            PRIMARY KEY (ecosystem, package_name, version)
        )
    """)
    # NORMALIZED storage to avoid duplicating large vuln bodies per package.
    # vulns: each OSV record stored ONCE; pkg_map: lightweight package->id links.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vulns (
            ecosystem TEXT, vuln_id TEXT, vuln_json TEXT,
            PRIMARY KEY (ecosystem, vuln_id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS pkg_map (
            ecosystem TEXT, package_name TEXT, vuln_id TEXT,
            PRIMARY KEY (ecosystem, package_name, vuln_id)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_pkgmap ON pkg_map (ecosystem, package_name)")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS import_meta (
            ecosystem TEXT PRIMARY KEY, vuln_count INTEGER, imported_at REAL
        )
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- exact layer
def store_exact(ecosystem: str, name: str, version: str, raw_vulns: List[dict]) -> None:
    """Durably store a live OSV result (raw `vulns` list) for offline reuse."""
    try:
        init_db()
        conn = _connect()
        conn.execute(
            "INSERT OR REPLACE INTO exact_cache "
            "(ecosystem, package_name, version, vulns_json, updated_at) VALUES (?,?,?,?,?)",
            (ecosystem, name.lower(), version, json.dumps(raw_vulns), time.time()),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"store_exact failed for {name}@{version}: {e}")


def lookup_exact(ecosystem: str, name: str, version: str) -> Optional[List[dict]]:
    try:
        init_db()
        conn = _connect()
        row = conn.execute(
            "SELECT vulns_json FROM exact_cache WHERE ecosystem=? AND package_name=? AND version=?",
            (ecosystem, name.lower(), version),
        ).fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception as e:
        logger.error(f"lookup_exact failed: {e}")
    return None


# ------------------------------------------------------------- version compare
# Version-range evaluation now delegates to common/version_ranges.py, which
# selects ordering rules per ecosystem (npm SemVer / PyPI PEP 440 / Maven
# qualifiers / generic tolerant compare) and handles re-opened windows
# (multiple introduced/fixed pairs) and last_affected inclusive ends.


def _vuln_affects(vuln: dict, name: str, version: str) -> bool:
    """Does this OSV vuln affect name@version?

    Ecosystem-aware: the affected entry's package ecosystem (npm, PyPI,
    Maven, Go, ...) selects the comparator. Falls back to the generic
    tolerant comparator for unknown ecosystems; never raises.
    """
    name_l = name.lower()
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("name", "").lower() != name_l:
            continue
        eco = pkg.get("ecosystem", "")
        # explicit version list wins when present
        if version in aff.get("versions", []):
            return True
        for rng in aff.get("ranges", []):
            if version_ranges.affects(
                version, eco,
                events=rng.get("events") or [],
                range_type=rng.get("type"),
            ):
                return True
    return False


# ------------------------------------------------------------- pkg_index layer
def lookup_by_package(ecosystem: str, name: str, version: str) -> Optional[List[dict]]:
    """Offline lookup against imported dumps with best-effort version match."""
    try:
        init_db()
        conn = _connect()
        rows = conn.execute(
            "SELECT v.vuln_json FROM pkg_map p "
            "JOIN vulns v ON v.ecosystem = p.ecosystem AND v.vuln_id = p.vuln_id "
            "WHERE p.ecosystem=? AND p.package_name=?",
            (ecosystem, name.lower()),
        ).fetchall()
        conn.close()
        if not rows:
            return None
        matched = []
        for (vj,) in rows:
            try:
                vuln = json.loads(vj)
            except Exception:
                continue
            if _vuln_affects(vuln, name, version):
                matched.append(vuln)
        return matched  # may be [] (package known, this version not affected)
    except Exception as e:
        logger.error(f"lookup_by_package failed: {e}")
        return None


def lookup(ecosystem: str, name: str, version: str) -> Optional[List[dict]]:
    """Unified offline lookup: exact store first, then imported dump index."""
    exact = lookup_exact(ecosystem, name, version)
    if exact is not None:
        return exact
    return lookup_by_package(ecosystem, name, version)


# ------------------------------------------------------------- ecosystem index
_FALLBACK_ECOSYSTEMS = [
    "Debian", "Alpine", "Ubuntu", "Rocky Linux", "AlmaLinux", "Wolfi",
    "PyPI", "npm", "Go", "Maven", "RubyGems", "crates.io", "NuGet", "Packagist",
]


def fetch_ecosystems_index(timeout: int = 20) -> List[str]:
    """Fetch the live OSV ecosystems list (ecosystems.txt). Falls back to a
    small static list if the index cannot be retrieved."""
    url = f"{OSV_DUMP_BASE_URL}/ecosystems.txt"
    try:
        resp = _http_get(url, timeout=timeout)
        if resp["status_code"] == 200:
            ecos = [ln.strip() for ln in resp["text"].splitlines() if ln.strip()]
            if ecos:
                return ecos
        logger.warning(f"ecosystems.txt HTTP {resp['status_code']}; using fallback list.")
    except Exception as e:
        logger.warning(f"ecosystems.txt fetch failed ({e}); using fallback list.")
    return list(_FALLBACK_ECOSYSTEMS)


# ------------------------------------------------------------- dump import
def import_ecosystem_dump(ecosystem: str,
                          progress_cb: Optional[Callable[[int], None]] = None,
                          timeout: int = 120) -> Dict[str, Any]:
    """Download OSV's `all.zip` for an ecosystem and index it for offline use.

    `ecosystem` must be the exact OSV ecosystem string, e.g. "PyPI", "npm",
    "Debian:12", "Alpine:v3.19". Returns stats dict.
    """
    url = f"{OSV_DUMP_BASE_URL}/{urllib.parse.quote(ecosystem)}/all.zip"
    logger.info(f"Downloading OSV dump: {url}")
    try:
        resp = _http_get(url, timeout=timeout)
        if resp["status_code"] != 200:
            return {"ok": False, "error": f"HTTP {resp['status_code']}", "url": url}
    except Exception as e:
        return {"ok": False, "error": str(e), "url": url}

    init_db()
    conn = _connect()
    cur = conn.cursor()
    count = 0
    try:
        with zipfile.ZipFile(io.BytesIO(resp["content"])) as zf:
            names = [n for n in zf.namelist() if n.endswith(".json")]
            for n in names:
                try:
                    vuln = json.loads(zf.read(n).decode("utf-8", "replace"))
                except Exception:
                    continue
                vuln_id = vuln.get("id", "")
                if not vuln_id:
                    continue
                # Store the vuln body ONCE
                cur.execute(
                    "INSERT OR REPLACE INTO vulns (ecosystem, vuln_id, vuln_json) VALUES (?,?,?)",
                    (ecosystem, vuln_id, json.dumps(vuln)),
                )
                # Lightweight package -> vuln_id links (no JSON duplication)
                seen_pkgs = set()
                for aff in vuln.get("affected", []):
                    pkg = aff.get("package", {})
                    pname = pkg.get("name", "")
                    if not pname:
                        continue
                    pl = pname.lower()
                    if pl in seen_pkgs:
                        continue
                    seen_pkgs.add(pl)
                    cur.execute(
                        "INSERT OR REPLACE INTO pkg_map "
                        "(ecosystem, package_name, vuln_id) VALUES (?,?,?)",
                        (ecosystem, pl, vuln_id),
                    )
                count += 1
                if progress_cb and count % 200 == 0:
                    progress_cb(count)
        cur.execute(
            "INSERT OR REPLACE INTO import_meta (ecosystem, vuln_count, imported_at) VALUES (?,?,?)",
            (ecosystem, count, time.time()),
        )
        conn.commit()
    finally:
        conn.close()

    logger.info(f"Imported {count} OSV records for {ecosystem}.")
    return {"ok": True, "ecosystem": ecosystem, "vuln_count": count, "url": url}


# ------------------------------------------------------------- stats
def stats() -> Dict[str, Any]:
    try:
        init_db()
        conn = _connect()
        exact_n = conn.execute("SELECT COUNT(*) FROM exact_cache").fetchone()[0]
        idx_rows = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
        imports = conn.execute(
            "SELECT ecosystem, vuln_count, imported_at FROM import_meta ORDER BY ecosystem"
        ).fetchall()
        conn.close()
        return {
            "db_path": DB_PATH,
            "exact_entries": exact_n,
            "indexed_rows": idx_rows,
            "imported_ecosystems": [
                {"ecosystem": e, "vuln_count": c,
                 "imported_at": time.strftime("%Y-%m-%d %H:%M", time.localtime(t))}
                for (e, c, t) in imports
            ],
        }
    except Exception as e:
        logger.error(f"stats failed: {e}")
        return {"db_path": DB_PATH, "exact_entries": 0, "indexed_rows": 0, "imported_ecosystems": []}
