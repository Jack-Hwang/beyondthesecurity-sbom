# vendored from common/osv_client.py (Apache-2.0 release) -- stdlib-only:
# pydantic model -> dataclass, requests -> urllib, config.settings -> env var.
import json
import logging
import math
import os
import time
import urllib.request
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple

# (config.settings decoupled for the standalone package; requests replaced with
#  urllib so bts-sbom stays stdlib-only. Same endpoint + retry/backoff contract.)
OSV_API_URL = os.environ.get("BTS_SBOM_OSV_API_URL") or "https://api.osv.dev/v1/query"


def _post_json(url: str, payload: dict, timeout: int = 15):
    """POST JSON, return (http_status, parsed-body-or-None). Raises on network failure."""
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "bts-sbom/0.1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
        return resp.status, (json.loads(body.decode("utf-8", "replace")) if body else None)

logger = logging.getLogger("OsvClient")

def _cvss_score_from_vector(vector: str) -> Optional[float]:
    """Extract CVSS base score from a v3.x or v4.0 vector string.
    Returns None if the vector is unparseable."""
    if not vector:
        return None
    upper = vector.upper()
    if "CVSS:4" in upper:
        # CVSS v4.0 — EQ lookup table (mirrors osvscanner._cvss_v40_base_score)
        try:
            metrics: Dict[str, str] = {}
            for part in vector.split("/"):
                if ":" in part:
                    k, _, v = part.partition(":")
                    metrics[k.upper()] = v.upper()
            av = metrics.get("AV", "N")
            pr = metrics.get("PR", "N")
            ui = metrics.get("UI", "N")
            ac = metrics.get("AC", "L")
            at = metrics.get("AT", "N")
            vc = metrics.get("VC", "N")
            vi = metrics.get("VI", "N")
            va = metrics.get("VA", "N")
            sc = metrics.get("SC", "N")
            si = metrics.get("SI", "N")
            sa = metrics.get("SA", "N")
            e = metrics.get("E", "X")
            _AV4 = {"N": 0, "A": 1, "L": 2, "P": 3}
            _PR4 = {"N": 0, "L": 1, "H": 2}
            _UI4 = {"N": 0, "P": 1, "A": 2}
            _CIA4 = {"H": 0, "L": 1, "N": 2}
            _E4 = {"X": 0, "A": 0, "P": 1, "U": 2}
            eq1 = 0 if av == "N" and pr == "N" and ui == "N" else (
                  1 if av != "P" and (av == "N" or pr == "N" or ui == "N") else 2)
            eq2 = 0 if ac == "L" and at == "N" else 1
            eq3_val = 0 if vc == "H" and vi == "H" else (1 if vc == "H" or vi == "H" or va == "H" else 2)
            eq4 = 0 if sc == "H" or si == "H" or sa == "H" else (1 if sc == "L" or si == "L" or sa == "L" else 2)
            eq5 = _E4.get(e, 0)
            _ANCHORS = {
                (0,0,0,0):10.0,(0,0,0,1):9.9,(0,0,0,2):9.8,(0,0,1,0):9.5,(0,0,1,1):9.3,
                (0,0,1,2):9.2,(0,0,2,0):9.3,(0,0,2,1):9.1,(0,0,2,2):8.8,(0,1,0,0):9.4,
                (0,1,0,1):9.3,(0,1,0,2):9.2,(0,1,1,0):8.9,(0,1,1,1):8.7,(0,1,1,2):8.6,
                (0,1,2,0):8.7,(0,1,2,1):8.5,(0,1,2,2):8.4,(1,0,0,0):8.9,(1,0,0,1):8.8,
                (1,0,0,2):8.7,(1,0,1,0):8.5,(1,0,1,1):8.3,(1,0,1,2):8.2,(1,0,2,0):8.3,
                (1,0,2,1):8.1,(1,0,2,2):8.0,(1,1,0,0):8.4,(1,1,0,1):8.3,(1,1,0,2):8.2,
                (1,1,1,0):7.9,(1,1,1,1):7.7,(1,1,1,2):7.6,(1,1,2,0):7.7,(1,1,2,1):7.5,
                (1,1,2,2):7.4,(2,0,0,0):7.4,(2,0,0,1):7.3,(2,0,0,2):7.2,(2,0,1,0):7.0,
                (2,0,1,1):6.8,(2,0,1,2):6.7,(2,0,2,0):6.8,(2,0,2,1):6.6,(2,0,2,2):6.4,
                (2,1,0,0):7.0,(2,1,0,1):6.8,(2,1,0,2):6.7,(2,1,1,0):6.4,(2,1,1,1):6.2,
                (2,1,1,2):6.1,(2,1,2,0):6.2,(2,1,2,1):6.0,(2,1,2,2):5.8,
            }
            e5_delta = {0: 0.0, 1: -1.0, 2: -1.5}
            base = _ANCHORS.get((eq1, eq2, eq3_val, eq4), 0.0)
            return max(0.0, round(base + e5_delta.get(eq5, 0.0), 1))
        except Exception:
            return None
    if "CVSS:3" in upper:
        # CVSS v3.0 / v3.1
        _AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        _AC = {"L": 0.77, "H": 0.44}
        _UI = {"N": 0.85, "R": 0.62}
        _CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
        _PRU = {"N": 0.85, "L": 0.62, "H": 0.27}
        _PRC = {"N": 0.85, "L": 0.68, "H": 0.50}
        try:
            m: Dict[str, str] = {}
            for part in vector.split("/"):
                if ":" in part:
                    k, _, v = part.partition(":")
                    m[k.upper()] = v.upper()
            changed = m.get("S") == "C"
            av = _AV[m["AV"]]
            ac = _AC[m["AC"]]
            ui = _UI[m["UI"]]
            pr = (_PRC if changed else _PRU)[m["PR"]]
            c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
            isc = 1 - (1 - c) * (1 - i) * (1 - a)
            impact = (7.52 * (isc - 0.029) - 3.25 * (isc - 0.02) ** 15) if changed else 6.42 * isc
            if impact <= 0:
                return 0.0
            expl = 8.22 * av * ac * pr * ui
            raw = (1.08 if changed else 1.0) * (impact + expl)
            x = min(raw, 10.0) * 100000
            ix = int(round(x))
            score = ix / 100000.0 if ix % 10000 == 0 else (math.floor(ix / 10000) + 1) / 10.0
            return score
        except (KeyError, Exception):
            return None
    # CVSS v2 — vectors like "AV:N/AC:L/Au:N/C:P/I:P/A:P" or prefixed "CVSS2#AV:..."
    if "AV:" in upper and "AU:" in upper:
        _AV2 = {"L": 0.395, "A": 0.646, "N": 1.0}
        _AC2 = {"H": 0.35, "M": 0.61, "L": 0.71}
        _AU2 = {"M": 0.45, "S": 0.56, "N": 0.704}
        _CIA2 = {"N": 0.0, "P": 0.275, "C": 0.660}
        try:
            m2: Dict[str, str] = {}
            for part in vector.split("/"):
                if ":" in part:
                    k, _, v = part.partition(":")
                    m2[k.upper()] = v.upper()
            av2 = _AV2[m2["AV"]]
            ac2 = _AC2[m2["AC"]]
            au2 = _AU2[m2["AU"]]
            c2, i2, a2 = _CIA2[m2["C"]], _CIA2[m2["I"]], _CIA2[m2["A"]]
            impact2 = 10.41 * (1 - (1 - c2) * (1 - i2) * (1 - a2))
            expl2 = 20 * av2 * ac2 * au2
            f_impact = 0.0 if impact2 == 0 else 1.176
            raw2 = ((0.6 * impact2) + (0.4 * expl2) - 1.5) * f_impact
            return round(min(max(raw2, 0.0), 10.0) * 10) / 10.0
        except (KeyError, Exception):
            return None
    return None


@dataclass
class OsvVuln:
    vuln_id: str
    aliases: List[str] = field(default_factory=list)
    summary: str = ""
    severity: str = "LOW"  # LOW | MEDIUM | HIGH | CRITICAL
    cvss_score: float = 0.0
    cvss_vector: Optional[str] = None
    affected_versions: List[str] = field(default_factory=list)
    fixed_version: Optional[str] = None
    references: List[str] = field(default_factory=list)

class OsvClient:
    def __init__(self):
        self.api_url = os.environ.get("BTS_SBOM_OSV_API_URL") or OSV_API_URL
        self.batch_url = self.api_url.replace("/query", "/querybatch") if self.api_url.endswith("/query") else "https://api.osv.dev/v1/querybatch"

    def map_ecosystem(self, source_ecosystem: str) -> str:
        """
        Maps generic ecosystem names to OSV ecosystem naming conventions.

        Keep this mapping in sync with ``common.manifests``.  Falling back to
        OSS-Fuzz for a known package-manager ecosystem is unsafe: it produces a
        syntactically successful OSV query for the wrong namespace and can make
        a vulnerable package look clean.
        """
        ecosystem_map = {
            "debian": "Debian",
            "ubuntu": "Ubuntu",
            "alpine": "Alpine",
            "rocky linux": "Rocky Linux",
            "almalinux": "AlmaLinux",
            "wolfi": "Wolfi",
            "rpm": "Red Hat",
            "fedora": "Red Hat",
            "redhat": "Red Hat",
            "opkg": "Linux",
            "openwrt": "Linux",
            "linux": "Linux",
            "python": "PyPI",
            "pypi": "PyPI",
            "npm": "npm",
            "node": "npm",
            "go": "Go",
            "golang": "Go",
            "cargo": "crates.io",
            "crates.io": "crates.io",
            "ruby": "RubyGems",
            "rubygems": "RubyGems",
            "composer": "Packagist",
            "packagist": "Packagist",
            "php": "Packagist",
            "maven": "Maven",
            "gradle": "Maven",
            "java": "Maven",
            "nuget": "NuGet",
            "dotnet": "NuGet",
            ".net": "NuGet",
            "pub": "Pub",
            "dart": "Pub",
            "flutter": "Pub",
            "hex": "Hex",
            "elixir": "Hex",
            "cmake": "OSS-Fuzz",
            "conan": "OSS-Fuzz",
            "generic": "OSS-Fuzz"
        }
        raw = (source_ecosystem or "generic").strip()
        key = raw.lower()
        # OSV uses version-qualified distro ecosystems such as Debian:12 and
        # Alpine:v3.20. Preserve the qualifier while canonicalising the base.
        if ":" in raw:
            base, qualifier = raw.split(":", 1)
            canonical = ecosystem_map.get(base.lower().strip())
            if canonical in {"Debian", "Ubuntu", "Alpine", "Rocky Linux",
                             "AlmaLinux", "Wolfi"} and qualifier.strip():
                return f"{canonical}:{qualifier.strip()}"
        return ecosystem_map.get(key, "OSS-Fuzz")

    def post_query(self, url: str, payload: dict) -> Tuple[Optional[dict], bool]:
        """
        POST with exponential backoff. Returns (data, ok).
          ok=True  -> reached OSV (data may be {} when there are no vulns)
          ok=False -> OSV unreachable after retries (network/server failure)
        This distinction lets callers fall back to the local offline DB only
        on genuine connectivity failure, not on a legitimate "no vulns" result.
        """
        retries = 3
        backoff = 1.0

        # Enforce rate limit delay (0.1s)
        time.sleep(0.1)

        while retries > 0:
            try:
                status, data = _post_json(url, payload, timeout=15)
                if status == 200:
                    return data, True
                elif status == 429:
                    logger.warning(f"OSV API rate limited (429). Retrying in {backoff}s...")
                else:
                    logger.warning(f"OSV API error HTTP {status}. Retrying...")
            except Exception as exc:
                logger.warning(f"OSV API connection failed: {exc}. Retrying in {backoff}s...")

            retries -= 1
            if retries > 0:
                time.sleep(backoff)
                backoff *= 2.0

        logger.error(f"OSV API requests exhausted for URL {url}.")
        return None, False

    def _post_with_retry(self, url: str, payload: dict) -> dict:
        """Backwards-compatible wrapper returning {} on failure."""
        data, ok = self.post_query(url, payload)
        return data if (ok and data is not None) else {}

    def query_package_raw(self, name: str, version: str, ecosystem: str) -> Tuple[List[dict], bool]:
        """
        Query OSV for one package, returning (raw_vulns_list, ok).
        ok=False means OSV was unreachable (caller should use the local DB).
        """
        osv_ecosystem = self.map_ecosystem(ecosystem)
        payload = {
            "version": version,
            "package": {"name": name, "ecosystem": osv_ecosystem},
        }
        data, ok = self.post_query(self.api_url, payload)
        if not ok:
            return [], False
        return (data.get("vulns", []) if data else []), True

    def query_package(self, name: str, version: str, ecosystem: str) -> List[OsvVuln]:
        """
        Queries OSV database for a single package.
        """
        osv_ecosystem = self.map_ecosystem(ecosystem)
        payload = {
            "version": version,
            "package": {
                "name": name,
                "ecosystem": osv_ecosystem
            }
        }
        
        res = self._post_with_retry(self.api_url, payload)
        if not res or "vulns" not in res:
            return []
        
        return self._parse_vulns(res["vulns"], name, version)

    def query_batch(self, packages: List[Dict[str, Any]]) -> List[List[OsvVuln]]:
        """
        Queries OSV database using the querybatch endpoint (up to 1000 packages).
        Each package in list should be dict: {"name": str, "version": str, "ecosystem": str}
        Returns a list of lists of OsvVuln corresponding to each input package.
        """
        results: List[List[OsvVuln]] = []
        if not packages:
            return results

        # Group packages into chunks of 1000
        chunk_size = 1000
        for i in range(0, len(packages), chunk_size):
            chunk = packages[i:i + chunk_size]
            queries = []
            for pkg in chunk:
                queries.append({
                    "version": pkg["version"],
                    "package": {
                        "name": pkg["name"],
                        "ecosystem": self.map_ecosystem(pkg.get("ecosystem", "generic"))
                    }
                })

            payload = {"queries": queries}
            res = self._post_with_retry(self.batch_url, payload)
            
            if not res or "results" not in res:
                # Fill empty list for this chunk's packages
                for _ in chunk:
                    results.append([])
                continue

            for idx, item in enumerate(res["results"]):
                pkg = chunk[idx]
                vulns_raw = item.get("vulns", [])
                parsed = self._parse_vulns(vulns_raw, pkg["name"], pkg["version"])
                results.append(parsed)

        return results

    def _parse_vulns(self, vulns_raw: List[dict], pkg_name: str, pkg_ver: str) -> List[OsvVuln]:
        parsed_vulns = []
        for v in vulns_raw:
            vuln_id = v.get("id", "")
            aliases = v.get("aliases", [])
            summary = v.get("summary", v.get("details", ""))

            # Parse severity and CVSS score/vector.
            # Priority: CVSS_V4 > CVSS_V3 > CVSS_V2 > database_specific.cvss
            cvss_score = 0.0
            cvss_vector: Optional[str] = None
            severity = "LOW"

            # Seed severity from database_specific if present; may be refined below.
            database_specific = v.get("database_specific") or {}
            ds_severity = str(database_specific.get("severity", "")).upper()
            if ds_severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                severity = ds_severity

            # Single-pass over OSV severity items: prefer CVSS_V4/V3 over V2.
            # We track the best v3/v4 vector and a fallback v2 vector separately
            # so that a later CVSS_V2 entry never overwrites an earlier CVSS_V3 entry.
            best_v3_vector: Optional[str] = None  # CVSS_V3 or CVSS_V4
            best_v2_vector: Optional[str] = None  # CVSS_V2 fallback
            for sev_item in v.get("severity", []) or []:
                stype = (sev_item.get("type") or "").upper()
                vec = (sev_item.get("score") or "").strip()
                if not vec:
                    continue
                if stype in ("CVSS_V3", "CVSS_V4"):
                    # Prefer the higher-scoring v3/v4 vector when multiple are present.
                    candidate = _cvss_score_from_vector(vec)
                    current_best = _cvss_score_from_vector(best_v3_vector) if best_v3_vector else None
                    if candidate is not None and (current_best is None or candidate >= current_best):
                        best_v3_vector = vec
                elif stype == "CVSS_V2" and best_v2_vector is None:
                    best_v2_vector = vec

            cvss_vector = best_v3_vector or best_v2_vector

            if cvss_vector:
                computed = _cvss_score_from_vector(cvss_vector)
                if computed is not None:
                    cvss_score = computed

            # database_specific.cvss is used ONLY as a last resort — it frequently
            # carries a CVSS v2 pre-computed score that would silently downgrade a
            # properly computed v3.1 score when blindly applied.
            if cvss_score == 0.0:
                cvss_data = database_specific.get("cvss") or {}
                if isinstance(cvss_data, dict):
                    ds_score_raw = cvss_data.get("score")
                    if ds_score_raw is not None:
                        try:
                            cvss_score = float(ds_score_raw)
                        except (TypeError, ValueError):
                            pass
                    ds_vector = cvss_data.get("vectorString") or ""
                    if ds_vector and not cvss_vector:
                        cvss_vector = ds_vector

            # Derive severity band from score when we have a numeric value.
            if cvss_score > 0.0:
                if cvss_score >= 9.0:
                    severity = "CRITICAL"
                elif cvss_score >= 7.0:
                    severity = "HIGH"
                elif cvss_score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

            # Fixed version and affected version list.
            # Round-2 E2 change: the fixed bound is now taken from the RANGE
            # CONTAINING the queried version (introduced <= version < fixed,
            # ecosystem-aware ordering via version_match.eco_compare), falling
            # back to the first recorded fixed bound. Previously the first
            # `fixed` event anywhere in the record won, which pointed a
            # multi-window advisory at the wrong upgrade target.
            fixed_version = None
            first_fixed_any = None
            containing_fixed = None
            affected_versions = []
            from bts_sbom._internal import version_match as _vm
            for affected in v.get("affected", []) or []:
                affected_pkg = affected.get("package", {})
                if affected_pkg.get("name", "").lower() != pkg_name.lower():
                    continue
                affected_versions.extend(affected.get("versions", []))
                aff_eco = str(affected_pkg.get("ecosystem", "") or "")
                for range_item in affected.get("ranges", []) or []:
                    introduced = "0"
                    in_window = False
                    for event in range_item.get("events", []) or []:
                        if "introduced" in event:
                            introduced = event.get("introduced") or "0"
                            in_window = introduced in ("0", "") or (
                                bool(pkg_ver) and _vm.eco_compare(
                                    pkg_ver, introduced, aff_eco) >= 0)
                        elif "fixed" in event:
                            fixed = event.get("fixed") or ""
                            if fixed:
                                if first_fixed_any is None:
                                    first_fixed_any = fixed
                                if pkg_ver and in_window and _vm.eco_compare(
                                        pkg_ver, fixed, aff_eco) < 0:
                                    containing_fixed = fixed
                            in_window = False
            if containing_fixed is not None:
                fixed_version = containing_fixed
            else:
                fixed_version = first_fixed_any

            references = [ref.get("url", "") for ref in v.get("references", []) or [] if ref.get("url")]

            parsed_vulns.append(OsvVuln(
                vuln_id=vuln_id,
                aliases=aliases,
                summary=summary,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                affected_versions=affected_versions,
                fixed_version=fixed_version,
                references=references
            ))
        return parsed_vulns
