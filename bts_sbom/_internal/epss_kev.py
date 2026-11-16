# vendored from common/epss_kev.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
EPSS + CISA KEV enrichment for CVE prioritization.

- EPSS (Exploit Prediction Scoring System) from FIRST.org: probability (0-1)
  that a CVE will be exploited in the next 30 days.
  API: https://api.first.org/data/v1/epss?cve=CVE-...,CVE-...
- CISA KEV (Known Exploited Vulnerabilities): CVEs with confirmed in-the-wild
  exploitation — the strongest "patch now" signal.
  Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Both require network access. Failures degrade gracefully (return empty / no flags).
"""
import time
import logging
from typing import List, Dict, Any, Set, Optional

import urllib.request
import urllib.parse

logger = logging.getLogger("EpssKev")

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# In-process KEV cache (the feed is ~1MB; fetch once per run, refresh after TTL)
_kev_cache: Optional[Set[str]] = None
_kev_cached_at: float = 0.0
_KEV_TTL = 6 * 3600  # 6 hours


def fetch_epss(cve_ids: List[str], timeout: int = 20) -> Dict[str, Dict[str, float]]:
    """Return {cve_id: {"epss": float, "percentile": float}} for CVE-* ids."""
    ids = [c for c in dict.fromkeys(cve_ids) if c and c.upper().startswith("CVE-")]
    result: Dict[str, Dict[str, float]] = {}
    if not ids:
        return result

    # FIRST.org accepts a comma-separated list; chunk to stay within URL limits.
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        try:
            import json as _json
            url = EPSS_API_URL + "?" + urllib.parse.urlencode({"cve": ",".join(chunk)})
            with urllib.request.urlopen(url, timeout=timeout) as _resp:
                status = _resp.status
                payload = _json.loads(_resp.read().decode("utf-8", "replace"))
            if status != 200:
                logger.warning(f"EPSS API HTTP {status}")
                continue
            for row in (payload or {}).get("data", []):
                cve = row.get("cve")
                if not cve:
                    continue
                try:
                    result[cve.upper()] = {
                        "epss": float(row.get("epss", 0.0)),
                        "percentile": float(row.get("percentile", 0.0)),
                    }
                except (TypeError, ValueError):
                    continue
        except Exception as e:
            logger.warning(f"EPSS fetch failed: {e}")
        time.sleep(0.1)  # be polite
    return result


def load_kev_set(timeout: int = 30, force: bool = False) -> Set[str]:
    """Return the set of KEV CVE ids (cached in-process for the TTL)."""
    global _kev_cache, _kev_cached_at
    if not force and _kev_cache is not None and (time.time() - _kev_cached_at) < _KEV_TTL:
        return _kev_cache
    try:
        import json as _json
        with urllib.request.urlopen(KEV_FEED_URL, timeout=timeout) as _resp:
            status, data = _resp.status, _json.loads(_resp.read().decode("utf-8", "replace"))
        if status == 200:
            kev = {
                v.get("cveID", "").upper()
                for v in data.get("vulnerabilities", [])
                if v.get("cveID")
            }
            _kev_cache = kev
            _kev_cached_at = time.time()
            logger.info(f"Loaded {len(kev)} CISA KEV entries.")
            return kev
        logger.warning(f"KEV feed HTTP {status}")
    except Exception as e:
        logger.warning(f"KEV feed fetch failed: {e}")
    return _kev_cache if _kev_cache is not None else set()


def enrich_cves(cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Combined lookup: {cve_id: {"epss", "percentile", "kev"}}."""
    epss = fetch_epss(cve_ids)
    kev = load_kev_set()
    out: Dict[str, Dict[str, Any]] = {}
    for cve in dict.fromkeys(cve_ids):
        if not cve:
            continue
        cu = cve.upper()
        e = epss.get(cu, {})
        out[cu] = {
            "epss": e.get("epss", 0.0),
            "percentile": e.get("percentile", 0.0),
            "kev": cu in kev,
        }
    return out
