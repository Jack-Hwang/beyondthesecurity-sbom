# vendored from common/epss_kev.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
EPSS + CISA KEV enrichment for CVE prioritization.

- EPSS (Exploit Prediction Scoring System) from FIRST.org: probability (0-1)
  that a CVE will be exploited in the next 30 days.
  API: https://api.first.org/data/v1/epss?cve=CVE-...,CVE-...
- CISA KEV (Known Exploited Vulnerabilities): CVEs with confirmed in-the-wild
  exploitation — the strongest "patch now" signal.
  Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Both require network access. On an outage (network error, non-200 status,
timeout, or malformed JSON) this module never fabricates a measured-looking
{"epss": 0.0, "kev": False} for every requested CVE: see enrich_cves() below,
which falls back to the curated offline table and, failing that, reports an
explicit unknown rather than a zero.
"""
import time
import logging
from typing import List, Dict, Any, Set, Optional, Tuple

import urllib.request
import urllib.parse

logger = logging.getLogger("EpssKev")

EPSS_API_URL = "https://api.first.org/data/v1/epss"
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# In-process KEV cache (the feed is ~1MB; fetch once per run, refresh after TTL)
_kev_cache: Optional[Set[str]] = None
_kev_cached_at: float = 0.0
_KEV_TTL = 6 * 3600  # 6 hours


def _fetch_epss_with_status(cve_ids: List[str], timeout: int = 20) -> Tuple[Dict[str, Dict[str, float]], bool]:
    """Like fetch_epss(), but also reports whether the feed actually answered.

    Returns (data, ok). ok is False when ANY chunk hit a network error, a
    non-200 status, or malformed JSON -- i.e. a genuine outage, as opposed to
    the feed legitimately having no row for a given CVE (which still leaves
    ok True, just that id absent from data).
    """
    ids = [c for c in dict.fromkeys(cve_ids) if c and c.upper().startswith("CVE-")]
    result: Dict[str, Dict[str, float]] = {}
    if not ids:
        return result, True

    ok = True
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
                ok = False
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
            ok = False
        time.sleep(0.1)  # be polite
    return result, ok


def fetch_epss(cve_ids: List[str], timeout: int = 20) -> Dict[str, Dict[str, float]]:
    """Return {cve_id: {"epss": float, "percentile": float}} for CVE-* ids.

    Degrades gracefully on failure (returns whatever was fetched before the
    failure, possibly empty) -- kept for backwards compatibility. Callers
    that need to tell "outage" apart from "no data" should use enrich_cves().
    """
    data, _ok = _fetch_epss_with_status(cve_ids, timeout=timeout)
    return data


def _load_kev_set_with_status(timeout: int = 30, force: bool = False) -> Tuple[Set[str], bool]:
    """Like load_kev_set(), but also reports whether the feed actually answered."""
    global _kev_cache, _kev_cached_at
    if not force and _kev_cache is not None and (time.time() - _kev_cached_at) < _KEV_TTL:
        return _kev_cache, True
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
            return kev, True
        logger.warning(f"KEV feed HTTP {status}")
    except Exception as e:
        logger.warning(f"KEV feed fetch failed: {e}")
    return (_kev_cache if _kev_cache is not None else set()), False


def load_kev_set(timeout: int = 30, force: bool = False) -> Set[str]:
    """Return the set of KEV CVE ids (cached in-process for the TTL).

    Degrades gracefully on failure (returns the stale cache, or empty) --
    kept for backwards compatibility. Callers that need to tell "outage"
    apart from "no data" should use enrich_cves().
    """
    kev, _ok = _load_kev_set_with_status(timeout=timeout, force=force)
    return kev


def _offline_fallback(cve_id: str) -> Optional[Dict[str, Any]]:
    """Return {"epss", "percentile", "kev"} from the curated offline table,
    or None if this exact CVE is not in it -- never fabricate a 0.0/False
    for a CVE the curated table has simply never heard of."""
    try:
        from bts_sbom._internal.epss_offline import EPSS_OFFLINE, KEV_OFFLINE, epss_offline_lookup
    except Exception:
        return None
    cu = (cve_id or "").upper().strip()
    if cu not in EPSS_OFFLINE and cu not in KEV_OFFLINE:
        return None
    off = epss_offline_lookup(cu)
    return {
        "epss": off.get("epss", 0.0),
        "percentile": off.get("percentile", 0.0),
        "kev": bool(off.get("kev", False)),
    }


def enrich_cves(cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Combined lookup: {cve_id: {"epss", "percentile", "kev", "source"[, "reason"]}}.

    "source" is "live-api" when both the EPSS and KEV feeds answered normally.
    On an outage (network error, non-200 status, timeout, or malformed JSON)
    this never returns a measured-looking {"epss": 0.0, "kev": False, ...}:
    it falls back to the curated offline table (epss_offline.py) when that
    table has the CVE -- source "offline-table" -- otherwise it reports an
    explicit unknown: epss=None, percentile=None, kev=None, source
    "unavailable", plus a "reason" string naming which feed(s) failed. This
    lets callers tell "confirmed not KEV / low EPSS" apart from "we don't
    know" instead of silently treating a dead feed as a measured zero.
    """
    epss, epss_ok = _fetch_epss_with_status(cve_ids)
    kev_set, kev_ok = _load_kev_set_with_status()
    live_ok = epss_ok and kev_ok

    reasons = []
    if not epss_ok:
        reasons.append("EPSS feed unreachable")
    if not kev_ok:
        reasons.append("KEV feed unreachable")
    reason = "; ".join(reasons)

    out: Dict[str, Dict[str, Any]] = {}
    for cve in dict.fromkeys(cve_ids):
        if not cve:
            continue
        cu = cve.upper()
        if live_ok:
            e = epss.get(cu, {})
            out[cu] = {
                "epss": e.get("epss", 0.0),
                "percentile": e.get("percentile", 0.0),
                "kev": cu in kev_set,
                "source": "live-api",
            }
            continue
        offline = _offline_fallback(cu)
        if offline is not None:
            out[cu] = {**offline, "source": "offline-table"}
        else:
            out[cu] = {
                "epss": None,
                "percentile": None,
                "kev": None,
                "source": "unavailable",
                "reason": reason,
            }
    return out
