"""Exploit intelligence for the findings of one project: EPSS scores (FIRST.org) and CISA KEV membership.

Why this is not the core's ``enrich_cves``: that helper turns a failed request into epss 0.0 / kev False, so a network error
would read as "nobody exploits this". Here every source ends in an explicit status, and a finding only gets a field when the
source really answered for it:

* ``ok``          - the source answered for every asked CVE (a CVE without an EPSS row has no published score; a CVE that is not in
                    the KEV catalog is not known to be exploited as of the catalog date);
* ``partial``     - some EPSS requests failed; only the CVEs of the answered requests count as covered;
* ``table``       - offline mode: only the core's curated subset was consulted (a hit is real, a miss says nothing);
* ``unavailable`` - the source did not answer; the report then carries no value from it.

The result is stored next to the evidence (``<evidence>/.intel/``), never inside the analysis record, because EPSS changes daily.
Every request goes through ``net`` (User-Agent, retry, accounting, test hook); the CVE ids come from analysed data, so they are
checked against a strict pattern before they reach a URL.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import math
import os
import re
import time
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import engine, net

SCHEMA = "bts-sbom.intel.v1"
CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
CHUNK = 100                      # CVE ids per EPSS request (the API's page size)
MAX_IDS = 3000                   # bounds the run time of one lookup; the rest stays "not looked up"
KEV_FIELDS = (("added", "dateAdded"), ("due", "dueDate"), ("ransomware", "knownRansomwareCampaignUse"),
              ("vendor", "vendorProject"), ("product", "product"), ("name", "vulnerabilityName"))


def valid_ids(ids: Iterable[Any]) -> List[str]:
    """Unique, upper-cased, well-formed CVE ids in sorted order."""
    return sorted({str(c).strip().upper() for c in ids if CVE_RE.match(str(c).strip().upper())})


def _now() -> str:
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def _txt(v: Any, n: int = 200) -> str:
    return str(v if v is not None else "")[:n]


def _prob(v: Any) -> Optional[float]:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return None
    return x if math.isfinite(x) and 0.0 <= x <= 1.0 else None


def _failures() -> int:
    with net._LOCK:
        return int(net.STATS["failures"])


def _why(before: int) -> str:
    with net._LOCK:
        return str(net.STATS["last_error"]) if net.STATS["failures"] > before else "unexpected answer"


def _epss_online(ids: List[str]) -> Dict[str, Any]:
    url = engine.intel_endpoints()["epss"]
    out: Dict[str, Any] = {"status": "unavailable", "source": "FIRST.org EPSS API", "date": "", "error": "", "scores": {}, "covered": []}
    covered: List[str] = []
    for i in range(0, len(ids), CHUNK):
        chunk = ids[i:i + CHUNK]
        before = _failures()
        data = net.http_json(url + "?" + urllib.parse.urlencode({"cve": ",".join(chunk)}), timeout=15.0, retries=1)
        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            out["error"] = _why(before)
            break                                   # one failed request: stop instead of waiting for a timeout per remaining chunk
        for row in rows:
            cve = _txt(row.get("cve") if isinstance(row, dict) else "", 40).upper()
            e, p = (_prob(row.get("epss")), _prob(row.get("percentile"))) if isinstance(row, dict) else (None, None)
            if cve in chunk and e is not None:
                out["scores"][cve] = {"epss": e, "percentile": p if p is not None else 0.0}
                out["date"] = max(out["date"], _txt(row.get("date"), 10))
        covered.extend(chunk)
        if i + CHUNK < len(ids):
            time.sleep(0.1)                         # the API is a free public service
    out["covered"] = covered
    out["status"] = "ok" if covered and len(covered) == len(ids) else "partial" if covered else "unavailable"
    return out


def _kev_online(ids: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"status": "unavailable", "source": "CISA Known Exploited Vulnerabilities catalog", "catalog_version": "",
                           "date_released": "", "count": 0, "error": "", "entries": {}}
    before = _failures()
    data = net.http_json(engine.intel_endpoints()["kev"], timeout=30.0, retries=1)
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list) or not vulns:       # an empty catalog is a broken answer, never "nothing is exploited"
        out["error"] = _why(before)
        return out
    want = set(ids)
    for v in vulns:
        cve = _txt(v.get("cveID") if isinstance(v, dict) else "", 40).upper()
        if cve in want:
            out["entries"][cve] = {k: _txt(v.get(src), 160) for k, src in KEV_FIELDS}
    out.update(status="ok", count=len(vulns), catalog_version=_txt(data.get("catalogVersion"), 40), date_released=_txt(data.get("dateReleased"), 40))
    return out


def _tables(ids: List[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    epss_tab, kev_tab = engine.intel_tables()
    note = "offline table (a curated subset of %d CVEs, not the full data)" % len(epss_tab)
    epss = {"status": "table", "source": note, "date": "", "error": "", "covered": [],
            "scores": {c: {"epss": float(epss_tab[c]["epss"]), "percentile": float(epss_tab[c]["percentile"])} for c in ids if c in epss_tab}}
    kev = {"status": "table", "source": "offline table (a curated subset of %d KEV ids; a miss does not mean not listed)" % len(kev_tab),
           "catalog_version": "", "date_released": "", "count": len(kev_tab), "error": "",
           "entries": {c: {k: "" for k, _ in KEV_FIELDS} for c in ids if c in kev_tab}}
    return epss, kev


def lookup(cve_ids: Iterable[Any], *, offline: bool = False, now: Optional[str] = None) -> Dict[str, Any]:
    """Ask EPSS and KEV about these CVEs. Never raises for a network problem: that becomes a status inside the result."""
    ids = valid_ids(cve_ids)
    truncated = len(ids) > MAX_IDS
    ids = ids[:MAX_IDS]
    doc: Dict[str, Any] = {"schema": SCHEMA, "fetched_at": now or _now(), "mode": "offline-table" if offline else "online", "asked": ids, "truncated": truncated}
    if offline:
        doc["epss"], doc["kev"] = _tables(ids)
    else:
        doc["epss"], doc["kev"] = (_epss_online(ids) if ids else _empty("FIRST.org EPSS API")), (_kev_online(ids) if ids else _empty("CISA KEV catalog"))
    return doc


def _empty(source: str) -> Dict[str, Any]:
    return {"status": "ok", "source": source, "date": "", "error": "", "scores": {}, "entries": {}, "covered": [], "count": 0}


def annotate(findings: List[Dict[str, Any]], doc: Optional[Dict[str, Any]]) -> None:
    """Put epss / epss_percentile / kev on the findings the lookup really answered for. Everything else stays without the field."""
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return
    asked, e, k = set(doc.get("asked") or []), doc.get("epss") or {}, doc.get("kev") or {}
    scores, entries = e.get("scores") or {}, k.get("entries") or {}
    for f in findings:
        cve = str(f.get("cve") or "").upper()
        if cve not in asked:
            continue
        if cve in scores:
            f["epss"], f["epss_percentile"] = scores[cve]["epss"], scores[cve]["percentile"]
        if cve in entries:
            f["kev"], f["kev_info"] = True, entries[cve]
        elif k.get("status") == "ok":
            f["kev"] = False                         # the whole catalog was read and the CVE is not in it


def summarize(doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """What the page needs to say about the lookup (status of each source, when, how many CVEs got an answer)."""
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return None
    asked, e, k = list(doc.get("asked") or []), doc.get("epss") or {}, doc.get("kev") or {}
    scores, entries, covered = e.get("scores") or {}, k.get("entries") or {}, set(e.get("covered") or [])
    known = [c for c in asked if k.get("status") == "ok" or c in covered or c in scores or c in entries]
    return {"fetched_at": doc.get("fetched_at"), "mode": doc.get("mode"), "asked": len(asked), "truncated": bool(doc.get("truncated")), "known": known,
            "epss": {"status": e.get("status"), "source": e.get("source"), "date": e.get("date"), "error": e.get("error"), "scored": len(scores)},
            "kev": {"status": k.get("status"), "source": k.get("source"), "catalog_version": k.get("catalog_version"),
                    "date_released": k.get("date_released"), "count": k.get("count"), "error": k.get("error"), "listed": len(entries)}}


def sidecar_path(evidence: str, project: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", project).lstrip(".")[:60] or "project"      # a project name never becomes a path or a hidden name
    return os.path.join(evidence, ".intel", "%s-%s.json" % (safe, hashlib.sha1(project.encode("utf-8")).hexdigest()[:8]))


def load(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) and d.get("schema") == SCHEMA else None


def save(path: str, doc: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, path)
