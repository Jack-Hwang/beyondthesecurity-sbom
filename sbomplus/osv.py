"""Direct OSV.dev client (api.osv.dev): batch version queries + advisory documents, cached.

Used to verify candidate fix versions: "is (package, safe_version) itself free of known advisories?".
Only package coordinates (ecosystem, name, version) leave the machine - never source code.
"""
from __future__ import annotations

import concurrent.futures as cf
import threading
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import net

API = "https://api.osv.dev/v1"
_DOCS: Dict[str, Optional[Dict[str, Any]]] = {}
_LOCK = threading.Lock()
Coord = Tuple[str, str, str]          # (ecosystem, name, version)


def query_batch(coords: Sequence[Coord], chunk: int = 500) -> Dict[Coord, Optional[List[str]]]:
    """coord -> list of advisory ids ([] = answered, none known); None = the query FAILED (never read as clean)."""
    out: Dict[Coord, Optional[List[str]]] = {}
    coords = list(dict.fromkeys(coords))
    for i in range(0, len(coords), chunk):
        part = coords[i:i + chunk]
        doc = net.http_json(API + "/querybatch", body={"queries": [
            {"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in part]}, timeout=40)
        results = (doc or {}).get("results") if isinstance(doc, dict) else None
        if not isinstance(results, list) or len(results) != len(part):
            for c in part:
                out[c] = None
            continue
        for c, r in zip(part, results):
            ids = [v.get("id") for v in (r or {}).get("vulns") or [] if v.get("id")]
            if (r or {}).get("next_page_token"):          # >1 page of ids: fetch the single-query path for completeness
                full = net.http_json(API + "/query", body={"package": {"name": c[1], "ecosystem": c[0]}, "version": c[2]}, timeout=40)
                ids = [v.get("id") for v in (full or {}).get("vulns") or [] if v.get("id")] if isinstance(full, dict) else ids
            out[c] = ids
    return out


def get_vuln(vid: str) -> Optional[Dict[str, Any]]:
    with _LOCK:
        if vid in _DOCS:
            return _DOCS[vid]
    doc = net.http_json(API + "/vulns/" + vid, timeout=30)
    doc = doc if isinstance(doc, dict) else None
    with _LOCK:
        _DOCS[vid] = doc
    return doc


def get_vulns(ids: Sequence[str], workers: int = 8) -> Dict[str, Optional[Dict[str, Any]]]:
    ids = list(dict.fromkeys(ids))
    with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        return dict(zip(ids, ex.map(get_vuln, ids)))


def clear_cache() -> None:
    with _LOCK:
        _DOCS.clear()
