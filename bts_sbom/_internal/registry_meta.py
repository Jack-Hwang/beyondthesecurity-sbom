# vendored from common/registry_meta.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""Optional ONLINE registry lookup: who authored a package, and where it is hosted.

Used only to fill SBOM gaps the lockfile/manifest cannot answer (an unscoped npm
or PyPI package has no namespace to derive a supplier from).  Disclosed, bounded
and strictly additive:

  * online scans only - ``offline=True`` does zero network I/O;
  * never overwrites a value the manifest/lockfile/ingested SBOM already has;
  * a failed lookup leaves the component exactly as it was (no placeholder);
  * the registry's ``author`` is recorded as the AUTHOR with basis
    ``registry:<name>`` - it is not promoted to "supplier organisation";
  * at most ``ECU_SENTINEL_REGISTRY_META_MAX`` (default 300) distinct
    components are looked up per scan, the rest are counted as skipped.

Supported registries: npm (registry.npmjs.org), PyPI (pypi.org).  Other
ecosystems return ``unsupported`` - not an error, not a guess.
"""
from __future__ import annotations
from bts_sbom._version import __version__ as _BTS_VERSION

import json
import logging
import os
import re
import threading
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("registry_meta")

_TIMEOUT = 8
_WORKERS = 8
_UA = "bts-sbom/%s (sbom enrichment)" % _BTS_VERSION

_cache: Dict[Tuple[str, str, str], Optional[Dict[str, Any]]] = {}
_cache_lock = threading.Lock()


def _http_json(url: str) -> Optional[Dict[str, Any]]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            if r.status != 200:
                return None
            return json.loads(r.read().decode("utf-8"))
    except Exception as exc:
        logger.debug("registry lookup failed for %s: %s", url, exc)
        return None


def _person_name(value: Any) -> Optional[str]:
    """npm ``author`` is a string ``"Name <mail> (url)"`` or ``{name,email,url}``."""
    if isinstance(value, dict):
        value = value.get("name")
    if not isinstance(value, str):
        return None
    value = re.sub(r"\s*[<(].*$", "", value).strip()
    return value or None


def _npm(name: str, version: str) -> Optional[Dict[str, Any]]:
    # scoped names keep the "@" and encode the slash: @babel%2fcore
    quoted = urllib.parse.quote(name, safe="@")
    data = _http_json("https://registry.npmjs.org/%s/%s" % (quoted, urllib.parse.quote(version, safe="")))
    if not isinstance(data, dict):
        return None
    out: Dict[str, Any] = {"registry": "npm"}
    author = _person_name(data.get("author"))
    if not author:
        maint = data.get("maintainers")
        if isinstance(maint, list) and maint:
            author = _person_name(maint[0])
    if author:
        out["author"] = author
    dist = data.get("dist") or {}
    if isinstance(dist, dict) and dist.get("tarball"):
        out["download"] = dist["tarball"]
    return out


def _pypi(name: str, version: str) -> Optional[Dict[str, Any]]:
    data = _http_json("https://pypi.org/pypi/%s/%s/json" % (urllib.parse.quote(name, safe=""),
                                                             urllib.parse.quote(version, safe="")))
    if not isinstance(data, dict):
        return None
    info = data.get("info") or {}
    out: Dict[str, Any] = {"registry": "pypi"}
    author = _person_name(info.get("author")) or _person_name(info.get("maintainer"))
    if not author:                                   # author_email "Name <mail>" form
        author = _person_name(info.get("author_email"))
        if author and "@" in author:
            author = None
    if author:
        out["author"] = author
    urls = [u for u in (data.get("urls") or []) if isinstance(u, dict) and u.get("url")]
    sdist = [u for u in urls if u.get("packagetype") == "sdist"]
    pick = (sdist or urls or [None])[0]
    if pick:
        out["download"] = pick["url"]
    return out


_FETCHERS: Dict[str, Callable[[str, str], Optional[Dict[str, Any]]]] = {"npm": _npm, "pypi": _pypi}
_ECO_ALIAS = {"npm": "npm", "node": "npm", "pypi": "pypi", "python": "pypi"}


def fetch(ecosystem: str, name: str, version: str) -> Optional[Dict[str, Any]]:
    kind = _ECO_ALIAS.get(str(ecosystem or "").strip().lower())
    if not kind or not name or not version:
        return None
    key = (kind, name.lower(), str(version))
    with _cache_lock:
        if key in _cache:
            return _cache[key]
    res = _FETCHERS[kind](name, str(version))
    with _cache_lock:
        _cache[key] = res
    return res


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def enrich(packages: List[Dict[str, Any]], offline: bool = False,
           fetcher: Optional[Callable[[str, str, str], Optional[Dict[str, Any]]]] = None
           ) -> Dict[str, Any]:
    """Fill ``author`` / ``author_basis`` / ``download_location`` in place where
    missing.  Returns the disclosure block ``{source, queried, resolved, failed,
    skipped, unsupported, note?}``.  ``fetcher`` is injectable for tests."""
    info: Dict[str, Any] = {"source": "registry (npm, PyPI)", "queried": 0, "resolved": 0,
                            "failed": 0, "skipped": 0, "unsupported": 0}
    if offline:
        info["note"] = "offline - no registry lookups"
        return info
    do = fetcher or fetch
    todo: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for p in packages:
        kind = _ECO_ALIAS.get(str(p.get("ecosystem") or "").strip().lower())
        if not kind:
            info["unsupported"] += 1
            continue
        needs_author = not (p.get("supplier") or p.get("author"))
        needs_url = not p.get("download_location")
        if not (needs_author or needs_url) or not p.get("name") or not p.get("version"):
            continue
        todo.setdefault((kind, str(p["name"]), str(p["version"])), []).append(p)
    try:
        cap = int(os.environ.get("ECU_SENTINEL_REGISTRY_META_MAX", "300"))
    except ValueError:
        cap = 300
    keys = list(todo)
    if len(keys) > cap:
        info["skipped"] = len(keys) - cap
        info["note"] = "lookup cap %d reached; %d components not queried" % (cap, info["skipped"])
        keys = keys[:cap]
    results: Dict[Tuple[str, str, str], Optional[Dict[str, Any]]] = {}
    workers = max(1, min(_WORKERS, len(keys)))
    if workers > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="registry") as pool:
            for k, r in zip(keys, pool.map(lambda k: do(*k), keys)):
                results[k] = r
    else:
        for k in keys:
            results[k] = do(*k)
    for k in keys:
        info["queried"] += 1
        r = results.get(k)
        if not r:
            info["failed"] += 1
            continue
        filled = False
        for p in todo[k]:
            if r.get("author") and not (p.get("supplier") or p.get("author")):
                p["author"] = r["author"]
                p["author_basis"] = "registry:%s" % r.get("registry", k[0])
                filled = True
            if r.get("download") and not p.get("download_location"):
                p["download_location"] = r["download"]
                p["download_basis"] = "registry:%s" % r.get("registry", k[0])
                filled = True
        info["resolved"] += 1 if filled else 0
    return info


__all__ = ["fetch", "enrich", "clear_cache"]
