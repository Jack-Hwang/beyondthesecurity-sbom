"""Measure the OSV lookup strategies against the REAL api.osv.dev (read-only, public data, package coordinates only).

    python scripts/osv_bench.py [--packages N] [--keep-db]

Scenarios (each starts from an empty cache DB unless noted):
  legacy_single_8_workers          the previous online path: one POST /v1/query per component, a new TLS connection
                                   per call, a 0.1 s courtesy sleep, 8 workers
  per_component_pooled_24_workers  the same queries over keep-alive connections with 24 workers
  auto_cold / auto_warm            the default strategy: per-component on a cold cache, then querybatch + the
                                   revision-validated record cache once the cache is warm
  feed_cold / feed_warm            --osv-mode feed: first run starts tracking the change feed; the second answers
                                   from the cache the feed proves current
  forced_batch_cold                querybatch on a cold cache (what auto avoids)
  change_feed                      first contact, a no-op poll, and delta polls (bytes and seconds)

It also CHECKS that batch and single return the same advisory ids for every component - the fast path is only
worth having if it is not different.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PYPI = """requests 2.19.1|flask 0.12.2|django 2.0|jinja2 2.10|pyyaml 3.13|urllib3 1.24.1|pillow 5.2.0|numpy 1.14.0|
cryptography 2.3|paramiko 2.4.0|sqlalchemy 1.2.0|lxml 4.2.0|tornado 5.0|aiohttp 3.4.0|werkzeug 0.14.1|setuptools 39.0.0|
pip 9.0.1|idna 2.7|certifi 2018.8.24|chardet 3.0.4|six 1.11.0|click 6.7|markupsafe 1.0|itsdangerous 0.24|pytz 2018.5|
python-dateutil 2.7.0|pycryptodome 3.6.0|mako 1.0.7|pygments 2.2.0|babel 2.5.0|docutils 0.14|sphinx 1.7.0|celery 4.1.0|
gunicorn 19.7.0|redis 2.10.6|pymysql 0.8.0|psycopg2 2.7.4|twisted 18.4.0|scrapy 1.5.0|bleach 2.1.3|markdown 2.6.11|
ansible 2.5.0|fabric 2.0.0|waitress 1.1.0|pyjwt 1.5.0|httplib2 0.11.0|oauthlib 2.0.6|tensorflow 1.8.0|scipy 1.0.0|pandas 0.22.0|
matplotlib 2.1.0|pyopenssl 17.5.0|treq 17.8.0|zope.interface 4.5.0|jsonschema 2.6.0|simplejson 3.13.0|ujson 1.35|
protobuf 3.5.0|grpcio 1.10.0|boto 2.48.0|boto3 1.7.0|botocore 1.10.0|pytest 3.5.0|nose 1.3.7""".replace("\n", "")
NPM = """lodash 4.17.4|express 4.16.0|minimist 1.2.0|axios 0.18.0|moment 2.19.0|request 2.85.0|handlebars 4.0.5|jquery 3.3.0|
underscore 1.8.3|async 2.5.0|debug 2.6.8|body-parser 1.18.2|marked 0.3.6|mongoose 5.0.0|socket.io 2.0.4|ws 3.3.0|
tar 4.4.0|node-forge 0.7.1|yargs-parser 9.0.0|merge 1.2.0|mixin-deep 1.3.0|set-value 2.0.0|extend 3.0.1|hoek 4.2.0|
sequelize 4.37.0|jsonwebtoken 8.1.0|angular 1.6.0|bootstrap 3.3.7|dot-prop 4.2.0|kind-of 6.0.0""".replace("\n", "")


def inventory(n):
    keys = []
    for item in PYPI.split("|"):
        name, ver = item.split()
        keys.append(("PyPI", name, ver))
    for item in NPM.split("|"):
        name, ver = item.split()
        keys.append(("npm", name, ver))
    return keys[:n] if n else keys


def project(keys, d):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "requirements.txt"), "w", encoding="utf-8") as fh:
        fh.write("\n".join("%s==%s" % (n, v) for e, n, v in keys if e == "PyPI") + "\n")
    lock = {"name": "bench", "lockfileVersion": 1,
            "dependencies": {n: {"version": v} for e, n, v in keys if e == "npm"}}
    with open(os.path.join(d, "package-lock.json"), "w", encoding="utf-8") as fh:
        json.dump(lock, fh)
    return d


def ids_of(result):
    return {(s["source"]["path"].split(os.sep)[-1], p["package"]["name"], p["package"]["version"]):
            sorted(v["id"] for v in p["vulnerabilities"])
            for s in result["results"] for p in s["packages"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packages", type=int, default=0, help="limit the inventory (default: all)")
    ap.add_argument("--keep-db", action="store_true")
    ap.add_argument("--out", default=None, help="write the numbers as JSON")
    args = ap.parse_args()

    tmp = tempfile.mkdtemp(prefix="osvbench_")
    os.environ["BTS_SBOM_OSV_DB_PATH"] = os.path.join(tmp, "bench.db")
    from bts_sbom._internal import osv_client, osv_http, osv_local_db, osv_mirror
    from bts_sbom.osvscanner import OsvScanner

    keys = inventory(args.packages)
    proj = project(keys, os.path.join(tmp, "proj"))
    out = {"components": len(keys), "scenarios": {}}

    def fresh(tag):
        osv_local_db.DB_PATH = os.path.join(tmp, "%s.db" % tag)
        osv_http._DEFAULT = osv_http.HttpClient()

    def run(label, mode, workers=None):
        if workers:
            os.environ["BTS_SBOM_OSV_WORKERS"] = str(workers)
        else:
            os.environ.pop("BTS_SBOM_OSV_WORKERS", None)
        t0 = time.monotonic()
        res = OsvScanner(osv_mode=mode).scan(proj)
        dt = time.monotonic() - t0
        info = {"seconds": round(dt, 2), "queried_online": res["scan_status"]["queried_online"],
                "http_requests": osv_http.default_client().snapshot()["requests"],
                "advisories": sum(len(p["vulnerabilities"]) for s in res["results"] for p in s["packages"])}
        fv = res["scan_status"].get("feed_validated")
        if fv:
            info.update(answered_from_validated_cache=fv["answered_from_validated_cache"], asked_osv=fv["asked_osv"],
                        not_validated=fv["not_validated_reasons"])
        fast = res["scan_status"].get("osv_fast")
        if fast:
            info.update(strategy="batch", query_many_seconds=fast["elapsed_s"], fetched=fast["fetched"],
                        cache_hits=fast["cache_hits"], bulk_queries=fast.get("bulk_queries"),
                        detail_gets=fast.get("detail_gets"))
        elif not fv:
            info["strategy"] = "per-component"
        else:
            info["strategy"] = "feed-validated cache" + (" + per-component for the rest" if fv["asked_osv"] else "")
        out["scenarios"][label] = info
        return res

    # 1) what HEAD did: urllib per request (new TLS connection each), 0.1 s courtesy sleep, 8 workers
    fresh("legacy")
    legacy_calls = {"n": 0}

    def legacy_post_query(self, url, payload):
        legacy_calls["n"] += 1
        time.sleep(0.1)
        for attempt in range(3):
            try:
                status, data = osv_client._post_json(url, payload, timeout=15)
                if status == 200:
                    return data, True
            except Exception:
                pass
            time.sleep(1.0 * (2 ** attempt))
        return None, False

    orig = osv_client.OsvClient.post_query
    osv_client.OsvClient.post_query = legacy_post_query
    res_legacy = run("legacy_single_8_workers", "single", workers=8)
    out["scenarios"]["legacy_single_8_workers"]["http_requests"] = legacy_calls["n"]
    osv_client.OsvClient.post_query = orig

    # 2) pooled keep-alive connections, 24 workers
    fresh("pooled")
    res_pooled = run("per_component_pooled_24_workers", "single")

    # 3) auto on a cold cache (picks per-component) and again on the warm cache (picks batch)
    fresh("auto")
    res_auto_cold = run("auto_cold", "auto")
    osv_http._DEFAULT = osv_http.HttpClient()
    res_auto_warm = run("auto_warm", "auto")

    # 3b) feed mode: the first run starts tracking the change feed, the second answers from the cache the feed
    #     proves current (a few KiB per ecosystem instead of one query per component)
    fresh("feedscan")
    res_feed_cold = run("feed_cold", "feed")
    osv_http._DEFAULT = osv_http.HttpClient()
    res_feed_warm = run("feed_warm", "feed")

    # 4) forced batch on a cold cache - shows the overhead the auto heuristic avoids
    fresh("batchcold")
    res_batch_cold = run("forced_batch_cold", "batch")

    # ---- equivalence of every strategy against the previous behaviour ---------------------------------
    ref = ids_of(res_legacy)
    out["equivalence"] = {"components_compared": len(ref), "advisories": sum(len(v) for v in ref.values())}
    for label, res in (("pooled", res_pooled), ("auto_cold", res_auto_cold), ("auto_warm", res_auto_warm),
                       ("feed_cold", res_feed_cold), ("feed_warm", res_feed_warm),
                       ("forced_batch_cold", res_batch_cold)):
        cur = ids_of(res)
        diff = {"%s|%s|%s" % k: (ref.get(k), cur.get(k)) for k in set(ref) | set(cur) if ref.get(k) != cur.get(k)}
        out["equivalence"][label + "_identical_to_legacy"] = not diff
        if diff:
            out["equivalence"][label + "_differences"] = dict(list(diff.items())[:10])

    # ---- change feed -----------------------------------------------------------------------------------
    fresh("feed")
    m = osv_mirror.OsvMirror()
    t0 = time.monotonic()
    r1 = m.sync(["PyPI", "npm"])
    t_first = time.monotonic() - t0
    t0 = time.monotonic()
    r2 = m.sync(["PyPI", "npm"])
    t_poll = time.monotonic() - t0
    feed = {"first_contact_seconds": round(t_first, 2),
            "first_contact_bytes": sum(e["feed_bytes"] for e in r1["ecosystems"]),
            "noop_poll_seconds": round(t_poll, 2),
            "noop_poll_statuses": {e["ecosystem"]: e["feed_status"] for e in r2["ecosystems"]},
            "noop_poll_bytes": sum(e["feed_bytes"] for e in r2["ecosystems"])}
    head = m.http.get(m._feed_url("PyPI"), headers={"Range": "bytes=0-0"})
    cr = head.headers.get("content-range", "")
    if "/" in cr and cr.split("/")[-1].isdigit():
        feed["pypi_feed_total_bytes_for_comparison"] = int(cr.split("/")[-1])
    for label, secs in (("delta_last_hour", 3600), ("delta_last_day", 86400)):
        wm = osv_mirror.norm_ts(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - secs)))
        m._set_state("PyPI", watermark=wm, etag=None)
        t0 = time.monotonic()
        r3 = m.sync(["PyPI"])["ecosystems"][0]
        feed[label] = {"seconds": round(time.monotonic() - t0, 2), "records_changed": r3["fetched"],
                       "feed_bytes": r3["feed_bytes"], "ingest_lag_s": r3["ingest_lag_s"], "error": r3["error"]}
    feed["http"] = m.http.snapshot()
    out["scenarios"]["change_feed"] = feed

    sc = out["scenarios"]
    base = sc["legacy_single_8_workers"]["seconds"]
    out["speedup_vs_legacy"] = {k: round(base / max(sc[k]["seconds"], 0.01), 1) for k in
                                ("per_component_pooled_24_workers", "auto_cold", "auto_warm", "feed_cold", "feed_warm",
                                 "forced_batch_cold")}
    text = json.dumps(out, indent=2, ensure_ascii=False)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 0 if all(v for k, v in out["equivalence"].items() if k.endswith("identical_to_legacy")) else 1


if __name__ == "__main__":
    sys.exit(main())
