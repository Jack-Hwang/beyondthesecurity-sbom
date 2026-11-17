"""OSV live layer: pooled HTTP client, incremental mirror, querybatch fast path, scanner integration, watch.

No test touches the real network: ``osv_http.TRANSPORT`` is replaced by an in-memory OSV (api.osv.dev +
the osv-vulnerabilities bucket) or, for the HTTP client itself, a real local HTTP/1.1 server.
"""
from __future__ import annotations

import gzip
import hashlib
import http.server
import io
import json
import os
import re
import threading
import urllib.parse
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from bts_sbom._internal import osv_fast, osv_http, osv_local_db, osv_mirror, osv_watch
from bts_sbom._internal.osv_mirror import OsvMirror, norm_ts, record_affects, ts_epoch

DUMP = "https://storage.googleapis.com/osv-vulnerabilities"


# ======================================================================== in-memory OSV
class VClock:
    """Virtual wall clock shared by the fake OSV (advisory ``modified`` stamps) and the code under test
    (``time.time()`` in osv_mirror / osv_local_db), so cache-validity rules can be tested without sleeping."""

    def __init__(self):
        self.now = datetime(2026, 11, 17, 10, 0, 0, tzinfo=timezone.utc).timestamp()

    def advance(self, seconds):
        self.now += seconds

    def module(self):
        import time as _real
        clock = self

        class _T:
            def __getattr__(self, name):
                return getattr(_real, name)

            @staticmethod
            def time():
                return clock.now

        return _T()


class FakeOsv:
    """api.osv.dev + the public bucket, in memory.  Records are real OSV-shaped dicts."""

    def __init__(self):
        self.clock = VClock()
        self.records = {}            # id -> record
        self.calls = []              # [(method, url)]
        self.down = False
        self.fail_ids = set()        # ids whose record download fails (500)
        self.fail_feed = set()       # ecosystems whose feed returns 503
        self.fail_query = False      # POST /v1/query answers 500
        self.omit_modified = False   # querybatch results without a "modified" field
        self.page_size = None        # querybatch: max vulns per page (to exercise next_page_token)
        self._tick = 0
        self._fracs = [6, 8, 9, 7]

    # -- authoring --------------------------------------------------------------------------
    def stamp(self):
        self._tick += 1
        self.clock.advance(7)
        dt = datetime.fromtimestamp(self.clock.now, tz=timezone.utc)
        digits = self._fracs[self._tick % len(self._fracs)]
        frac = str(123456789 + self._tick)[:digits].ljust(digits, "0")
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + "." + frac + "Z"

    def publish(self, vid, eco, name, *, introduced="0", fixed=None, summary="", severity=None, git_fixed=None,
                versions=None, withdrawn=None, extra_affected=None):
        events = [{"introduced": introduced}] + ([{"fixed": fixed}] if fixed else [])
        aff = {"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}
        if versions:
            aff["versions"] = versions
        if git_fixed:
            aff["ranges"].append({"type": "GIT", "repo": "https://example.invalid/r",
                                  "events": [{"introduced": "0"}, {"fixed": git_fixed}]})
        rec = {"id": vid, "modified": self.stamp(), "summary": summary or vid, "aliases": ["CVE-" + vid[-4:]],
               "affected": [aff] + list(extra_affected or [])}
        if severity:
            rec["severity"] = [{"type": "CVSS_V3", "score": severity}]
        if withdrawn:
            rec["withdrawn"] = withdrawn
        self.records[vid] = rec
        return rec

    def count(self, needle):
        if needle == "/v1/query":                      # exact path: do not also match /v1/querybatch
            return sum(1 for _m, u in self.calls if urllib.parse.urlsplit(u).path == "/v1/query")
        return sum(1 for _m, u in self.calls if needle in u)

    # -- helpers ------------------------------------------------------------------------------
    @staticmethod
    def _resp(obj, status=200, headers=None):
        body = obj if isinstance(obj, (bytes, bytearray)) else json.dumps(obj).encode("utf-8")
        h = {"Content-Type": "application/json"}
        h.update(headers or {})
        return status, h, bytes(body)

    def _eco_dirs(self, rec):
        return {osv_mirror.base_ecosystem(a["package"]["ecosystem"]) for a in rec["affected"]}

    def _feed_bytes(self, eco):
        rows = [(norm_ts(r["modified"]), r["modified"], vid) for vid, r in self.records.items()
                if eco in self._eco_dirs(r)]
        rows.sort(reverse=True)
        return ("".join("%s,%s\n" % (raw, vid) for _n, raw, vid in rows)).encode("utf-8")

    # -- transport ----------------------------------------------------------------------------
    def transport(self, method, url, headers, body):
        self.calls.append((method, url))
        if self.down:
            raise ConnectionError("fake network down")
        u = urllib.parse.urlsplit(url)
        path = urllib.parse.unquote(u.path)
        if u.netloc == "api.osv.dev":
            if path == "/v1/querybatch" and method == "POST":
                return self._querybatch(json.loads(body.decode("utf-8")))
            if path == "/v1/query" and method == "POST":
                if self.fail_query:
                    return self._resp({"error": "boom"}, 500)
                return self._query(json.loads(body.decode("utf-8")))
            m = re.match(r"^/v1/vulns/(.+)$", path)
            if m and method == "GET":
                if m.group(1) in self.fail_ids:
                    return self._resp({"error": "boom"}, 500)
                rec = self.records.get(m.group(1))
                return self._resp(rec) if rec else self._resp({"code": 5}, 404)
        if u.netloc == "storage.googleapis.com" and path.startswith("/osv-vulnerabilities/"):
            eco, _, leaf = path[len("/osv-vulnerabilities/"):].partition("/")
            if leaf == "modified_id.csv":
                if eco in self.fail_feed:
                    return self._resp(b"", 503)
                return self._ranged(self._feed_bytes(eco), headers)
            if leaf == "all.zip":
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w") as zf:
                    for vid, r in self.records.items():
                        if eco in self._eco_dirs(r):
                            zf.writestr(vid + ".json", json.dumps(r))
                return self._resp(buf.getvalue(), 200, {"Content-Type": "application/zip"})
            if leaf.endswith(".json"):
                vid = leaf[:-5]
                if vid in self.fail_ids:
                    return self._resp({"error": "boom"}, 500)
                rec = self.records.get(vid)
                if rec and eco in self._eco_dirs(rec):
                    return self._resp(rec)
                return self._resp({"code": 5}, 404)
        return self._resp({"error": "unexpected url " + url}, 599)

    def _ranged(self, data, headers):
        etag = '"%s"' % hashlib.md5(data).hexdigest()
        if headers.get("If-None-Match") == etag:
            return 304, {"ETag": etag}, b""
        rng = headers.get("Range")
        if not rng:
            return 200, {"ETag": etag}, data
        a, b = re.match(r"bytes=(\d+)-(\d+)", rng).groups()
        a, b = int(a), int(b)
        if a >= len(data) and len(data) > 0:
            return 416, {"ETag": etag}, b""
        part = data[a:b + 1]
        return 206, {"ETag": etag, "Content-Range": "bytes %d-%d/%d" % (a, a + len(part) - 1, len(data))}, part

    def _query(self, q):
        pk = q["package"]
        ids = sorted(vid for vid, r in self.records.items()
                     if not r.get("withdrawn") and record_affects(r, pk["ecosystem"], pk["name"], q["version"]))
        start = int(q["page_token"][2:]) if q.get("page_token") else 0
        size = self.page_size or len(ids) or 1
        page, rest = ids[start:start + size], ids[start + size:]
        doc = {"vulns": [self.records[i] for i in page]}
        if rest:
            doc["next_page_token"] = "t:%d" % (start + size)
        return self._resp(doc)

    def _querybatch(self, payload):
        out = []
        for q in payload["queries"]:
            pk = q["package"]
            if pk["ecosystem"] == "BAD":
                return self._resp({"code": 3, "message": "Invalid ecosystem"}, 400)
            ids = sorted(vid for vid, r in self.records.items()
                         if not r.get("withdrawn") and record_affects(r, pk["ecosystem"], pk["name"], q["version"]))
            start = int(q["page_token"][2:]) if q.get("page_token") else 0
            if self.page_size:
                page, rest = ids[start:start + self.page_size], ids[start + self.page_size:]
            else:
                page, rest = ids[start:], []
            item = {"vulns": [({"id": i} if self.omit_modified else {"id": i, "modified": self.records[i]["modified"]}) for i in page]}
            if rest:
                item["next_page_token"] = "t:%d" % (start + self.page_size)
            out.append(item if page or rest else {})
        return self._resp({"results": out})


@pytest.fixture
def world(tmp_path, monkeypatch):
    w = FakeOsv()
    monkeypatch.setattr(osv_http, "TRANSPORT", w.transport)
    monkeypatch.setattr(osv_mirror, "time", w.clock.module())
    monkeypatch.setattr(osv_local_db, "time", w.clock.module())
    monkeypatch.setattr(osv_local_db, "DB_PATH", str(tmp_path / "osv.db"))
    monkeypatch.setattr(osv_http, "_DEFAULT", osv_http.HttpClient(retries=2, sleep=lambda s: None))
    w.http = osv_http.HttpClient(retries=2, sleep=lambda s: None)
    w.mirror = OsvMirror(db_path=str(tmp_path / "osv.db"), http=w.http)
    w.fast = osv_fast.FastOsv(http=w.http, mirror=w.mirror, workers=4)
    yield w
    w.fast.close()


# ============================================================================ HTTP client
class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    flaky = {"n": 0}

    def setup(self):
        super().setup()
        self.server.connections += 1

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/gz":
            raw = json.dumps({"hello": "world" * 50}).encode()
            self._send(200, gzip.compress(raw), {"Content-Encoding": "gzip", "Content-Type": "application/json"})
        elif self.path == "/flaky":
            type(self).flaky["n"] += 1
            if type(self).flaky["n"] <= 2:
                self._send(503, b"busy", {"Retry-After": "0"})
            else:
                self._send(200, b'{"ok": true}')
        elif self.path == "/gone":
            self._send(404, b"{}")
        elif self.path == "/bad":
            self._send(400, b"{}")
        else:
            self._send(200, b'{"ok": true}')


@pytest.fixture
def local_server(monkeypatch):
    monkeypatch.setattr(osv_http, "TRANSPORT", None)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.connections = 0
    _Handler.flaky["n"] = 0
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_http_keepalive_reuses_one_connection(local_server, monkeypatch):
    monkeypatch.setattr(osv_http.HttpClient, "_proxied", staticmethod(lambda url: False))
    c = osv_http.HttpClient(retries=1, sleep=lambda s: None)
    base = "http://127.0.0.1:%d" % local_server.server_address[1]
    for _ in range(6):
        assert c.get(base + "/ok").ok
    assert local_server.connections == 1, "6 requests must share ONE TCP connection (keep-alive)"
    assert c.snapshot()["connections_reused"] == 5


def test_http_gzip_decoded_and_json(local_server, monkeypatch):
    monkeypatch.setattr(osv_http.HttpClient, "_proxied", staticmethod(lambda url: False))
    c = osv_http.HttpClient(sleep=lambda s: None)
    res = c.get("http://127.0.0.1:%d/gz" % local_server.server_address[1])
    assert res.ok and res.json()["hello"].startswith("world")


def test_http_retries_503_then_succeeds_and_counts(local_server, monkeypatch):
    monkeypatch.setattr(osv_http.HttpClient, "_proxied", staticmethod(lambda url: False))
    c = osv_http.HttpClient(retries=3, sleep=lambda s: None)
    res = c.get("http://127.0.0.1:%d/flaky" % local_server.server_address[1])
    assert res.ok and res.attempts == 3
    assert c.snapshot()["retries"] == 2


def test_http_404_is_an_answer_not_retried_and_400_is_a_failure(local_server, monkeypatch):
    monkeypatch.setattr(osv_http.HttpClient, "_proxied", staticmethod(lambda url: False))
    c = osv_http.HttpClient(retries=3, sleep=lambda s: None)
    base = "http://127.0.0.1:%d" % local_server.server_address[1]
    r404 = c.get(base + "/gone")
    assert r404.not_found and r404.answered and not r404.ok and r404.attempts == 1 and r404.error is None
    r400 = c.get(base + "/bad")
    assert not r400.ok and not r400.answered and r400.attempts == 1 and r400.error == "http 400"


def test_http_connection_failure_is_status_none_never_ok(monkeypatch):
    monkeypatch.setattr(osv_http, "TRANSPORT", None)
    monkeypatch.setattr(osv_http.HttpClient, "_proxied", staticmethod(lambda url: False))
    c = osv_http.HttpClient(retries=1, timeout=1.0, sleep=lambda s: None)
    res = c.get("http://127.0.0.1:1/x")          # nothing listens on port 1
    assert res.status is None and not res.ok and not res.answered and res.error
    assert c.snapshot()["failures"] == 1


def test_http_transport_hook_and_post_json(world):
    seen = {}

    def tr(method, url, headers, body):
        seen.update(method=method, url=url, ct=headers.get("Content-Type"), body=body)
        return 200, {}, b'{"x": 1}'

    osv_http.TRANSPORT = tr
    res = world.http.post_json("https://example.invalid/p", {"a": 1})
    assert res.json() == {"x": 1} and seen["method"] == "POST" and seen["ct"] == "application/json"
    assert json.loads(seen["body"]) == {"a": 1}


# =============================================================================== mirror
def test_norm_ts_orders_mixed_fraction_widths():
    a = norm_ts("2026-11-17T10:15:04.080536323Z")
    b = norm_ts("2026-11-17T10:15:36.50379755Z")      # 8 digits - plain string compare would mis-order vs 9 digits
    c = norm_ts("2026-11-17T10:15:36.6Z")
    assert a < b < c
    assert norm_ts("2026-11-17T10:15:04Z") == "2026-11-17T10:15:04.000000000Z"
    assert norm_ts("2026-11-17T12:15:04+02:00") == "2026-11-17T10:15:04.000000000Z"
    assert norm_ts("garbage") == "" and norm_ts(None) == ""
    assert ts_epoch(a) < ts_epoch(b)


def test_record_affects_ignores_git_ranges_and_honours_versions(world):
    r = world.publish("GHSA-1111", "PyPI", "Requests", fixed="2.20.0", git_fixed="9abcdef0123", versions=["2.25.9"])
    assert record_affects(r, "PyPI", "requests", "2.19.1")           # PEP 503 name + ECOSYSTEM range
    assert not record_affects(r, "PyPI", "requests", "2.20.0")
    assert record_affects(r, "PyPI", "requests", "2.25.9")           # explicit versions list
    assert not record_affects(r, "npm", "requests", "2.19.1")        # ecosystem is part of identity
    git_only = {"id": "X", "modified": "2026-01-01T00:00:00Z", "affected": [
        {"package": {"ecosystem": "npm", "name": "p"}, "ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "9f"}]}]}]}
    assert not record_affects(git_only, "npm", "p", "1.0.0"), "GIT ranges are commit hashes: never a version match"


def test_put_records_keeps_the_newer_revision(world):
    old = world.publish("GHSA-2222", "PyPI", "a", fixed="1.0")
    new = dict(old, modified=world.stamp(), summary="newer")
    assert world.mirror.put_records([new])["new"] == 1
    res = world.mirror.put_records([old])                              # a stale copy racing in later
    assert res["skipped"] == 1
    assert world.mirror.get_records(["GHSA-2222"])["GHSA-2222"][1]["summary"] == "newer"
    assert world.mirror.put_records([dict(new, summary="newest", modified=world.stamp())])["updated"] == 1


def test_read_feed_pages_without_losing_or_duplicating_rows(world):
    for i in range(40):
        world.publish("GHSA-%04d" % i, "PyPI", "pkg%d" % i, fixed="1.0")
    ids_newest_first = [v for _n, v in sorted(((norm_ts(r["modified"]), v) for v, r in world.records.items()), reverse=True)]
    wm = norm_ts(world.records[ids_newest_first[25]]["modified"])
    fr = world.mirror.read_feed("PyPI", wm, page=96)                   # tiny pages force carry-over of partial lines
    assert fr.complete and fr.reached_watermark and fr.error is None
    # the watermark row itself is re-examined (rows stamped exactly at the watermark may be exported in separate polls)
    assert [e.vuln_id for e in fr.entries] == ids_newest_first[:26]
    assert fr.bytes_read > 96 * 2, "the delta must span several Range pages"
    # watermark older than everything: the whole file is read and reported complete
    fr = world.mirror.read_feed("PyPI", "0", page=96)
    assert fr.complete and len(fr.entries) == 40
    # head-only read (no watermark)
    head = world.mirror.read_feed("PyPI", None, page=96)
    assert head.newest == norm_ts(world.records[ids_newest_first[0]]["modified"]) and head.entries == []
    # unchanged feed => 304 through the ETag, no body
    etag = head.etag
    fr304 = world.mirror.read_feed("PyPI", wm, etag=etag)
    assert fr304.status == 304 and fr304.entries == [] and fr304.complete


def test_read_feed_budget_exhaustion_is_incomplete_not_up_to_date(world):
    for i in range(30):
        world.publish("GHSA-%04d" % i, "PyPI", "pkg%d" % i, fixed="1.0")
    fr = world.mirror.read_feed("PyPI", "0", page=64, max_bytes=128)
    assert fr.complete is False and fr.entries, "an exhausted byte budget must be reported, not hidden"


def test_sync_lazy_then_delta_then_304(world):
    world.publish("GHSA-0001", "PyPI", "requests", fixed="2.20.0")
    rep = world.mirror.sync(["PyPI"])
    assert rep["ecosystems"][0]["action"] == "init_lazy" and rep["ok"]
    assert world.mirror.lookup("PyPI", "requests", "2.19.1") is None, "a lazy mirror can never prove 'no advisory'"
    r2 = world.publish("GHSA-0002", "PyPI", "requests", fixed="2.31.0")
    r3 = world.publish("GHSA-0003", "PyPI", "flask", fixed="2.2.5")
    rep = world.mirror.sync(["PyPI"])["ecosystems"][0]
    # GHSA-0001 sits exactly at the watermark and was never stored in lazy mode: it is picked up here, once
    assert rep["action"] == "delta" and rep["fetched"] == 3 and rep["new"] == 3 and not rep["error"]
    assert {c["id"] for c in rep["changes"]} == {"GHSA-0001", "GHSA-0002", "GHSA-0003"}
    assert rep["ingest_lag_s"] is not None
    assert world.mirror.state("PyPI")["watermark"] == norm_ts(r3["modified"])
    before = world.count("/GHSA-")
    rep = world.mirror.sync(["PyPI"])["ecosystems"][0]
    assert rep["action"] == "up_to_date" and rep["feed_status"] == 304 and world.count("/GHSA-") == before
    # an update to an already-mirrored record is fetched again and reported as "updated"
    world.records["GHSA-0002"]["modified"] = world.stamp()
    rep = world.mirror.sync(["PyPI"])["ecosystems"][0]
    assert rep["updated"] == 1 and rep["new"] == 0
    assert r2["id"] == "GHSA-0002"


def test_records_sharing_the_watermark_timestamp_are_not_lost(world):
    world.publish("GHSA-0001", "PyPI", "a", fixed="1.0")
    world.mirror.sync(["PyPI"])
    first = world.publish("GHSA-0002", "PyPI", "b", fixed="1.0")
    world.mirror.sync(["PyPI"])                                   # watermark is now exactly first["modified"]
    twin = dict(first, id="GHSA-0003")                            # exported later, but stamped with the same modified
    world.records["GHSA-0003"] = twin
    rep = world.mirror.sync(["PyPI"])["ecosystems"][0]
    assert {c["id"] for c in rep["changes"]} == {"GHSA-0003"} and not rep["error"]


def test_sync_failure_never_advances_the_watermark_and_loses_nothing(world):
    world.publish("GHSA-0001", "PyPI", "a", fixed="1.0")
    world.mirror.sync(["PyPI"])
    wm0 = world.mirror.state("PyPI")["watermark"]
    world.publish("GHSA-0002", "PyPI", "b", fixed="1.0")
    world.publish("GHSA-0003", "PyPI", "c", fixed="1.0")
    world.fail_ids = {"GHSA-0002"}
    rep = world.mirror.sync(["PyPI"])["ecosystems"][0]
    assert rep["error"] and rep["action"] == "partial" and len(rep["failed"]) == 1
    st = world.mirror.state("PyPI")
    assert st["watermark"] == wm0 and st["last_error"], "a failed fetch leaves the watermark where it was"
    world.fail_ids = set()
    rep = world.mirror.sync(["PyPI"])["ecosystems"][0]
    assert not rep["error"] and world.mirror.get_modified(["GHSA-0002", "GHSA-0003"]).keys() == {"GHSA-0002", "GHSA-0003"}


def test_sync_feed_outage_is_an_error_not_up_to_date(world):
    world.publish("GHSA-0001", "PyPI", "a", fixed="1.0")
    world.mirror.sync(["PyPI"])
    world.fail_feed = {"PyPI"}
    rep = world.mirror.sync(["PyPI"])
    assert rep["ok"] is False and rep["ecosystems"][0]["error"].startswith("feed:")
    assert world.mirror.state("PyPI")["last_error"]


def test_sync_deferred_batches_advance_monotonically(world):
    world.publish("GHSA-0000", "PyPI", "seed", fixed="1.0")
    world.mirror.sync(["PyPI"])
    for i in range(1, 8):
        world.publish("GHSA-%04d" % i, "PyPI", "p%d" % i, fixed="1.0")
    seen = set()
    for _ in range(6):
        rep = world.mirror.sync(["PyPI"], max_fetch=3)["ecosystems"][0]
        seen |= {c["id"] for c in rep["changes"]}
        if not rep["deferred"]:
            break
    assert seen == {"GHSA-%04d" % i for i in range(0, 8)}, "every record is eventually fetched through the cap"


def test_full_bootstrap_makes_the_mirror_authoritative_and_empty_ecosystem_works(world):
    world.publish("GHSA-0001", "PyPI", "requests", fixed="2.20.0")
    world.publish("GHSA-0002", "PyPI", "Flask", fixed="2.0.1", git_fixed="abc123")
    rep = world.mirror.sync(["PyPI"], full=True)["ecosystems"][0]
    assert rep["action"] == "bootstrap_full" and rep["imported"] == 2 and not rep["error"]
    assert world.mirror.state("PyPI")["mode"] == "full"
    assert [r["id"] for r in world.mirror.lookup("PyPI", "requests", "2.19.1")] == ["GHSA-0001"]
    assert world.mirror.lookup("PyPI", "requests", "2.25.0") == []            # complete mirror: genuinely none
    assert [r["id"] for r in world.mirror.lookup("PyPI", "flask", "1.0")] == ["GHSA-0002"]
    # the legacy offline lookup prefers the complete mirror
    assert [r["id"] for r in osv_local_db.lookup("PyPI", "requests", "2.19.1")] == ["GHSA-0001"]
    # an ecosystem whose feed is still empty must still pick up records published later
    assert world.mirror.sync(["Hex"])["ecosystems"][0]["watermark"] == osv_mirror.EPOCH_WATERMARK
    world.publish("GHSA-0009", "Hex", "plug", fixed="1.0")
    assert world.mirror.sync(["Hex"])["ecosystems"][0]["new"] == 1


# ============================================================================= fast path
def _keys(*items):
    return [(e, n, v) for e, n, v in items]


def test_fast_batch_fetches_each_advisory_once_and_second_run_needs_no_detail_calls(world):
    world.publish("GHSA-A", "PyPI", "requests", fixed="2.20.0")
    world.publish("GHSA-B", "PyPI", "requests", fixed="2.31.0")
    world.publish("GHSA-C", "PyPI", "flask", fixed="2.2.5")
    keys = _keys(("PyPI", "requests", "2.19.1"), ("PyPI", "flask", "2.0.0"), ("PyPI", "idna", "3.4"))
    out = world.fast.query_many(keys)
    assert [v["id"] for v in out[keys[0]].vulns] == ["GHSA-A", "GHSA-B"] and out[keys[0]].ok
    assert [v["id"] for v in out[keys[1]].vulns] == ["GHSA-C"]
    assert out[keys[2]].ok and out[keys[2]].vulns == [], "answered, none known"
    assert world.count("/querybatch") == 1 and world.count("/vulns/") == 3
    # a NEW client instance over the same sqlite mirror: one batch, zero detail requests
    world.calls.clear()
    fresh = osv_fast.FastOsv(http=world.http, mirror=world.mirror)
    out2 = fresh.query_many(keys)
    fresh.close()
    assert world.count("/querybatch") == 1 and world.count("/vulns/") == 0
    assert [v["id"] for v in out2[keys[0]].vulns] == ["GHSA-A", "GHSA-B"]
    assert fresh.last_stats["cache_hits"] == 3 and fresh.last_stats["fetched"] == 0


def test_fast_refetches_only_the_advisory_whose_modified_changed(world):
    world.publish("GHSA-A", "PyPI", "requests", fixed="2.20.0")
    world.publish("GHSA-B", "PyPI", "requests", fixed="2.31.0")
    k = ("PyPI", "requests", "2.19.1")
    world.fast.query_many([k])
    world.records["GHSA-B"]["modified"] = world.stamp()
    world.records["GHSA-B"]["summary"] = "revised"
    world.calls.clear()
    out = world.fast.query_many([k])
    assert world.count("/vulns/GHSA-B") == 1 and world.count("/vulns/GHSA-A") == 0
    assert {v["id"]: v["summary"] for v in out[k].vulns}["GHSA-B"] == "revised"


def test_fast_uses_one_query_per_component_when_many_advisories_are_missing(world):
    """Measured on the real API: a vulnerability-dense component costs ONE /v1/query, not one GET per advisory."""
    for i in range(6):
        world.publish("GHSA-D%d" % i, "PyPI", "django", fixed="9.9.9")
    world.publish("GHSA-S", "PyPI", "six", fixed="9.9.9")
    keys = _keys(("PyPI", "django", "1.0"), ("PyPI", "six", "1.0"))
    out = world.fast.query_many(keys)
    assert sorted(v["id"] for v in out[keys[0]].vulns) == ["GHSA-D%d" % i for i in range(6)]
    assert [v["id"] for v in out[keys[1]].vulns] == ["GHSA-S"]
    assert world.count("/v1/query") == 1 and world.count("/vulns/") == 1, "6 missing -> 1 query; 1 missing -> 1 GET"
    assert world.fast.last_stats["bulk_queries"] == 1
    world.calls.clear()
    again = osv_fast.FastOsv(http=world.http, mirror=world.mirror).query_many(keys)
    assert world.count("/v1/query") == 0 and world.count("/vulns/") == 0 and again[keys[0]].ok


def test_fast_bulk_query_failure_falls_back_to_per_advisory_gets(world):
    for i in range(5):
        world.publish("GHSA-D%d" % i, "PyPI", "django", fixed="9.9.9")
    world.fail_query = True
    out = world.fast.query_many([("PyPI", "django", "1.0")])
    assert out[("PyPI", "django", "1.0")].ok and len(out[("PyPI", "django", "1.0")].vulns) == 5
    assert world.fast.last_stats["bulk_failed"] == 1 and world.count("/vulns/") == 5


def test_fast_bulk_query_follows_pagination(world):
    for i in range(7):
        world.publish("GHSA-D%d" % i, "PyPI", "django", fixed="9.9.9")
    world.page_size = 3
    out = world.fast.query_many([("PyPI", "django", "1.0")])
    assert len(out[("PyPI", "django", "1.0")].vulns) == 7


def test_fast_follows_querybatch_pagination(world):
    for i in range(5):
        world.publish("GHSA-%d" % i, "PyPI", "requests", fixed="9.9.9")
    world.page_size = 2
    out = world.fast.query_many([("PyPI", "requests", "2.0.0")])
    assert sorted(v["id"] for v in out[("PyPI", "requests", "2.0.0")].vulns) == ["GHSA-%d" % i for i in range(5)]
    assert world.count("/querybatch") == 3, "ids pages 2 and 3 are fetched with page_token"


def test_fast_detail_failure_is_not_ok_and_never_read_as_clean(world):
    world.publish("GHSA-A", "PyPI", "requests", fixed="2.20.0")
    world.publish("GHSA-B", "PyPI", "flask", fixed="2.2.5")
    world.fail_ids = {"GHSA-A"}
    out = world.fast.query_many(_keys(("PyPI", "requests", "2.19.1"), ("PyPI", "flask", "2.0.0")))
    bad, good = out[("PyPI", "requests", "2.19.1")], out[("PyPI", "flask", "2.0.0")]
    assert not bad.ok and "GHSA-A" in bad.error and bad.vulns == []
    assert good.ok and [v["id"] for v in good.vulns] == ["GHSA-B"]


def test_fast_bisects_a_rejected_batch_so_one_bad_query_spares_the_rest(world):
    world.publish("GHSA-A", "PyPI", "requests", fixed="2.20.0")
    keys = _keys(("PyPI", "requests", "2.19.1"), ("BAD", "x", "1"), ("PyPI", "idna", "3.4"), ("npm", "left-pad", "1.0.0"))
    out = world.fast.query_many(keys)
    assert not out[("BAD", "x", "1")].ok
    assert out[("PyPI", "requests", "2.19.1")].ok and [v["id"] for v in out[("PyPI", "requests", "2.19.1")].vulns] == ["GHSA-A"]
    assert out[("PyPI", "idna", "3.4")].ok and out[("npm", "left-pad", "1.0.0")].ok


def test_fast_unreachable_is_reported_as_such(world):
    world.down = True
    out = world.fast.query_many(_keys(("PyPI", "requests", "2.19.1"), ("npm", "left-pad", "1.0.0")))
    assert all((not o.ok) and o.error.startswith("unreachable:") for o in out.values())


def test_fast_chunks_requests_at_1000(world):
    fast = osv_fast.FastOsv(http=world.http, mirror=world.mirror, chunk=3, workers=2)
    keys = [("PyPI", "p%d" % i, "1.0") for i in range(7)]
    out = fast.query_many(keys)
    fast.close()
    assert all(o.ok for o in out.values()) and world.count("/querybatch") == 3


# ======================================================================= scanner integration
def _project(tmp_path, pins):
    d = tmp_path / "proj"
    d.mkdir()
    (d / "requirements.txt").write_text("\n".join("%s==%s" % p for p in pins) + "\n", encoding="utf-8")
    return str(d)


def _scan(path, **kw):
    from bts_sbom.osvscanner import OsvScanner
    sc = OsvScanner(**kw)
    return sc, sc.scan(path)


def _vuln_ids(result):
    return {p["package"]["name"]: sorted(v["id"] for v in p["vulnerabilities"])
            for s in result["results"] for p in s["packages"]}


def test_scanner_batch_mode_answers_every_component_as_queried_online(world, tmp_path):
    world.publish("GHSA-A", "PyPI", "requests", fixed="2.20.0", severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    pins = [("requests", "2.19.1"), ("flask", "2.0.0"), ("idna", "3.4"), ("six", "1.16.0"), ("pyyaml", "6.0")]
    sc, res = _scan(_project(tmp_path, pins), osv_mode="batch")
    assert res["scan_status"]["queried_online"] == 5 and res["scan_status"].get("unqueried", 0) == 0
    assert res["scan_status"]["osv_fast"]["answered"] == 5
    assert _vuln_ids(res)["requests"] == ["GHSA-A"] and res["completeness"]["data_status"] == "complete"
    assert world.count("/querybatch") == 1 and world.count("/vulns/") == 1
    # the durable offline cache is still being built
    assert [v["id"] for v in osv_local_db.lookup_exact("PyPI", "requests", "2.19.1")] == ["GHSA-A"]


def test_scanner_batch_and_single_modes_produce_identical_findings(world, tmp_path, monkeypatch):
    world.publish("GHSA-A", "PyPI", "requests", fixed="2.20.0")
    world.publish("GHSA-B", "PyPI", "flask", fixed="2.2.5")
    pins = [("requests", "2.19.1"), ("flask", "2.0.0"), ("idna", "3.4"), ("six", "1.16.0")]
    path = _project(tmp_path, pins)

    def fake_post_query(self, url, payload):
        pk = payload["package"]
        vulns = [r for r in world.records.values() if record_affects(r, pk["ecosystem"], pk["name"], payload["version"])]
        return {"vulns": vulns}, True

    from bts_sbom._internal.osv_client import OsvClient
    monkeypatch.setattr(OsvClient, "post_query", fake_post_query)
    _sc1, single = _scan(path, osv_mode="single")
    _sc2, batch = _scan(path, osv_mode="batch")
    assert _vuln_ids(single) == _vuln_ids(batch) == {"requests": ["GHSA-A"], "flask": ["GHSA-B"], "idna": [], "six": []}
    assert "osv_fast" not in single["scan_status"] and "osv_fast" in batch["scan_status"]
    assert single["scan_status"]["queried_online"] == batch["scan_status"]["queried_online"] == 4


def test_scanner_auto_mode_goes_per_component_when_cold_then_batch_when_warm(world, tmp_path):
    """Measured on the real API: on a cold cache the batch round trip is pure overhead; once the cache is warm it
    replaces every advisory download with one request.  auto must pick accordingly, with identical findings."""
    world.publish("GHSA-A", "PyPI", "requests", fixed="2.20.0")
    path = _project(tmp_path, [("requests", "2.19.1")] + [("pkg%d" % i, "1.0") for i in range(9)])
    _s, cold = _scan(path)                                         # auto, nothing cached
    assert "osv_fast" not in cold["scan_status"]
    assert world.count("/v1/query") == 10 and world.count("/querybatch") == 0
    assert world.mirror.get_modified(["GHSA-A"]), "the per-component path feeds the record cache for next time"
    world.calls.clear()
    _s, warm = _scan(path)                                         # auto, every answer is cached now
    assert warm["scan_status"]["osv_fast"]["cache_hits"] == 1
    assert world.count("/querybatch") == 1 and world.count("/vulns/") == 0 and world.count("/v1/query") == 0
    assert _vuln_ids(cold) == _vuln_ids(warm) and _vuln_ids(warm)["requests"] == ["GHSA-A"]


def test_scanner_auto_mode_skips_batch_for_small_inventories(world, tmp_path):
    from bts_sbom._internal import osv_local_db as db
    keys = [("PyPI", "p%d" % i, "1.0") for i in range(5)]
    db.store_exact_many([(e, n, v, []) for e, n, v in keys])      # fully cached, but only 5 components
    _s, res = _scan(_project(tmp_path, [(n, v) for _e, n, v in keys]))
    assert "osv_fast" not in res["scan_status"]


def test_scanner_batch_network_down_is_honest_and_does_not_storm_the_single_path(world, tmp_path, monkeypatch):
    world.down = True
    pins = [("requests", "2.19.1"), ("flask", "2.0.0"), ("idna", "3.4"), ("six", "1.16.0")]
    sc, res = _scan(_project(tmp_path, pins), osv_mode="batch")
    from bts_sbom.osvscanner import gate_exit_code
    assert res["scan_status"]["queried_online"] == 0 and res["scan_status"]["unqueried"] == 4
    assert res["completeness"]["data_status"] != "complete" and gate_exit_code(res) == 2
    assert world.count("/querybatch") <= 3, "retries of ONE batch request, not one storm per component"
    assert world.count("/v1/query") == 0, "no per-component request after the batch proved OSV unreachable"


def test_scanner_falls_back_per_component_when_one_advisory_cannot_be_resolved(world, tmp_path, monkeypatch):
    world.publish("GHSA-A", "PyPI", "requests", fixed="2.20.0")
    world.fail_ids = {"GHSA-A"}
    from bts_sbom._internal.osv_client import OsvClient
    monkeypatch.setattr(OsvClient, "post_query", lambda self, url, payload: (
        ({"vulns": [world.records["GHSA-A"]]}, True) if payload["package"]["name"] == "requests" else ({"vulns": []}, True)))
    pins = [("requests", "2.19.1"), ("flask", "2.0.0"), ("idna", "3.4"), ("six", "1.16.0")]
    sc, res = _scan(_project(tmp_path, pins), osv_mode="batch")
    assert res["scan_status"]["osv_fast"]["per_component_fallback"] == 1
    assert _vuln_ids(res)["requests"] == ["GHSA-A"], "the unresolved advisory must reach the report via the fallback"


# ================================================================== feed-validated cache
def test_feed_mode_serves_validated_cache_without_osv_queries_and_requeries_only_touched(world, tmp_path):
    world.publish("GHSA-A", "PyPI", "requests", fixed="2.20.0")
    path = _project(tmp_path, [("requests", "2.19.1")] + [("pkg%d" % i, "1.0") for i in range(9)])
    world.clock.advance(300)
    _s, r1 = _scan(path, osv_mode="feed")                       # nothing tracked yet: asks OSV, tracking starts
    assert r1["scan_status"]["feed_validated"]["answered_from_validated_cache"] == 0
    assert world.count("/v1/query") == 10

    world.clock.advance(600)
    world.calls.clear()
    _s, r2 = _scan(path, osv_mode="feed")
    assert world.count("/v1/query") == 0 and world.count("/querybatch") == 0 and world.count("/vulns/") == 0
    fv = r2["scan_status"]["feed_validated"]
    assert fv["answered_from_validated_cache"] == 10 and fv["asked_osv"] == 0 and "caveat" in fv
    assert r2["scan_status"]["queried_offline"] == 10, "local data validated as of the last sync - not a live query"
    assert _vuln_ids(r2) == _vuln_ids(r1) and r2["completeness"]["data_status"] == "complete"
    assert r2["completeness"]["stale"]["stale"] is False

    world.clock.advance(600)                                    # OSV publishes a new advisory for ONE package
    world.publish("GHSA-NEW", "PyPI", "pkg3", fixed="9.9.9")
    world.clock.advance(60)
    world.calls.clear()
    _s, r3 = _scan(path, osv_mode="feed")
    assert world.count("/v1/query") == 1, "only the touched component asks OSV"
    assert _vuln_ids(r3)["pkg3"] == ["GHSA-NEW"] and _vuln_ids(r3)["requests"] == ["GHSA-A"]
    assert r3["scan_status"]["feed_validated"]["answered_from_validated_cache"] == 9
    assert r3["scan_status"]["feed_validated"]["not_validated_reasons"] == {"advisory_changed_since_cached": 1}


def test_feed_mode_never_validates_when_the_feed_sync_failed_this_scan(world, tmp_path):
    path = _project(tmp_path, [("pkg%d" % i, "1.0") for i in range(6)])
    world.clock.advance(300)
    _scan(path, osv_mode="feed")
    world.clock.advance(60)
    world.fail_feed = {"PyPI"}
    world.calls.clear()
    _s, res = _scan(path, osv_mode="feed")
    fv = res["scan_status"]["feed_validated"]
    assert fv["answered_from_validated_cache"] == 0 and fv["not_validated_reasons"]["feed_sync_failed_or_deferred_this_scan"] == 6
    assert world.count("/v1/query") == 6 and res["scan_status"]["queried_online"] == 6


def test_feed_validation_ignores_answers_cached_before_tracking_began(world, tmp_path):
    from bts_sbom._internal import osv_local_db as db
    keys = [("PyPI", "pkg%d" % i, "1.0") for i in range(4)]
    db.store_exact_many([(e, n, v, []) for e, n, v in keys])    # cached by an old scan, nobody was watching the feed
    world.clock.advance(600)
    path = _project(tmp_path, [(n, v) for _e, n, v in keys])
    _s, res = _scan(path, osv_mode="feed")
    fv = res["scan_status"]["feed_validated"]
    assert fv["answered_from_validated_cache"] == 0 and fv["not_validated_reasons"] == {"cached_before_tracking_started": 4}
    assert world.count("/v1/query") == 4


def test_touch_covers_packages_removed_from_an_advisory(world):
    from bts_sbom._internal import osv_local_db as db
    bar = {"package": {"ecosystem": "PyPI", "name": "bar"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}
    rec = world.publish("GHSA-R", "PyPI", "foo", fixed="2.0", extra_affected=[bar])
    world.mirror._set_state("PyPI", mode="lazy", watermark="0", last_ok=world.clock.now, bootstrapped_at=world.clock.now - 5000)
    world.mirror.put_records([rec])
    world.clock.advance(1000)
    db.store_exact_many([("PyPI", "foo", "1.0", [rec]), ("PyPI", "bar", "1.0", [rec])])
    world.mirror._set_state("PyPI", last_ok=world.clock.now)
    ans, _ = world.mirror.validated_cache([("PyPI", "foo", "1.0"), ("PyPI", "bar", "1.0")])
    assert len(ans) == 2
    world.clock.advance(1000)
    revised = dict(rec, modified=world.stamp(), affected=[a for a in rec["affected"] if a["package"]["name"] == "foo"])
    world.mirror.put_records([revised])                         # "bar" is no longer listed - its cached answer is wrong
    world.mirror._set_state("PyPI", last_ok=world.clock.now)
    ans, info = world.mirror.validated_cache([("PyPI", "foo", "1.0"), ("PyPI", "bar", "1.0")])
    assert ans == {} and info["not_validated"] == {"advisory_changed_since_cached": 2}


# ================================================================ GIT ranges are not versions
def test_git_range_commit_sha_is_never_a_fixed_version():
    from bts_sbom._internal import remediation
    from bts_sbom._internal.osv_client import OsvClient
    rec = {"id": "GHSA-G", "modified": "2026-01-01T00:00:00Z", "affected": [
        {"package": {"ecosystem": "npm", "name": "left-pad"},
         "ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "9abcdef0123456789abcdef0123456789abcdef0"}]}]}]}
    assert OsvClient()._parse_vulns([rec], "left-pad", "1.0.0")[0].fixed_version is None
    assert remediation.iter_fix_bounds(rec) == []
    assert remediation.suggest_fixes(rec, "npm", current="1.0.0")[0]["fixed_suggestion"] is None
    assert osv_local_db._vuln_affects(rec, "left-pad", "99.0.0") is False
    mixed = dict(rec, affected=[dict(rec["affected"][0], ranges=rec["affected"][0]["ranges"] + [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}])])
    assert OsvClient()._parse_vulns([mixed], "left-pad", "1.0.0")[0].fixed_version == "1.2.0"


# ==================================================================================== watch
NOW = datetime(2026, 11, 17, 10, 30, 0, tzinfo=timezone.utc).timestamp()


def _watcher(world, comps, tmp_path, state=True):
    events = []
    w = osv_watch.Watcher(comps, mirror=world.mirror, fast=world.fast, emit=events.append, clock=lambda: NOW,
                          sleep=lambda s: None, state_path=str(tmp_path / "w.json") if state else None,
                          events_path=str(tmp_path / "ev.jsonl"))
    return w, events


def test_watch_reports_new_updated_and_resolved_with_lag_and_rechecks_only_candidates(world, tmp_path):
    world.publish("GHSA-OLD", "PyPI", "requests", fixed="2.20.0")
    comps = [("PyPI", "requests", "2.19.1"), ("npm", "left-pad", "1.0.0")]
    w, events = _watcher(world, comps, tmp_path)
    prep = w.prepare()
    assert prep["baseline"] == "taken" and prep["findings"] == 1 and not prep["errors"]

    # 1) unrelated advisory: the feed changes, but no component is a candidate -> no re-check at all
    world.publish("GHSA-NOISE", "PyPI", "django", fixed="4.2.1")
    world.calls.clear()
    rep = w.cycle()
    assert rep["changed_records"] == 1 and rep["candidate_components"] == 0 and rep["events"] == []
    assert world.count("/querybatch") == 0

    # 2) a new advisory for a watched component
    new = world.publish("GHSA-NEW", "PyPI", "requests", fixed="2.31.0", severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    rep = w.cycle()
    ev = [e for e in rep["events"] if e["type"] == "new"]
    assert len(ev) == 1 and ev[0]["id"] == "GHSA-NEW" and ev[0]["severity"] == "CRITICAL"
    assert ev[0]["component"]["name"] == "requests" and ev[0]["fixed_version"] == "2.31.0"
    assert ev[0]["lag_s"] == round(NOW - ts_epoch(norm_ts(new["modified"])), 1) and ev[0]["lag_s"] >= 0
    assert rep["candidate_components"] == 1 and world.count("/querybatch") == 1, "only the affected component is re-checked"

    # 3) an existing advisory is revised
    world.records["GHSA-OLD"]["modified"] = world.stamp()
    world.records["GHSA-OLD"]["summary"] = "revised text"
    rep = w.cycle()
    assert [(e["type"], e["id"]) for e in rep["events"]] == [("updated", "GHSA-OLD")]

    # 4) an advisory is withdrawn upstream
    world.records["GHSA-NEW"]["modified"] = world.stamp()
    world.records["GHSA-NEW"]["withdrawn"] = "2026-11-17T10:20:00Z"
    rep = w.cycle()
    res = [e for e in rep["events"] if e["type"] == "resolved"]
    assert [(e["id"], e["reason"]) for e in res] == [("GHSA-NEW", "withdrawn")]

    # quiet cycle
    rep = w.cycle()
    assert rep["events"] == [] and rep["errors"] == []
    lines = (tmp_path / "ev.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert [json.loads(l)["type"] for l in lines] == ["new", "updated", "resolved"]


def test_watch_state_file_makes_a_restart_report_what_changed_while_down(world, tmp_path):
    world.publish("GHSA-OLD", "PyPI", "requests", fixed="2.20.0")
    comps = [("PyPI", "requests", "2.19.1")]
    w1, _ = _watcher(world, comps, tmp_path)
    w1.prepare()
    world.publish("GHSA-DOWNTIME", "PyPI", "requests", fixed="2.31.0")      # published while the watcher is not running
    w2, events = _watcher(world, comps, tmp_path)
    world.calls.clear()
    prep = w2.prepare()
    assert prep["baseline"] == "loaded" and world.count("/querybatch") == 0, "a matching state file skips the baseline"
    rep = w2.cycle()
    assert [(e["type"], e["id"]) for e in rep["events"]] == [("new", "GHSA-DOWNTIME")]


def test_watch_sync_failure_is_an_error_event_and_exit_code_2_never_quiet(world, tmp_path):
    world.publish("GHSA-OLD", "PyPI", "requests", fixed="2.20.0")
    w, events = _watcher(world, [("PyPI", "requests", "2.19.1")], tmp_path, state=False)
    w.prepare()
    world.fail_feed = {"PyPI"}
    rep = w.cycle()
    assert rep["errors"] and rep["events"][0]["type"] == "error"
    code = w.run(once=True)
    assert code == 2


def test_watch_recheck_failure_keeps_the_old_answer_and_reports_an_error(world, tmp_path):
    world.publish("GHSA-OLD", "PyPI", "requests", fixed="2.20.0")
    w, events = _watcher(world, [("PyPI", "requests", "2.19.1")], tmp_path, state=False)
    w.prepare()
    world.publish("GHSA-NEW", "PyPI", "requests", fixed="2.31.0")
    world.fail_ids = {"GHSA-NEW"}                      # the record cannot be fetched from the bucket nor the API
    rep = w.cycle()
    assert rep["errors"], "a change we could not process must be visible"
    world.fail_ids = set()
    rep = w.cycle()                                    # next poll retries the same entries and succeeds
    assert [(e["type"], e["id"]) for e in rep["events"] if e["type"] != "error"] == [("new", "GHSA-NEW")]


def test_watch_run_once_exit_codes(world, tmp_path):
    world.publish("GHSA-OLD", "PyPI", "requests", fixed="2.20.0")
    w, _ = _watcher(world, [("PyPI", "requests", "2.19.1")], tmp_path, state=False)
    assert w.run(once=True) == 0
    world.publish("GHSA-NEW", "PyPI", "requests", fixed="2.31.0")
    assert w.run(once=True) == 1


def test_components_from_target_uses_scanner_discovery_and_exact_versions_only(tmp_path):
    d = tmp_path / "p"
    d.mkdir()
    (d / "requirements.txt").write_text("requests==2.19.1\nflask>=2.0\nidna==3.4\n", encoding="utf-8")
    keys = osv_watch.components_from_target(str(d))
    assert ("PyPI", "requests", "2.19.1") in keys and ("PyPI", "idna", "3.4") in keys
    assert not any(k[1] == "flask" for k in keys), "a range cannot be matched honestly"


# ====================================================================================== CLI
def test_cli_osv_status_sync_and_scan_flag(world, tmp_path, capsys):
    from bts_sbom import cli
    world.publish("GHSA-A", "PyPI", "requests", fixed="2.20.0")
    db = str(tmp_path / "cli.db")
    assert cli.main(["osv", "sync", "--ecosystem", "PyPI", "--db", db]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] and out["ecosystems"][0]["action"] == "init_lazy"
    assert cli.main(["osv", "status", "--db", db]) == 0
    st = json.loads(capsys.readouterr().out)
    assert st["ecosystems"][0]["ecosystem"] == "PyPI" and st["ecosystems"][0]["mode"] == "lazy"
    world.fail_feed = {"PyPI"}
    assert cli.main(["osv", "sync", "--ecosystem", "PyPI", "--db", db]) == 2
    capsys.readouterr()
    assert cli.main(["osv", "sync", "--db", db]) == 2          # no --ecosystem / --target: usage error, not a crash
    args = cli.build_parser().parse_args(["scan", "x", "--osv-mode", "single"])
    assert args.osv_mode == "single"


def test_cli_help_is_ascii_for_every_osv_subcommand():
    from bts_sbom import cli
    p = cli.build_parser()
    for argv in (["osv", "--help"], ["osv", "sync", "--help"], ["osv", "status", "--help"], ["osv", "watch", "--help"],
                 ["scan", "--help"]):
        with pytest.raises(SystemExit):
            try:
                import contextlib
                with contextlib.redirect_stdout(io.StringIO()) as buf:
                    p.parse_args(argv)
            finally:
                text = buf.getvalue()
                text.encode("cp949")           # the project's own rule: help text must survive a cp949 console



# ======================================================================== regressions from the adversarial review
import gzip as _gzip
import sqlite3 as _sqlite3


def test_feed_read_survives_the_object_changing_between_pages_without_losing_the_newest_row(world):
    for i in range(30):
        world.publish("GHSA-%04d" % i, "PyPI", "p%d" % i, fixed="1.0")
    page_calls = {"n": 0}
    real = world.transport

    def drifting(method, url, headers, body):
        if url.endswith("PyPI/modified_id.csv"):
            page_calls["n"] += 1
            if page_calls["n"] == 2:                    # the exporter appends a row between page 1 and page 2
                world.publish("GHSA-NEWEST", "PyPI", "newest", fixed="1.0")
        return real(method, url, headers, body)

    osv_http.TRANSPORT = drifting
    fr = world.mirror.read_feed("PyPI", "0", page=96)
    assert fr.error is None and fr.complete
    ids = [e.vuln_id for e in fr.entries]
    assert "GHSA-NEWEST" in ids and len(ids) == 31 and len(set(ids)) == 31, "no row lost, none duplicated"
    assert fr.malformed == 0


def test_feed_read_that_never_settles_is_an_error_not_success(world):
    for i in range(30):
        world.publish("GHSA-%04d" % i, "PyPI", "p%d" % i, fixed="1.0")
    real = world.transport
    n = {"i": 0}

    def always_drifting(method, url, headers, body):
        if url.endswith("PyPI/modified_id.csv") and headers.get("Range", "").startswith("bytes=0-"):
            n["i"] += 1
        if url.endswith("PyPI/modified_id.csv") and not headers.get("Range", "").startswith("bytes=0-"):
            world.publish("GHSA-X%d" % n["i"], "PyPI", "x", fixed="1.0")      # a new revision on every later page
        return real(method, url, headers, body)

    osv_http.TRANSPORT = always_drifting
    fr = world.mirror.read_feed("PyPI", "0", page=96)
    assert fr.error and "changed while it was being read" in fr.error and not fr.complete


def test_feed_read_answered_with_the_whole_object_on_a_later_page_is_parsed_from_its_start(world):
    for i in range(20):
        world.publish("GHSA-%04d" % i, "PyPI", "p%d" % i, fixed="1.0")
    real = world.transport
    calls = {"n": 0}

    def whole_on_page_two(method, url, headers, body):
        if url.endswith("PyPI/modified_id.csv"):
            calls["n"] += 1
            if calls["n"] == 2:
                headers = {k: v for k, v in headers.items() if k not in ("Range", "If-Range")}      # server ignores Range
        return real(method, url, headers, body)

    osv_http.TRANSPORT = whole_on_page_two
    fr = world.mirror.read_feed("PyPI", "0", page=96)
    assert fr.error is None and len(fr.entries) == 20 and len({e.vuln_id for e in fr.entries}) == 20


def test_malformed_feed_rows_are_an_error(world):
    world.publish("GHSA-0001", "PyPI", "a", fixed="1.0")
    real = world.transport

    def garbled(method, url, headers, body):
        st, h, data = real(method, url, headers, body)
        if url.endswith("PyPI/modified_id.csv") and st in (200, 206):
            data = b"not-a-timestamp,GHSA-9999\n" + data
        return st, h, data

    osv_http.TRANSPORT = garbled
    fr = world.mirror.read_feed("PyPI", "0")
    assert fr.malformed == 1 and fr.error and "malformed" in fr.error


def test_deferred_sync_does_not_vouch_for_cached_answers(world):
    from bts_sbom._internal import osv_local_db as db
    world.publish("GHSA-0000", "PyPI", "seed", fixed="1.0")
    world.mirror.sync(["PyPI"])
    world.clock.advance(600)
    db.store_exact_many([("PyPI", "pkga", "1.0", [])])
    world.clock.advance(600)
    for i in range(3):
        world.publish("GHSA-N%d" % i, "PyPI", "pkg%s" % ("a" if i == 2 else i), fixed="9.9")
    world.clock.advance(10)
    rep = world.mirror.sync(["PyPI"], max_fetch=1)["ecosystems"][0]
    assert rep["deferred"] >= 2
    ans, info = world.mirror.validated_cache([("PyPI", "pkga", "1.0")])
    assert ans == {} and info["not_validated"] == {"sync_stale_or_failed": 1}, "a deferred poll must not make the mirror look current"
    for _ in range(4):
        r = world.mirror.sync(["PyPI"], max_fetch=1)["ecosystems"][0]
        if not r["deferred"]:
            break
    assert world.mirror.state("PyPI")["last_ok"] is not None


def test_scanner_feed_mode_skips_ecosystems_whose_poll_deferred(world, tmp_path):
    world.publish("GHSA-0000", "PyPI", "seed", fixed="1.0")
    path = _project(tmp_path, [("pkg%d" % i, "1.0") for i in range(6)])
    world.clock.advance(300)
    _scan(path, osv_mode="feed")
    world.clock.advance(300)
    for i in range(3):
        world.publish("GHSA-N%d" % i, "PyPI", "other%d" % i, fixed="9.9")
    world.clock.advance(10)
    real = osv_mirror.OsvMirror.sync

    def tiny_budget(self, ecosystems, **kw):
        kw["max_fetch"] = 1
        return real(self, ecosystems, **kw)

    osv_mirror.OsvMirror.sync = tiny_budget
    try:
        _s, res = _scan(path, osv_mode="feed")
    finally:
        osv_mirror.OsvMirror.sync = real
    fv = res["scan_status"]["feed_validated"]
    assert fv["answered_from_validated_cache"] == 0 and fv["not_validated_reasons"]["feed_sync_failed_or_deferred_this_scan"] == 6


def test_watch_ignores_a_state_file_whose_mirror_was_reset(world, tmp_path):
    world.publish("GHSA-OLD", "PyPI", "requests", fixed="2.20.0")
    comps = [("PyPI", "requests", "2.19.1")]
    w1, _ = _watcher(world, comps, tmp_path)
    w1.prepare()
    world.publish("GHSA-MISSED", "PyPI", "requests", fixed="2.31.0")
    fresh_db = OsvMirror(db_path=str(tmp_path / "other.db"), http=world.http)             # relocated / deleted mirror database
    events = []
    w2 = osv_watch.Watcher(comps, mirror=fresh_db, fast=osv_fast.FastOsv(http=world.http, mirror=fresh_db), emit=events.append,
                           clock=lambda: NOW, sleep=lambda s: None, state_path=str(tmp_path / "w.json"))
    prep = w2.prepare()
    assert prep["baseline"] == "retaken" and prep["notes"] and "cannot be reported as events" in prep["notes"][0]
    assert set(w2.known[osv_watch._key_str(comps[0])]) == {"GHSA-OLD", "GHSA-MISSED"}, "the new baseline reflects today's truth"


def test_watch_old_format_state_file_is_not_trusted(world, tmp_path):
    world.publish("GHSA-OLD", "PyPI", "requests", fixed="2.20.0")
    comps = [("PyPI", "requests", "2.19.1")]
    (tmp_path / "w.json").write_text(json.dumps({"version": 1, "components": [osv_watch._key_str(comps[0])], "known": {}}), encoding="utf-8")
    w, _ = _watcher(world, comps, tmp_path)
    assert w.prepare()["baseline"] == "taken"


def test_watch_retries_a_failed_recheck_even_when_the_feed_shows_nothing_new(world, tmp_path):
    world.publish("GHSA-OLD", "PyPI", "requests", fixed="2.20.0")
    comps = [("PyPI", "requests", "2.19.1")]
    w, events = _watcher(world, comps, tmp_path)
    w.prepare()
    world.publish("GHSA-NEW", "PyPI", "requests", fixed="2.31.0")
    real = w.fast.query_many
    flaky = {"fail": True}

    def maybe_fail(keys):
        if flaky["fail"]:
            flaky["fail"] = False
            return {k: osv_fast.Outcome(False, [], "unreachable: simulated") for k in keys}
        return real(keys)

    w.fast.query_many = maybe_fail
    rep1 = w.cycle()
    assert rep1["errors"] and not [e for e in rep1["events"] if e["type"] == "new"] and rep1["pending_rechecks"] == 1
    rep2 = w.cycle()                                    # the feed has nothing new, but the pending re-check is retried
    assert [(e["type"], e["id"]) for e in rep2["events"]] == [("new", "GHSA-NEW")] and rep2["pending_rechecks"] == 0
    w3, _ = _watcher(world, comps, tmp_path)            # pending survives a restart through the state file
    assert w3._load() and w3.pending == {}


def test_watch_survives_storage_errors_and_unwritable_state(world, tmp_path, monkeypatch):
    world.publish("GHSA-OLD", "PyPI", "requests", fixed="2.20.0")
    comps = [("PyPI", "requests", "2.19.1")]
    w, events = _watcher(world, comps, tmp_path)
    w.prepare()
    real = w.mirror.sync
    n = {"i": 0}

    def boom(eco, **kw):
        n["i"] += 1
        if n["i"] == 1:
            raise _sqlite3.OperationalError("database is locked")
        return real(eco, **kw)

    w.mirror.sync = boom
    code = w.run(max_cycles=2, interval=1)
    assert any(e["type"] == "error" and e.get("scope") == "watch" for e in events) and code == 0, "error reported, watch continued"
    # os.replace failing for a few attempts (Windows reader holding the state file) is retried
    seen = {"n": 0}
    real_replace = os.replace

    def flaky_replace(a, b):
        seen["n"] += 1
        if seen["n"] <= 2:
            raise PermissionError("[WinError 5] Access is denied")
        return real_replace(a, b)

    monkeypatch.setattr(os, "replace", flaky_replace)
    monkeypatch.setattr(osv_watch.time, "sleep", lambda s: None)
    w._save()
    assert seen["n"] == 3
    monkeypatch.setattr(os, "replace", lambda a, b: (_ for _ in ()).throw(PermissionError("locked")))
    rep = w.cycle()
    assert any("state file not saved" in e for e in rep["errors"])


def test_mirror_recreates_its_schema_if_the_database_file_disappears(world, tmp_path):
    m = world.mirror
    assert m.state("PyPI") is None
    os.remove(m.db_path)
    for ext in ("-wal", "-shm"):
        if os.path.exists(m.db_path + ext):
            os.remove(m.db_path + ext)
    assert m.state("PyPI") is None and m.stats()["records"] == 0


def test_ecosystem_names_are_validated_and_canonicalised(world):
    assert osv_mirror.canonical_ecosystem("pypi") == "PyPI" and osv_mirror.canonical_ecosystem("RED HAT:9") == "Red Hat"
    assert osv_mirror.canonical_ecosystem("Weird Eco") == "Weird Eco"
    for bad in ("..", "a/b", "../x", "", "x" * 80, "a\nb"):
        assert not osv_mirror.valid_ecosystem(bad)
    world.calls.clear()
    rep = world.mirror.sync_ecosystem("..")
    assert rep["error"] and "invalid ecosystem" in rep["error"] and world.calls == [], "no request is made for a hostile name"
    world.publish("GHSA-0001", "PyPI", "a", fixed="1.0")
    rep = world.mirror.sync(["pypi"])["ecosystems"][0]
    assert rep["ecosystem"] == "PyPI" and not rep["error"], "a lower-case name from the CLI or a purl must still find the bucket"
    with pytest.raises(ValueError):
        world.mirror.read_feed("a/b", None)


def test_bootstrap_skips_oversized_and_unparseable_members(world, monkeypatch):
    world.publish("GHSA-0001", "PyPI", "requests", fixed="2.20.0")
    real = world.transport

    def evil_zip(method, url, headers, body):
        if url.endswith("PyPI/all.zip"):
            import io as _io
            buf = _io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("GHSA-0001.json", json.dumps(world.records["GHSA-0001"]))
                zf.writestr("BIG.json", json.dumps({"id": "BIG", "modified": "2026-01-01T00:00:00Z", "pad": "A" * 5000}))
                zf.writestr("DEEP.json", "[" * 100000 + "]" * 100000)
            return 200, {}, buf.getvalue()
        return real(method, url, headers, body)

    osv_http.TRANSPORT = evil_zip
    monkeypatch.setattr(osv_mirror, "MAX_RECORD_BYTES", 2000)
    rep = world.mirror.sync_ecosystem("PyPI", full=True)
    assert rep["imported"] == 1 and not rep["error"]
    assert world.mirror.get_modified(["BIG"]) == {}
    monkeypatch.setattr(osv_mirror, "MAX_RECORD_BYTES", 8 << 20)
    monkeypatch.setattr(osv_mirror, "MAX_BOOTSTRAP_BYTES", 10)
    rep = world.mirror.sync_ecosystem("PyPI", full=True, refull=True)
    assert rep["error"] and "refusing" in rep["error"]


def test_withdrawn_advisories_are_not_local_hits(world):
    world.publish("GHSA-LIVE", "PyPI", "requests", fixed="2.20.0")
    world.publish("GHSA-GONE", "PyPI", "requests", fixed="2.20.0", withdrawn="2026-11-01T00:00:00Z")
    world.mirror.sync(["PyPI"], full=True)
    assert [r["id"] for r in world.mirror.lookup("PyPI", "requests", "2.19.1")] == ["GHSA-LIVE"]


def test_cache_entry_cannot_be_validated_without_a_modified_from_osv(world):
    world.publish("GHSA-A", "PyPI", "requests", fixed="2.20.0")
    k = ("PyPI", "requests", "2.19.1")
    world.fast.query_many([k])                           # caches GHSA-A
    world.records["GHSA-A"]["summary"] = "changed upstream"
    world.records["GHSA-A"]["modified"] = world.stamp()
    world.omit_modified = True                           # a querybatch answer that carries no usable timestamp
    out = world.fast.query_many([k])
    assert out[k].ok and out[k].vulns[0]["summary"] == "changed upstream", "an unvalidatable cache entry is refetched, never trusted"


def test_scanner_fixed_version_ignores_git_ranges():
    from bts_sbom.osvscanner import OsvScanner, _fixed_version
    rec = {"id": "X", "modified": "2026-01-01T00:00:00Z", "affected": [
        {"package": {"ecosystem": "npm", "name": "p"}, "ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "9abcdef0123456789abcdef0123456789abcdef0"}]}]}]}
    assert _fixed_version(rec, "p", "1.0.0") is None
    mixed = dict(rec, affected=[dict(rec["affected"][0], ranges=rec["affected"][0]["ranges"] + [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}])])
    assert _fixed_version(mixed, "p", "1.0.0") == "1.2.0"


# ---------------------------------------------------------------------------------------------- http hardening
def test_decompression_bomb_is_refused_not_inflated(monkeypatch):
    bomb = _gzip.compress(b"\0" * 2_000_000)
    with pytest.raises(osv_http.ResponseTooLarge):
        osv_http._decode_body(bomb, "gzip", limit=100_000)
    assert len(osv_http._decode_body(bomb, "gzip", limit=3_000_000)) == 2_000_000
    monkeypatch.setattr(osv_http, "MAX_BODY", 100_000)
    osv_http.TRANSPORT = lambda m, u, h, b: (200, {"Content-Encoding": "gzip"}, bomb)
    res = osv_http.HttpClient(retries=3, sleep=lambda s: None).get("https://example.invalid/x")
    assert not res.ok and res.status is None and "too large" in res.error and res.attempts == 1, "refused once, never retried"
    osv_http.TRANSPORT = lambda m, u, h, b: (200, {}, b"A" * 200_000)
    assert "too large" in osv_http.HttpClient(retries=0).get("https://example.invalid/x").error


def test_deeply_nested_json_does_not_crash_the_caller():
    r = osv_http.HttpResult(200, b"[" * 200_000 + b"]" * 200_000)
    assert r.json() is None


def test_total_deadline_stops_a_trickling_server(monkeypatch):
    import socket
    import time as _t
    monkeypatch.setattr(osv_http, "TRANSPORT", None)
    monkeypatch.setattr(osv_http.HttpClient, "_proxied", staticmethod(lambda url: False))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def serve():
        c, _ = srv.accept()
        c.recv(4096)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 60\r\n\r\n")
        try:
            for _ in range(60):
                c.sendall(b"x")
                _t.sleep(0.25)
        except OSError:
            pass
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    t0 = _t.monotonic()
    res = osv_http.HttpClient(timeout=5.0, total_timeout=1.0, retries=0).get("http://127.0.0.1:%d/" % srv.getsockname()[1])
    assert not res.ok and "total time" in (res.error or "") and _t.monotonic() - t0 < 4, "the whole request is bounded, not each socket read"
    srv.close()


def test_proxy_fallback_never_follows_a_redirect_to_another_host(local_server, monkeypatch):
    class Redirect(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setattr(osv_http.HttpClient, "_proxied", staticmethod(lambda url: True))
        res = osv_http.HttpClient(retries=0).get("http://127.0.0.1:%d/" % srv.server_address[1])
        assert res.status == 302 and not res.ok
    finally:
        srv.shutdown()
        srv.server_close()


def test_download_is_capped(local_server, monkeypatch, tmp_path):
    monkeypatch.setattr(osv_http.HttpClient, "_proxied", staticmethod(lambda url: False))
    c = osv_http.HttpClient(retries=0)
    res = c.download_to_file("http://127.0.0.1:%d/ok" % local_server.server_address[1], str(tmp_path / "d.bin"), max_bytes=5)
    assert not res.ok and "larger" in (res.error or "")


def test_client_query_batch_uses_querybatch_resolves_records_and_never_hides_a_failure(world):
    from bts_sbom._internal.osv_client import OsvClient, OsvQueryError
    world.publish("GHSA-A", "PyPI", "requests", fixed="2.20.0", severity="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    pkgs = [{"name": "requests", "version": "2.19.1", "ecosystem": "pypi"}, {"name": "idna", "version": "3.4", "ecosystem": "pypi"}]
    res = OsvClient().query_batch(pkgs)
    assert [len(r) for r in res] == [1, 0] and res[0][0].vuln_id == "GHSA-A" and res[0][0].severity == "CRITICAL"
    assert res[0][0].fixed_version == "2.20.0", "full record fields, not the id/modified stub"
    world.down = True
    with pytest.raises(OsvQueryError) as exc:
        OsvClient().query_batch(pkgs)
    assert "could not answer 2 package" in str(exc.value)
