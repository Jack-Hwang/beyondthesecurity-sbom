"""The OSS Scanner screen: scan job lifecycle, result views, downloads, notice, compare, and the safety rules of the API."""
from __future__ import annotations

import http.client
import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom import ossreport, ossscan
from bts_sbom.ossreport import OssItem, OssReport
from bts_sbom_app import evals, oss_api, server


def _fake_scanners(monkeypatch, items_by_mode=None, delay=0.0):
    items_by_mode = items_by_mode or {
        "oss_source": [dict(kind="src", oss_name="libidn", version="1.33", licenses=["GPL-3.0-only"], source_path="src/a.c",
                            copyright="Copyright (C) Simon", evidence=["SPDX tag at src/a.c:1"]),
                       dict(kind="src", oss_name="zlib", version="1.2", licenses=["Zlib"], source_path="src/z.c"),
                       dict(kind="src", oss_name="<script>alert(1)</script>", licenses=["MIT"], source_path="x/<img src=x onerror=1>.c")],
        "oss_dependency": [dict(kind="dep", oss_name="left-pad", version="1.3.0", licenses=["MIT"], purl="pkg:npm/left-pad@1.3.0",
                                source_path="package.json", extra={"manager": "npm"})],
        "oss_binary": [dict(kind="bin", oss_name="", source_path="bin/tool", checksum="a" * 64, comment="no open source identified")]}

    class M:
        def __init__(self, items):
            self.items = items

        def scan(self, root, **kw):
            if delay:
                time.sleep(delay)
            r = OssReport(info=ossreport.new_info(root), items=[OssItem(**i) for i in self.items])
            r.info["scanners"]["fake"] = "ok"
            return r

    monkeypatch.setattr(ossscan, "_import", lambda name: M(items_by_mode[name]))


@pytest.fixture
def ui(tmp_path, monkeypatch):
    _fake_scanners(monkeypatch)
    ev = tmp_path / "ev"
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "a.txt").write_text("x", encoding="utf-8")
    yield {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "ev": ev, "st": st, "proj": str(proj), "tmp": tmp_path}
    httpd.shutdown()


def _req(url, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"} if body is not None else {}
    h.update(headers or {})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=h), timeout=20) as r:
            raw = r.read()
            ct = r.headers.get("Content-Type", "")
            return r.status, (json.loads(raw) if "json" in ct and raw else raw), dict(r.headers)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw), dict(e.headers)
        except ValueError:
            return e.code, raw, dict(e.headers)


def _scan(ui, **extra):
    body = {"target": ui["proj"]}
    body.update(extra)
    code, d, _ = _req(ui["base"] + "/api/oss/scan", body)
    assert code == 202, d
    jid = d["job"]
    for _ in range(100):
        code, job, _ = _req(ui["base"] + "/api/oss/jobs/" + jid)
        if job["state"] != "running":
            return jid, job
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


# ------------------------------------------------------------------------------------------------ lifecycle
def test_scan_job_runs_through_stages_and_yields_overview_and_rows(ui):
    jid, job = _scan(ui)
    assert job["state"] == "done" and job["counts"] == {"src": 3, "dep": 1, "bin": 1}
    ov = _req(ui["base"] + "/api/oss/overview/" + jid)[1]
    assert [r["license"] for r in ov["license_tiers"]["High"]] == ["GPL-3.0-only"]
    code, rows, _ = _req(ui["base"] + "/api/oss/items/%s?kind=src&sort=oss_name&dir=desc&limit=2&offset=0" % jid)
    assert code == 200 and rows["total"] == 3 and len(rows["rows"]) == 2 and rows["rows"][0]["oss_name"] == "zlib"
    q = _req(ui["base"] + "/api/oss/items/%s?kind=src&q=gpl" % jid)[1]
    assert [r["oss_name"] for r in q["rows"]] == ["libidn"]
    dep = _req(ui["base"] + "/api/oss/items/%s?kind=dep" % jid)[1]["rows"][0]
    assert dep["path"] == "pkg:npm/left-pad@1.3.0"
    assert os.path.exists(os.path.join(str(ui["ev"]), "oss", jid, "result.json"))


def test_modes_selection_and_unknown_modes(ui, monkeypatch):
    seen = []
    orig = ossscan._import
    monkeypatch.setattr(ossscan, "_import", lambda n: (seen.append(n), orig(n))[1])
    jid, job = _scan(ui, modes=["source", "bogus"])
    assert job["counts"] == {"src": 3, "dep": 0, "bin": 0} and seen == ["oss_source"]
    jid2, job2 = _scan(ui, modes=["bogus"])
    assert job2["modes"] == list(oss_api.MODES), "no valid mode -> all modes"


def test_failed_target_is_reported_not_hidden(ui):
    code, d, _ = _req(ui["base"] + "/api/oss/scan", {"target": "/definitely/not/here"})
    assert code == 202
    for _ in range(100):
        job = _req(ui["base"] + "/api/oss/jobs/" + d["job"])[1]
        if job["state"] != "running":
            break
        time.sleep(0.05)
    assert job["state"] == "error" and "not a folder" in job["error"]


def test_cancel_stops_a_running_job(ui, monkeypatch):
    _fake_scanners(monkeypatch, delay=0.4)
    code, d, _ = _req(ui["base"] + "/api/oss/scan", {"target": ui["proj"]})
    assert _req(ui["base"] + "/api/oss/jobs/%s/cancel" % d["job"], {})[0] == 200
    for _ in range(100):
        job = _req(ui["base"] + "/api/oss/jobs/" + d["job"])[1]
        if job["state"] != "running":
            break
        time.sleep(0.05)
    assert job["state"] == "cancelled"


def test_too_many_running_scans_are_refused(ui, monkeypatch):
    _fake_scanners(monkeypatch, delay=0.5)
    monkeypatch.setattr(oss_api, "MAX_RUNNING", 1)
    first = _req(ui["base"] + "/api/oss/scan", {"target": ui["proj"]})
    second = _req(ui["base"] + "/api/oss/scan", {"target": ui["proj"]})
    assert first[0] == 202 and second[0] == 429


# ------------------------------------------------------------------------------------------ downloads / notice
def test_report_downloads_in_every_format(ui):
    jid, _ = _scan(ui)
    for fmt in ossreport.FORMATS:
        code, body, hdr = _req(ui["base"] + "/api/oss/report/%s?format=%s" % (jid, fmt))
        assert code == 200 and "attachment" in hdr["Content-Disposition"] and len(body if isinstance(body, bytes) else json.dumps(body)) > 40, fmt
    code, body, _ = _req(ui["base"] + "/api/oss/report/%s?format=xlsx" % jid)
    assert body[:2] == b"PK"
    assert _req(ui["base"] + "/api/oss/report/%s?format=exe" % jid)[0] == 400


def test_notice_endpoint_returns_text_and_an_honest_audit(ui):
    jid, _ = _scan(ui)
    code, d, _ = _req(ui["base"] + "/api/oss/notice", {"job": jid, "format": "html", "contact": "oss@example.com", "product": "Demo"})
    assert code == 200 and "libidn" in d["notice"] and "&lt;script&gt;" in d["notice"] and "<script>alert" not in d["notice"]
    assert d["audit"]["complete"] is False and "GPL-3.0-only" in d["audit"]["missing_license_text"], "no text is invented"
    assert _req(ui["base"] + "/api/oss/notice", {"job": jid, "format": "pdf"})[0] == 400
    assert _req(ui["base"] + "/api/oss/notice", {"job": "0123456789"})[0] == 404


def test_history_reopen_and_compare(ui, monkeypatch):
    a, _ = _scan(ui)
    _fake_scanners(monkeypatch, {"oss_source": [dict(kind="src", oss_name="libidn", version="1.34", licenses=["GPL-3.0-only"], source_path="src/a.c")],
                                 "oss_dependency": [], "oss_binary": []})
    b, _ = _scan(ui)
    hist = _req(ui["base"] + "/api/oss/history")[1]["history"]
    assert {h["id"] for h in hist} == {a, b}
    cmp = _req(ui["base"] + "/api/oss/compare?a=%s&b=%s" % (a, b))[1]
    assert cmp["summary"]["changed"] == 1 and cmp["summary"]["deleted"] >= 2
    ui["st"].oss_jobs = None                                           # a "restarted server": results come back from disk
    again = _req(ui["base"] + "/api/oss/jobs/" + a)[1]
    assert again["state"] == "done" and again["counts"]["src"] == 3


# ------------------------------------------------------------------------------------------------- safety
def test_cross_origin_post_is_refused_same_origin_and_no_origin_pass(ui):
    host = ui["base"].split("//")[1]
    assert _req(ui["base"] + "/api/oss/scan", {"target": ui["proj"]}, {"Origin": "https://evil.example"})[0] == 403
    assert _req(ui["base"] + "/api/oss/scan", {"target": ui["proj"]}, {"Origin": "http://" + host})[0] == 202
    assert _req(ui["base"] + "/api/oss/scan", {"target": ui["proj"]})[0] == 202


@pytest.mark.parametrize("bad", ["../../etc/passwd", "zzzzzzzzzz", "0123456789ab", "%2e%2e%2f%2e%2e", ""])
def test_job_ids_are_validated(ui, bad):
    for sub in ("jobs", "items", "report", "overview"):
        code = _req(ui["base"] + "/api/oss/%s/%s" % (sub, bad))[0]
        assert code in (404, 400)


def test_input_bounds_excludes_and_target(ui):
    assert _req(ui["base"] + "/api/oss/scan", {"target": ""})[0] == 400
    assert _req(ui["base"] + "/api/oss/scan", {"target": "x" * 5000})[0] == 400
    jid, job = _scan(ui, excludes=["e%d" % i for i in range(500)], branch="--upload-pack=x")
    meta = json.load(open(os.path.join(str(ui["ev"]), "oss", jid, "result.json"), encoding="utf-8"))["meta"]
    assert len(meta["excludes"]) == 50
    assert _req(ui["base"] + "/api/oss/items/%s?kind=bogus" % jid)[0] == 400
    assert _req(ui["base"] + "/api/oss/items/%s?limit=abc" % jid)[0] == 400
    big = _req(ui["base"] + "/api/oss/items/%s?kind=src&limit=100000" % jid)[1]
    assert big["limit"] == oss_api.MAX_ROWS


def test_precheck_rejects_missing_paths(ui):
    assert _req(ui["base"] + "/api/oss/precheck?path=/nope/nope")[0] == 400


# -------------------------------------------------------------------------------------------------- the page
def test_page_has_the_oss_tab_and_the_script_never_writes_data_with_innerhtml(ui):
    code, body, hdr = _req(ui["base"] + "/")
    assert code == 200 and b'data-sv="oss"' in body and b"/static/oss_scanner.js" in body and b'id="paneOss"' in body
    js = _req(ui["base"] + "/static/oss_scanner.js")[1].decode("utf-8")
    assert "innerHTML" not in js and "eval(" not in js and "document.write" not in js
    assert _req(ui["base"] + "/static/oss_scanner.css")[0] == 200
    console_js = open(os.path.join(server.WEB_DIR, "bts_console.js"), encoding="utf-8").read()
    assert "'git': ['git', 'oss', 'lock', 'container']" in console_js   # the OSS Scanner group is a Scan-section member now


# ------------------------------------------------------------------------------- host pin, body size, jobs, cancel
def test_every_oss_request_must_carry_the_services_own_host(ui):
    port = ui["base"].rsplit(":", 1)[1]
    assert _req(ui["base"] + "/api/oss/history", headers={"Host": "evil.example:" + port})[0] == 403    # DNS rebinding: GET too
    assert _req(ui["base"] + "/api/oss/history", headers={"Host": "127.0.0.1:1"})[0] == 403             # not the bound port
    assert _req(ui["base"] + "/api/oss/history", headers={"Host": "localhost:" + port})[0] == 200
    assert _req(ui["base"] + "/api/oss/history", headers={"Host": "[::1]:" + port})[0] == 200
    evil = "evil.example:" + port
    # a rebinding page is "same-origin" with itself: Origin == Host, but the Host is not ours
    assert _req(ui["base"] + "/api/oss/scan", {"target": ui["proj"]}, {"Host": evil, "Origin": "http://" + evil})[0] == 403


def test_allowed_hosts_env_admits_a_reverse_proxy_name(ui, monkeypatch):
    port = ui["base"].rsplit(":", 1)[1]
    host = "oss.internal.example:" + port
    assert _req(ui["base"] + "/api/oss/history", headers={"Host": host})[0] == 403
    monkeypatch.setenv("BTS_OSS_ALLOWED_HOSTS", host)
    assert _req(ui["base"] + "/api/oss/history", headers={"Host": host})[0] == 200


def test_sec_fetch_site_cross_site_post_is_refused(ui):
    assert _req(ui["base"] + "/api/oss/scan", {"target": ui["proj"]}, {"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert _req(ui["base"] + "/api/oss/scan", {"target": ui["proj"]}, {"Sec-Fetch-Site": "same-origin"})[0] == 202


def _raw_post(base, path, content_length, body=b"{}"):
    host, port = base.split("//")[1].split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=10)
    conn.putrequest("POST", path)
    conn.putheader("Content-Type", "application/json")
    if content_length is not None:
        conn.putheader("Content-Length", content_length)
    conn.endheaders(body)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


@pytest.mark.parametrize("cl", ["abc", "-5", "1e3", "1_0", "99999999999"])
def test_bad_content_length_is_rejected_not_hung_or_crashed(ui, cl):
    code, _ = _raw_post(ui["base"], "/api/chat", cl)
    assert code in (400, 413)


def test_missing_content_length_means_no_body(ui):
    code, _ = _raw_post(ui["base"], "/api/oss/jobs/0123456789/cancel", None, b"")
    assert code == 404                                    # routed normally (unknown job), not a 400/hang


def test_finished_error_jobs_are_evicted_from_memory(ui, monkeypatch):
    monkeypatch.setattr(oss_api, "MAX_JOBS", 5)
    j = oss_api._jobs(ui["st"])
    for n in range(30):
        jid = "%010x" % n
        j.jobs[jid] = {"id": jid, "state": "error", "started": "2026-01-01T00:00:%02d" % n,
                       "finished": "2026-01-01T00:01:%02d" % n}
        j.cancel[jid] = threading.Event()
    j.jobs["ffffffffff"] = {"id": "ffffffffff", "state": "running", "started": "2025-01-01T00:00:00"}
    j.cancel["ffffffffff"] = threading.Event()
    oss_api._evict(j)
    assert len([k for k, v in j.jobs.items() if v["state"] == "error"]) == 5
    assert "ffffffffff" in j.jobs and "ffffffffff" in j.cancel, "a running job is never dropped"
    assert set(j.cancel) <= {"ffffffffff"}, "events of finished jobs are released"
    assert "%010x" % 29 in j.jobs, "the newest finished jobs are the ones kept"


def test_cancel_stops_a_scan_in_the_middle_of_a_scanner(ui, monkeypatch):
    from bts_sbom._internal import oss_common

    class Slow:
        def scan(self, root, **kw):
            for _ in range(500):
                oss_common.check_cancel()
                time.sleep(0.02)
            return OssReport(info=ossreport.new_info(root))

    monkeypatch.setattr(ossscan, "_import", lambda name: Slow())
    code, out, _ = _req(ui["base"] + "/api/oss/scan", {"target": ui["proj"], "modes": ["source"]})
    assert code == 202
    jid = out["job"]
    time.sleep(0.2)
    assert _req(ui["base"] + "/api/oss/jobs/%s/cancel" % jid, {})[0] == 200
    deadline = time.time() + 10
    state = ""
    while time.time() < deadline:
        state = _req(ui["base"] + "/api/oss/jobs/" + jid)[1]["state"]
        if state != "running":
            break
        time.sleep(0.1)
    assert state == "cancelled", "the scanner loop must notice the cancel long before its 10 s are up"
    assert _req(ui["base"] + "/api/oss/jobs/%s/cancel" % jid, {})[0] == 200      # cancelling a finished job is harmless


def test_private_and_loopback_urls_are_refused_by_the_web_service(ui):
    code, out, _ = _req(ui["base"] + "/api/oss/scan", {"target": "http://127.0.0.1:9/pkg.zip"})
    assert code == 202
    jid = out["job"]
    deadline = time.time() + 10
    job = {}
    while time.time() < deadline:
        job = _req(ui["base"] + "/api/oss/jobs/" + jid)[1]
        if job["state"] != "running":
            break
        time.sleep(0.1)
    assert job["state"] == "error" and "non-public" in job["error"]
