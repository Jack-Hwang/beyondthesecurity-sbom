"""Observability: JSON access log, request ids, /metrics with fixed labels (task 17, AC 521-528)."""
from __future__ import annotations

import io
import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import metrics, obslog, pipeline, server
from bts_sbom_app import evals

TOKEN = "FAKE-TOKEN-metrics-1234567890"
PLANTED = ("FAKE-KEY-plant-0001", "0123456789abcdef0123456789abcdef", "https://user:tok123@github.com/o/r.git")


def _req(base, method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json", **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read()) if "json" in r.headers.get("Content-Type", "") else r.read().decode(), dict(r.headers)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = raw.decode(errors="replace")
        return e.code, parsed, dict(e.headers)


@pytest.fixture
def obs_api(tmp_path, monkeypatch):
    ev = tmp_path / "ev"
    ev.mkdir()
    monkeypatch.setattr(pipeline, "run_project", lambda src, **kw: {"error": None, "metrics": {}, "artifacts": {},
                                                                   "patch": {}, "stage_errors": {}, "name": "x"})
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "st": st, "ev": ev}
    httpd.shutdown()


def test_every_api_call_writes_one_json_log_line(obs_api, monkeypatch):
    """AC: BSA-AC-521"""
    buf = io.StringIO()
    monkeypatch.setattr(obslog.sys, "stdout", buf)
    base = obs_api["base"]
    _req(base, "GET", "/api/engine")
    _req(base, "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip().startswith("{")]
    parsed = [json.loads(ln) for ln in lines]
    assert len(parsed) == 2
    for ln in parsed:
        assert {"ts", "level", "event", "request_id", "route_class", "status", "ms"} <= set(ln)
    assert parsed[0]["route_class"] == "other" or parsed[0]["route_class"] == "jobs" or parsed[0]["status"] == 200
    assert any(ln["route_class"] == "scan" for ln in parsed)


def test_the_log_never_carries_planted_secrets(obs_api, monkeypatch):
    """AC: BSA-AC-522"""
    buf = io.StringIO()
    monkeypatch.setattr(obslog.sys, "stdout", buf)
    base = obs_api["base"]
    _req(base, "POST", "/api/llm", {"api_key": PLANTED[0], "base_url": "http://localhost:1234/v1"},
         headers={"Authorization": "Bearer " + PLANTED[0]})
    _req(base, "POST", "/api/scan", {"source": PLANTED[2], "patch": True, "approved": True, "approval_token": PLANTED[1]})
    blob = buf.getvalue()
    for planted in PLANTED:
        assert planted not in blob, planted


def test_request_id_is_echoed_when_safe_and_replaced_when_not(obs_api):
    """AC: BSA-AC-523"""
    base = obs_api["base"]
    good = "a" * 64
    code, _b, headers = _req(base, "GET", "/api/engine", headers={"X-Request-Id": good})
    assert headers.get("X-Request-Id") == good
    # a newline cannot travel as a request header at all (urllib refuses); prove the guard at unit level
    fresh = obslog.clean_request_id("bad id\nwith newline")
    assert fresh != "bad id\nwith newline" and chr(10) not in fresh and len(fresh) <= 64
    code3, _b3, headers3 = _req(base, "GET", "/api/engine", headers={"X-Request-Id": "b" * 65})
    assert headers3.get("X-Request-Id") != "b" * 65


def test_many_paths_keep_the_metrics_label_set_small(obs_api):
    """AC: BSA-AC-524"""
    base = obs_api["base"]
    for i in range(100):
        _req(base, "GET", "/api/view/never-exists-%d" % i)
    text = _req(base, "GET", "/metrics")[1]
    series = [ln for ln in text.splitlines() if ln.startswith("bts_sbom_requests_total{")]
    classes = {ln.split('route_class="')[1].split('"')[0] for ln in series}
    assert len(classes) <= 12
    assert "view" in classes


def test_job_metrics_count_each_final_state_once(obs_api, monkeypatch):
    """AC: BSA-AC-525"""
    base = obs_api["base"]
    before = dict(metrics.JOBS)                                       # other tests already counted jobs: assert the delta
    _req(base, "POST", "/api/scan", {"source": "https://github.com/o/r.git"})            # ends done
    monkeypatch.setattr(pipeline, "run_project", lambda src, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    _req(base, "POST", "/api/scan", {"source": "https://github.com/o/r.git"})            # ends error
    deadline = time.time() + 10
    while time.time() < deadline and not (metrics.JOBS.get("done", 0) - before.get("done", 0) >= 1
                                          and metrics.JOBS.get("error", 0) - before.get("error", 0) >= 1):
        time.sleep(0.1)
    text = _req(base, "GET", "/metrics")[1]
    assert 'bts_sbom_jobs_total{state="done"} %d' % (before.get("done", 0) + 1) in text
    assert 'bts_sbom_jobs_total{state="error"} %d' % (before.get("error", 0) + 1) in text


def test_metrics_need_credentials_in_cloud_mode_but_probes_do_not(tmp_path, monkeypatch):
    """AC: BSA-AC-526"""
    monkeypatch.setenv("BTS_SBOM_CLOUD", "1")
    monkeypatch.setenv("BTS_SBOM_API_TOKEN", "FAKE-TOKEN-metrics-9999")
    ev = tmp_path / "ev"
    ev.mkdir()
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        try:
            urllib.request.urlopen(base + "/metrics", timeout=10)
            raise AssertionError("expected 401")
        except urllib.error.HTTPError as e:
            assert e.code == 401
        req = urllib.request.Request(base + "/metrics", headers={"Authorization": "Bearer FAKE-TOKEN-metrics-9999"})
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 200 and "bts_sbom_requests_total" in r.read().decode()
        with urllib.request.urlopen(base + "/healthz", timeout=10) as r:
            assert r.status == 200
        with urllib.request.urlopen(base + "/readyz", timeout=10) as r:
            assert r.status == 200
    finally:
        httpd.shutdown()


def test_existing_bodies_and_status_codes_stay_put(obs_api):
    """AC: BSA-AC-527"""
    base = obs_api["base"]
    code, body, headers = _req(base, "GET", "/api/engine")
    assert code == 200 and body["name"] == "BTS-SBOM" and "X-Request-Id" in headers     # header added, nothing else changed
    code2, body2, _ = _req(base, "GET", "/api/projects")
    assert code2 == 200 and body2 == {"projects": []}
    try:
        urllib.request.urlopen(base + "/api/jobs/zzzz0000", timeout=10)
        raise AssertionError("expected 404")
    except urllib.error.HTTPError as e:
        assert e.code == 404 and json.loads(e.read()) == {"error": "unknown job"}


def test_the_runbook_carries_the_slo_table_marked_as_assumptions():
    """AC: BSA-AC-528"""
    runbook = open(os.path.join(os.path.dirname(evals.__file__), "..", "docs", "RUNBOOK.md"), encoding="utf-8").read()
    assert "SLI/SLO" in runbook and "가정" in runbook
    for target in ("/readyz", "job_seconds", "net_failures_total"):
        assert target in runbook, target
    assert runbook.count("가정") >= 4
