"""Cloud mode: one fail-closed switch that flips localhost-only defaults (task 12, AC 465-470)."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import cloud, pipeline, server
from bts_sbom_app import evals
from conftest import FakeScanner

ROUTES = ("/api/health", "/api/llm", "/api/engine", "/api/projects", "/api/history", "/api/fleet", "/api/triage")


def _get(base, path):
    try:
        with urllib.request.urlopen(urllib.request.Request(base + path, headers={"X-MS-CLIENT-PRINCIPAL-NAME": "tester"}), timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _post(base, body):
    req = urllib.request.Request(base + "/api/scan" if False else base + "/api/llm", data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "X-MS-CLIENT-PRINCIPAL-NAME": "tester"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture
def cloud_api(tmp_path, make_repo, world, monkeypatch):
    monkeypatch.setenv("BTS_SBOM_CLOUD", "1")
    monkeypatch.setenv("BTS_SBOM_TRUST_IDENTITY_HEADER", "1")   # cloud tests authenticate through the identity header
    monkeypatch.setenv("EXAONE_API_KEY", "FAKE-KEY-cloudmode-1234")
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    ev.mkdir()
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False, scanner=FakeScanner(), run_arch=False,
                               cache_dir=str(tmp_path / "cache"))
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "ev": ev, "st": st, "rec": rec}
    httpd.shutdown()


def test_cloud_mode_refuses_llm_writes_and_writes_zero_files(cloud_api):
    """AC: BSA-AC-465"""
    base, ev = cloud_api["base"], cloud_api["ev"]
    before = set(os.listdir(ev))
    code, body = _post(base, {"api_key": "FAKE-KEY-another-0000", "remember": True})
    assert code == 403 and body["error"] == "disabled_in_cloud_mode"
    assert set(os.listdir(ev)) == before, "a refused llm connect must write 0 files under the evidence folder"
    code2, body2 = _post(base, {})
    assert code2 == 403                                       # /api/llm/clear is refused the same way


def test_chat_actions_stay_off_in_cloud_mode_despite_the_flag(cloud_api):
    """AC: BSA-AC-466"""
    st = server.State(evals.repo_root(), str(cloud_api["ev"]), None, chat_actions=True)
    assert st.chat_actions is False and st.cloud_policy["chat_actions_refused"] is True
    os.environ["BTS_SBOM_CLOUD_ALLOW_ACTIONS"] = "1"
    try:
        st2 = server.State(evals.repo_root(), str(cloud_api["ev"]), None, chat_actions=True)
        assert st2.chat_actions is True and "chat_actions_refused" not in st2.cloud_policy
    finally:
        os.environ.pop("BTS_SBOM_CLOUD_ALLOW_ACTIONS", None)


def test_a_scan_asking_for_use_llm_makes_zero_llm_calls_without_the_opt_in(cloud_api, world, monkeypatch):
    """AC: BSA-AC-467"""
    base = cloud_api["base"]

    def handler(body):
        raise AssertionError("the LLM must not be called")

    world.llm_handler = handler
    monkeypatch.setenv("BTS_SBOM_SOURCE_HOSTS", "scanhost.invalid")   # an allow-listed host whose DNS we fake (no real network)
    real_gai = socket.getaddrinfo

    def fake_gai(host, port, *a, **kw):                   # fake DNS for the scanned host only; loopback stays real
        if host in ("127.0.0.1", "localhost", "::1"):
            return real_gai(host, port, *a, **kw)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    monkeypatch.setattr(pipeline, "run_project", lambda src, **kw: {"error": None, "metrics": {}, "artifacts": {},
                                                                   "patch": {}, "stage_errors": {}, "name": "x"})
    req = urllib.request.Request(base + "/api/scan", data=json.dumps({"source": "https://scanhost.invalid/o/r.git", "use_llm": True}).encode(),
                                 headers={"Content-Type": "application/json", "X-MS-CLIENT-PRINCIPAL-NAME": "tester"})
    with urllib.request.urlopen(req, timeout=10) as r:
        jid = json.loads(r.read())["job"]
    deadline = time.time() + 20
    rec = None
    while time.time() < deadline:
        rec = cloud_api["st"].store.get(jid)
        if rec and rec.get("state") in ("done", "error"):
            break
        time.sleep(0.1)
    assert world.llm_calls == 0
    assert rec and rec.get("state") in ("done", "error")
    assert world.llm_calls == 0
    rec = cloud_api["st"].store.get(jid)
    assert rec and rec.get("use_llm") is False


def test_engine_reports_cloud_state_and_the_four_policy_flags(cloud_api):
    """AC: BSA-AC-468"""
    code, body = _get(cloud_api["base"], "/api/engine")
    assert code == 200
    cl = body["cloud"]
    assert cl["enabled"] is True
    flags = cl["policy"]
    assert flags["local_paths_allowed"] is False and flags["chat_actions_allowed"] is False
    assert flags["llm_write_allowed"] is False and flags["llm_default"] is False
    assert "FAKE-KEY" not in json.dumps(body)                                       # 0 secrets in the response


def test_unrecognised_cloud_values_count_as_on(monkeypatch):
    """AC: BSA-AC-469"""
    for odd in ("maybe", "enabled", "sure"):
        monkeypatch.setenv("BTS_SBOM_CLOUD", odd)
        assert cloud.is_cloud() is True, odd
    monkeypatch.setenv("BTS_SBOM_CLOUD", "")
    assert cloud.is_cloud() is False


def test_with_cloud_mode_off_the_routes_behave_exactly_as_before(tmp_path, monkeypatch):
    """AC: BSA-AC-470"""
    monkeypatch.delenv("BTS_SBOM_CLOUD", raising=False)
    monkeypatch.delenv("EXAONE_API_KEY", raising=False)
    ev = tmp_path / "ev"
    ev.mkdir()
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        assert _get(base, "/api/health")[1]["ok"] is True
        assert "key_configured" in _get(base, "/api/llm")[1]
        eng = _get(base, "/api/engine")[1]
        assert eng["cloud"]["enabled"] is False and eng["cloud"]["policy"]["local_paths_allowed"] is True
        assert _get(base, "/api/projects")[1] == {"projects": []}
        assert _get(base, "/api/history")[1] == {"history": []}
        assert _get(base, "/api/triage")[1] == {"triage": {}}
        assert "projects" in _get(base, "/api/fleet")[1]
        assert _get(base, "/api/jobs/zzzz0000") == (404, {"error": "unknown job"})
        assert _post(base, {"api_key": "FAKE-KEY-ok-in-local-mode-9999"})[0] == 200     # llm connect still allowed
    finally:
        httpd.shutdown()
