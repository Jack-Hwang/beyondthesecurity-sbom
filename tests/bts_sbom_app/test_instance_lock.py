"""Single-writer evidence lock + standby mode (task 13, AC 473-480)."""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import instance, pipeline, server
from bts_sbom_app import evals


def _fake_time(start=1_700_000_000.0):
    state = {"t": start}

    def clock():
        return state["t"]

    return clock, state


def test_the_first_instance_creates_the_lock_record(tmp_path):
    """AC: BSA-AC-473"""
    clock, _st = _fake_time()
    lock = instance.acquire(str(tmp_path), clock=clock, host="host-a", pid=111)
    rec = json.loads(open(os.path.join(str(tmp_path), ".instance.lock"), encoding="utf-8").read())
    assert rec["host"] == "host-a" and rec["pid"] == 111 and "heartbeat" in rec and "started" in rec
    lock.release()


def test_a_second_instance_refuses_to_start_while_the_lock_is_fresh(tmp_path):
    """AC: BSA-AC-474"""
    clock, st = _fake_time()
    lock = instance.acquire(str(tmp_path), clock=clock, host="host-a", pid=111, standby_ok=False)
    with pytest.raises(instance.LockHeld):
        instance.acquire(str(tmp_path), clock=clock, host="host-b", pid=222, standby_ok=False)
    lock.release()


def test_standby_mode_answers_503_to_every_write_and_writes_nothing(tmp_path):
    """AC: BSA-AC-475"""
    clock, st = _fake_time()
    holder = instance.acquire(str(tmp_path), clock=clock, host="host-a", pid=111, standby_ok=False)
    waiter = instance.acquire(str(tmp_path), clock=clock, host="host-b", pid=222, standby_ok=True)
    assert waiter.standby is True and waiter.active is False
    ev_api = server.State(evals.repo_root(), str(tmp_path), None)
    ev_api.instance_lock = waiter
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(ev_api))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        before = sorted(os.listdir(str(tmp_path)))
        refused = 0
        for path, body in (("/api/scan", {"source": "https://github.com/o/r.git"}),
                           ("/api/triage", {"check_id": "CVE-1", "status": "fixed", "note": "n"}),
                           ("/api/llm", {"api_key": "FAKE-KEY-x"})):
            req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
            try:
                urllib.request.urlopen(req, timeout=10)
                raise AssertionError("expected 503 for %s" % path)
            except urllib.error.HTTPError as e:
                assert e.code == 503 and json.loads(e.read())["error"] == "standby", path
                refused += 1
        assert refused == 3
        after = sorted(os.listdir(str(tmp_path)))
        assert [f for f in after if f not in (".instance.lock",)] == [f for f in before if f not in (".instance.lock",)]
        with urllib.request.urlopen(base + "/readyz", timeout=10) as r:
            assert r.status == 200 and json.loads(r.read())["mode"] == "standby"
    finally:
        httpd.shutdown()
        holder.release()


def test_a_stale_heartbeat_is_taken_over_and_standby_switches_to_active(tmp_path):
    """AC: BSA-AC-476"""
    clock, st = _fake_time()
    instance.acquire(str(tmp_path), clock=clock, host="host-a", pid=111, standby_ok=False)
    waiter = instance.acquire(str(tmp_path), clock=clock, host="host-b", pid=222, standby_ok=True)
    assert waiter.standby and not waiter.active
    st["t"] += 61.0                                                  # the holder's heartbeat is now older than 60 s
    assert waiter.promote() is True
    assert waiter.active is True and waiter.standby is True
    rec = json.loads(open(os.path.join(str(tmp_path), ".instance.lock"), encoding="utf-8").read())
    assert rec["pid"] == 222
    waiter.release()


def test_a_clean_shutdown_removes_the_lock(tmp_path):
    """AC: BSA-AC-477"""
    clock, _st = _fake_time()
    lock = instance.acquire(str(tmp_path), clock=clock, host="host-a", pid=111)
    assert os.path.exists(os.path.join(str(tmp_path), ".instance.lock"))
    lock.release()
    assert not os.path.exists(os.path.join(str(tmp_path), ".instance.lock"))


def test_a_lost_lock_fails_readiness(tmp_path):
    """AC: BSA-AC-478"""
    clock, st = _fake_time()
    lock = instance.acquire(str(tmp_path), clock=clock, host="host-a", pid=111)
    stt = server.State(evals.repo_root(), str(tmp_path), None)
    stt.instance_lock = lock
    checks = server._readiness_checks(stt)
    assert checks["evidence_lock"] is None
    lock.lost.set()
    checks2 = server._readiness_checks(stt)
    assert checks2["evidence_lock"] == "evidence_lock"


def test_work_copies_live_outside_the_evidence_folder(tmp_path, monkeypatch):
    """AC: BSA-AC-479"""
    ev = tmp_path / "ev"
    ev.mkdir()
    monkeypatch.setattr(pipeline, "run_project", lambda src, **kw: {"error": None, "metrics": {}, "artifacts": {},
                                                                   "patch": {"status": "applied"}, "stage_errors": {}, "name": "x"})
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        req = urllib.request.Request(base + "/api/scan", data=json.dumps({"source": "https://github.com/o/r.git", "patch": True,
                                                                         "approved": True, "approval_token": "0123456789abcdef0123456789abcdef"}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            jid = json.loads(r.read())["job"]
        deadline = time.time() + 15
        rec = None
        while time.time() < deadline:
            rec = st.store.get(jid)
            if rec and rec.get("state") in ("done", "error"):
                break
            time.sleep(0.1)
        assert rec and rec.get("state") == "done"
        wc = rec.get("work_copy")
        assert wc and not os.path.abspath(wc).startswith(os.path.abspath(str(ev)))
    finally:
        httpd.shutdown()


def test_single_instance_no_lock_file_behaves_as_before(tmp_path):
    """AC: BSA-AC-480"""
    ev = tmp_path / "ev"
    ev.mkdir()
    st = server.State(str(tmp_path), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        for path in ("/api/health", "/api/llm", "/api/engine", "/api/projects", "/api/history", "/api/fleet", "/api/triage", "/api/jobs/zzzz0000"):
            try:
                with urllib.request.urlopen(base + path, timeout=10) as r:
                    assert r.status == 200, path
            except urllib.error.HTTPError as e:
                assert e.code == 404, path                                   # only the unknown job is 404
    finally:
        httpd.shutdown()
