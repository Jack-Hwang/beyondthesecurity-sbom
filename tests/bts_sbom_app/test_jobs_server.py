"""Server-side job persistence: restart visibility, idempotency, secrets never stored (task 6, AC 401-412 server side)."""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import pipeline, server


def _post(base, body):
    req = urllib.request.Request(base + "/api/scan", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _get(base, path):
    try:
        with urllib.request.urlopen(base + path, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _fake(ok=True):
    rec = {"error": None if ok else "boom: scan failed", "metrics": {"components": 1}, "artifacts": {},
           "patch": {"status": "not_requested"}, "stage_errors": {}, "name": "x"}

    def run(src, *, work_root, out_dir, progress=None, **kw):
        if progress:
            progress({"type": "step_start", "step": "scan"})
            progress({"type": "step_end", "step": "scan", "ok": ok, "seconds": 0.05})
        if not ok:
            rec["error"] = "boom: scan failed"
        return rec

    return run


@pytest.fixture
def jobs_api(tmp_path, monkeypatch):
    ev = tmp_path / "ev"
    ev.mkdir()
    monkeypatch.setattr(pipeline, "run_project", _fake())
    st = server.State(str(tmp_path), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "ev": ev, "root": str(tmp_path), "st": st,
           "restate": lambda: server.State(str(tmp_path), str(ev), None)}
    httpd.shutdown()


def test_a_finished_job_survives_a_server_restart(jobs_api):
    """AC: BSA-AC-401, BSA-AC-411"""
    base, restate = jobs_api["base"], jobs_api["restate"]
    _code, body = _post(base, {"source": "https://github.com/o/r.git"})
    jid = body["job"]
    for _ in range(50):
        rec = jobs_api["st"].store.get(jid)
        if rec and rec.get("state") in ("done", "error"):
            break
        time.sleep(0.1)
    # a brand-new State over the same evidence folder answers for the same job
    st2 = restate()
    got = st2.store.get(jid)
    assert got["state"] == "done" and got["metrics"] == {"components": 1}
    code2, via_http = _get(base, "/api/jobs/" + jid)
    assert code2 == 200 and via_http["state"] == "done"


def test_a_running_record_becomes_interrupted_after_a_restart(jobs_api):
    """AC: BSA-AC-402"""
    st = server.State(jobs_api["root"], str(jobs_api["ev"]), None)
    rec, _ = st.store.create("https://github.com/o/r.git")
    st2 = server.State(jobs_api["root"], str(jobs_api["ev"]), None)          # the "restart"
    d = st2.store.get(rec["id"])
    assert d["state"] == "interrupted" and d["interrupted_reason"] == "server_restart"


def test_an_approval_token_is_in_zero_job_files(jobs_api):
    """AC: BSA-AC-403"""
    base, ev = jobs_api["base"], jobs_api["ev"]
    token = "0123456789abcdef0123456789abcdef"
    _post(base, {"source": "https://github.com/o/r.git", "patch": True, "approved": True, "approval_token": token})
    deadline = time.time() + 15
    blobs = []
    while time.time() < deadline:
        files = os.listdir(ev / ".jobs") if (ev / ".jobs").exists() else []
        blobs = [open(os.path.join(str(ev / ".jobs"), f), encoding="utf-8").read() for f in files]
        if blobs and all(j.get("state") in ("done", "error") for j in (json.loads(b) for b in blobs)):
            break
        time.sleep(0.1)
    assert blobs, "no job files written"
    assert sum(b.count(token) for b in blobs) == 0


def _find_job_files(ev):
    d = ev / ".jobs"
    return d.exists() and os.listdir(d)


def test_a_credentialed_source_is_stored_without_credentials(jobs_api):
    """AC: BSA-AC-404"""
    base, ev = jobs_api["base"], jobs_api["ev"]
    _code, body = _post(base, {"source": "https://user:tok123@github.com/o/r.git"})
    jid = body["job"]
    rec = server.State(jobs_api["root"], str(ev), None).store.get(jid)
    assert rec and rec["source"] == "https://github.com/o/r.git"
    assert ":" + "tok123" not in rec["source"] and "@" not in rec["source"]


def test_malformed_job_ids_answer_404_and_open_nothing(jobs_api):
    """AC: BSA-AC-405"""
    base = jobs_api["base"]
    for bad in ("..%2Fx", "A1B2C3D4E5", "x"):
        code, body = _get(base, "/api/jobs/" + bad)
        assert code == 404 and body == {"error": "unknown job"}, bad


def test_the_same_idempotency_key_returns_the_first_job_and_starts_no_new_thread(jobs_api, monkeypatch):
    """AC: BSA-AC-406"""
    base = jobs_api["base"]
    gate = threading.Event()
    started = []
    holder = {"n": 0}

    def counting_run(src, *, work_root, out_dir, progress=None, **kw):
        holder["n"] += 1
        started.append(src)
        gate.wait(timeout=15)
        return {"error": None, "metrics": {}, "artifacts": {}, "patch": {}, "stage_errors": {}, "name": "x"}

    monkeypatch.setattr(pipeline, "run_project", counting_run)
    try:
        c1, b1 = _post(base, {"source": "https://github.com/o/r.git", "idempotency_key": "same-key"})
        assert c1 == 202
        c2, b2 = _post(base, {"source": "https://github.com/o/r.git", "idempotency_key": "same-key"})
        assert c2 == 200 and b2["reused"] is True and b2["job"] == b1["job"]
        assert holder["n"] == 1
    finally:
        gate.set()


def test_an_errored_earlier_job_starts_one_new_job_for_the_same_key(jobs_api, monkeypatch):
    """AC: BSA-AC-407"""
    base = jobs_api["base"]
    monkeypatch.setattr(pipeline, "run_project", _fake(ok=False))
    c1, b1 = _post(base, {"source": "https://github.com/o/r.git", "idempotency_key": "err-key"})
    deadline = time.time() + 15
    while time.time() < deadline:
        rec = jobs_api["st"].store.get(b1["job"])
        if rec and rec.get("state") in ("done", "error"):
            break
        time.sleep(0.1)
    monkeypatch.setattr(pipeline, "run_project", _fake(ok=True))
    c2, b2 = _post(base, {"source": "https://github.com/o/r.git", "idempotency_key": "err-key"})
    assert c2 == 202 and b2["job"] != b1["job"]


def test_an_interrupted_job_streams_exactly_one_error_event(jobs_api):
    """AC: BSA-AC-412"""
    st = server.State(jobs_api["root"], str(jobs_api["ev"]), None)
    rec, _ = st.store.create("https://github.com/o/r.git")
    st.store.update(rec["id"], state="interrupted", interrupted_reason="server_restart")
    base = jobs_api["base"]
    with urllib.request.urlopen(base + "/api/jobs/%s/events" % rec["id"], timeout=10) as r:
        raw = r.read()
    frames = [b for b in raw.decode("utf-8", errors="replace").split(chr(10) * 2) if "event: error" in b]
    assert len(frames) == 1, frames
    assert '"interrupted"' in raw.decode("utf-8")
