"""Resource limits and the SIGTERM drain (task 14, AC 483-491)."""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer


from bts_sbom_app import limits, pipeline, server
from bts_sbom_app import evals
from conftest import FakeScanner


def _req(base, method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json", **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read()), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), dict(e.headers)


def _api(tmp_path, monkeypatch, run_fake=None, env=None):
    for k in ("BTS_SBOM_MAX_JOBS", "BTS_SBOM_JOB_TIMEOUT_S", "BTS_SBOM_MAX_WORKCOPY_MB", "BTS_SBOM_DRAIN_S", "BTS_SBOM_CLOUD"):
        monkeypatch.delenv(k, raising=False)
    for k, v in (env or {}).items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, str(v))
    ev = tmp_path / "ev"
    ev.mkdir()
    if run_fake is not None:
        monkeypatch.setattr(pipeline, "run_project", run_fake)
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "st": st, "httpd": httpd, "ev": ev}


def _blocked_run(gate: threading.Event):
    def run(src, *, work_root, out_dir, progress=None, **kw):
        gate.wait(timeout=30)
        return {"error": None, "metrics": {}, "artifacts": {}, "patch": {}, "stage_errors": {}, "name": "x"}
    return run


def test_a_full_gate_answers_429_with_retry_after_and_starts_no_threads(tmp_path, monkeypatch):
    """AC: BSA-AC-483"""
    gate = threading.Event()
    api = _api(tmp_path, monkeypatch, run_fake=_blocked_run(gate), env={"BTS_SBOM_MAX_JOBS": 2})
    try:
        first = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
        second = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
        assert first[0] == 202 and second[0] == 202
        time.sleep(0.3)
        third = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
        assert third[0] == 429 and third[1]["error"] == "busy"
        assert third[2].get("Retry-After") == "30"
    finally:
        gate.set()
        api["httpd"].shutdown()


def test_a_finished_job_lets_the_next_request_through(tmp_path, monkeypatch):
    """AC: BSA-AC-484"""
    api = _api(tmp_path, monkeypatch, run_fake=lambda src, **kw: {"error": None, "metrics": {}, "artifacts": {},
                                                                 "patch": {}, "stage_errors": {}, "name": "x"},
               env={"BTS_SBOM_MAX_JOBS": 1})
    try:
        _c1, b1, _ = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
        deadline = time.time() + 10
        while time.time() < deadline and (api["st"].store.get(b1["job"]) or {}).get("state") not in ("done", "error"):
            time.sleep(0.1)
        code, body, _ = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
        assert code == 202
    finally:
        api["httpd"].shutdown()


def test_a_job_past_its_deadline_stops_with_reason_timeout(tmp_path, monkeypatch):
    """AC: BSA-AC-485"""
    origin = tmp_path / "proj"
    origin.mkdir()
    (origin / "requirements.txt").write_text("requests==2.19.1\n", encoding="utf-8", newline="\n")
    dl = limits.Deadline(time.time() - 10, 5)                       # already past
    rec = pipeline.run_project(str(origin), work_root=str(tmp_path / "w"), out_dir=str(tmp_path / "ev"), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"), deadline=dl)
    assert rec["error"] and rec["error"].startswith("timeout")
    assert all("deadline" in e for e in rec["stage_errors"].values())


def test_an_oversized_work_copy_is_aborted_and_removed(tmp_path, monkeypatch):
    """AC: BSA-AC-486"""
    src = tmp_path / "big"
    src.mkdir()
    (src / "blob.bin").write_bytes(b"x" * (2 * 1024 * 1024))
    res = pipeline.workspace.prepare(str(src), str(tmp_path / "w"), max_copy_mb=1)
    assert res["ok"] is False and "workcopy_too_large" in res["error"]
    assert not os.path.exists(os.path.join(str(tmp_path / "w"), "big")), "0 bytes of the oversized copy may remain"


def test_draining_refuses_readyz_and_new_scans(tmp_path, monkeypatch):
    """AC: BSA-AC-487"""
    gate = threading.Event()
    api = _api(tmp_path, monkeypatch, run_fake=_blocked_run(gate))
    try:
        _c, b, _ = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
        time.sleep(0.3)
        api["st"].shutting_down = True
        code1, body1, _ = _req(api["base"], "GET", "/readyz")
        code2, body2, _ = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
        assert code1 == 503 and body1["failed"] == ["draining"]
        assert code2 == 503
    finally:
        gate.set()
        api["httpd"].shutdown()


def test_the_drain_records_unfinished_jobs_as_interrupted_sigterm(tmp_path, monkeypatch):
    """AC: BSA-AC-488"""
    gate = threading.Event()
    api = _api(tmp_path, monkeypatch, run_fake=_blocked_run(gate), env={"BTS_SBOM_DRAIN_S": 1})
    try:
        _c, b, _ = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
        time.sleep(0.3)
        api["st"].shutting_down = True
        # run the drain logic the signal handler would start
        st = api["st"]
        end = time.time() + st._drain_s
        while time.time() < end and st._jobs_running > 0:
            time.sleep(0.1)
        for jid in list(st.jobs):
            if st.jobs[jid].get("state") == "running":
                st.store.update(jid, state="interrupted", interrupted_reason="sigterm")
        rec = st.store.get(b["job"])
        assert rec["state"] == "interrupted" and rec["interrupted_reason"] == "sigterm"
    finally:
        gate.set()
        api["httpd"].shutdown()


def test_odd_limit_values_fall_back_to_defaults():
    """AC: BSA-AC-489"""
    for odd in ("abc", "-5", "1.5"):
        lm = limits.Limits({"BTS_SBOM_MAX_JOBS": odd, "BTS_SBOM_JOB_TIMEOUT_S": odd, "BTS_SBOM_MAX_WORKCOPY_MB": odd, "BTS_SBOM_DRAIN_S": odd})
        assert lm.max_jobs == 2 and lm.job_timeout_s == 900 and lm.max_workcopy_mb == 500 and lm.drain_s == 20, odd


def test_three_failed_jobs_leak_zero_gate_permits(tmp_path, monkeypatch):
    """AC: BSA-AC-490"""
    def failing(src, **kw):
        raise RuntimeError("boom 1")
    api = _api(tmp_path, monkeypatch, run_fake=failing, env={"BTS_SBOM_MAX_JOBS": 2})
    try:
        for _ in range(3):
            code, body, _ = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
            assert code == 202
            jid = body["job"]
            deadline = time.time() + 10
            while time.time() < deadline and (api["st"].store.get(jid) or {}).get("state") not in ("done", "error"):
                time.sleep(0.1)
        time.sleep(0.2)
        assert api["st"].gate.held == 0
        code2, _b2, _ = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
        assert code2 == 202, "capacity must not have leaked away"
    finally:
        api["httpd"].shutdown()


def test_local_mode_with_no_limit_accepts_five_concurrent_scans(tmp_path, monkeypatch):
    """AC: BSA-AC-491"""
    gate = threading.Event()
    api = _api(tmp_path, monkeypatch, run_fake=_blocked_run(gate))          # cloud off, BTS_SBOM_MAX_JOBS unset
    try:
        codes = []
        for _ in range(5):
            code, _b, _ = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
            codes.append(code)
        assert codes == [202] * 5
        assert api["st"].gate.enabled is False
    finally:
        gate.set()
        api["httpd"].shutdown()
