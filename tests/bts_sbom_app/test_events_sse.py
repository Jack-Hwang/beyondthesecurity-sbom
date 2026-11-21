"""SSE progress events for scan jobs (task 3, AC 336-344, 354)."""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import events, pipeline, server
from conftest import FakeScanner


def _frame_lines(raw: bytes) -> list:
    """SSE text -> list of (id, type, data) tuples."""
    out = []
    for block in raw.decode("utf-8", errors="replace").split("\n\n"):
        ev, i, d = None, None, None
        for line in block.splitlines():
            if line.startswith("id: "):
                i = int(line[4:])
            elif line.startswith("event: "):
                ev = line[7:]
            elif line.startswith("data: "):
                d = line[6:]
        if ev:
            out.append((i, ev, d))
    return out


@pytest.fixture
def sse_api(tmp_path, monkeypatch):
    ev = tmp_path / "ev"
    ev.mkdir()
    st = server.State(str(tmp_path), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    monkeypatch.setattr(server, "HEARTBEAT_SECONDS", 0.2)
    yield "http://127.0.0.1:%d" % httpd.server_address[1], st
    httpd.shutdown()


def _post(base, body):
    req = urllib.request.Request(base + "/api/scan", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def _fake_run(progress=None, gate: threading.Event = None, steps=("prepare", "scan")):
    rec = {"error": None, "metrics": {"components": 1}, "artifacts": {}, "patch": {"status": "not_requested"},
           "stage_errors": {}, "name": "x"}

    def run(src, *, work_root, out_dir, progress=progress, **kw):
        for s in steps:
            progress({"type": "step_start", "step": s})
            progress({"type": "step_end", "step": s, "ok": True, "seconds": 0.1})
        if gate is not None:
            gate.wait(timeout=20)
        return rec

    return run


def test_stream_starts_with_job_start_and_ends_with_final(sse_api, monkeypatch):
    """AC: BSA-AC-336"""
    base, st = sse_api
    monkeypatch.setattr(pipeline, "run_project", _fake_run())
    job = _post(base, {"source": "https://github.com/o/r.git"})["job"]
    with urllib.request.urlopen(base + "/api/jobs/%s/events" % job, timeout=10) as r:
        frames = _frame_lines(r.read())
    assert frames[0][1] == "job_start" and frames[-1][1] == "final"
    seqs = [f[0] for f in frames]
    assert len(frames) >= 4 and seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


def test_reconnect_with_last_event_id_2_resends_nothing_earlier(sse_api, monkeypatch):
    """AC: BSA-AC-337"""
    base, st = sse_api
    monkeypatch.setattr(pipeline, "run_project", _fake_run())
    job = _post(base, {"source": "https://github.com/o/r.git"})["job"]
    with urllib.request.urlopen(base + "/api/jobs/%s/events" % job, timeout=10) as r:
        r.read()
    req = urllib.request.Request(base + "/api/jobs/%s/events" % job, headers={"Last-Event-ID": "2"})
    with urllib.request.urlopen(req, timeout=10) as r:
        frames = _frame_lines(r.read())
    assert frames and all(i > 2 for i, _t, _d in frames)


def test_unknown_job_answers_404_and_opens_no_stream(sse_api):
    """AC: BSA-AC-338"""
    base, _st = sse_api
    try:
        urllib.request.urlopen(base + "/api/jobs/deadbeef00/events", timeout=10)
        raise AssertionError("expected 404")
    except urllib.error.HTTPError as e:
        assert e.code == 404 and json.loads(e.read())["error"] == "unknown job"


def test_the_event_bus_refuses_a_malformed_event_and_publishes_nothing():
    """AC: BSA-AC-339"""
    bus = events.EventBus()
    bad = bus.publish("final")                                # missing state
    assert bad is None and list(bus._history) == []          # nothing published, one problem reported in the return contract
    assert events.validate({"schema": events.SCHEMA, "seq": 1, "type": "final"}) != []


def test_a_raising_progress_callback_never_breaks_the_analysis(tmp_path):
    """AC: BSA-AC-340"""
    origin = tmp_path / "proj"
    origin.mkdir()
    (origin / "requirements.txt").write_text("requests==2.19.1\n", encoding="utf-8", newline="\n")

    def boom(ev):
        raise RuntimeError("callback broke")

    rec = pipeline.run_project(str(origin), work_root=str(tmp_path / "w"), out_dir=str(tmp_path / "ev"), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"), progress=boom)
    assert rec["error"] is None and rec["components"]
    assert "progress_callback" in rec["stage_errors"]


def test_the_pipeline_record_is_identical_with_and_without_a_progress_callback(tmp_path):
    """AC: BSA-AC-341"""
    origin = tmp_path / "proj"
    origin.mkdir()
    (origin / "requirements.txt").write_text("requests==2.19.1\n", encoding="utf-8", newline="\n")
    base = dict(work_root=None, use_llm=False, scanner=FakeScanner(), run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    r1 = pipeline.run_project(str(origin), out_dir=str(tmp_path / "ev1"), work_root=str(tmp_path / "w1"), **{k: v for k, v in base.items() if v is not None})
    r2 = pipeline.run_project(str(origin), out_dir=str(tmp_path / "ev2"), work_root=str(tmp_path / "w2"), progress=lambda ev: None,
                              **{k: v for k, v in base.items() if v is not None})
    assert set(r1) == set(r2)
    assert r1["timings"].keys() == r2["timings"].keys()


def test_an_approved_patch_stream_has_one_patch_gate_and_zero_token_characters(sse_api, monkeypatch):
    """AC: BSA-AC-342"""
    base, st = sse_api
    monkeypatch.setattr(pipeline, "run_project", _fake_run())
    token = "0123456789abcdef0123456789abcdef"
    job = _post(base, {"source": "https://github.com/o/r.git", "patch": True, "approved": True, "approval_token": token})["job"]
    with urllib.request.urlopen(base + "/api/jobs/%s/events" % job, timeout=10) as r:
        raw = r.read()
    frames = _frame_lines(raw)
    assert sum(1 for _i, t, _d in frames if t == "patch_gate") == 1
    assert token.encode() not in raw


def test_the_fifth_subscriber_is_refused_with_429(sse_api, monkeypatch):
    """AC: BSA-AC-343"""
    base, st = sse_api
    gate = threading.Event()
    monkeypatch.setattr(pipeline, "run_project", _fake_run(gate=gate))
    job = _post(base, {"source": "https://github.com/o/r.git"})["job"]
    readers = []
    try:
        for _ in range(4):
            readers.append(urllib.request.urlopen(base + "/api/jobs/%s/events" % job, timeout=30))
        time.sleep(0.3)
        try:
            urllib.request.urlopen(base + "/api/jobs/%s/events" % job, timeout=10)
            raise AssertionError("expected 429")
        except urllib.error.HTTPError as e:
            assert e.code == 429
    finally:
        gate.set()
        for r in readers:
            r.close()


def test_an_idle_stream_sends_a_keepalive_comment_within_two_intervals(sse_api, monkeypatch):
    """AC: BSA-AC-344"""
    base, st = sse_api
    gate = threading.Event()
    monkeypatch.setattr(pipeline, "run_project", _fake_run(gate=gate))
    job = _post(base, {"source": "https://github.com/o/r.git"})["job"]
    try:
        with urllib.request.urlopen(base + "/api/jobs/%s/events" % job, timeout=30) as r:
            raw = b""
            deadline = time.time() + 5
            while time.time() < deadline and b": keepalive" not in raw:
                raw += r.read1(4096)
            assert b": keepalive" in raw
    finally:
        gate.set()


def test_existing_job_and_health_routes_keep_their_shapes(sse_api):
    """AC: BSA-AC-354"""
    base, st = sse_api
    with urllib.request.urlopen(base + "/api/health", timeout=10) as r:
        d = json.loads(r.read())
    assert d["ok"] is True and "llm" in d
    try:
        urllib.request.urlopen(base + "/api/jobs/nothere", timeout=10)
        raise AssertionError("expected 404")
    except urllib.error.HTTPError as e:
        assert e.code == 404 and json.loads(e.read()) == {"error": "unknown job"}
