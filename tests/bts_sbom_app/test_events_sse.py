"""Scan-progress events: the bts-sbom.events.v1 schema/bus (events.py), the pipeline progress hook, and the
GET /api/jobs/<id>/events endpoint (fake pipeline - no network, no real scan). All socket reads carry a timeout so a
bug can never hang the test suite."""
from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional

import pytest

from bts_sbom_app import events, pipeline, server

_READ_TIMEOUT = 5.0


# ---------------------------------------------------------------------------------------------- events.py unit tests


def test_schema_names_six_types_and_assigns_increasing_seq():
    """AC: BSA-AC-336"""
    assert events.EVENT_TYPES == ("job_start", "step_start", "step_end", "patch_gate", "final", "error")
    bus = events.EventBus("job-1")
    e1 = bus.publish("job_start", source="x")
    e2 = bus.publish("step_start", name="a")
    e3 = bus.publish("final", state="done")
    for e in (e1, e2, e3):
        for field in ("schema", "type", "seq", "ts", "job"):
            assert field in e
        assert e["schema"] == events.SCHEMA
    assert (e1["seq"], e2["seq"], e3["seq"]) == (1, 2, 3)


def _good_event(etype: str) -> Dict[str, Any]:
    base = {"schema": events.SCHEMA, "type": etype, "seq": 1, "ts": "2026-01-01T00:00:00+00:00", "job": "j1"}
    extra = {"job_start": {}, "step_start": {"name": "a"}, "step_end": {"name": "a", "ok": True, "seconds": 0.1},
             "patch_gate": {"state": "approved"}, "final": {"state": "done"},
             "error": {"error_type": "RuntimeError", "severity": "high", "retryable": False, "recovery_hint": "retry later"}}[etype]
    base.update(extra)
    return base


@pytest.mark.parametrize("etype", events.EVENT_TYPES)
def test_validate_accepts_a_well_formed_event_of_every_type(etype):
    """AC: BSA-AC-339"""
    assert events.validate(_good_event(etype)) == []


_MALFORMED_CASES = [
    ("job_start", lambda e: e.pop("seq")),                               # missing envelope field
    ("job_start", lambda e: e.update(type="not_a_real_type")),           # unknown type
    ("step_start", lambda e: e.pop("name")),                             # missing required field
    ("step_end", lambda e: e.pop("ok")),                                 # missing required field
    ("patch_gate", lambda e: e.update(state="sideways")),                # state outside the 3 allowed values
    ("error", lambda e: e.pop("error_type")),                            # missing required field
]


@pytest.mark.parametrize("etype,mutate", _MALFORMED_CASES)
def test_validate_rejects_six_malformed_events(etype, mutate):
    """AC: BSA-AC-339"""
    event = _good_event(etype)
    mutate(event)
    problems = events.validate(event)
    assert problems, "expected at least one problem for %r" % (event,)


def test_format_sse_is_newline_safe_and_carries_id_and_event():
    """AC: BSA-AC-336"""
    bus = events.EventBus("j2")
    e = bus.publish("error", error_type="X", severity="low", retryable=True, recovery_hint="line one\nline two")
    text = events.format_sse(e)
    lines = text.split("\n")
    assert lines[0] == "id: 1" and lines[1] == "event: error"
    data_lines = [ln for ln in lines if ln.startswith("data: ")]
    assert len(data_lines) >= 1
    payload = json.loads("\n".join(ln[len("data: "):] for ln in data_lines))
    assert payload["recovery_hint"] == "line one\nline two"
    assert text.endswith("\n\n")


def test_eventbus_publish_is_thread_safe_under_concurrent_load():
    """AC: BSA-AC-357"""
    bus = events.EventBus("concurrent")
    threads_n, per_thread = 8, 50

    def worker():
        for i in range(per_thread):
            bus.publish("step_start", name="s%d" % i)

    threads = [threading.Thread(target=worker) for _ in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    seqs = [e["seq"] for e in bus.all_events()]
    assert len(seqs) == threads_n * per_thread == 400
    assert len(set(seqs)) == 400
    assert sorted(seqs) == list(range(1, 401))


def test_eventbus_closes_after_a_terminal_event_and_refuses_further_publishes():
    bus = events.EventBus("term")
    bus.publish("job_start", source="x")
    bus.publish("final", state="done")
    with pytest.raises(RuntimeError):
        bus.publish("step_start", name="too-late")


def test_eventbus_subscriber_cap_is_four():
    """AC: BSA-AC-347 (bus-level half of the contract; the HTTP half is in test_events_sse_server below)"""
    bus = events.EventBus("cap")
    for _ in range(4):
        bus.subscribe()
    with pytest.raises(events.TooManySubscribers):
        bus.subscribe()
    bus.unsubscribe()
    bus.subscribe()                                                     # a freed slot is usable again


# --------------------------------------------------------------------------------------- pipeline progress hook unit


def test_stages_progress_callback_exception_is_recorded_once_and_never_breaks_a_stage():
    """AC: BSA-AC-344"""
    calls: List[Any] = []

    def boom(*a: Any, **k: Any) -> None:
        calls.append((a, k))
        raise ValueError("callback is broken")

    rec: Dict[str, Any] = {}
    S = pipeline._Stages(rec, progress=boom)
    results = [S.run("stage%d" % i, lambda i=i: i * 10) for i in range(3)]
    assert results == [0, 10, 20]                                       # each stage's own return value is unaffected
    assert rec["stage_errors"] == {"progress_callback": "ValueError: callback is broken"}
    assert set(rec["timings"]) == {"stage0", "stage1", "stage2"}
    assert len(calls) == 6                                              # step_start + step_end for each of the 3 stages, every one raised


def test_stages_progress_none_behaves_exactly_like_no_callback():
    rec: Dict[str, Any] = {}
    S = pipeline._Stages(rec, progress=None)
    assert S.run("a", lambda: 1) == 1
    assert rec["stage_errors"] == {}


def test_run_project_with_progress_none_matches_omitting_the_argument(tmp_path, make_repo, world):
    """AC: BSA-AC-345"""
    from conftest import FakeScanner
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    kw = dict(work_root=str(tmp_path / "w1"), use_llm=False, scanner=FakeScanner(), run_arch=False, run_proposals=False,
             offline=True, cache_dir=str(tmp_path / "cache"))
    rec_explicit = pipeline.run_project(origin, progress=None, **kw)
    kw["work_root"] = str(tmp_path / "w2")
    rec_omitted = pipeline.run_project(origin, **kw)
    # Two independent calls to run_project differ in ways that have nothing to do with `progress`: wall-clock
    # durations (elapsed_s, timings, and metrics.elapsed_s which just copies it), the (deliberately distinct)
    # work_root of each run (path), a fresh "baseline snapshot" commit workspace.prepare makes on every call with
    # the real commit time (lineage.commit, and every place that commit sha is echoed back - e.g. a CycloneDX
    # metadata property) and build timestamps embedded in the generated SBOM/VEX documents and carried into
    # sectors' evidence (CycloneDX metadata.timestamp, SPDX creationInfo.created, VEX timestamp). None of those
    # vary because of the new keyword - they vary on every call to run_project regardless, which is exactly why
    # they are scrubbed out of this equivalence claim instead of being part of it.
    top_level_volatile = {"timings", "path", "lineage", "_docs"}

    def _is_volatile_key(k: str) -> bool:
        lk = k.lower()
        return "timestamp" in lk or "created" in lk or k in ("elapsed_s", "commit")

    def scrub(obj):
        if isinstance(obj, dict):
            return {k: ("<scrubbed>" if _is_volatile_key(k) else scrub(v)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [scrub(x) for x in obj]
        return obj

    a = scrub({k: v for k, v in rec_explicit.items() if k not in top_level_volatile})
    b = scrub({k: v for k, v in rec_omitted.items() if k not in top_level_volatile})
    assert a == b


def test_stages_progress_notified_with_outcome_of_each_stage():
    """AC: BSA-AC-338"""
    events_seen: List[Any] = []
    rec: Dict[str, Any] = {}
    S = pipeline._Stages(rec, progress=lambda *a, **k: events_seen.append((a, k)))

    def boom():
        raise KeyError("missing")

    S.run("ok_stage", lambda: 42)
    S.run("bad_stage", boom, default="fallback")
    assert events_seen[0] == (("step_start", "ok_stage"), {})
    assert events_seen[1][0] == ("step_end", "ok_stage")
    assert events_seen[1][1]["ok"] is True and isinstance(events_seen[1][1]["seconds"], float) and events_seen[1][1]["error"] is None
    assert events_seen[2] == (("step_start", "bad_stage"), {})
    assert events_seen[3][0] == ("step_end", "bad_stage")
    assert events_seen[3][1]["ok"] is False and "KeyError" in events_seen[3][1]["error"]
    assert rec["stage_errors"]["bad_stage"] == events_seen[3][1]["error"]


# ------------------------------------------------------------------------------------------- HTTP SSE endpoint tests


def _make_fake_run_project(stage_names: List[str], *, fail_stage: Optional[str] = None, rec_error: Optional[str] = None,
                           patch_rec: Optional[Dict[str, Any]] = None, hold_event: Optional[threading.Event] = None,
                           step_sleep: float = 0.0) -> Callable[..., Dict[str, Any]]:
    def fake(src: str, *, work_root: str, out_dir: Optional[str] = None, progress: Optional[Callable[..., None]] = None,
             **kw: Any) -> Dict[str, Any]:
        for name in stage_names:
            if progress is not None:
                progress("step_start", name)
            if step_sleep:
                time.sleep(step_sleep)
            if hold_event is not None and name == stage_names[-1]:
                hold_event.wait(10)
            if fail_stage == name:
                raise RuntimeError("boom in stage %s" % name)
            if progress is not None:
                progress("step_end", name, ok=True, seconds=0.001, error=None)
        rec: Dict[str, Any] = {"name": "proj", "error": rec_error, "metrics": {"components": 1}, "artifacts": {}, "stage_errors": {}}
        rec["patch"] = patch_rec if patch_rec is not None else {"status": "not_requested"}
        return rec
    return fake


@pytest.fixture
def sse_server(tmp_path):
    st = server.State(str(tmp_path), str(tmp_path / "ev"), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    yield base, st
    httpd.shutdown()


def _post_scan(base: str, body: Dict[str, Any]) -> str:
    req = urllib.request.Request(base + "/api/scan", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=_READ_TIMEOUT) as r:
        assert r.status == 202
        return json.loads(r.read())["job"]


def _read_sse(url: str, *, headers: Optional[Dict[str, str]] = None, max_events: Optional[int] = None,
             timeout: float = _READ_TIMEOUT) -> List[Dict[str, Any]]:
    """Reads one SSE response until the connection closes, ``max_events`` records/heartbeats were seen, or
    ``timeout`` seconds pass with no data - never blocks longer than that."""
    req = urllib.request.Request(url, headers=headers or {})
    out: List[Dict[str, Any]] = []
    resp = urllib.request.urlopen(req, timeout=timeout)
    try:
        data_lines: List[str] = []
        ev_type, ev_id = None, None
        while True:
            try:
                raw = resp.readline()
            except socket.timeout:
                break
            if not raw:
                break
            line = raw.decode("utf-8").rstrip("\r\n")
            if line == "":
                if data_lines or ev_type:
                    out.append({"id": ev_id, "event": ev_type, "data": "\n".join(data_lines)})
                    data_lines, ev_type, ev_id = [], None, None
                    if max_events and len(out) >= max_events:
                        break
                continue
            if line.startswith(":"):
                out.append({"heartbeat": True})
                if max_events and len(out) >= max_events:
                    break
                continue
            if line.startswith("id: "):
                ev_id = line[len("id: "):]
            elif line.startswith("event: "):
                ev_type = line[len("event: "):]
            elif line.startswith("data: "):
                data_lines.append(line[len("data: "):])
        return out
    finally:
        resp.close()


def test_sse_delivers_job_start_steps_then_final_in_order(sse_server, monkeypatch):
    """AC: BSA-AC-337"""
    base, _ = sse_server
    fake = _make_fake_run_project(["prepare", "analyze", "sbom"])
    monkeypatch.setattr(pipeline, "run_project", fake)
    jid = _post_scan(base, {"source": "./x"})
    recs = _read_sse(base + "/api/jobs/%s/events" % jid, max_events=8)
    types = [r["event"] for r in recs if "event" in r]
    assert types == ["job_start", "step_start", "step_end", "step_start", "step_end", "step_start", "step_end", "final"]
    seqs = [int(r["id"]) for r in recs if "id" in r]
    assert seqs == sorted(seqs) and len(seqs) == len(set(seqs))
    assert types.count("final") == 1


def test_sse_step_end_carries_ok_seconds_and_error(sse_server, monkeypatch):
    """AC: BSA-AC-338"""
    base, _ = sse_server
    fake = _make_fake_run_project(["only"])
    monkeypatch.setattr(pipeline, "run_project", fake)
    jid = _post_scan(base, {"source": "./x"})
    recs = _read_sse(base + "/api/jobs/%s/events" % jid, max_events=4)
    step_end = json.loads(next(r["data"] for r in recs if r.get("event") == "step_end"))
    assert step_end["ok"] is True and isinstance(step_end["seconds"], float) and "error" not in step_end


def test_sse_resume_with_last_event_id_and_after_query(sse_server, monkeypatch):
    """AC: BSA-AC-340"""
    base, _ = sse_server
    fake = _make_fake_run_project(["a"], patch_rec={"status": "applied"})
    monkeypatch.setattr(pipeline, "run_project", fake)
    jid = _post_scan(base, {"source": "./x", "patch": True, "approved": True, "approval_token": "deadbeef"})
    url = base + "/api/jobs/%s/events" % jid
    full = _read_sse(url, max_events=5)
    assert [r["event"] for r in full] == ["job_start", "step_start", "step_end", "patch_gate", "final"]
    second_seq = full[1]["id"]
    resumed = _read_sse(url, headers={"Last-Event-ID": second_seq}, max_events=3)
    assert [r["event"] for r in resumed] == ["step_end", "patch_gate", "final"]
    resumed_q = _read_sse(url + "?after=%s" % second_seq, max_events=3)
    assert [r["event"] for r in resumed_q] == ["step_end", "patch_gate", "final"]


def test_sse_unknown_job_is_plain_404_json_not_a_stream(sse_server):
    """AC: BSA-AC-341"""
    base, _ = sse_server
    req = urllib.request.Request(base + "/api/jobs/does-not-exist/events")
    try:
        urllib.request.urlopen(req, timeout=_READ_TIMEOUT)
        raise AssertionError("expected 404")
    except urllib.error.HTTPError as exc:
        assert exc.code == 404
        assert exc.headers.get("Content-Type", "").startswith("application/json")
        assert json.loads(exc.read())["error"]


@pytest.mark.parametrize("patch_rec,expected_state,expect_digest", [
    ({"status": "not_approved", "digest": "abc123"}, "awaiting_approval", True),
    ({"status": "applied"}, "approved", False),
])
def test_sse_patch_gate_state_matches_the_request(sse_server, monkeypatch, patch_rec, expected_state, expect_digest):
    """AC: BSA-AC-343"""
    base, _ = sse_server
    fake = _make_fake_run_project(["a"], patch_rec=patch_rec)
    monkeypatch.setattr(pipeline, "run_project", fake)
    body = {"source": "./x", "patch": True}
    if expected_state == "approved":
        body.update(approved=True, approval_token="deadbeef")
    jid = _post_scan(base, body)
    recs = _read_sse(base + "/api/jobs/%s/events" % jid, max_events=5)
    gate = json.loads(next(r["data"] for r in recs if r.get("event") == "patch_gate"))
    assert gate["state"] == expected_state
    assert ("digest" in gate) == expect_digest


def test_sse_no_patch_gate_event_when_no_patch_requested(sse_server, monkeypatch):
    """AC: BSA-AC-343"""
    base, _ = sse_server
    fake = _make_fake_run_project(["a"])
    monkeypatch.setattr(pipeline, "run_project", fake)
    jid = _post_scan(base, {"source": "./x"})
    recs = _read_sse(base + "/api/jobs/%s/events" % jid, max_events=3)
    assert "patch_gate" not in [r.get("event") for r in recs]


def test_sse_error_event_on_unhandled_exception(sse_server, monkeypatch):
    """AC: BSA-AC-346"""
    base, _ = sse_server
    fake = _make_fake_run_project(["a", "b"], fail_stage="b")
    monkeypatch.setattr(pipeline, "run_project", fake)
    jid = _post_scan(base, {"source": "./x"})
    # job_start, step_start(a), step_end(a), step_start(b) [raises before step_end(b)], error: 5 events.
    recs = _read_sse(base + "/api/jobs/%s/events" % jid, max_events=5)
    types = [r.get("event") for r in recs]
    assert "final" not in types and types[-1] == "error"
    err = json.loads(recs[-1]["data"])
    assert err["error_type"] == "RuntimeError" and err["severity"] == "high" and err["retryable"] is False


def test_sse_error_event_when_record_carries_an_error(sse_server, monkeypatch):
    """AC: BSA-AC-346"""
    base, _ = sse_server
    fake = _make_fake_run_project(["a"], rec_error="workspace preparation failed: boom")
    monkeypatch.setattr(pipeline, "run_project", fake)
    jid = _post_scan(base, {"source": "./x"})
    # job_start, step_start, step_end, error: 4 events.
    recs = _read_sse(base + "/api/jobs/%s/events" % jid, max_events=4)
    types = [r.get("event") for r in recs]
    assert "final" not in types and types[-1] == "error"
    err = json.loads(recs[-1]["data"])
    assert "workspace preparation failed" in err["recovery_hint"]


def test_sse_heartbeat_then_real_event_on_same_connection(sse_server, monkeypatch):
    """AC: BSA-AC-351"""
    base, _ = sse_server
    monkeypatch.setattr(server, "EVENTS_HEARTBEAT_SECONDS", 0.05)
    fake = _make_fake_run_project(["slow"], step_sleep=0.3)
    monkeypatch.setattr(pipeline, "run_project", fake)
    jid = _post_scan(base, {"source": "./x"})
    # job_start, step_start, several heartbeats (0.3s sleep / 0.05s interval), step_end, final: plenty of room at 12.
    recs = _read_sse(base + "/api/jobs/%s/events" % jid, max_events=12, timeout=10)
    kinds = ["heartbeat" if r.get("heartbeat") else r.get("event") for r in recs]
    assert "heartbeat" in kinds
    first_heartbeat = kinds.index("heartbeat")
    assert "step_end" in kinds[first_heartbeat + 1:]                    # a real event still arrives on the same connection afterward
    assert kinds[-1] == "final"


def test_sse_subscriber_cap_of_four_is_enforced_and_frees_up(sse_server, monkeypatch):
    """AC: BSA-AC-347"""
    base, _ = sse_server
    monkeypatch.setattr(server, "EVENTS_HEARTBEAT_SECONDS", 0.05)
    hold = threading.Event()
    fake = _make_fake_run_project(["wait"], hold_event=hold)
    monkeypatch.setattr(pipeline, "run_project", fake)
    jid = _post_scan(base, {"source": "./x"})
    url = base + "/api/jobs/%s/events" % jid
    conns = [urllib.request.urlopen(urllib.request.Request(url), timeout=_READ_TIMEOUT) for _ in range(4)]
    try:
        for c in conns:
            assert c.status == 200
        try:
            urllib.request.urlopen(urllib.request.Request(url), timeout=_READ_TIMEOUT)
            raise AssertionError("expected the 5th connection to be refused")
        except urllib.error.HTTPError as exc:
            assert exc.code == 503
        conns[0].close()
        time.sleep(0.5)                                                # give the server thread time to notice the closed socket and unsubscribe
        fifth = urllib.request.urlopen(urllib.request.Request(url), timeout=_READ_TIMEOUT)
        assert fifth.status == 200
        fifth.close()
    finally:
        hold.set()
        for c in conns[1:]:
            try:
                c.close()
            except Exception:
                pass
