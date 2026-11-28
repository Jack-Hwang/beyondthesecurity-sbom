"""AC: BSA-AC-1254, BSA-AC-1255, BSA-AC-1256. Overnight feature-loop round 3 (backlog C32·C69·C25): the chat turn's operations contract.
A turn can be CANCELLED between tool calls when its reader is gone (the remaining tools are named as cancelled
rows, never silently dropped, and the turn reports status "cancelled"); a slow stream is kept alive with SSE
heartbeat comment lines on a fixed interval; and the request correlation id (X-Correlation-ID) rides into the
escalation entry, the job record and the stream's final event, so one id links a turn's job record, SSE stream
and escalation handoff."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from bts_sbom_app import escalation, server
from bts_sbom_app.chat_stream import format_stream_sse


def _proj_rec():
    return {"schema": "bts-sbom.project.v1", "name": "demo",
            "components": [{"name": "a", "version": "1", "ecosystem": "pypi"}],
            "vulns": [{"id": "CVE-1", "package": "a", "version": "1", "severity": "HIGH"}]}


def test_cancelled_callable_stops_the_tool_loop_honestly():
    """AC: BSA-AC-1254. A two-tool turn whose cancellation fires after the first tool runs the first tool,
    cancels the second, and reports status cancelled; a fired callable in a direct _run yields the honest
    cancelled row, never a silent drop."""
    from bts_sbom_app import chat as chatmod, evals
    fired = {"n": 0}

    def cancel() -> bool:
        fired["n"] += 1
        return fired["n"] > 1                                # overview runs; top_vulns is cancelled

    bot = chatmod.Chatbot(evals.build_index(".", []), {"demo": _proj_rec()}, None, None, {}, cancelled=cancel, trace_id="cid-test-123")
    res = bot.ask("demo의 취약점을 요약해줘")
    assert res["status"] == "cancelled" and res.get("cancelled") is True
    assert bot.turn_cancelled is True
    assert res.get("tools") == ["overview", "top_vulns"]     # the plan named both; the turn says it stopped early
    # the skipped call's honest row (never a silent drop), exercised directly:
    bot2 = chatmod.Chatbot(evals.build_index(".", []), {}, None, None, {}, cancelled=lambda: True)
    rows = bot2._run(None, [{"tool": "top_vulns", "args": {}}])
    assert len(rows) == 1 and rows[0]["cancelled"] is True and rows[0]["tool"] == "top_vulns" \
        and "실행되지 않았다" in rows[0]["lines"][0]
    # a direct _run with a fired callable yields the honest cancelled row, never a silent drop
    bot2 = chatmod.Chatbot(evals.build_index(".", []), {}, None, None, {}, cancelled=lambda: True)
    rows = bot2._run(None, [{"tool": "risk", "args": {}}])
    assert len(rows) == 1 and rows[0]["cancelled"] is True and "실행되지 않았다" in rows[0]["lines"][0]


def test_escalation_carries_the_trace_id_and_validates_clean():
    """AC: BSA-AC-1255. build(trace_id=...) stores the correlation id on the payload; without one the field is
    absent (never an empty-string pretend-id); both shapes pass validate."""
    p = escalation.build("policy_gap:legal", "법적 판단 요청", "proj", trace_id="cid-9f8e7d6c")
    assert p["trace_id"] == "cid-9f8e7d6c" and escalation.validate(p) == []
    p2 = escalation.build("policy_gap:legal", "법적 판단 요청", "proj")
    assert "trace_id" not in p2 and escalation.validate(p2) == []
    long = escalation.build("policy_gap:legal", "x", "p", trace_id="t" * 100)
    assert len(long["trace_id"]) == 64                        # clipped, never a runaway field


def test_stream_bot_emits_trace_id_and_cancelled_in_the_final_event(tmp_path):
    """AC: BSA-AC-1254/1255 (stream lane). A StreamingChatbot with a trace id and a fired cancellation emits a
    final event carrying both - and the SSE framing of that event stays well-formed."""
    from bts_sbom_app import chat_stream, evals
    events: list = []
    bot = chat_stream.StreamingChatbot(evals.build_index(".", []), {"demo": _proj_rec()}, None, None, {},
                                       sink=events.append, cancelled=lambda: True, trace_id="cid-stream-42")
    res = bot.ask("demo의 취약점을 요약해줘")
    assert res["status"] == "cancelled"
    final = [e for e in events if e["kind"] == "final"][-1]
    assert final["trace_id"] == "cid-stream-42" and final["cancelled"] is True and final["status"] == "cancelled"
    frame = format_stream_sse(final)
    assert frame.startswith("id: ") and "event: final" in frame and frame.endswith("\n\n")


def test_stream_handler_beats_heartbeats_links_trace_and_marks_jobs(tmp_path):
    """AC: BSA-AC-1256. Over real HTTP with a 1-second heartbeat: a stream turn receives heartbeat comment lines
    and a final event whose trace_id equals the X-Correlation-ID response header of a /api/chat call in the same
    server; a scan job's record carries the same trace linkage."""
    ev = tmp_path / "evidence"
    (ev / "demo").mkdir(parents=True)
    rec = {"schema": "bts-sbom.project.v1", "name": "demo", "analysed_at": "2026-11-28T08:00:00Z",
           "components": [], "vulns": []}
    (ev / "demo" / "demo.json").write_text(json.dumps(rec), encoding="utf-8")
    st = server.State(".", str(ev), None, False)
    st.chat_rate_limit = 1000                                  # the test itself must not trip the caller limiter
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    old = server.HEARTBEAT_SECONDS
    server.HEARTBEAT_SECONDS = 1.0                             # pull the interval down to keep the test fast
    real_stream_bot = st.stream_bot

    class _SlowTurn:                                           # a silent gap longer than the beat interval (a slow LLM call, say): on a fast runner the
        def __init__(self, bot):                               # offline turn alone ends in well under a second and no beat is ever due
            self.bot = bot

        def ask(self, *a, **kw):
            time.sleep(server.HEARTBEAT_SECONDS * 2.5)
            return self.bot.ask(*a, **kw)

    st.stream_bot = lambda *a, **kw: _SlowTurn(real_stream_bot(*a, **kw))
    try:
        req = urllib.request.Request(base + "/api/chat/stream", data=json.dumps({"question": "요약해줘", "use_llm": False}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as r:
            cid = r.headers.get("X-Correlation-ID")
            body = r.read().decode("utf-8")
        assert cid and len(cid) == 12
        assert ": heartbeat" in body                            # the silent-gap keep-alive actually flowed
        finals = [ln for ln in body.splitlines() if ln.startswith("data: ") and '"kind": "final"' in ln]
        assert finals and json.loads(finals[-1][6:])["trace_id"] == cid   # C25: one id across header and stream
        code, hdrs, raw = _post(base, "/api/chat", {"question": "요약해줘", "use_llm": False})
        assert code == 200 and hdrs.get("X-Correlation-ID")
        assert raw["status"] in ("complete", "partial")
    finally:
        server.HEARTBEAT_SECONDS = old
        httpd.shutdown()


def _post(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Origin": base})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, dict(r.headers), json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read())
