"""The Arch Intel API (arch_api.py) over a real stdlib server: scan -> poll -> result, the SSE event stream,
the Host guard, the report download, cancellation and history. The fixture tree is tiny and built in tmp_path;
no network is touched (no LLM key is configured, so the AI lane runs its deterministic fallback)."""
from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from typing import Any, Dict, List, Optional

import pytest

from bts_sbom_app import arch_api, evals, events, server

from test_arch_intel import make_arch_repo

_READ_TIMEOUT = 5.0


@pytest.fixture
def arch_repo(tmp_path):
    return make_arch_repo(str(tmp_path / "archrepo"))


@pytest.fixture
def svc(tmp_path, arch_repo):
    st = server.State(evals.repo_root(), str(tmp_path / "ev"), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "st": st, "repo": arch_repo, "bind": httpd.server_address}
    httpd.shutdown()


def _get(url, headers: Optional[Dict[str, str]] = None):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _wait_done(base, jid, timeout=90.0):
    deadline = time.time() + timeout
    job: Dict[str, Any] = {}
    while time.time() < deadline:
        code, _, body = _get(base + "/api/arch/jobs/" + jid)
        job = json.loads(body)
        if job.get("state") != "running":
            return job
        time.sleep(0.3)
    return job


# ------------------------------------------------------------------- AC: BSA-AC-454
def test_scan_job_runs_to_done_and_reports_the_overview(svc):
    """AC: BSA-AC-454"""
    base = svc["base"]
    code, out = _post(base + "/api/arch/scan", {"source": svc["repo"], "use_llm": False})
    assert code == 202 and len(out["job"]) == 10
    jid = out["job"]
    code, _, body = _get(base + "/api/arch/jobs/" + jid)
    assert code == 200 and json.loads(body)["state"] in ("running", "done")
    job = _wait_done(base, jid)
    assert job["state"] == "done", job.get("error")
    ov = job["overview"]
    assert ov["project_license"] == "GPL-3.0-only"
    assert ov["category"] == "strong-copyleft"
    assert ov["ai_source"] == "deterministic"
    # the full result document carries the diagrams, snippets and the notice checklist
    code, _, body = _get(base + "/api/arch/result/" + jid)
    doc = json.loads(body)
    assert code == 200
    assert doc["schema"] == "bts-sbom.arch-intel.v1"
    assert doc["diagrams"]["components"]["mermaid"].startswith("flowchart TD")
    assert doc["license"]["notice"]["checklist"]
    assert doc["honesty"]["executed"] is False
    code, _, body = _get(base + "/api/arch/jobs/nope0aaaaa")
    assert code == 404


# ------------------------------------------------------------------- AC: BSA-AC-455
def test_sse_stream_validates_and_ends_after_exactly_one_terminal_event(svc):
    """AC: BSA-AC-455"""
    base = svc["base"]
    _code, out = _post(base + "/api/arch/scan", {"source": svc["repo"], "use_llm": False})
    jid = out["job"]
    _wait_done(base, jid)
    out_events: List[Dict[str, Any]] = []
    req = urllib.request.Request(base + "/api/arch/jobs/%s/events" % jid)
    resp = urllib.request.urlopen(req, timeout=_READ_TIMEOUT)
    try:
        data_lines: List[str] = []
        while True:
            try:
                raw = resp.readline()
            except socket.timeout:
                break
            if not raw:
                break
            line = raw.decode("utf-8").rstrip("\r\n")
            if line == "":
                if data_lines:
                    out_events.append(json.loads("\n".join(data_lines)))
                    data_lines = []
                continue
            if line.startswith("data: "):
                data_lines.append(line[len("data: "):])
    finally:
        resp.close()
    assert out_events, "the stream replayed no events"
    assert [events.validate(e) for e in out_events] == [[] for _ in out_events]
    terminal = [e for e in out_events if e["type"] in ("final", "error")]
    assert len(terminal) == 1 and terminal[0]["type"] == "final"
    code, _, body = _get(base + "/api/arch/jobs/0000000000/events")
    assert code == 404                                                   # unknown job -> plain JSON, never a stream


# ------------------------------------------------------------------- AC: BSA-AC-456
def test_a_foreign_host_header_is_refused(svc):
    """AC: BSA-AC-456"""
    st, bind = svc["st"], svc["bind"]
    hit = arch_api.route("GET", "/api/arch/history", {}, {}, {"Host": "evil.example"}, st, bind=bind)
    assert hit is not None and hit[0] == 403
    hit2 = arch_api.route("GET", "/api/arch/history", {}, {}, {"Host": "127.0.0.1:%d" % bind[1]}, st, bind=bind)
    assert hit2 is not None and hit2[0] == 200


# ------------------------------------------------------------------- AC: BSA-AC-457
def test_report_download_holds_the_verdict_and_a_mermaid_fence(svc):
    """AC: BSA-AC-457"""
    base = svc["base"]
    _code, out = _post(base + "/api/arch/scan", {"source": svc["repo"], "use_llm": False})
    jid = out["job"]
    _wait_done(base, jid)
    code, hdr, body = _get(base + "/api/arch/report/%s?format=md" % jid)
    text = body.decode("utf-8")
    assert code == 200 and "GPL-3.0-only" in text and "```mermaid" in text
    assert "attachment" in hdr["Content-Disposition"]
    assert _get(base + "/api/arch/report/%s?format=xz" % jid)[0] == 400


# ------------------------------------------------------------------- AC: BSA-AC-458
def test_cancelled_job_reports_cancelled_and_finished_jobs_land_in_history(svc):
    """AC: BSA-AC-458"""
    st, repo = svc["st"], svc["repo"]
    j = arch_api._jobs(st)
    jid = "c0ffee0000"
    j.jobs[jid] = {"id": jid, "state": "running", "stage": "queued", "source": repo, "started": "t"}
    j.cancel[jid] = threading.Event()
    j.cancel[jid].set()
    j.buses[jid] = events.EventBus(jid)
    arch_api._run_job(st, jid, repo, "", False, "ko", "binary")
    assert j.jobs[jid]["state"] == "cancelled"
    assert j.buses[jid].closed is True
    # and a finished run lands in the history
    base = svc["base"]
    _code, out = _post(base + "/api/arch/scan", {"source": repo, "use_llm": False})
    _wait_done(base, out["job"])
    code, _, body = _get(base + "/api/arch/history")
    rows = json.loads(body)["history"]
    assert code == 200 and any(r["id"] == out["job"] for r in rows)
