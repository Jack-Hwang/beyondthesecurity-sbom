"""Azure architecture-center applications (AC-617/618): the bulkhead cap on background jobs, the top-level
exception guard (no traceback in any response, a correlation id on every exchange), the SIGTERM drain, and the
cache-control headers - each maps to a specific architecture-center best-practice article (see
docs/AZURE_ARCHITECTURE_CENTER_APPLIED.md for the full catalog mapping)."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from bts_sbom_app import evals, server


def _serve(tmp_path):
    st = server.State(evals.repo_root(), str(tmp_path / "ev"), None, False)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return st, httpd, "http://127.0.0.1:%d" % httpd.server_address[1]


def _post(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, dict(r.headers), json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read())


def test_bulkhead_caps_background_jobs_and_throttles_the_second(tmp_path, monkeypatch):
    """AC: BSA-AC-617. One background job at a time on the single replica: a second POST while one runs is
    refused 429 with Retry-After (Bulkhead/Throttling patterns) instead of fanning out job threads."""
    st, httpd, base = _serve(tmp_path)
    src = tmp_path / "proj"
    src.mkdir()
    release = threading.Event()

    def slow(*a, **kw):
        release.wait(30)
        return {"error": None, "metrics": {}, "artifacts": {}, "stage_errors": {}, "name": "proj", "patch": {}}

    monkeypatch.setattr(server.pipeline, "run_project", slow)
    try:
        code, _, body = _post(base, "/api/scan", {"source": str(src)})
        assert code == 202, body
        code2, hdrs2, _ = _post(base, "/api/scan", {"source": str(src)})
        assert code2 == 429, code2
        assert "Retry-After" in hdrs2
        release.set()
        state = "running"
        for _ in range(100):
            j = json.loads(urllib.request.urlopen(base + "/api/jobs/" + body["job"], timeout=10).read())
            if j.get("state") != "running":
                break
            time.sleep(0.1)
        assert j["state"] == "done"
    finally:
        release.set()
        httpd.shutdown()


def test_internal_errors_answer_clean_500_with_a_correlation_id(tmp_path, monkeypatch):
    """AC: BSA-AC-617. api-implementation best practice: an unexpected exception must answer a meaningful response
    (no exception object, no stack trace in the body) - before this guard the same failure killed the connection
    (RemoteDisconnected), measured live on the KeyError round."""
    st, httpd, base = _serve(tmp_path)

    def boom():
        raise RuntimeError("boom-test-marker")

    monkeypatch.setattr(st, "bot", boom)
    try:
        code, hdrs, body = _post(base, "/api/chat", {"question": "요약해줘"})
        assert code == 500
        assert body["error"] == "internal error"
        assert body.get("correlation_id")
        assert "boom-test-marker" not in json.dumps(body)
        assert hdrs.get("X-Correlation-ID") == body["correlation_id"]
    finally:
        httpd.shutdown()


def test_every_response_carries_a_correlation_id_and_cache_headers(tmp_path):
    """AC: BSA-AC-617. Monitoring/api-implementation best practices: every response carries X-Correlation-ID;
    mutable API responses are Cache-Control no-store, served files get a short max-age."""
    _, httpd, base = _serve(tmp_path)
    try:
        with urllib.request.urlopen(base + "/healthz", timeout=20) as r:
            assert r.headers.get("Cache-Control") == "no-store"
            assert (r.headers.get("X-Correlation-ID") or "-") != "-"
        with urllib.request.urlopen(base + "/", timeout=20) as r:
            assert r.headers.get("Cache-Control") == "public, max-age=60"
    finally:
        httpd.shutdown()


def test_drain_rejects_new_jobs_with_503_and_retry_after(tmp_path):
    """AC: BSA-AC-618. background-jobs best practice: on SIGTERM the service stops accepting new jobs (503 +
    Retry-After) and lets the running one finish inside the platform grace period. The test drives the same
    entry point (State.begin_drain) that serve()'s SIGTERM handler uses."""
    st, httpd, base = _serve(tmp_path)
    try:
        src = tmp_path / "proj"
        src.mkdir()
        st.begin_drain(timeout=0.5)
        assert st.draining is True
        code, hdrs, body = _post(base, "/api/scan", {"source": str(src)})
        assert code == 503 and "Retry-After" in hdrs
        assert "draining" in body["error"]
    finally:
        httpd.shutdown()

def test_licence_risks_names_the_clean_room_path_for_strong_copyleft(tmp_path):
    """AC: BSA-AC-620. A patch cannot fix a license: the strong-copyleft screening names the clean-room
    reimplementation path with the component names (the compliance trigger surface)."""
    from bts_sbom_app.chat import _license_risks
    rec = {"name": "proj", "components": [
        {"name": "concurrencytest", "version": "0.1.2", "license": "GPL-3.0-only", "license_category": "strong-copyleft"},
        {"name": "requests", "version": "2.31.0", "license": "Apache-2.0", "license_category": "permissive"}],
        "license": {"project_license": "Apache-2.0"}}
    body = chr(10).join(_license_risks(rec, None))
    assert "clean-room reimplementation" in body and "concurrencytest@0.1.2" in body
