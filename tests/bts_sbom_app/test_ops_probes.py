"""GET /healthz and GET /readyz: liveness vs. readiness (lecture 4-1's "probes 3 kinds" translated to this product's
2 endpoints - liveness is unconditional, readiness is the 3 checks below). No network, no LLM; the only "service"
used here is an in-process ThreadingHTTPServer on an OS-assigned port, same fixture pattern as test_server_cli.py."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from typing import Any, Dict, Tuple

import pytest

from bts_sbom_app import engine, evals, server

_TIMEOUT = 5.0


@pytest.fixture
def probes(tmp_path):
    st = server.State(str(tmp_path), str(tmp_path / "ev"), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    yield base, st
    httpd.shutdown()


def _get(url: str) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return r.status, json.loads(r.read()), dict(r.headers.items())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read()), dict(exc.headers.items())


# --------------------------------------------------------------------------------------------- unit: readyz_checks()


def test_readyz_checks_pass_when_evidence_core_and_knowledge_are_all_fine(tmp_path):
    """AC: BSA-AC-349"""
    st = server.State(str(tmp_path), str(tmp_path / "ev"), None)
    assert server.readyz_checks(st) == []


def test_readyz_checks_report_evidence_writable_alone(tmp_path):
    """AC: BSA-AC-342"""
    blocked = tmp_path / "ev_blocked"
    blocked.write_text("a plain file, not a directory", encoding="utf-8")   # os.makedirs(..., exist_ok=True) still raises on this
    st = server.State(str(tmp_path), str(blocked), None)
    assert server.readyz_checks(st) == ["evidence_writable"]


def test_readyz_checks_report_core_import_alone(tmp_path, monkeypatch):
    """AC: BSA-AC-342"""
    st = server.State(str(tmp_path), str(tmp_path / "ev"), None)

    def boom():
        raise ImportError("bts_sbom is required")

    monkeypatch.setattr(engine, "core_version", boom)
    assert server.readyz_checks(st) == ["core_import"]


def test_readyz_checks_report_knowledge_corpus_alone(tmp_path, monkeypatch):
    """AC: BSA-AC-342"""
    st = server.State(str(tmp_path), str(tmp_path / "ev"), None)
    monkeypatch.setattr(evals, "repo_root", lambda: str(tmp_path / "empty_root"))
    (tmp_path / "empty_root").mkdir()
    assert server.readyz_checks(st) == ["knowledge_corpus"]
    (tmp_path / "empty_root" / "knowledge").mkdir()
    assert server.readyz_checks(st) == ["knowledge_corpus"]             # exists but empty is still not ready
    (tmp_path / "empty_root" / "knowledge" / "a.md").write_text("x", encoding="utf-8")
    assert server.readyz_checks(st) == []                               # and recovers once a file is there (the State half of AC-342)


def test_readyz_checks_never_leak_paths_or_exception_text(tmp_path, monkeypatch):
    """AC: BSA-AC-350"""
    st = server.State(str(tmp_path), str(tmp_path / "ev"), None)

    def boom():
        raise ImportError("secret internal path: " + str(tmp_path) + " Traceback (most recent call last):")

    monkeypatch.setattr(engine, "core_version", boom)
    failed = server.readyz_checks(st)
    assert failed == ["core_import"]
    blob = json.dumps(failed)
    assert str(tmp_path) not in blob and "Traceback" not in blob and st.evidence not in blob


# --------------------------------------------------------------------------------------------------- HTTP endpoints


def test_healthz_is_always_200_even_when_readiness_would_fail(probes, monkeypatch):
    """AC: BSA-AC-348"""
    base, st = probes
    monkeypatch.setattr(engine, "core_version", lambda: (_ for _ in ()).throw(ImportError("down")))
    blocked = st.evidence
    import os
    os.makedirs(os.path.dirname(blocked), exist_ok=True)
    with open(blocked, "w", encoding="utf-8") as fh:                    # turn st.evidence itself into a file: evidence_writable now fails too
        fh.write("x")
    t0 = time.time()
    code, body, _ = _get(base + "/healthz")
    elapsed = time.time() - t0
    assert code == 200 and body == {"ok": True}
    assert elapsed < 1.0


def test_readyz_http_503_while_failing_then_200_once_fixed(probes, monkeypatch):
    """AC: BSA-AC-342 (State: while a probe fails, /readyz stays 503; the HTTP half of the contract)"""
    base, st = probes
    monkeypatch.setattr(engine, "core_version", lambda: (_ for _ in ()).throw(ImportError("down")))
    code, body, _ = _get(base + "/readyz")
    assert code == 503 and body["ready"] is False and body["failed"] == ["core_import"]
    monkeypatch.undo()                                                  # the probe recovers
    code, body, _ = _get(base + "/readyz")
    assert code == 200 and body["ready"] is True and body["failed"] == []


def test_readyz_http_200_with_empty_failed_list_when_all_pass(probes):
    """AC: BSA-AC-349"""
    base, _ = probes
    code, body, headers = _get(base + "/readyz")
    assert code == 200 and body == {"ready": True, "failed": []}
    assert headers.get("Content-Type", "").startswith("application/json")
