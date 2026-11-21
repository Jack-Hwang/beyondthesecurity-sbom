"""Operational probes /healthz and /readyz (task 4, AC 345-347) + container & runbook policy (AC 348-354)."""
from __future__ import annotations

import json
import threading
import os
import re
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import server

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(server.__file__)))


@pytest.fixture
def probe_api(tmp_path):
    ev = tmp_path / "ev"
    ev.mkdir()
    st = server.State(_REPO, str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1], st
    httpd.shutdown()


def _get(base, path):
    try:
        with urllib.request.urlopen(base + path, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_a_failing_readiness_check_answers_503_with_check_names_only(probe_api, monkeypatch):
    """AC: BSA-AC-345"""
    base, _st = probe_api
    monkeypatch.setattr(server, "_check_evidence_writable", lambda ev: "evidence_writable")
    monkeypatch.setattr(server, "_check_knowledge_corpus", lambda root: "knowledge_corpus")
    code, body = _get(base, "/readyz")
    assert code == 503 and body["ok"] is False
    assert body["failed"] == ["evidence_writable", "knowledge_corpus"]
    assert not any(("/" in f or "\\" in f or "Exception" in f) for f in body["failed"])          # names only: no paths, no tracebacks


def test_all_passing_readiness_checks_answer_200(probe_api):
    """AC: BSA-AC-346"""
    base, _st = probe_api
    code, body = _get(base, "/readyz")
    assert code == 200 and body["ok"] is True


def test_healthz_answers_200_fast_even_while_readiness_fails(probe_api, monkeypatch):
    """AC: BSA-AC-347"""
    base, _st = probe_api
    monkeypatch.setattr(server, "_check_core_importable", lambda: "core_importable")
    t0 = time.time()
    code, body = _get(base, "/healthz")
    assert code == 200 and body == {"ok": True}
    assert time.time() - t0 < 1.0


# ------------------------------------------------------------------ static container / runbook policy
_DOCKERFILE = None


_DOCKERFILE = None


def _dockerfile():
    global _DOCKERFILE
    if _DOCKERFILE is None:
        _DOCKERFILE = open(os.path.join(_REPO, "Dockerfile.bts-sbom-app"), encoding="utf-8").read()
    return _DOCKERFILE


def test_dockerfile_runs_as_a_numeric_non_root_user():
    """AC: BSA-AC-348"""
    users = [ln.strip() for ln in _dockerfile().splitlines() if ln.strip().startswith("USER ")]
    assert users, "the image must declare its runtime user"
    assert all(re.fullmatch(r"USER \d+", u) and int(u.split()[1]) != 0 for u in users)


def test_dockerfile_declares_one_healthcheck_calling_readyz():
    """AC: BSA-AC-349"""
    assert _dockerfile().count("HEALTHCHECK") == 1
    hc = [ln for ln in _dockerfile().splitlines() if "readyz" in ln]
    assert hc, "the HEALTHCHECK must call /readyz"


def test_dockerfile_base_image_is_minor_pinned_not_latest():
    """AC: BSA-AC-350"""
    froms = [ln.strip() for ln in _dockerfile().splitlines() if ln.strip().startswith("FROM ")]
    assert len(froms) == 1
    tag = froms[0].split()[1].rsplit(":", 1)[-1] if ":" in froms[0].split()[1] else ""
    assert "latest" not in froms[0] and tag and tag not in ("3", "3.12"), "pin a minor tag (python:3.12-slim)"


def test_dockerfile_sets_no_secret_looking_env_or_arg():
    """AC: BSA-AC-351"""
    bad = [ln for ln in _dockerfile().splitlines()
           if re.match(r"^(ENV|ARG)\s+", ln.strip()) and re.search(r"KEY|TOKEN|SECRET|PASSWORD|PASSWD", ln.upper())]
    assert bad == [], bad


def test_dockerfile_expose_equals_the_server_default_port():
    """AC: BSA-AC-352"""
    cli_src = open(os.path.join(os.path.dirname(server.__file__), "cli.py"), encoding="utf-8").read()
    m = re.search(r'sv\.add_argument\("--port", type=int, default=(\d+)\)', cli_src)
    assert m, "the serve command must declare its default port"
    exposes = [ln.strip() for ln in _dockerfile().splitlines() if ln.strip().startswith("EXPOSE ")]
    assert exposes == ["EXPOSE %s" % m.group(1)]


def test_runbook_carries_the_four_required_blocks():
    """AC: BSA-AC-353"""
    runbook = open(os.path.join(_REPO, "docs", "RUNBOOK.md"), encoding="utf-8").read()
    for block in ("Delivery State", "Deployment", "Rollback", "Monitoring"):
        assert "## %s" % block in runbook, block
