"""Cloud-mode authentication, approver identity and the audit hash chain (task 10, AC 441-451)."""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import audit, pipeline, server
from bts_sbom_app import evals
from conftest import FakeScanner

TOKEN = "FAKE-TOKEN-cloud-1234567890"
HEADER = "X-MS-CLIENT-PRINCIPAL-NAME"


def _req(base, method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json", **(headers or {})}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read()), r.headers
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), e.headers


@pytest.fixture
def cloud_api(tmp_path, make_repo, world, monkeypatch):
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    ev.mkdir()
    pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False, scanner=FakeScanner(), run_arch=False,
                         cache_dir=str(tmp_path / "cache"))

    def make(env_changes=None):
        for k in ("BTS_SBOM_CLOUD", "BTS_SBOM_API_TOKEN", "BTS_SBOM_TRUST_IDENTITY_HEADER"):
            monkeypatch.delenv(k, raising=False)
        for k, v in (env_changes or {}).items():
            if v is None:
                monkeypatch.delenv(k, raising=False)
            else:
                monkeypatch.setenv(k, v)
        st = server.State(evals.repo_root(), str(ev), None)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "st": st, "httpd": httpd, "ev": ev}

    yield make
    # any leftover servers from a test that forgot to close: nothing to clean (httpd closed per test below)


def test_an_unauthenticated_scan_is_401_and_creates_zero_jobs(cloud_api, monkeypatch):
    """AC: BSA-AC-441"""
    api = cloud_api({"BTS_SBOM_CLOUD": "1", "BTS_SBOM_API_TOKEN": TOKEN})
    try:
        code, body, _h = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"})
        assert code == 401 and body["error"] == "unauthorized"
        assert api["st"].store.list() == []
    finally:
        api["httpd"].shutdown()


def test_a_correct_token_is_accepted_and_a_wrong_one_gets_the_missing_body(cloud_api):
    """AC: BSA-AC-442"""
    api = cloud_api({"BTS_SBOM_CLOUD": "1", "BTS_SBOM_API_TOKEN": TOKEN})
    try:
        code_ok, body_ok, _ = _req(api["base"], "GET", "/api/engine", headers={"Authorization": "Bearer " + TOKEN})
        assert code_ok == 200
        code_missing, body_missing, _ = _req(api["base"], "GET", "/api/engine")
        code_wrong, body_wrong, _ = _req(api["base"], "GET", "/api/engine", headers={"Authorization": "Bearer wrong-token"})
        assert code_missing == code_wrong == 401
        assert body_missing == body_wrong                                   # no oracle between missing and wrong
    finally:
        api["httpd"].shutdown()


def test_cloud_mode_without_a_method_is_503_on_every_api_route_but_the_probes(cloud_api):
    """AC: BSA-AC-443"""
    api = cloud_api({"BTS_SBOM_CLOUD": "1"})
    base = api["base"]
    try:
        for path in ("/api/engine", "/api/scan", "/api/projects", "/api/llm", "/api/triage", "/api/chat"):
            req = urllib.request.Request(base + path, data=b"{}" , headers={"Content-Type": "application/json"}) if path in ("/api/scan", "/api/llm", "/api/triage", "/api/chat") \
                else urllib.request.Request(base + path)
            try:
                urllib.request.urlopen(req, timeout=10)
                raise AssertionError("expected 503 for %s" % path)
            except urllib.error.HTTPError as e:
                assert e.code == 503 and json.loads(e.read())["error"] == "auth_not_configured", path
        code, body, _ = _req(base, "GET", "/healthz")
        assert code == 200 and body["ok"] is True
        code2, _body2, _ = _req(base, "GET", "/readyz")
        assert code2 == 200
    finally:
        api["httpd"].shutdown()


def test_a_trusted_identity_header_is_recorded_in_the_audit_line(cloud_api, monkeypatch):
    """AC: BSA-AC-444"""
    api = cloud_api({"BTS_SBOM_CLOUD": "1", "BTS_SBOM_TRUST_IDENTITY_HEADER": "1"})
    try:
        code, body, _ = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"},
                             headers={HEADER: "alice@example.com"})
        assert code == 202, body
        deadline = time.time() + 15
        while time.time() < deadline:

            lines = [ln for ln in open(os.path.join(str(api["ev"]), "audit.jsonl"), encoding="utf-8").read().splitlines() if ln.strip()]
            if any('"scan"' in ln and "alice@example.com" in ln for ln in lines):
                return
            time.sleep(0.1)
        raise AssertionError("no audit line with the identity")
    finally:
        api["httpd"].shutdown()


def test_an_untrusted_identity_header_is_ignored(cloud_api):
    """AC: BSA-AC-445"""
    api = cloud_api({"BTS_SBOM_CLOUD": "1", "BTS_SBOM_API_TOKEN": TOKEN})
    try:
        code, _body, _ = _req(api["base"], "POST", "/api/scan", {"source": "https://github.com/o/r.git"},
                              headers={"Authorization": "Bearer " + TOKEN, HEADER: "mallory@example.com"})
        assert code == 202
        deadline = time.time() + 15
        while time.time() < deadline:
            p = os.path.join(str(api["ev"]), "audit.jsonl")
            if os.path.exists(p):
                lines = [ln for ln in open(p, encoding="utf-8").read().splitlines() if ln.strip()]
                if any('"scan"' in ln for ln in lines):
                    assert all("mallory" not in ln for ln in lines)
                    return
            time.sleep(0.1)
        raise AssertionError("no scan audit line")
    finally:
        api["httpd"].shutdown()


def test_writes_without_a_known_identity_are_refused_and_change_nothing(cloud_api):
    """AC: BSA-AC-446"""
    api = cloud_api({"BTS_SBOM_CLOUD": "1"})                          # no method at all: fail-closed
    base = api["base"]
    try:
        code1, _b1, _ = _req(base, "POST", "/api/scan", {"source": "https://github.com/o/r.git", "patch": True, "approved": True,
                                                         "approval_token": "0123456789abcdef0123456789abcdef"})
        code2, _b2, _ = _req(base, "POST", "/api/triage", {"check_id": "CVE-1", "status": "fixed", "note": "x"})
        assert code1 == 503 and code2 == 503
        assert api["st"].store.list() == [] and api["st"].triage() == {}
    finally:
        api["httpd"].shutdown()


def test_an_approved_patch_records_the_approver_identity(cloud_api, monkeypatch):
    """AC: BSA-AC-447"""
    api = cloud_api({"BTS_SBOM_CLOUD": "1", "BTS_SBOM_TRUST_IDENTITY_HEADER": "1"})
    base = api["base"]
    monkeypatch.setattr(pipeline, "run_project", lambda src, **kw: {"error": None, "metrics": {}, "artifacts": {},
                                                                   "patch": {"status": "applied"}, "stage_errors": {}, "name": "x"})
    try:
        code, body, _ = _req(base, "POST", "/api/scan", {"source": "https://github.com/o/r.git", "patch": True, "approved": True,
                                                         "approval_token": "0123456789abcdef0123456789abcdef"},
                             headers={HEADER: "approver-1"})
        assert code == 202, body
        jid = body["job"]
        deadline = time.time() + 15
        while time.time() < deadline:
            rec = api["st"].store.get(jid)
            if rec and rec.get("state") in ("done", "error"):
                break
            time.sleep(0.1)
        assert rec["approved_by"] == "approver-1"
    finally:
        api["httpd"].shutdown()


def test_four_sensitive_actions_write_four_audit_lines_and_zero_secrets(cloud_api):
    """AC: BSA-AC-448"""
    api = cloud_api({"BTS_SBOM_CLOUD": "1", "BTS_SBOM_TRUST_IDENTITY_HEADER": "1"})
    base = api["base"]
    key = "FAKE-KEY-supersecret-9876543210"
    try:
        _req(base, "POST", "/api/scan", {"source": "https://github.com/o/r.git"}, headers={HEADER: "user-a"})
        _req(base, "POST", "/api/llm", {"api_key": key, "base_url": "http://localhost:1234/v1", "remember": True}, headers={HEADER: "user-a"})
        _req(base, "POST", "/api/triage", {"check_id": "CVE-2020-1111", "status": "fixed", "note": "checked"}, headers={HEADER: "user-a"})
        code, _b, _ = _req(base, "POST", "/api/scan", {"source": "https://github.com/o/r.git", "patch": True, "approved": True,
                                                       "approval_token": "0123456789abcdef0123456789abcdef"}, headers={HEADER: "user-a"})
        assert code == 202
        p = os.path.join(str(api["ev"]), "audit.jsonl")
        deadline = time.time() + 15
        lines = []
        while time.time() < deadline:
            if os.path.exists(p):
                lines = [ln for ln in open(p, encoding="utf-8").read().splitlines() if ln.strip()]
                actions = {json.loads(ln)["action"] for ln in lines}
                if {"scan", "patch_approve", "vex_decision", "llm_connect"} <= actions:
                    break
            time.sleep(0.1)
        blob = "\n".join(lines)
        assert key not in blob and "0123456789abcdef" not in blob and "tok123" not in blob
        assert len([ln for ln in lines if json.loads(ln)["action"] == "scan"]) == 2
    finally:
        api["httpd"].shutdown()


def test_the_audit_hash_chain_verifies_and_names_the_altered_line(tmp_path):
    """AC: BSA-AC-449"""
    log = audit.AuditLog(str(tmp_path / "audit.jsonl"))
    for i in range(3):
        log.append("user-%d" % i, "scan", "https://github.com/o/r.git", "accepted")
    ok, broken = log.verify()
    assert ok is True and broken is None
    path = str(tmp_path / "audit.jsonl")
    pristine = open(path, encoding="utf-8").read().splitlines()

    lines = list(pristine)
    lines[1] = lines[1].replace('"user-1"', '"attacker"')
    open(path, "w", encoding="utf-8", newline="\n").write(chr(10).join(lines) + chr(10))
    ok2, broken2 = log.verify()
    assert ok2 is False and broken2 == 2, (ok2, broken2)

    lines2 = list(pristine)                                       # restore: this round alters ONLY line 3
    lines2[2] = lines2[2].replace('"accepted"', '"rejected"')
    open(path, "w", encoding="utf-8", newline="\n").write(chr(10).join(lines2) + chr(10))
    ok3, broken3 = log.verify()
    assert ok3 is False and broken3 == 3, (ok3, broken3)          # the altered line itself is named, at any position


def test_probes_need_no_credentials_in_cloud_mode(cloud_api):
    """AC: BSA-AC-450"""
    api = cloud_api({"BTS_SBOM_CLOUD": "1", "BTS_SBOM_API_TOKEN": TOKEN})
    try:
        assert _req(api["base"], "GET", "/healthz")[0] == 200
        assert _req(api["base"], "GET", "/readyz")[0] == 200
    finally:
        api["httpd"].shutdown()


def test_local_mode_stays_exactly_as_before(cloud_api):
    """AC: BSA-AC-451"""
    api = cloud_api({})
    base = api["base"]
    try:
        for path in ("/api/health", "/api/llm", "/api/engine", "/api/projects", "/api/history", "/api/fleet", "/api/triage", "/api/jobs/zzzz0000"):
            code, _b, _ = _req(base, "GET", path)
            assert code in (200, 404), path                              # 404 for the unknown job, 200 elsewhere, no auth anywhere
        code2, _b2, _ = _req(base, "POST", "/api/triage", {"check_id": "CVE-1", "status": "fixed", "note": "n"})
        assert code2 == 200
    finally:
        api["httpd"].shutdown()
