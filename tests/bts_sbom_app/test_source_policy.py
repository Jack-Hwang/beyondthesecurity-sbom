"""Cloud-mode source policy: no local paths, https-only, allow-list, public addresses, no credentials (task 11, AC 453-460)."""
from __future__ import annotations

import json
import socket
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import pipeline, server, workspace
from bts_sbom_app import evals
from bts_sbom_app.actions import ChatActions
from conftest import FakeScanner


def _fake_resolver(addrs):
    """A fake DNS: getaddrinfo-shaped answer for any host."""
    def resolve(host, port):
        return [(socket.AF_INET, None, None, "", (a, 0)) for a in addrs]
    return resolve


def _policy(src, resolver=None):
    spec = workspace.normalize_source(src)
    return workspace.check_source_policy(spec, cloud=True, resolver=resolver)


def test_local_paths_are_refused_without_reading_anything(tmp_path, monkeypatch):
    """AC: BSA-AC-453"""
    monkeypatch.setenv("BTS_SBOM_CLOUD", "1")
    monkeypatch.setattr(pipeline, "run_project", None)          # if anything tried to run it would explode
    reads = []

    def spy_walk(p, *a, **kw):
        reads.append(str(p))
        return iter(())

    def spy_listdir(p, *a, **kw):
        reads.append(str(p))
        return []

    monkeypatch.setattr(workspace.os, "walk", spy_walk)
    monkeypatch.setattr(workspace.os, "listdir", spy_listdir)
    for p in ("/etc", "C:/Windows", "/definitely/not/here"):
        reason = _policy(p)
        assert reason == "local paths are disabled in cloud mode", p
    assert reads == [], "a refused local path must have 0 directories read (an existence probe in normalize_source is fine)"


def test_ssh_git_and_file_schemes_are_refused_in_cloud_mode(monkeypatch):
    """AC: BSA-AC-454"""
    monkeypatch.setenv("BTS_SBOM_CLOUD", "1")
    for s in ("ssh://git@github.com/o/r.git", "git@github.com:o/r.git", "file:///tmp/repo"):
        assert _policy(s) == "only https:// git URLs are allowed in cloud mode", s


def test_private_and_metadata_addresses_are_refused_and_start_no_clone(monkeypatch):
    """AC: BSA-AC-455"""
    monkeypatch.setenv("BTS_SBOM_CLOUD", "1")
    for bad in ("169.254.169.254", "127.0.0.1", "10.0.0.5"):
        reason = _policy("https://github.com/o/r.git", resolver=_fake_resolver([bad]))     # an allow-listed host with poisoned DNS
        assert reason == "host github.com resolves to a non-public address (%s)" % bad, bad


def test_allow_list_and_public_addresses(monkeypatch):
    """AC: BSA-AC-456"""
    monkeypatch.setenv("BTS_SBOM_CLOUD", "1")
    reason = _policy("https://evil.invalid/o/r.git", resolver=_fake_resolver(["93.184.216.34"]))
    assert reason == "host evil.invalid is not in the source allow-list"
    monkeypatch.setenv("BTS_SBOM_SOURCE_HOSTS", "github.com,example.invalid")
    assert _policy("https://github.com/o/r.git", resolver=_fake_resolver(["93.184.216.34"])) is None
    assert _policy("https://example.invalid/o/r.git", resolver=_fake_resolver(["93.184.216.34", "104.16.0.1"])) is None


def test_credentialled_urls_are_refused_in_cloud_mode(monkeypatch):
    """AC: BSA-AC-457"""
    monkeypatch.setenv("BTS_SBOM_CLOUD", "1")
    reason = _policy("https://user:tok@github.com/o/r.git")
    assert reason == "URLs carrying credentials are refused in cloud mode"


def test_cloud_off_keeps_the_six_earlier_source_forms(monkeypatch):
    """AC: BSA-AC-458"""
    monkeypatch.delenv("BTS_SBOM_CLOUD", raising=False)
    forms = ["https://github.com/o/r.git", "ssh://git@github.com/o/r.git", "git@github.com:o/r.git", "file:///tmp/repo",
             "owner/repo", "."]
    accepted = 0
    for s in forms:
        spec = workspace.normalize_source(s)
        assert workspace.check_source_policy(spec, cloud=False) is None, s
        accepted += 1
    assert accepted == 6


def test_the_chat_analyze_action_refuses_like_the_scan_route(tmp_path, monkeypatch):
    """AC: BSA-AC-459"""
    monkeypatch.setenv("BTS_SBOM_CLOUD", "1")
    acts = ChatActions(tmp_path, str(tmp_path / "ev"), client=None)
    res = acts.analyze("/etc")
    assert res["ok"] is False and res["error"] == "local paths are disabled in cloud mode"
    res2 = acts.analyze("https://user:tok@github.com/o/r.git")
    assert res2["error"] == "URLs carrying credentials are refused in cloud mode"


def test_a_refused_scan_answers_400_with_a_reason_and_creates_zero_jobs(cloud_scan_api):
    """AC: BSA-AC-460"""
    base = cloud_scan_api["base"]
    req = urllib.request.Request(base + "/api/scan", data=json.dumps({"source": "/etc"}).encode(), headers={"Content-Type": "application/json", "X-MS-CLIENT-PRINCIPAL-NAME": "tester"})
    try:
        urllib.request.urlopen(req, timeout=10)
        raise AssertionError("expected 400")
    except urllib.error.HTTPError as e:
        body = json.loads(e.read())
        assert e.code == 400 and "local paths are disabled in cloud mode" in body["error"]
    assert cloud_scan_api["st"].store.list() == []          # 0 jobs created


@pytest.fixture
def cloud_scan_api(tmp_path, make_repo, world, monkeypatch):
    monkeypatch.setenv("BTS_SBOM_CLOUD", "1")
    monkeypatch.setenv("BTS_SBOM_TRUST_IDENTITY_HEADER", "1")
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    ev.mkdir()
    pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False, scanner=FakeScanner(), run_arch=False,
                         cache_dir=str(tmp_path / "cache"))
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "st": st}
    httpd.shutdown()
