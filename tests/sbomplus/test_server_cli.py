"""HTTP API and CLI entry points (local server on a free port, fake scanner/world)."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from sbomplus import cli, evals, pipeline, server
from conftest import FakeScanner


@pytest.fixture
def api(tmp_path, make_repo, world):
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False, scanner=FakeScanner(), run_arch=False,
                               cache_dir=str(tmp_path / "cache"))
    assert rec["error"] is None, rec
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1], rec
    httpd.shutdown()


def _post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_api_rejects_unsafe_source_and_empty_question(api):
    """AC: SP-AC-55"""
    base, _ = api
    assert _post(base + "/api/scan", {"source": "ext::sh -c id"})[0] == 400
    assert _post(base + "/api/chat", {"question": "   "})[0] == 400


def test_api_chat_answers_from_the_analysed_project(api):
    """AC: SP-AC-56"""
    base, rec = api
    code, ans = _post(base + "/api/chat", {"question": "CVE-2020-1111 취약점이 뭐야"})
    assert code == 200 and ans["found"] is True and ans["citation_accuracy"] == 1.0 and "vuln_lookup" in ans["tools"]
    with urllib.request.urlopen(base + "/api/projects", timeout=10) as r:
        assert rec["name"] in json.loads(r.read())["projects"]


def test_cli_evalrag_exits_zero(capsys):
    """AC: SP-AC-57"""
    assert cli.main(["evalrag"]) == 0
    out = capsys.readouterr().out
    assert "recall@5=" in out and "citation=1.0" in out
