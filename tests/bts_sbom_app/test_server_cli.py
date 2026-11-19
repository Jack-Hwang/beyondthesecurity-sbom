"""HTTP API and CLI entry points (local server on a free port, fake scanner/world)."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import cli, evals, pipeline, server
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
    """AC: BSA-AC-55"""
    base, _ = api
    assert _post(base + "/api/scan", {"source": "ext::sh -c id"})[0] == 400
    assert _post(base + "/api/chat", {"question": "   "})[0] == 400


def test_api_chat_answers_from_the_analysed_project(api):
    """AC: BSA-AC-56"""
    base, rec = api
    code, ans = _post(base + "/api/chat", {"question": "CVE-2020-1111 취약점이 뭐야"})
    assert code == 200 and ans["found"] is True and ans["citation_accuracy"] == 1.0 and "vuln_lookup" in ans["tools"]
    with urllib.request.urlopen(base + "/api/projects", timeout=10) as r:
        assert rec["name"] in json.loads(r.read())["projects"]


def test_cli_evalrag_exits_zero(capsys):
    """AC: BSA-AC-57"""
    assert cli.main(["evalrag"]) == 0
    out = capsys.readouterr().out
    assert "recall@5=" in out and "citation=1.0" in out


# ------------------------------------------------------------------ EXAONE connection from the web console (POST /api/llm)
_KEY = "sk-exaone-test-9f8e7d6c"


@pytest.fixture
def llm_api(tmp_path, make_repo, world):
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False, scanner=FakeScanner(), run_arch=False,
                               cache_dir=str(tmp_path / "cache"))
    assert rec["error"] is None, rec

    def restate():
        return server.State(evals.repo_root(), str(ev), None)

    st = restate()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "ev": ev, "restate": restate}
    httpd.shutdown()


def _planner_handler():
    def handler(body):
        user = body["messages"][-1]["content"]
        if "QUESTION:" in user:
            return 200, json.dumps({"choices": [{"message": {"content": "not json"}}], "usage": {}})
        return 200, json.dumps({"choices": [{"message": {"content": json.dumps({"calls": [{"tool": "top_vulns", "args": {}}]})}}], "usage": {}})
    return handler


def test_api_llm_connects_masks_the_key_and_plans_with_the_llm(llm_api, world):
    """AC: BSA-AC-216"""
    base, ev = llm_api["base"], llm_api["ev"]
    world.llm_handler = _planner_handler()
    code, d = _post(base + "/api/llm", {"api_key": _KEY, "model": "k-exaone_v2.5", "remember": True})
    assert code == 200 and d["ok"] is True and d["llm"]["key_configured"] is True and d["llm"]["model"] == "k-exaone_v2.5"
    assert d["llm"]["key_tail"] == "7d6c" and _KEY not in json.dumps(d)
    cfg = json.loads((ev / ".llm_config.json").read_text(encoding="utf-8"))                       # remembered, plain text in the local evidence folder
    assert cfg["api_key"] == _KEY and cfg["model"] == "k-exaone_v2.5"
    leaked = [p.name for p in ev.rglob("*") if p.is_file() and _KEY in p.read_text(encoding="utf-8", errors="ignore")]
    assert leaked == [".llm_config.json"]                                                          # the key ends up in exactly one file
    code, ans = _post(base + "/api/chat", {"question": "가장 심각한 취약점이 뭐야", "use_llm": True})
    assert code == 200 and ans.get("routing") == "llm"                                             # the chatbot plans with the connected model
    with urllib.request.urlopen(base + "/api/llm", timeout=10) as r:
        st = json.loads(r.read())
    assert st["key_configured"] is True and st["key_tail"] == "7d6c" and st["saved"] is True and _KEY not in json.dumps(st)
    assert _post(base + "/api/llm", {"base_url": "https://api.exaone.ai/v1"})[0] == 400            # no key, remote base: refused


def test_api_llm_restarts_from_the_saved_file_and_clear_removes_it(llm_api, world):
    """AC: BSA-AC-217"""
    base, ev, restate = llm_api["base"], llm_api["ev"], llm_api["restate"]
    world.llm_handler = _planner_handler()
    assert _post(base + "/api/llm", {"api_key": _KEY, "remember": True})[0] == 200
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(restate()))                  # a restart on the same evidence folder
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/api/llm" % httpd.server_address[1], timeout=10) as r:
            st = json.loads(r.read())
        assert st["key_configured"] is True and st["saved"] is True                                 # connected from the saved file, no env involved
    finally:
        httpd.shutdown()
    code, d = _post(base + "/api/llm/clear", {})
    assert code == 200 and d["llm"]["key_configured"] is False and d["llm"]["saved"] is False and d["llm"]["saved_removed"] is True
    assert not (ev / ".llm_config.json").exists()
    code, ans = _post(base + "/api/chat", {"question": "가장 심각한 취약점이 뭐야", "use_llm": True})
    assert code == 200 and ans.get("routing") == "regex"                                           # disconnected: back to the regex router


def test_api_llm_saved_file_loses_to_a_startup_key(llm_api, world, monkeypatch):
    """AC: BSA-AC-218"""
    base, ev, restate = llm_api["base"], llm_api["ev"], llm_api["restate"]
    assert _post(base + "/api/llm", {"api_key": _KEY, "remember": True})[0] == 200
    env_key = "sk-startup-env-key-11223344"
    monkeypatch.setenv("EXAONE_API_KEY", env_key)
    st = restate()
    assert st.client.available is True and st.client.api_key == env_key                            # the startup key wins over the saved file
    world.llm_handler = _planner_handler()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    base2 = "http://127.0.0.1:%d" % httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        code, d = _post(base2 + "/api/llm/clear", {})
        assert code == 200 and d["llm"]["key_configured"] is True and d["llm"]["key_tail"] == "3344"   # falls back to the startup key, honestly
        assert d["llm"]["saved_removed"] is True and not (ev / ".llm_config.json").exists()
        with urllib.request.urlopen(base2 + "/api/llm", timeout=10) as r:
            d = json.loads(r.read())
        assert d["key_tail"] == "3344" and env_key not in json.dumps(d) and d["saved"] is False        # masked, never the key itself
    finally:
        httpd.shutdown()
