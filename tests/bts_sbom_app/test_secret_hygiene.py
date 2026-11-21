"""EXAONE key storage hygiene (task 8): gitignore, POSIX mode, no key in any response/evidence/error, key-file pattern."""
from __future__ import annotations

import json
import os
import subprocess

import pytest

from bts_sbom_app import llm, server
from bts_sbom_app import evals
from conftest import FakeScanner

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_KEY = "FAKE-KEY-0123456789"


def test_gitignore_lists_the_saved_key_file_and_jobs_folder():
    """AC: BSA-AC-425"""
    text = open(os.path.join(ROOT, ".gitignore"), encoding="utf-8").read().splitlines()
    assert "evidence/.llm_config.json" in text
    assert "evidence/.jobs/" in text


def test_saved_key_file_is_owner_only_on_posix(tmp_path):
    """AC: BSA-AC-426"""
    if os.name != "posix":
        pytest.skip("POSIX only")
    ev = tmp_path / "ev"
    ev.mkdir()
    st = server.State(ROOT, str(ev), None)
    st.set_llm({"api_key": _KEY}, remember=True)
    path = ev / ".llm_config.json"
    assert path.exists()
    assert os.stat(path).st_mode & 0o077 == 0


def test_no_route_response_ever_contains_the_key(tmp_path, make_repo, world):
    """AC: BSA-AC-427, BSA-AC-428"""
    import threading
    import urllib.request
    from http.server import ThreadingHTTPServer
    from bts_sbom_app import pipeline
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False, scanner=FakeScanner(), run_arch=False,
                         cache_dir=str(tmp_path / "cache"))
    st = server.State(evals.repo_root(), str(ev), None)
    st.set_llm({"api_key": _KEY}, remember=True)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        # while a key is saved the status reports the plaintext-file storage (and never the key itself)
        with urllib.request.urlopen(base + "/api/llm", timeout=10) as r:
            st_obj = json.loads(r.read())
        assert st_obj["storage"] == "plaintext-file"
        bodies = []
        for route in ("/api/health", "/api/llm", "/api/engine", "/api/projects", "/api/history", "/api/fleet", "/api/triage", "/api/jobs/zzzz"):
            try:
                with urllib.request.urlopen(base + route, timeout=10) as r:
                    bodies.append((route, r.read().decode("utf-8", errors="replace")))
            except urllib.error.HTTPError as e:                      # a 404 body must not leak the key either
                bodies.append((route, e.read().decode("utf-8", errors="replace")))
        req = urllib.request.Request(base + "/api/chat", data=json.dumps({"question": "CVE-2020-1111"}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as r:
            bodies.append(("/api/chat", r.read().decode("utf-8", errors="replace")))
        leaked = [(route, b) for route, b in bodies if _KEY in b]
        assert leaked == [], leaked
    finally:
        httpd.shutdown()


def test_clear_llm_removes_every_trace_from_the_evidence_folder(tmp_path):
    """AC: BSA-AC-428 (after disconnect, 0 files under evidence hold the key)"""
    ev = tmp_path / "ev"
    ev.mkdir()
    st = server.State(ROOT, str(ev), None)
    st.set_llm({"api_key": _KEY}, remember=True)
    assert (ev / ".llm_config.json").exists()
    status = st.clear_llm()
    assert status["storage"] == "none"
    hits = []
    for dp, _, fns in os.walk(ev):
        for fn in fns:
            fp = os.path.join(dp, fn)
            try:
                if _KEY in open(fp, encoding="utf-8", errors="replace").read():
                    hits.append(fp)
            except OSError:
                pass
    assert hits == [], hits


def test_provider_error_string_never_carries_the_key(world, tmp_path):
    """AC: BSA-AC-429"""
    ledger = str(tmp_path / ".llm_ledger.json")

    def boom(url, headers, body):
        return 502, "bad gateway: rejected auth for key=%s" % _KEY              # provider text embeds the planted key

    llm.TRANSPORT = boom
    c = llm.ChatClient.from_config(_KEY, ledger=ledger)
    with pytest.raises(llm.LLMError) as ei:
        c.complete("s", "u")
    assert _KEY not in str(ei.value)
    with open(ledger, encoding="utf-8") as fh:
        assert _KEY not in fh.read()
    for e in c.errors:
        assert _KEY not in e


def test_key_file_with_trailing_newline_is_trimmed_and_available(tmp_path):
    """AC: BSA-AC-430"""
    kf = tmp_path / "key.txt"
    kf.write_text(_KEY + "\n", encoding="utf-8")
    os.environ["EXAONE_API_KEY_FILE"] = str(kf)
    try:
        c = llm.ChatClient.from_env()
        assert c.available and c.api_key == _KEY
    finally:
        os.environ.pop("EXAONE_API_KEY_FILE", None)


def test_missing_key_file_leaves_the_client_unavailable_without_an_exception(tmp_path):
    """AC: BSA-AC-431"""
    os.environ["EXAONE_API_KEY_FILE"] = str(tmp_path / "does-not-exist.txt")
    try:
        c = llm.ChatClient.from_env()
        assert c.available is False
        assert "key_file_unreadable" in c.describe().get("reasons", [])
        assert str(tmp_path) not in json.dumps(c.describe())               # the path is never recorded
    finally:
        os.environ.pop("EXAONE_API_KEY_FILE", None)


def test_git_tracks_zero_files_named_llm_config():
    """AC: BSA-AC-432"""
    try:
        out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("git unavailable - NOT RUN")
    assert ".llm_config.json" not in [os.path.basename(line) for line in out.splitlines()]
