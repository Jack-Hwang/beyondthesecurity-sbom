"""Clean-room reimplementation workbench (brief 6): interface extraction, two-wall generation, the measured
copy gate, the isolated test lane, and folder publish."""
from __future__ import annotations

import json
import os

import pytest

from bts_sbom_app import evals, llm, reimpl

ORIGINAL = '''"""A tiny GPL-licensed helper we must stop depending on."""

SECRET_MARKER = "implementation-body-that-must-never-appear-in-the-spec-or-prompt"

def flatten(rows, sep=","):
    """Join every cell of every row with sep."""
    out = []
    for row in rows:
        out.append(sep.join(str(c) for c in row))
    return "\\n".join(out)

class Merger:
    """Merges rows pairwise."""

    def merge(self, a, b):
        """Row-wise merge."""
        return [x + b[i] for i, x in enumerate(a)]

def _private_helper():
    pass
'''


def _make_source(root):
    src = os.path.join(root, "src")
    os.makedirs(src, exist_ok=True)
    with open(os.path.join(src, "flatten.py"), "w", encoding="utf-8") as fh:
        fh.write(ORIGINAL)
    return src


def _clean_room_code():
    """What wall 2 produces: satisfies the contracts, written in a different shape (no copied lines)."""
    return (
        '"""Independent implementation written from the spec only."""\n'
        "\n"
        "def flatten(rows, sep=','):\n"
        "    \"\"\"Join every cell of every row with sep.\"\"\"\n"
        "    return chr(10).join(sep.join(str(cell) for cell in row) for row in rows)\n"
        "\n"
        "class Merger:\n"
        "    \"\"\"Merges rows pairwise.\"\"\"\n"
        "\n"
        "    def merge(self, a, b):\n"
        "        \"\"\"Row-wise merge.\"\"\"\n"
        "        return [left + right for left, right in zip(a, b)]\n"
    )


def test_interface_extraction_copies_signatures_never_bodies():
    """AC: BSA-AC-566"""
    path = os.path.join(_make_source(_tmp()), "flatten.py")
    iface = reimpl.extract_interface(path)
    names = [f["name"] for f in iface["functions"]]
    assert names == ["flatten"] and "classes" in iface and iface["classes"][0]["name"] == "Merger"
    spec = reimpl.spec_document(iface, "GPLv3 compliance risk")
    assert "flatten(rows" in spec                                                          # the signature travels
    assert "SECRET_MARKER" not in spec and "out.append" not in spec                        # bodies never do


def _tmp():
    import tempfile
    return tempfile.mkdtemp(prefix="reimpl_test_")


def test_copy_gate_measures_and_rejects_copies():
    """AC: BSA-AC-569"""
    overlap_copy = reimpl.shingle_overlap(ORIGINAL, ORIGINAL)
    assert overlap_copy == 1.0                                                             # a copy is a copy
    overlap_clean = reimpl.shingle_overlap(_clean_room_code(), ORIGINAL)
    assert overlap_clean <= reimpl.COPY_THRESHOLD                                          # independent work stays low
    assert reimpl.license_strings_in(_clean_room_code()) == []                             # no license text in clean code


def test_full_lane_offline_scaffold_publishes_with_events():
    """AC: BSA-AC-567, BSA-AC-568, BSA-AC-570, BSA-AC-571"""
    root = _tmp()
    src = _make_source(root)
    out = os.path.join(root, "reimpl")
    events: list = []
    r = reimpl.reimpl(src, "flatten.py", out, client=None, license_ok=True,
                      publish_dest=os.path.join(root, "published"), progress=events.append)
    kinds = [e["event"] for e in events]
    assert kinds[0] == "interface_ready" and "spec_ready" in kinds and "diagram_ready" in kinds
    assert "code_ready" in kinds and "copy_gate" in kinds and "tests_running" in kinds
    assert "tests_passed" in kinds and "published" in kinds
    assert r["verdict"] == "ok" and r["generated_by"] == "scaffold"
    assert "SCAFFOLD ONLY" in open(r["artifacts"]["code"], encoding="utf-8").read()        # the honest marker
    assert os.path.exists(os.path.join(out, "spec.md")) and os.path.exists(os.path.join(out, "dependencies.dgml"))
    assert os.path.exists(os.path.join(root, "published", "flatten.py"))
    assert any(e["event"] == "copy_gate" and e["passed"] for e in events)


def test_license_gate_refuses_before_generation():
    """AC: BSA-AC-571"""
    src = _make_source(_tmp())
    events: list = []
    r = reimpl.reimpl(src, "flatten.py", os.path.join(_tmp(), "out2"), license_ok=False, progress=events.append)
    assert r["verdict"] == "refused" and events[0]["event"] == "refused"
    assert not os.path.exists(os.path.join(_tmp(), "out2", "spec.md"))                     # nothing was generated


def test_barrier2_llm_prompt_carries_spec_only_and_retryable_failures_reported(world, monkeypatch):
    """AC: BSA-AC-568"""
    calls = []

    def transport(url, headers, body):
        calls.append(body["messages"][0]["content"] + body["messages"][1]["content"])
        return 200, json.dumps({"choices": [{"message": {"content": json.dumps({"code": _clean_room_code()})}}],
                                "usage": {"prompt_tokens": 5, "completion_tokens": 7}})

    monkeypatch.setattr(llm, "TRANSPORT", transport)
    client = llm.ChatClient("k")
    src = _make_source(_tmp())
    out = os.path.join(_tmp(), "out3")
    r = reimpl.reimpl(src, "flatten.py", out, client=client, license_ok=True)
    assert r["generated_by"] == "llm" and r["verdict"] == "ok"
    assert all("SECRET_MARKER" not in c and "out.append" not in c for c in calls)          # wall 2: spec-only prompt
    assert any("clean-room" in c.lower() for c in calls)


def test_api_reimpl_job_runs_and_streams(tmp_path, make_repo):
    """AC: BSA-AC-566..571 end to end through the HTTP surface."""
    import threading
    import time
    import urllib.request
    from http.server import ThreadingHTTPServer

    from bts_sbom_app import server as server_mod
    origin = make_repo({"requirements.txt": "requests==2.19.1\n", "pkg/legacy.py": "def combine(a, b):\n    \"\"\"Concatenate rows.\"\"\"\n    return a + b\n"})
    ev = tmp_path / "ev"
    st = server_mod.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server_mod.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % httpd.server_address[1]
        body = json.dumps({"source": origin, "component": "pkg/legacy.py", "use_llm": False}).encode()
        req = urllib.request.Request(base + "/api/reimpl", data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            assert r.status == 202
            jid = json.loads(r.read())["job"]
        deadline = time.time() + 60
        state = None
        while time.time() < deadline:
            with urllib.request.urlopen(base + "/api/jobs/" + jid, timeout=10) as r:
                job = json.loads(r.read())
            state = job.get("state")
            if state in ("done", "error"):
                break
            time.sleep(0.5)
        assert state == "done", job
        artifacts = os.path.join(str(ev), "reimpl", jid)
        assert os.path.exists(os.path.join(artifacts, "spec.md"))
        assert os.path.exists(os.path.join(artifacts, "dependencies.dgml"))
        with urllib.request.urlopen(base + "/api/jobs/" + jid + "/events", timeout=10) as r:
            stream = r.read().decode("utf-8")
        assert "interface_ready" in stream and "tests_passed" in stream          # every stage was streamed live
    finally:
        httpd.shutdown()
