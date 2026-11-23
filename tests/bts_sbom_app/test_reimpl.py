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


def _u_boot_shaped_oracle(root):
    """The u-boot dtoc shape, measured 2026-11-23 (test_src_scan.py): the suite imports the component through
    its package, defines TestCase classes with NO main tail, and its helper package lives beside the source."""
    src = os.path.join(root, "src")
    os.makedirs(src, exist_ok=True)
    original = 'def scan(rows):\n    """The ORIGINAL behaviour: deliberately not what the oracle expects."""\n    return {}\n'
    with open(os.path.join(src, "src_scan.py"), "w", encoding="utf-8") as fh:
        fh.write(original)
    os.makedirs(os.path.join(root, "u_boot_pylib"), exist_ok=True)
    with open(os.path.join(root, "u_boot_pylib", "__init__.py"), "w", encoding="utf-8") as fh:
        fh.write("MARKER = 'helper'\n")
    suite = "\n".join([
        "import unittest",
        "from dtoc import src_scan",
        "from u_boot_pylib import MARKER",
        "class TestSrcScan(unittest.TestCase):",
        "    def test_marks(self):",
        "        self.assertEqual(src_scan.scan(['a', '?b']), {'w': ['?b']})",
        "    def test_helper(self):",
        "        self.assertEqual(MARKER, 'helper')",
    ]) + "\n"
    with open(os.path.join(src, "test_src_scan.py"), "w", encoding="utf-8") as fh:
        fh.write(suite)
    return src


def test_adopted_oracle_rebounds_package_imports_and_runs_mainless_suites():
    """AC: BSA-AC-616. The oracle must grade the NEW module (package import rebound to the flat copy), a
    pytest-collected TestCase suite without its own main tail must actually RUN its classes, and the suite's
    helper package resolves from the source tree - all measured on u-boot tools/dtoc."""
    root = _tmp()
    src = _u_boot_shaped_oracle(root)
    adopted = reimpl.discover_adopted_tests(src)
    work = os.path.join(root, "work")
    os.makedirs(work)
    fresh = 'def scan(rows):\n    """NEW code: marks flagged rows."""\n    return {"w": [r for r in rows if r.startswith("?")]}\n'
    with open(os.path.join(work, "src_scan.py"), "w", encoding="utf-8") as fh:
        fh.write(fresh)
    atr = reimpl.run_adopted_tests(work, adopted, module_name="src_scan", source_root=src)
    assert atr["ok"], atr["tail"]
    assert "Ran 2 tests" in atr["tail"] and not atr["skipped"]
    copied = open(os.path.join(work, "test_src_scan.py"), encoding="utf-8").read()
    assert "from dtoc import src_scan" not in copied            # the binding points at the NEW flat module
    assert "unittest.main(argv" in copied                        # the injected runner tail (copy only)
    assert "from dtoc import src_scan" in open(os.path.join(src, "test_src_scan.py"), encoding="utf-8").read()  # the ORIGIN is untouched
    # and the same oracle graded against the ORIGINAL behaviour fails - the suite discriminates:
    work2 = os.path.join(root, "work2")
    os.makedirs(work2)
    stale = 'def scan(rows):\n    return {}\n'
    with open(os.path.join(work2, "src_scan.py"), "w", encoding="utf-8") as fh:
        fh.write(stale)
    atr2 = reimpl.run_adopted_tests(work2, adopted, module_name="src_scan", source_root=src)
    assert not atr2["ok"]


def test_adopted_suite_skips_files_without_runnable_tests():
    """AC: BSA-AC-616. A test_-prefixed helper file (u_boot_pylib/test_util.py shape) that defines no TestCase
    and calls no unittest.main would read as a silent 0-test pass - it is skipped and recorded instead."""
    root = _tmp()
    src = os.path.join(root, "src")
    os.makedirs(src)
    comp = 'def add(a, b):\n    """Add."""\n    return a + b\n'
    with open(os.path.join(src, "thing.py"), "w", encoding="utf-8") as fh:
        fh.write(comp)
    with open(os.path.join(src, "test_util.py"), "w", encoding="utf-8") as fh:
        fh.write("MODE = 'helper'\n")                          # a helper, not a test - the honest skip
    suite = "\n".join([
        "import unittest",
        "from thing import add",
        "class TestThing(unittest.TestCase):",
        "    def test_add(self):",
        "        self.assertEqual(add(2, 3), 5)",
        "",
        "if __name__ == '__main__':",
        "    unittest.main()",
    ]) + "\n"
    with open(os.path.join(src, "test_thing.py"), "w", encoding="utf-8") as fh:
        fh.write(suite)
    work = os.path.join(root, "work")
    os.makedirs(work)
    fresh_thing = 'def add(a, b):\n    return a + b\n'
    with open(os.path.join(work, "thing.py"), "w", encoding="utf-8") as fh:
        fh.write(fresh_thing)
    atr = reimpl.run_adopted_tests(work, reimpl.discover_adopted_tests(src), module_name="thing", source_root=src)
    assert atr["ok"] and {s["file"] for s in atr["skipped"]} == {"test_util.py"}
    assert "SKIPPED" in atr["tail"]


def _pattern_source(root):
    src = os.path.join(root, "src")
    os.makedirs(src, exist_ok=True)
    code = "\n".join([
        '"""Run check callables concurrently and join their outcomes."""',
        "",
        "def run_parallel(fns, max_workers=4):",
        '    """Run fns concurrently, return [(name, ok)]."""',
        "    return []",
        "",
        "def join(outcomes):",
        '    """True when every outcome passed."""',
        "    return all(ok for _, ok in outcomes)",
    ]) + "\n"
    with open(os.path.join(src, "conctest.py"), "w", encoding="utf-8") as fh:
        fh.write(code)
    return src


class _StubBookIndex:
    """A book-KB stub: answers only queries mentioning its domain words."""

    def __init__(self, hit=True):
        self.hit = hit

    def search(self, q, k=3, **kw):
        if not (self.hit and any(w in q.lower() for w in ("parallel", "test", "run", "concurrently"))):
            return {"found": False, "results": []}
        return {"found": True, "results": [{"chunk": {"id": "books/x.md:3", "source": "books/x.md",
                                                      "heading": "Testing patterns",
                                                      "text": "Run verifications concurrently and join them before asserting.",
                                                      "meta": {"kind": "books", "book": "테스트 아키텍처"}}, "rrf": 0.9}]}


def test_infer_patterns_prefers_the_book_tier(tmp_path):
    """AC: BSA-AC-619. Tier 1: the merged book+notes index answers the interface-derived queries -> tier=book
    with the book/section attribution carried on every pattern."""
    from bts_sbom_app import reimpl
    iface = {"module": "conctest", "imports": [], "functions": [
        {"name": "run_parallel", "args": ["fns", "max_workers"], "docstring": "Run fns concurrently", "is_async": False},
        {"name": "join", "args": ["outcomes"], "docstring": "all passed", "is_async": False}], "classes": []}
    pack = reimpl.infer_patterns(iface, book_index=_StubBookIndex(hit=True), client=None)
    assert pack["tier"] == "book" and pack["patterns"]
    assert pack["patterns"][0]["ref"].startswith("테스트 아키텍처")


def test_infer_patterns_falls_back_to_the_model_tier(tmp_path):
    """AC: BSA-AC-619. Tier 2: an empty book KB falls through to the deployment model's own architecture
    knowledge; without a client the tier is honestly none."""
    import json as _json
    from bts_sbom_app import reimpl
    iface = {"module": "cryptoutil", "imports": [], "functions": [
        {"name": "seal", "args": ["data"], "docstring": "encrypt and authenticate", "is_async": False}], "classes": []}

    class ModelClient:
        def complete(self, system, user, max_tokens=2048, json_mode=False):
            return _json.dumps({"patterns": [{"name": "Provider Interface", "guidance": "separate key handling from sealing."}]})

    pack = reimpl.infer_patterns(iface, book_index=_StubBookIndex(hit=False), client=ModelClient())
    assert pack["tier"] == "model" and pack["patterns"][0]["name"] == "Provider Interface"
    none = reimpl.infer_patterns(iface, book_index=_StubBookIndex(hit=False), client=None)
    assert none["tier"] == "none" and none["patterns"] == []


def test_pattern_pack_reaches_the_spec_and_the_record(tmp_path):
    """AC: BSA-AC-619. reimpl(pattern_pack=...) appends the guidance section to the spec artifact and records the
    provenance (tier + names) on the result; without a pack the spec has no such section (back-compat)."""
    root = _tmp()
    src = _make_source(root)
    out = os.path.join(root, "reimpl")
    pack = {"tier": "book", "queries": ["flatten"], "patterns": [{"name": "Pipes and Filters", "guidance": "join per row, then join rows.", "ref": "테스트 아키텍처 · Testing patterns"}]}
    events: list = []
    r = reimpl.reimpl(src, "flatten.py", out, client=None, license_ok=True, pattern_pack=pack, progress=events.append)
    spec_text = open(r["artifacts"]["spec"], encoding="utf-8").read()
    assert "Recommended architecture patterns" in spec_text and "Pipes and Filters" in spec_text
    assert r["patterns"]["tier"] == "book" and r["patterns"]["patterns"][0]["name"] == "Pipes and Filters"
    assert any(e["event"] == "patterns_ready" for e in events)
    r2 = reimpl.reimpl(_make_source(_tmp()), "flatten.py", os.path.join(_tmp(), "out3"), client=None, license_ok=True)
    assert "Recommended architecture patterns" not in open(r2["artifacts"]["spec"], encoding="utf-8").read()
