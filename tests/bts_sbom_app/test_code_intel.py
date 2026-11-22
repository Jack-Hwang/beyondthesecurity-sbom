"""Code Intel: the function-level comprehension lane (call graph, cyclomatic complexity, dead code, clones) -
natively reimplemented Understand features over the stdlib ast, Python-only and honest about it."""
from __future__ import annotations

import os

import pytest

from bts_sbom_app import code_intel, arch, console

TREE = {
    "app.py": (
        "import helpers\n"
        "\n"
        "\n"
        "def hot(a, b):\n"
        "    total = 0\n"
        "    for x in range(10):\n"
        "        if x > 3 and a:\n"
        "            total += x\n"
        "        elif b:\n"
        "            total -= 1\n"
        "        else:\n"
        "            pass\n"
        "    return total + helpers.twice(total)\n"
        "\n"
        "\n"
        "def twice(n):\n"
        "    return n * 2\n"
        "\n"
        "\n"
        "def unused_calc(n):\n"
        "    return n + 1\n"
        "\n"
        "\n"
        "def duplicate_one(items):\n"
        "    out = []\n"
        "    for it in items:\n"
        "        if it:\n"
        "            out.append(it * 3)\n"
        "    return out\n"
        "\n"
        "\n"
        "def duplicate_two(values):\n"
        "    res = []\n"
        "    for v in values:\n"
        "        if v:\n"
        "            res.append(v * 4)\n"
        "    return res\n"
        "\n"
        "\n"
        "@app.route('/x')\n"
        "def handler_fn():\n"
        "    return 'x'\n"
    ),
    "helpers.py": (
        "def twice(n):\n"
        "    return n * 2\n"
        "\n"
        "\n"
        "def orphans():\n"
        "    return 0\n"
    ),
}


@pytest.fixture()
def repo(tmp_path):
    root = tmp_path / "tree"
    root.mkdir()
    for name, body in TREE.items():
        (root / name).write_text(body, encoding="utf-8")
    return str(root)


def _one(r, name):
    return next(f for f in r["functions"] if f["name"] == name)


def test_complexity_counts_real_branches_not_a_file_regex(repo):
    """AC: BSA-AC-553."""
    r = code_intel.analyze(repo)
    hot = _one(r, "hot")
    # 1 + for + if + bool-op extra + elif => 5 (the old file-level regex proxy could not say this per function)
    assert hot["complexity"] == 5 and _one(r, "twice")["complexity"] == 1
    assert r["metrics"]["functions"] == 8 and r["metrics"]["max_complexity"]["name"] == "hot"
    assert r["metrics"]["max_complexity"]["cc"] == 5


def test_call_resolution_is_name_based_and_counts_unknowns(repo):
    """AC: BSA-AC-554."""
    r = code_intel.analyze(repo)
    hot = _one(r, "hot")
    assert hot["fan_out"] >= 1 and hot["fan_in"] == 0
    twice = [f for f in r["functions"] if f["name"] == "twice"]
    assert sum(f["fan_in"] for f in twice) >= 1                      # hot -> twice resolved across files
    assert r["metrics"]["unknown_calls"] >= 1                        # app.route etc. stay unknown, counted
    assert r["metrics"]["resolved_calls"] >= 1                       # call sites, not edges: hot -> twice


def test_dead_code_rules_are_explicit_and_decorators_are_kept(repo):
    """AC: BSA-AC-555."""
    r = code_intel.analyze(repo)
    dead_names = {d["name"] for d in r["dead_code"]}
    assert "unused_calc" in dead_names and "orphans" in dead_names
    assert "handler_fn" not in dead_names                            # decorated = framework-registered, kept
    # v2 same-file priority: hot calls the twice in app.py, so THAT one is called, while the identical
    # helpers.py::twice really has no caller and is honestly reported as dead
    app_twice = next(f for f in r["functions"] if f["name"] == "twice" and f["file"] == "app.py")
    assert app_twice["fan_in"] >= 1
    assert "twice" in dead_names                                     # helpers.py::twice is genuinely uncalled
    assert any("exclusions" in n for n in r["notes"])


def test_clone_groups_need_identical_normalized_bodies(repo):
    """AC: BSA-AC-556."""
    r = code_intel.analyze(repo)
    dup = [g for g in r["clones"] if {m["name"] for m in g["members"]} >= {"duplicate_one", "duplicate_two"}]
    assert dup, "duplicate_one/duplicate_two must form one clone group"
    assert not any({m["name"] for m in g["members"]} >= {"hot"} for g in r["clones"])
    assert all(g["count"] >= 2 for g in r["clones"])


def test_caps_and_notes_are_recorded_not_silent(tmp_path):
    """AC: BSA-AC-553."""
    root = tmp_path / "many"
    root.mkdir()
    for i in range(6):
        (root / f"m{i}.py").write_text("def f%d():\n    return %d\n" % (i, i), encoding="utf-8")
    r = code_intel.analyze(str(root), max_functions=3)
    assert r["metrics"]["truncated"] is True and len(r["functions"]) == 3
    assert any("truncated" in n for n in r["notes"])
    (root / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    r2 = code_intel.analyze(str(root))
    assert any("parse failed" in n for n in r2["notes"])


def test_arch_record_carries_code_and_the_view_projects_it_bounded(tmp_path):
    """AC: BSA-AC-554."""
    root = tmp_path / "proj"
    root.mkdir()
    (root / "one.py").write_text("def a():\n    return 1\n", encoding="utf-8")
    a = arch.analyze(str(root), online=True)
    assert (a["code"]["metrics"] or {}).get("functions") == 1
    v = console.build_view({"name": "p", "source": "local", "arch": a}, {})
    code = v["arch"]["code"]
    assert code and code["metrics"]["functions"] == 1
    assert len(code["functions"]) <= 15 and len(code["call_edges"]) <= 40
    empty = console.build_view({"name": "p2", "source": "local", "arch": {"graph": {}}}, {})
    assert empty["arch"]["code"] is None                           # honest absence, never an empty-zero


def test_arch_intel_prompt_carries_code_metadata_only(tmp_path):
    """AC: BSA-AC-557."""
    from bts_sbom_app import arch_intel
    root = tmp_path / "proj"
    root.mkdir()
    (root / "one.py").write_text(
        "SECRET_BODY_MARKER_9137 = 'x'\n"
        "\n"
        "\n"
        "def visible(c):\n"
        "    if c:\n"
        "        return 1\n"
        "    return 0\n"
        "\n"
        "\n"
        "def never(c):\n"
        "    return c and 1\n", encoding="utf-8")
    st = arch_intel.structure(str(root))
    assert (st["code"]["metrics"] or {}).get("functions") == 2
    ev = arch_intel.prompt_evidence("p", {"project_license": "MIT", "category": "permissive", "obligations": []}, st)
    blob = repr(ev.get("code"))
    assert "SECRET_BODY_MARKER_9137" not in blob and "def " not in blob and "visible" in blob
    assert ev["code"]["max_complexity"]["cc"] == 2                 # counts only - metadata, never source


def test_class_aware_resolution_and_class_inventory(tmp_path):
    """AC: BSA-AC-560."""
    (tmp_path / "svc.py").write_text(
        "class Svc:\n"
        "    def step(self, n):\n"
        "        return self.validate(n) + 1\n"
        "    def validate(self, n):\n"
        "        return n if n > 0 else 0\n"
        "\n"
        "\n"
        "def runner(s):\n"
        "    s2 = Svc()\n"
        "    return s2.step(3)\n", encoding="utf-8")
    r = code_intel.analyze(str(tmp_path))
    validate = _one(r, "validate")
    step = _one(r, "step")
    assert validate["fan_in"] == 1 and step["fan_in"] == 1        # self.validate / Svc().step resolved
    assert r["metrics"]["resolved_calls"] == 2
    assert validate["nesting"] == 1 and any(f["nesting"] >= 1 for f in r["functions"])
    cls = [c for c in r["classes"] if c["name"] == "Svc"]
    assert cls and cls[0]["methods"] == ["step", "validate"]
    runner = _one(r, "runner")
    assert runner["cls"] is None                                  # module-level function


def test_butterfly_neighbourhood_and_projection(tmp_path):
    """AC: BSA-AC-561."""
    (tmp_path / "one.py").write_text(
        "def entry():\n"
        "    return worker(1) + worker(2)\n"
        "\n"
        "\n"
        "def worker(n):\n"
        "    return helper(n)\n"
        "\n"
        "\n"
        "def helper(n):\n"
        "    return n\n", encoding="utf-8")
    r = code_intel.analyze(str(tmp_path))
    b = code_intel.butterfly(r, "worker")
    assert b is not None and b["fan_in"] == 2
    assert {c["name"] for c in b["callers"]} == {"entry"}
    assert {c["name"] for c in b["callees"]} == {"helper"}
    assert code_intel.butterfly(r, "no_such_fn") is None
    from bts_sbom_app import console
    v = console.build_view({"name": "p", "source": "local", "arch": {"code": r}}, {})
    bf = v["arch"]["code"]["butterfly"]
    # the projection butterflies the top-of-complexity-sort function (ties: first defined) = entry here
    assert bf["name"] == "entry" and {c["name"] for c in bf["callees"]} == {"worker"}


def test_code_metrics_csv_and_butterfly_api(tmp_path, make_repo, world):
    """AC: BSA-AC-562."""
    import json
    import threading
    import urllib.request
    from http.server import ThreadingHTTPServer
    from bts_sbom_app import pipeline, server as server_mod
    from conftest import FakeScanner
    origin = make_repo({"requirements.txt": "requests==2.19.1\n",
                        "svc.py": "def calc(n):\n    if n:\n        return n\n    return 0\n"})
    ev = tmp_path / "ev"
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False,
                               scanner=FakeScanner(), run_arch=True, cache_dir=str(tmp_path / "cache"))
    assert rec.get("error") is None
    st = server_mod.State(str(tmp_path), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server_mod.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        with urllib.request.urlopen(base + "/api/code-metrics/" + rec["name"], timeout=10) as r:
            body = r.read().decode("utf-8")
            cd = r.headers.get("Content-Disposition", "")
        assert r.status == 200 and body.startswith("name,file,line,complexity,nesting,loc,sloc,fan_in,fan_out\n")
        assert "calc" in body and "svc.py" in body and "code-metrics.csv" in cd
        fn = "calc"
        with urllib.request.urlopen(base + "/api/code-butterfly/" + rec["name"] + "?function=" + fn, timeout=10) as r:
            d = json.loads(r.read())
        assert d["name"] == "calc" and "callers" in d and "callees" in d
        try:
            with urllib.request.urlopen(base + "/api/code-butterfly/" + rec["name"] + "?function=nope", timeout=10) as r:
                code = r.status
        except urllib.error.HTTPError as e:
            code = e.code
        assert code == 404
    finally:
        httpd.shutdown()


def test_butterfly_accepts_stored_record_edges_in_both_shapes():
    """AC: BSA-AC-561 - a stored record carries call_edges as {"from","to"} dicts (the Arch Intel projection)
    while a fresh analysis yields pairs; the neighbourhood must read both, never KeyError."""
    from bts_sbom_app import code_intel as ci
    code = {"functions": [{"id": "a.py::run", "name": "run", "file": "a.py", "line": 1, "complexity": 3,
                           "fan_in": 1, "fan_out": 1},
                          {"id": "b.py::x", "name": "x", "file": "b.py", "line": 1, "complexity": 1,
                           "fan_in": 1, "fan_out": 0}],
            "call_edges": [{"from": "a.py::run", "to": "b.py::x"}]}
    b = ci.butterfly(code, "x")
    assert b["callers"][0]["name"] == "run" and b["callees"] == []
    code2 = dict(code, call_edges=[("a.py::run", "b.py::x")])
    assert ci.butterfly(code2, "x") == b
