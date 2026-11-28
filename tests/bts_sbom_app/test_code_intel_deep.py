"""The deep tier of code intel (the "down 500 floors" Understand-catalog adoption, 2026-11-28): eLOC,
Halstead, essential complexity, knots, decisions+path counts, call chains and cycles, class hierarchy
(DIT/NOC), file dependency cycles, module-variable usage, the entity inventory, the information-browser
dossier, and Understand-style changed-entities snapshot diffing - all with hand-computed expectations.
AC: BSA-AC-1274 (extended function metrics + entity inventory), AC: BSA-AC-1275 (chains, cycles incl.
self-recursion, hierarchy DIT/NOC, file deps, the dossier, and the changed-entities snapshot diff)."""
from __future__ import annotations

import os

from bts_sbom_app import code_intel


MOD_A = '''import mod_b

TOTAL = 0


def alpha(items):
    total = 0
    for i in items:
        if i > 0 and i != 5:
            total += i
    return total


def beta(x):
    if x > 0:
        return 1
    return 0


def delta():
    return alpha([1]) + alpha([2])


class Base:
    pass


class Mid(Base):
    def run(self):
        return 1


class Leaf(Mid):
    pass
'''

MOD_B = '''def gamma(n):
    if n <= 1:
        return n
    return gamma(n - 1) + n
'''


def _project(tmp_path):
    (tmp_path / "mod_a.py").write_text(MOD_A, encoding="utf-8")
    (tmp_path / "mod_b.py").write_text(MOD_B, encoding="utf-8")
    return code_intel.analyze(str(tmp_path))


def _fn(r, name):
    return next(f for f in r["functions"] if f["name"] == name)


def test_extended_function_metrics_match_hand_computations(tmp_path):
    r = _project(tmp_path)
    alpha = _fn(r, "alpha")
    # alpha: for(+1) + if(+1) + and(+1) -> cc 4, decisions 3, paths 8; structured (for, if) removed:
    # essential keeps only the boolean alternative = 2; no break/continue, one final return -> knots 0
    assert alpha["complexity"] == 4 and alpha["decisions"] == 3 and alpha["path_count"] == 8
    assert alpha["essential"] == 2 and alpha["knots"] == 0
    assert alpha["eloc"] == 6                       # every body line is code, none blank/comment
    # beta: one if -> cc 2, two returns -> 1 knot (the non-final one), essential 1
    beta = _fn(r, "beta")
    assert beta["complexity"] == 2 and beta["decisions"] == 1 and beta["path_count"] == 2
    assert beta["essential"] == 1 and beta["knots"] == 1 and beta["eloc"] == 4
    # halstead is present with the derived values consistent with its own counts
    h = alpha["halstead"]
    assert h["n"] > 0 and h["N"] > 0 and h["volume"] > 0 and h["effort"] > 0
    # fan counts through the resolved edges: delta calls alpha twice
    assert _fn(r, "delta")["fan_out"] == 2 and alpha["fan_in"] == 2


def test_call_chains_and_recursive_cycles(tmp_path):
    r = _project(tmp_path)
    chains = r["deep"]["call_chains"]
    assert chains["longest_depth"] == 2 and chains["longest"][0] == "delta"
    assert chains["cycles"] == 1                                    # gamma's self-recursion
    assert chains["cycle_examples"] and chains["cycle_examples"][0][0] == "gamma"


def test_class_hierarchy_dit_and_noc(tmp_path):
    r = _project(tmp_path)
    hier = r["deep"]["hierarchy"]
    rows = {x["name"]: x for x in hier["classes"]}
    assert rows["Base"]["dit"] == 0 and rows["Base"]["noc"] == 1
    assert rows["Mid"]["dit"] == 1 and rows["Mid"]["noc"] == 1
    assert rows["Leaf"]["dit"] == 2 and rows["Leaf"]["noc"] == 0
    assert hier["max_dit"] == 2


def test_file_dependencies_and_module_variables(tmp_path):
    r = _project(tmp_path)
    fd = r["deep"]["file_deps"]
    assert fd["edges"] == 1 and fd["cycles"] == 0                   # mod_a imports mod_b
    assert fd["top_coupled"] and fd["top_coupled"][0]["file"] == "mod_a.py"
    vs = r["deep"]["variables"]
    assert vs["module_vars"] >= 1                                   # TOTAL (+ import bindings as module names)
    ent = r["deep"]["entities"]
    assert ent["modules"] == 2 and ent["classes"] == 3
    assert ent["methods"] == 1 and ent["functions"] >= 3            # alpha, beta, delta (+gamma in mod_b)


def test_snapshot_diff_reports_changed_added_removed(tmp_path):
    r1 = _project(tmp_path)
    snap1 = code_intel.snapshot(r1)
    # change beta's body (complexity moves), add a function, remove delta
    changed_src = MOD_A.replace("    if x > 0:\n        return 1\n    return 0",
                                "    if x > 0 and x < 10:\n        return 1\n    return 0")
    changed_src = changed_src.replace("def delta():\n    return alpha([1]) + alpha([2])\n\n\n",
                                      "def epsilon():\n    return 7\n\n\n")
    (tmp_path / "mod_a.py").write_text(changed_src, encoding="utf-8")
    r2 = code_intel.analyze(str(tmp_path), prev_snapshot=snap1)
    ch = r2["deep"]["changed_entities"]
    ids = {k.split("::")[-1] for k in ch["changed"]}
    assert "beta" in ids                                            # complexity moved 2 -> 3
    assert "alpha" in ids                                           # legitimate: delta's removal dropped its fan-in
    assert "delta" in {k.split("::")[-1] for k in ch["removed"]}
    assert "epsilon" in {k.split("::")[-1] for k in ch["added"]}


def test_dossier_information_browser_function_and_class(tmp_path):
    r = _project(tmp_path)
    d = code_intel.dossier(r, "alpha")
    assert d["kind"] == "function" and d["id"].endswith("mod_a.py::alpha")
    assert d["metrics"]["essential"] == 2 and d["metrics"]["path_count"] == 8
    assert [c["name"] for c in d["callers"]] == ["delta"]
    assert d["halstead"]["volume"] > 0
    dc = code_intel.dossier(r, "Mid")
    assert dc["kind"] == "class" and dc["dit"] == 1 and dc["noc"] == 1
    assert dc["methods"] == ["run"] and dc["external_bases"] == []
    assert code_intel.dossier(r, "no-such-entity") is None
