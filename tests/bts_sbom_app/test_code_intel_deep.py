"""The deep tier of code intel (the "down 500 floors" Understand-catalog adoption, 2026-11-28): eLOC,
Halstead, essential complexity, knots, decisions+path counts, call chains and cycles, class hierarchy
(DIT/NOC), file dependency cycles, module-variable usage, the entity inventory, the information-browser
dossier, and Understand-style changed-entities snapshot diffing - all with hand-computed expectations.
AC: BSA-AC-1274 (extended function metrics + entity inventory), AC: BSA-AC-1275 (chains, cycles incl.
self-recursion, hierarchy DIT/NOC, file deps, the dossier, and the changed-entities snapshot diff),
AC: BSA-AC-1278 (the Understand-catalog tier: three cyclomatic flavours, statement and line taxonomies,
CountInput/Output, LCOM, CBO), AC: BSA-AC-1279 (the behavioral envelope: one file -> shape facts + totals,
the spec section that carries numbers without source text, and the scaffold-lane spec assertion),
AC: BSA-AC-1280 (the targeted behavioural-example injection into the retry feedback)."""
from __future__ import annotations

import os

from bts_sbom_app import code_intel, reimpl


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


def test_understand_catalog_metrics_cc_variants_stmts_lines(tmp_path):
    """AC: BSA-AC-1278. The Understand catalog tier measured from conf/understand/metrics (8.1.1269):
    the three cyclomatic flavours, the statement taxonomy (CountStmt/Decl/Exe/Empty), the line taxonomy
    (CountLine/Code/Comment/Blank/RatioCommentToCode), and CountInput/CountOutput (callers + globals
    read / callees + globals set) - hand-computed expectations."""
    src = "\n".join([
        "GV = 0",
        "",
        "",
        "def ccv(a, b, c):",
        "    if a and b and c:",
        "        return 1",
        "    if not a:",
        "        return 2",
        "    return 3",
        "",
        "",
        "def stmts(x):",
        "    y: int = 0",
        "    y = x + 1",
        "    if x:",
        "        pass",
        "    return y",
        "",
        "",
        "def lines(x):",
        "    # a comment",
        "    return x  # note",
        "",
        "",
        "def touch():",
        "    global GV",
        "    GV = GV + 1",
    ]) + "\n"
    (tmp_path / "cat.py").write_text(src, encoding="utf-8")
    r = code_intel.analyze(str(tmp_path))
    ccv = _fn(r, "ccv")
    assert ccv["complexity"] == 5 and ccv["complexity_modified"] == 4 and ccv["complexity_strict"] == 6
    st = _fn(r, "stmts")
    assert st["stmt_total"] == 5 and st["stmt_decl"] == 1 and st["stmt_empty"] == 1
    assert st["stmt_exe"] == 3 and st["stmt_assigns"] == 2 and st["returns"] == 1
    ln = _fn(r, "lines")
    assert ln["count_line"] == 3 and ln["count_line_code"] == 2 and ln["count_line_comment"] == 1
    assert ln["count_line_blank"] == 0 and ln["ratio_comment_to_code"] == 0.5
    touch = _fn(r, "touch")
    assert touch["gvar_reads"] == 1 and touch["gvar_writes"] == 1
    assert touch["count_input"] == 1 and touch["count_output"] == 1


def test_understand_catalog_metrics_lcom_and_cbo(tmp_path):
    """AC: BSA-AC-1278. PercentLackOfCohesion (Henderson-Sellers LCOM*) and CountClassCoupled (CBO)
    per class - hand-computed: Widget m=3 d=2 reach=5 -> LCOM* = 100*(1-5/6) -> 17; Car couples Motor."""
    src = "\n".join([
        "class Widget:",
        "    def __init__(self):",
        "        self.a = 0",
        "        self.b = 0",
        "",
        "    def tick(self, x):",
        "        self.a += x",
        "",
        "    def both(self, x):",
        "        self.a += x",
        "        self.b += x",
        "",
        "",
        "class Motor:",
        "    pass",
        "",
        "",
        "class Car:",
        "    def __init__(self):",
        "        self.motor = Motor()",
    ]) + "\n"
    (tmp_path / "cls.py").write_text(src, encoding="utf-8")
    r = code_intel.analyze(str(tmp_path))
    rows = {c["name"]: c for c in r["classes"]}
    assert rows["Widget"]["lcom"] == 17 and rows["Widget"]["cbo"] == 0
    assert rows["Car"]["cbo"] == 1 and rows["Car"]["lcom"] == 0      # m=1 d=1 reach=1: fully cohesive by the formula
    assert rows["Motor"]["lcom"] is None                            # no methods, no attrs: undefined
    assert rows["Motor"]["cbo"] == 0


def test_metrics_envelope_file_and_spec_section(tmp_path):
    """AC: BSA-AC-1279. The behavioral envelope: one file -> per-function shape facts + totals, and the
    spec section renders numbers only. Wall-2 honesty: the section carries NO source text - no
    statement bodies, no keywords from the implementation - just names, counts and derived values."""
    src = "\n".join([
        "def widen(items):",
        "    total = 0",
        "    for i in items:",
        "        if i > 0 and i < 9:",
        "            total += i",
        "    return total",
        "",
        "",
        "def shallow(x):",
        "    return x",
    ]) + "\n"
    f = tmp_path / "shape.py"
    f.write_text(src, encoding="utf-8")
    env = code_intel.metrics_envelope_file(str(f))
    widen = next(x for x in env["functions"] if x["name"] == "widen")
    assert widen["complexity"] == 4 and widen["essential"] == 2 and widen["stmt_total"] == 5
    assert widen["knots"] == 0 and widen["eloc"] == 6 and widen["params"] == 1
    assert widen["path_count"] == 8
    assert env["totals"]["functions"] == 2 and env["totals"]["eloc"] == 8   # widen 6 + shallow 2
    sec = code_intel.envelope_spec_section(env)
    assert "Behavioral envelope" in sec and "widen" in sec and "| shallow | 1 |" in sec
    # wall-2 honesty: implementation TEXT never rides the spec channel
    assert "total += i" not in sec and "for i in items" not in sec and "def widen" not in sec
    assert "return x" not in sec.replace("reach the same shape any honest way", "")


def test_reimpl_spec_carries_the_envelope_without_source_text(tmp_path):
    """AC: BSA-AC-1279. Even the scaffold lane writes the spec - assert the envelope section landed in
    the spec.md and the original source text did not."""
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "widener.py").write_text(
        "def widen(items):\n    total = 0\n    for i in items:\n        if i > 0:\n            total += i\n    return total\n",
        encoding="utf-8")
    out = tmp_path / "out"
    res = code_intel_reimpl_run(str(src_dir), "widener.py", str(out))
    spec = (out / "spec.md").read_text(encoding="utf-8")
    assert "Behavioral envelope" in spec and "| widen | 1 | 3 | 1 | 5 | 6 |" in spec
    assert "total += i" not in spec and "for i in items" not in spec
    assert res["metrics_envelope"]["totals"]["complexity"] == 3


def code_intel_reimpl_run(source_root, component, out_dir):
    from bts_sbom_app import reimpl
    return reimpl.reimpl(source_root, component, out_dir, client=None, attempts=1)


def test_failing_examples_targeted_oracle_pairs():
    """AC: BSA-AC-1280. The targeted behavioural-example injection: the FAIL blocks' description lines
    yield (function, args, expected) pairs - ONLY failing rows ride the retry prompt, which is the
    measured-safe variant (the full testdata table measured 29/29 failures on 2026-11-22)."""
    tail = "\n".join([
        "mimeparse_test.py -> FAILED",
        "======================================================================",
        "FAIL: unittest.case.FunctionTestCase (legacy_partial_test)",
        "parse_media_range(application/xml ; q=2;b=other) with expected result: ['application', 'xml', {'q': '1', 'b': 'other'}]",
        "----------------------------------------------------------------------",
        "Traceback (most recent call last):",
        "AssertionError: Expected: '('application', 'xml', {'q': '1', 'b': 'other'})' but got ('application', 'xml', {'q': '2', 'b': 'other'})",
        "======================================================================",
        "FAIL: unittest.case.FunctionTestCase (legacy_partial_test)",
        "best_match(['image/*', 'application/xml'], 'image/png') with expected result: image/*",
    ]) + "\n"
    ex = reimpl._failing_examples(tail)
    assert ex[0] == ("parse_media_range", "application/xml ; q=2;b=other",
                     "['application', 'xml', {'q': '1', 'b': 'other'}]")
    assert ex[1] == ("best_match", "['image/*', 'application/xml'], 'image/png'", "image/*")
    assert len(ex) == 2                                              # only FAIL rows, no traceback noise
    assert len(reimpl._failing_examples(tail * 20, limit=8)) == 8    # the cap holds on a huge tail
