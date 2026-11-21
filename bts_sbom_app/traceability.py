"""Traceability matrix: AC <-> EARS pattern <-> section <-> test node (task 5b) - stdlib only, deterministic.

Reuses speclint.AC_LINE (the spec's AC lines) and speclint.REF (the tests' "AC: BSA-AC-n" docstring refs). The
summary answers the lecture's question "where is the chain unlinked?": ACs without a test, tests citing unknown
ACs, modules that appear in no section's module list, and a warning when the spec holds 0 State-pattern ACs.
Rendering is byte-identical across runs (fixed sort order, no timestamps).
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from . import speclint

SECTION_TITLE = re.compile(r"^## (.+?) \(([^)]+)\)\s*$")


def parse_sections(spec_path: str) -> List[Tuple[str, List[str]]]:
    """[(section title, [module paths])] in spec order."""
    out: List[Tuple[str, List[str]]] = []
    title = ""
    mods: List[str] = []
    with open(spec_path, "r", encoding="utf-8") as fh:
        for line in fh:
            m = SECTION_TITLE.match(line.rstrip("\n"))
            if m:
                if title:
                    out.append((title, mods))
                title, mods = m.group(1).strip(), [x.strip() for x in m.group(2).split(",") if x.strip()]
    if title:
        out.append((title, mods))
    return out


def _acs_in_section(spec_path: str) -> Dict[str, Tuple[str, str]]:
    """AC id -> (pattern, section title)."""
    out: Dict[str, Tuple[str, str]] = {}
    title = ""
    with open(spec_path, "r", encoding="utf-8") as fh:
        for line in fh:
            m = SECTION_TITLE.match(line.rstrip("\n"))
            if m:
                title = m.group(1).strip()
                continue
            m2 = speclint.AC_LINE.match(line.rstrip("\n"))
            if m2 and title:
                out[m2.group(1)] = (m2.group(2), title)
    return out


def test_nodes(tests_dir: str) -> Dict[str, List[str]]:
    """AC id -> [test node ids "tests/<...>/<file>::<func>"] (docstring citations only)."""
    out: Dict[str, List[str]] = {}
    for dp, dns, fns in os.walk(tests_dir):
        dns[:] = sorted(d for d in dns if d != "__pycache__")
        for fn in sorted(fns):
            if not fn.endswith(".py"):
                continue
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, os.path.dirname(tests_dir)).replace("\\", "/")
            lines = open(full, encoding="utf-8", errors="replace").read().splitlines()
            for i, ln in enumerate(lines):
                m = speclint.REF.search(ln)
                if m:
                    func = None
                    for back in range(i - 1, -1, -1):          # the AC citation sits INSIDE the def's docstring:
                        fm = re.match(r"^def (test_[A-Za-z0-9_]+)\(", lines[back])   # the owner is the nearest def above
                        if fm:
                            func = fm.group(1)
                            break
                    for ac in [x.strip() for x in m.group(1).split(",") if x.strip()]:
                        node = "%s::%s" % (rel, func or "?")
                        out.setdefault(ac, [])
                        if node not in out[ac]:
                            out[ac].append(node)
    return out


def build(root: Optional[str] = None) -> Dict[str, Any]:
    """The full matrix + summary. Deterministic: every list is sorted."""
    root = root or os.getcwd()
    spec_path = os.path.join(root, "specs", "bts_sbom_app_features.md")
    tests_dir = os.path.join(root, "tests")
    acs = speclint.parse(spec_path)
    per_section = _acs_in_section(spec_path)
    sections = parse_sections(spec_path)
    nodes = test_nodes(os.path.join(tests_dir, "bts_sbom_app")) if os.path.isdir(os.path.join(tests_dir, "bts_sbom_app")) else test_nodes(tests_dir)
    rows = []
    for ac in sorted(acs, key=lambda s: int(s.split("-")[-1])):
        pat, section = per_section.get(ac, ("", ""))
        rows.append({"ac": ac, "pattern": pat, "section": section, "tests": sorted(nodes.get(ac, []))})
    without_tests = sorted(nodes_all_missing(acs, nodes), key=lambda s: int(s.split("-")[-1]))
    unknown_refs = sorted(set(nodes) - set(acs), key=lambda s: int(s.split("-")[-1]))
    named_modules = {os.path.basename(m) for _t, mods in sections for m in mods}
    all_modules = sorted(fn for fn in os.listdir(os.path.join(root, "bts_sbom_app")) if fn.endswith(".py") and fn != "__init__.py")
    unspecified = [m for m in all_modules if m not in named_modules]
    state_count = sum(1 for ac in acs if per_section.get(ac, ("", ""))[0] == "State")
    summary = {"acs": len(acs), "without_test": len(without_tests), "unknown_refs": len(unknown_refs),
               "pattern_counts": _pattern_counts(acs, per_section),
               "unspecified_modules": unspecified,
               "state_pattern_warning": "0 State-pattern ACs in the spec" if state_count == 0 else None}
    return {"rows": rows, "summary": summary}


def nodes_all_missing(acs: Dict[str, str], nodes: Dict[str, List[str]]):
    for ac in acs:
        if not nodes.get(ac):
            yield ac


def _pattern_counts(acs: Dict[str, str], per_section: Dict[str, Tuple[str, str]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for ac in acs:
        pat = per_section.get(ac, ("", ""))[0] or "?"
        counts[pat] = counts.get(pat, 0) + 1
    return counts


def render_json(matrix: Dict[str, Any]) -> str:
    return json.dumps(matrix, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def render_md(matrix: Dict[str, Any]) -> str:
    lines = ["# Traceability matrix", "", "| AC | EARS pattern | section | tests |", "|---|---|---|---|"]
    for row in matrix["rows"]:
        tests = "<br>".join("`%s`" % t for t in row["tests"]) or "-"
        lines.append("| %s | %s | %s | %s |" % (row["ac"], row["pattern"] or "?", row["section"] or "?", tests))
    s = matrix["summary"]
    lines += ["", "## Summary", "", "- ACs: %d" % s["acs"],
              "- pattern counts: %s" % json.dumps(s["pattern_counts"], sort_keys=True),
              "- ACs without a test: %d %s" % (s["without_test"], "(%s)" % ", ".join(s.get("_missing", [])) if False else ""),
              "- tests citing unknown ACs: %d" % s["unknown_refs"],
              "- modules named in no section: %s" % (", ".join("`%s`" % m for m in s["unspecified_modules"]) or "none")]
    if s["state_pattern_warning"]:
        lines.append("- WARNING: %s" % s["state_pattern_warning"])
    return "\n".join(lines) + "\n"
