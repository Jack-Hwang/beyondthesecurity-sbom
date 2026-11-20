"""AC | EARS pattern | spec section (module) | test node traceability matrix (BSA-AC-381..390).

Ties together three things that already exist but were never joined in one table:

- the spec's AC lines (``- BSA-AC-n [Pattern] ... shall ... <number>``), reusing ``speclint.AC_LINE``;
- the spec's section headers, each named ``## <title> (<module path>[, <module path> ...])``, whose module
  list says which code the section documents;
- the tests' ``AC: BSA-AC-n[, BSA-AC-m ...]`` docstring references, reusing ``speclint.REF``.

Everything here is read-only (it only reads the spec file and the tests tree) and purely a function of its
input: same spec + same tests -> byte-identical ``render_md`` / ``render_json`` output (no timestamps, every
list sorted). That determinism is itself one of this package's AC (BSA-AC-381).
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from . import speclint
from .util import read_text

SPEC_REL = os.path.join("specs", "bts_sbom_app_features.md")
TESTS_REL = os.path.join("tests", "bts_sbom_app")
MODULES_REL = "bts_sbom_app"

# EARS pattern keywords in a fixed order so pattern_counts (and its rendering) never depends on dict/set order.
PATTERNS: Tuple[str, ...] = ("Ubiquitous", "Event", "State", "Optional", "Unwanted")

SECTION_HEADER = re.compile(r"^## (.+)$")
# a top-level "def test_...(" - the function-boundary unit a test reference is attributed to (BSA-AC-382/383).
FUNC_DEF = re.compile(r"^def (test_[A-Za-z0-9_]*)\s*\(", re.MULTILINE)


def _normalize_modules(raw: str) -> List[str]:
    """"bts_sbom_app/a.py, b.py, c.py" -> every bare name inherits the previous full path's directory, so the
    list reads the same way the spec authors write it (one leading path per group)."""
    out: List[str] = []
    prefix = ""
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "/" in item:
            prefix = item.rsplit("/", 1)[0] + "/"
            out.append(item)
        else:
            out.append(prefix + item if prefix else item)
    return out


def parse_sections(spec_text: str) -> List[Dict[str, Any]]:
    """[{title, line, modules}] for every ``## ...`` header, in document order."""
    sections: List[Dict[str, Any]] = []
    for i, line in enumerate(spec_text.splitlines(), start=1):
        m = SECTION_HEADER.match(line)
        if not m:
            continue
        full = m.group(1).strip()
        pm = re.match(r"^(.*?)\s*\(([^()]*)\)\s*$", full)
        if pm:
            title, modules = pm.group(1).strip(), _normalize_modules(pm.group(2))
        else:
            title, modules = full, []
        sections.append({"title": title, "line": i, "modules": modules})
    return sections


def _section_for_line(sections: List[Dict[str, Any]], line: int) -> Optional[Dict[str, Any]]:
    """The last section header at or before ``line`` (an AC belongs to the section it is printed under)."""
    best: Optional[Dict[str, Any]] = None
    for s in sections:
        if s["line"] <= line:
            best = s
        else:
            break
    return best


def parse_ac_lines(spec_text: str) -> List[Dict[str, Any]]:
    """[{id, pattern, body, line}] for every well-formed ``- BSA-AC-n [Pattern] ...`` line, in document order.
    A malformed AC line (speclint's job to flag) is simply not EARS-pattern-matched here and is left out."""
    out: List[Dict[str, Any]] = []
    for i, line in enumerate(spec_text.splitlines(), start=1):
        m = speclint.AC_LINE.match(line)
        if m:
            ident, pattern, body = m.groups()
            out.append({"id": ident, "pattern": pattern, "body": body, "line": i})
    return out


def _ac_num(ac_id: str) -> int:
    try:
        return int(ac_id.rsplit("-", 1)[-1])
    except ValueError:
        return 0


def collect_test_refs(tests_dir: str, label: str = "tests/bts_sbom_app") -> Dict[str, List[str]]:
    """AC id -> sorted ["<label>/<relative path>::<test function>", ...] for every ``AC: BSA-AC-n`` found
    inside a top-level ``def test_...`` function body (including its docstring)."""
    refs: Dict[str, List[str]] = {}
    if not os.path.isdir(tests_dir):
        return refs
    label = label.replace(os.sep, "/").rstrip("/")
    for dp, dns, fns in os.walk(tests_dir):
        dns[:] = sorted(d for d in dns if d != "__pycache__")
        for fn in sorted(fns):
            if not fn.endswith(".py"):
                continue
            fp = os.path.join(dp, fn)
            text = read_text(fp)
            rel = os.path.relpath(fp, tests_dir).replace(os.sep, "/")
            matches = list(FUNC_DEF.finditer(text))
            for i, m in enumerate(matches):
                start = m.end()
                end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
                body = text[start:end]
                ids: List[str] = []
                for rm in speclint.REF.finditer(body):
                    ids.extend(x.strip() for x in rm.group(1).split(","))
                if not ids:
                    continue
                node = "%s/%s::%s" % (label, rel, m.group(1))
                for ident in ids:
                    refs.setdefault(ident, []).append(node)
    for ident in refs:
        refs[ident] = sorted(set(refs[ident]))
    return refs


def undeclared_modules(root: str, modules_rel: str = MODULES_REL, sections: Optional[List[Dict[str, Any]]] = None,
                        spec_text: Optional[str] = None) -> List[str]:
    """``modules_rel``/*.py files that no spec section's module list names (dunder files excluded: ``__init__.py``
    and ``__main__.py`` are package boilerplate, not a feature a spec section documents)."""
    if sections is None:
        if spec_text is None:
            spec_text = read_text(os.path.join(root, SPEC_REL))
        sections = parse_sections(spec_text)
    prefix = modules_rel.replace(os.sep, "/").rstrip("/") + "/"
    declared = {mod for s in sections for mod in s["modules"] if mod.startswith(prefix)}
    mod_dir = os.path.join(root, modules_rel)
    found: List[str] = []
    if os.path.isdir(mod_dir):
        for fn in sorted(os.listdir(mod_dir)):
            if fn.endswith(".py") and not fn.startswith("__") and os.path.isfile(os.path.join(mod_dir, fn)):
                found.append(prefix + fn)
    return sorted(set(found) - declared)


def build(root: str, spec_rel: str = SPEC_REL, tests_rel: str = TESTS_REL, modules_rel: str = MODULES_REL) -> Dict[str, Any]:
    """The full matrix + summary for one tree (the real repo, or a fake one built for a test)."""
    spec_path = os.path.join(root, spec_rel)
    if not os.path.isfile(spec_path):
        raise ValueError("no such spec file: %s" % spec_path)
    spec_text = read_text(spec_path)
    sections = parse_sections(spec_text)
    ac_lines = parse_ac_lines(spec_text)
    by_id: Dict[str, Dict[str, Any]] = {}
    for ac in ac_lines:                          # a duplicate id (speclint's own problem to flag) - last occurrence wins, like speclint.parse
        sect = _section_for_line(sections, ac["line"])
        by_id[ac["id"]] = {"id": ac["id"], "pattern": ac["pattern"], "section": sect["title"] if sect else "",
                            "modules": sect["modules"] if sect else []}
    tests_dir = os.path.join(root, tests_rel)
    refs = collect_test_refs(tests_dir, label=tests_rel)
    rows: List[Dict[str, Any]] = []
    pattern_counts: Dict[str, int] = {p: 0 for p in PATTERNS}
    for ident in sorted(by_id, key=_ac_num):
        ac = by_id[ident]
        pattern_counts[ac["pattern"]] = pattern_counts.get(ac["pattern"], 0) + 1
        rows.append({"id": ident, "pattern": ac["pattern"], "section": ac["section"], "modules": ac["modules"],
                     "tests": refs.get(ident, [])})
    untested = [r["id"] for r in rows if not r["tests"]]
    unknown_refs = sorted((set(refs) - set(by_id)), key=_ac_num)
    undeclared = undeclared_modules(root, modules_rel, sections=sections)
    state_warning = "" if pattern_counts.get("State", 0) > 0 else "no State-pattern (\"While ... shall ...\") AC in this spec"
    summary = {
        "ac_count": len(rows),
        "pattern_counts": pattern_counts,
        "state_pattern_warning": state_warning,
        "untested_acs": untested,
        "unknown_test_refs": unknown_refs,
        "undeclared_modules": undeclared,
    }
    return {"rows": rows, "summary": summary}


def render_md(result: Dict[str, Any]) -> str:
    s = result["summary"]
    L: List[str] = ["# Traceability matrix", "", "| AC | Pattern | Section | Modules | Tests |", "|---|---|---|---|---|"]
    for r in result["rows"]:
        L.append("| %s | %s | %s | %s | %s |" % (
            r["id"], r["pattern"], r["section"] or "(none)", ", ".join(r["modules"]) or "(none)",
            ", ".join(r["tests"]) or "(none)"))
    L += ["", "## Summary", "", "- AC count: %d" % s["ac_count"],
          "- pattern counts: " + ", ".join("%s=%d" % (p, s["pattern_counts"].get(p, 0)) for p in PATTERNS)]
    if s["state_pattern_warning"]:
        L.append("- WARNING: " + s["state_pattern_warning"])
    L.append("- AC with no test: %d (%s)" % (len(s["untested_acs"]), ", ".join(s["untested_acs"]) or "none"))
    L.append("- test references to an AC id missing from the spec: %d (%s)" % (len(s["unknown_test_refs"]), ", ".join(s["unknown_test_refs"]) or "none"))
    L.append("- modules named by no spec section: %d (%s)" % (len(s["undeclared_modules"]), ", ".join(s["undeclared_modules"]) or "none"))
    return "\n".join(L) + "\n"


def render_json(result: Dict[str, Any]) -> str:
    return json.dumps(result, ensure_ascii=True, indent=1, sort_keys=True) + "\n"
