"""Document lint for the governance doc pack: ADRs, the AI impact assessment, the model card, the origin/lineage
note, the data contract, the runbook and the enforcement map.

Every check is a pure function - ``str`` (the document text) in, a list of problem strings out - so the whole lint
can be exercised with hand-written strings, no filesystem needed (the enforcement-map check additionally needs a
repo root to confirm that a referenced file/function/test actually exists, since its entire job is to catch a
dangling reference).

Kind is picked from the file name unless ``--kind`` overrides it:
  adr(docs/adr/ADR-*.md) impact(AI_IMPACT_ASSESSMENT.md) modelcard(MODEL_CARD.md) lineage(ORIGIN_LINEAGE.md)
  datacontract(DATA_CONTRACT.md) runbook(RUNBOOK.md) enforcement(ENFORCEMENT_MAP.md)

``--strict`` additionally rejects TODO/FIXME markers and ``<placeholder>`` angle-bracket text. Exit code is 1 if any
document has a problem, 0 otherwise (including when nothing was found to lint).
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

HEADING = re.compile(r"^(#{1,6})\s*(.+?)\s*#*\s*$")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+\S")
PLACEHOLDER = re.compile(r"<[A-Za-z0-9가-힣 _/.\-]{1,60}>")
TABLE_ROW = re.compile(r"^\s*\|(.+)\|\s*$")
TABLE_SEP_CELL = re.compile(r"^:?-{1,}:?$")

# kind -> [(label, [alias substrings, lower-case])]
SECTIONS: Dict[str, List[Tuple[str, List[str]]]] = {
    "adr": [
        ("Status", ["status", "상태"]),
        ("Context", ["context", "rationale", "근거"]),
        ("Decision", ["decision", "결정"]),
        ("Rejected alternatives", ["rejected alternatives", "alternatives", "기각 대안", "기각대안"]),
        ("Consequences", ["consequences", "결과"]),
    ],
    "impact": [
        ("System overview", ["시스템 개요", "system overview"]),
        ("High-impact AI determination", ["고영향 ai", "고영향 인공지능", "high-impact ai", "high impact ai"]),
        ("Stakeholders", ["이해관계자", "stakeholder"]),
        ("Risk identification", ["위험 식별", "risk identification"]),
        ("Mitigation", ["완화 조치", "완화조치", "mitigation"]),
        ("Human oversight", ["사람 감독", "인간 감독", "human oversight"]),
        ("Monitoring", ["모니터링", "monitoring"]),
        ("Residual risk", ["잔여 위험", "잔여위험", "residual risk"]),
    ],
    "modelcard": [
        ("Model details", ["모델 개요", "model details"]),
        ("Intended use", ["사용 목적과 범위", "사용 목적", "intended use"]),
        ("Evaluation", ["데이터", "평가", "evaluation"]),
        ("Limitations", ["한계", "limitations"]),
        ("Risks", ["윤리", "위험", "risks"]),
    ],
    "lineage": [
        ("Sources", ["출처", "sources"]),
        ("Collection", ["수집 방법", "수집", "collection"]),
        ("Freshness", ["신선도", "갱신", "freshness"]),
        ("Failure behavior", ["실패 시 동작", "실패 시", "failure behavior"]),
        ("Terms", ["이용 조건", "terms"]),
    ],
    "datacontract": [
        ("Schema", ["스키마", "schema"]),
        ("Invariants", ["불변식", "invariants"]),
        ("Versioning", ["버전", "versioning"]),
        ("Compatibility", ["호환", "compatibility"]),
    ],
    "runbook": [
        ("Delivery State", ["delivery state"]),
        ("Deployment", ["deployment"]),
        ("Rollback", ["rollback"]),
        ("Monitoring", ["monitoring"]),
    ],
}

# file-name substring (lower-case, no extension requirement) -> kind
KIND_BY_NAME = [
    ("ai_impact_assessment", "impact"),
    ("model_card", "modelcard"),
    ("origin_lineage", "lineage"),
    ("data_contract", "datacontract"),
    ("enforcement_map", "enforcement"),
    ("runbook", "runbook"),
]

KINDS = tuple(SECTIONS) + ("enforcement",)


def detect_kind(path: str) -> Optional[str]:
    base = os.path.basename(path).lower()
    if re.match(r"adr-\d+", base):
        return "adr"
    for needle, kind in KIND_BY_NAME:
        if needle in base:
            return kind
    return None


def _headings(text: str) -> List[Tuple[int, int, str]]:
    """(line number 1-based, heading level, heading text) for every markdown heading line."""
    out: List[Tuple[int, int, str]] = []
    for n, line in enumerate(text.splitlines(), 1):
        m = HEADING.match(line)
        if m:
            out.append((n, len(m.group(1)), m.group(2)))
    return out


def check_sections(text: str, kind: str) -> List[str]:
    # level 1 is the document title (e.g. "# ADR-0007: ..."), never a required section - matching against it would let
    # a title that happens to mention a section's word (e.g. "...decision..." in prose) hide a genuinely missing section.
    heads = [h.lower() for _, level, h in _headings(text) if level >= 2]
    problems: List[str] = []
    for label, aliases in SECTIONS.get(kind, []):
        if not any(any(a in h for h in heads) for a in aliases):
            problems.append("missing section: %s (looked for a heading containing one of %s)" % (label, aliases))
    return problems


def _section_body(text: str, aliases: List[str]) -> Optional[str]:
    """Text between the first level->=2 heading matching one of ``aliases`` and the next heading of the same or a
    shallower level (None if no such heading is present). Level 1 (the document title) is never a section."""
    heads = _headings(text)
    lines = text.splitlines()
    for i, (lineno, level, htext) in enumerate(heads):
        if level >= 2 and any(a in htext.lower() for a in aliases):
            start = lineno  # 1-based line of the heading itself; body starts the line after
            end = len(lines)
            for lineno2, level2, _ in heads[i + 1:]:
                if level2 <= level:
                    end = lineno2 - 1
                    break
            return "\n".join(lines[start:end])
    return None


def check_rejected_alternatives(text: str) -> List[str]:
    aliases = next(a for label, a in SECTIONS["adr"] if label == "Rejected alternatives")
    body = _section_body(text, aliases)
    if body is None:
        return []  # already reported by check_sections as a missing section
    if not any(LIST_ITEM.match(line) for line in body.splitlines()):
        return ["Rejected alternatives section has 0 list items (need >= 1 real alternative that was actually considered)"]
    return []


def check_placeholders(text: str) -> List[str]:
    """TODO/FIXME anywhere; ``<angle>`` placeholders only in prose. Text inside `inline code` or a fenced block is a command or
    URL template (e.g. /api/jobs/<id>/events), which is documentation, not an unfilled placeholder."""
    problems: List[str] = []
    in_fence = False
    for n, line in enumerate(text.splitlines(), 1):
        if re.search(r"\bTODO\b", line) or re.search(r"\bFIXME\b", line):
            problems.append("line %d: TODO/FIXME placeholder left in a document that must be final" % n)
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        prose = re.sub(r"`[^`]*`", "", line)
        for m in PLACEHOLDER.finditer(prose):
            problems.append("line %d: placeholder-like text %r left unfilled" % (n, m.group(0)))
    return problems


def _table_rows(text: str) -> List[Tuple[int, List[str]]]:
    """(line number, cells) for every data row of the first markdown table found (header + separator skipped)."""
    lines = text.splitlines()
    rows: List[Tuple[int, List[str]]] = []
    header_cells: Optional[List[str]] = None
    sep_seen = False
    for n, line in enumerate(lines, 1):
        m = TABLE_ROW.match(line)
        if not m:
            if header_cells is not None and sep_seen:
                break  # table ended
            continue
        cells = [c.strip() for c in m.group(1).split("|")]
        if header_cells is None:
            header_cells = cells
            continue
        if not sep_seen and all(TABLE_SEP_CELL.match(c) for c in cells if c):
            sep_seen = True
            continue
        if sep_seen:
            rows.append((n, cells))
    return rows


def _header_index(text: str, aliases: List[str]) -> Optional[int]:
    lines = text.splitlines()
    for line in lines:
        m = TABLE_ROW.match(line)
        if m:
            cells = [c.strip().lower() for c in m.group(1).split("|")]
            for i, c in enumerate(cells):
                if any(a in c for a in aliases):
                    return i
            return None
    return None


_LOC_RE = re.compile(r"^`?([^`:]+?\.py)(?::([A-Za-z_][A-Za-z0-9_]*))?`?$")
_TEST_RE = re.compile(r"^`?([^`]+?\.py)::([A-Za-z_][A-Za-z0-9_]*)`?$")


def _resolve_inside(repo_root: str, rel_path: str) -> Optional[str]:
    """Real path of ``rel_path`` under ``repo_root``, or None when it would leave the repository (``..``, an absolute path, a symlink)."""
    root = os.path.realpath(repo_root)
    full = os.path.realpath(os.path.join(root, rel_path))
    if full != root and not full.startswith(root + os.sep):
        return None
    return full


def _func_defined(repo_root: str, rel_path: str, func: str) -> bool:
    full = _resolve_inside(repo_root, rel_path)
    if full is None or not os.path.isfile(full):
        return False
    try:
        with open(full, "r", encoding="utf-8") as fh:
            body = fh.read()
    except (OSError, UnicodeDecodeError):
        return False
    return re.search(r"^\s*(?:async\s+def|def|class)\s+%s\b" % re.escape(func), body, re.M) is not None


def check_enforcement_table(text: str, repo_root: Optional[str] = None) -> List[str]:
    problems: List[str] = []
    risk_i = _header_index(text, ["위험", "risk"])
    mech_i = _header_index(text, ["강제", "enforcement"])
    loc_i = _header_index(text, ["위치", "location"])
    test_i = _header_index(text, ["검증", "test"])
    if None in (risk_i, mech_i, loc_i, test_i):
        missing = [name for name, i in (("risk", risk_i), ("enforcement mechanism", mech_i), ("location", loc_i),
                                         ("verifying test", test_i)) if i is None]
        return ["enforcement table is missing column(s): %s" % ", ".join(missing)]
    rows = _table_rows(text)
    if not rows:
        return ["enforcement table has 0 data rows"]
    for n, cells in rows:
        if max(risk_i, mech_i, loc_i, test_i) >= len(cells):
            problems.append("line %d: row has fewer columns than the header" % n)
            continue
        loc = cells[loc_i].strip()
        test = cells[test_i].strip()
        lm = _LOC_RE.match(loc)
        if not lm:
            problems.append("line %d: location %r is not a file path (optionally file.py:function)" % (n, loc))
        elif repo_root is not None:
            rel, func = lm.group(1), lm.group(2)
            full = _resolve_inside(repo_root, rel)
            if full is None:
                problems.append("line %d: location path leaves the repository: %s" % (n, rel))
            elif not os.path.isfile(full):
                problems.append("line %d: location references a file that does not exist: %s" % (n, rel))
            elif func and not _func_defined(repo_root, rel, func):
                problems.append("line %d: location references %s:%s but that function/class was not found" % (n, rel, func))
        tm = _TEST_RE.match(test)
        if not tm:
            problems.append("line %d: verifying test %r is not in the form tests/.../test_x.py::test_y" % (n, test))
        elif repo_root is not None:
            rel, func = tm.group(1), tm.group(2)
            full = _resolve_inside(repo_root, rel)
            if full is None:
                problems.append("line %d: verifying test path leaves the repository: %s" % (n, rel))
            elif not os.path.isfile(full):
                problems.append("line %d: verifying test references a file that does not exist: %s" % (n, rel))
            elif not _func_defined(repo_root, rel, func):
                problems.append("line %d: verifying test references %s::%s but that test function was not found" % (n, rel, func))
    return problems


def lint_text(text: str, kind: str, *, strict: bool = False, repo_root: Optional[str] = None) -> List[str]:
    if kind not in KINDS:
        return ["unknown document kind: %s (expected one of %s)" % (kind, KINDS)]
    problems: List[str] = []
    if kind == "enforcement":
        problems += check_enforcement_table(text, repo_root)
    else:
        problems += check_sections(text, kind)
        if kind == "adr":
            problems += check_rejected_alternatives(text)
    if strict:
        problems += check_placeholders(text)
    return problems


def lint_file(path: str, *, kind: Optional[str] = None, strict: bool = False, repo_root: Optional[str] = None) -> List[str]:
    eff_kind = kind or detect_kind(path)
    if eff_kind is None:
        return ["cannot determine document kind from file name: %s (pass --kind)" % path]
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError) as exc:
        return ["could not read %s: %s" % (path, exc)]
    return lint_text(text, eff_kind, strict=strict, repo_root=repo_root)


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def discover(root: str) -> Tuple[List[Tuple[str, str]], List[str]]:
    """Every governance document that is supposed to exist: (found (path, kind) pairs, 'not present' notes)."""
    found: List[Tuple[str, str]] = []
    missing: List[str] = []
    adrs = sorted(glob.glob(os.path.join(root, "docs", "adr", "ADR-*.md")))
    if adrs:
        found += [(p, "adr") for p in adrs]
    else:
        missing.append("docs/adr/ADR-*.md: none present")
    governance_glob = sorted(glob.glob(os.path.join(root, "docs", "governance", "*.md")))
    for needle, kind in KIND_BY_NAME:
        if kind in ("runbook", "enforcement"):
            continue  # fixed single paths directly under docs/, handled below (not a docs/governance/ glob)
        matches = [p for p in governance_glob if needle in os.path.basename(p).lower()]
        if matches:
            found += [(p, kind) for p in matches]
        else:
            missing.append("docs/governance/*%s*.md: not present" % needle)
    runbook = os.path.join(root, "docs", "RUNBOOK.md")
    if os.path.isfile(runbook):
        found.append((runbook, "runbook"))
    else:
        missing.append("docs/RUNBOOK.md: not present (owned by another package)")
    enforcement = os.path.join(root, "docs", "ENFORCEMENT_MAP.md")
    if os.path.isfile(enforcement):
        found.append((enforcement, "enforcement"))
    else:
        missing.append("docs/ENFORCEMENT_MAP.md: not present")
    return found, missing


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="bts_sbom_app.doclint", description="Lint ADRs / governance docs / runbook / enforcement map")
    ap.add_argument("paths", nargs="*", help="documents to lint (default: discover under docs/)")
    ap.add_argument("--strict", action="store_true", help="also reject TODO/FIXME and <placeholder> text")
    ap.add_argument("--kind", choices=KINDS, help="force the document kind for every given path (ignored with no paths)")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    from .util import console_text

    a = build_parser().parse_args(argv)
    root = _repo_root()
    problems_total = 0
    if a.paths:
        for p in a.paths:
            probs = lint_file(p, kind=a.kind, strict=a.strict, repo_root=root)
            print(console_text("== %s ==" % p))
            if not probs:
                print(console_text("  ok"))
            for pr in probs:
                print(console_text("  PROBLEM: %s" % pr))
            problems_total += len(probs)
    else:
        found, missing = discover(root)
        for note in missing:
            print(console_text("(skip) " + note))
        for path, kind in found:
            probs = lint_file(path, kind=kind, strict=a.strict, repo_root=root)
            print(console_text("== %s [%s] ==" % (os.path.relpath(path, root), kind)))
            if not probs:
                print(console_text("  ok"))
            for pr in probs:
                print(console_text("  PROBLEM: %s" % pr))
            problems_total += len(probs)
    return 1 if problems_total else 0


if __name__ == "__main__":
    sys.exit(main())
