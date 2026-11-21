"""Documentation lint: ADRs, governance docs, runbook, enforcement map (task 5a) - stdlib only.

Every "… lint PASS" gate reuses this one place. Documents are checked by their KIND against a required-section
list (a heading line counts when one of the aliases appears as a SUBSTRING, case-insensitive, English or Korean).
A document that is absent is printed as "not present" and counted as 0 passes - absence is never a pass.
Kinds: adr, impact, modelcard, lineage, datacontract, runbook, enforcement.

Usage: python -m bts_sbom_app.doclint [--strict] [--kind KIND] [paths...]
Exit code 1 when any problem is found (strict mode additionally flags TODO/FIXME/<placeholder> markers).
"""
from __future__ import annotations

import os
import re
import sys
from typing import Dict, List, Tuple

SECTIONS: Dict[str, Tuple[Tuple[str, ...], ...]] = {
    # each required section: aliases; a heading line containing any alias (case-insensitive) satisfies it
    "adr": (("status", "상태"), ("context", "rationale", "근거"), ("decision", "결정"), ("rejected alternatives", "alternatives", "기각 대안"), ("consequences", "결과")),
    "impact": (("시스템 개요", "system overview", "overview"), ("고영향", "high-impact"), ("이해관계자", "stakeholder"),
               ("위험", "risk"), ("완화", "mitigation"), ("감독", "human oversight", "oversight"), ("모니터링", "monitoring"), ("잔여 위험", "residual")),
    "modelcard": (("model details", "모델 개요"), ("intended use", "사용 목적"), ("evaluation", "평가"), ("limitations", "한계"), ("risks", "윤리", "위험")),
    "lineage": (("sources", "출처"), ("collection", "수집"), ("freshness", "신선도", "갱신"), ("failure", "실패"), ("terms", "이용 조건")),
    "datacontract": (("schema", "스키마"), ("invariants", "불변식"), ("versioning", "버전"), ("compatibility", "호환")),
    "runbook": (("delivery state",), ("deployment", "배포"), ("rollback", "롤백"), ("monitoring", "모니터링")),
    "enforcement": (),
}

STRICT_MARKERS = re.compile(r"\bTODO\b|\bFIXME\b|<[^<>\n]{1,60}>")

ENFORCEMENT_MIN_ROWS = 12


def _headings(text: str) -> List[str]:
    return [ln.strip() for ln in text.splitlines() if ln.strip().startswith("#")]


def lint_doc(text: str, kind: str, *, strict: bool = False) -> List[str]:
    """Pure: text + kind -> problems. Tests feed strings directly."""
    problems: List[str] = []
    heads = _headings(text)
    low_heads = [h.lower() for h in heads]
    if kind == "enforcement":
        problems += _lint_enforcement(text)
    else:
        for aliases in SECTIONS.get(kind, ()):
            if not any(any(alias in h for alias in aliases) for h in low_heads):
                problems.append("missing required section: %s" % "/".join(aliases))
        if kind == "adr":
            # the rejected-alternatives section must carry at least one list item
            in_rejected = False
            has_item = False
            found = False
            for ln in text.splitlines():
                s = ln.strip().lower()
                if s.startswith("#"):
                    in_rejected = any(a in s for a in ("rejected alternatives", "alternatives", "기각 대안"))
                    if in_rejected:
                        found = True
                elif in_rejected and ln.strip().startswith("- "):
                    has_item = True
            if found and not has_item:
                problems.append("rejected alternatives section has no list item")
    if strict:
        for i, ln in enumerate(text.splitlines(), start=1):
            # <...> inside a `code span` is a documented convention (e.g. GET /api/jobs/<id>), not unfinished work
            probe = re.sub(r"`[^`]*`", "", ln)
            if STRICT_MARKERS.search(probe):
                problems.append("strict: placeholder marker at line %d" % i)
                break                                                # one marker finding is enough to fail strict mode
    return problems


def _lint_enforcement(text: str) -> List[str]:
    problems: List[str] = []
    rows = [ln for ln in text.splitlines() if ln.strip().startswith("|") and "---" not in ln]
    rows = rows[1:] if len(rows) > 1 else rows                    # drop the header row
    if len(rows) < ENFORCEMENT_MIN_ROWS:
        problems.append("enforcement map needs at least %d rows, found %d" % (ENFORCEMENT_MIN_ROWS, len(rows)))
    repo = os.environ.get("BTS_SBOM_REPO_ROOT") or os.getcwd()
    for row in rows:
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        if len(cells) < 4:
            problems.append("row needs 4 columns (위험|강제 수단|위치|검증 테스트): %s" % row.strip()[:60])
            continue
        location, test = cells[2], cells[3] if len(cells) >= 4 else (cells[-2], cells[-1])
        if "`" in location:
            location = location.strip("`")
        if "`" in test:
            test = test.strip("`")
        location = location.split(":")[0]
        m = re.match(r"(tests/[\w/]+\.py)::?([\w_]+)?", test)
        if not m:
            problems.append("dangling reference (test): %s" % test[:60])
            continue
        tpath, func = m.group(1), m.group(2)
        full = os.path.join(repo, tpath)
        if not os.path.isfile(full):
            problems.append("dangling reference (file): %s" % tpath)
            continue
        if func:
            content = open(full, encoding="utf-8", errors="replace").read()
            if not re.search(r"def %s\s*\(" % re.escape(func), content):
                problems.append("dangling reference (function): %s::%s" % (tpath, func))
        if location and not (os.path.isfile(os.path.join(repo, location)) or os.path.isdir(os.path.join(repo, location))):
            problems.append("dangling reference (location): %s" % location)
    return problems


_DEFAULT_TARGETS: List[Tuple[str, str, str]] = [
    ("adr", "docs/adr", "*.md"),
    ("impact", "docs/governance/AI_IMPACT_ASSESSMENT.md", ""),
    ("modelcard", "docs/governance/MODEL_CARD.md", ""),
    ("lineage", "docs/governance/ORIGIN_LINEAGE.md", ""),
    ("datacontract", "docs/governance/DATA_CONTRACT.md", ""),
    ("runbook", "docs/RUNBOOK.md", ""),
    ("enforcement", "docs/ENFORCEMENT_MAP.md", ""),
]


def collect(root: str, paths: List[str]) -> List[Tuple[str, str]]:
    """(kind, path) for an explicit path list, or the default document set under ``root``."""
    if paths:
        out = []
        for p in paths:
            out.append(("adr", p) if "adr" in p.lower() else ("runbook", p))
        return out
    targets: List[Tuple[str, str]] = []
    for kind, rel, pattern in _DEFAULT_TARGETS:
        full = os.path.join(root, rel)
        if pattern:
            if os.path.isdir(full):
                for fn in sorted(os.listdir(full)):
                    if fn.endswith(".md"):
                        targets.append((kind, os.path.join(full, fn)))
            continue
        targets.append((kind, full))
    return targets


def run(argv: List[str]) -> int:
    strict = "--strict" in argv
    argv = [a for a in argv if a != "--strict"]
    kind_filter = None
    if "--kind" in argv:
        i = argv.index("--kind")
        kind_filter = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    root = os.environ.get("BTS_SBOM_REPO_ROOT") or os.getcwd()
    if argv and not argv[0].startswith("-"):
        paths = argv
    else:
        paths = []
    total_problems = 0
    for kind, path in collect(root, paths):
        if kind_filter and kind != kind_filter:
            continue
        label = os.path.relpath(path, root) if os.path.isabs(path) else path
        try:
            text = open(path, encoding="utf-8").read()
        except OSError:
            print("%-12s %s: not present (counted as 0 passes)" % (kind, label))
            continue
        problems = lint_doc(text, kind, strict=strict)
        total_problems += len(problems)
        if problems:
            print("%-12s %s: %d problem(s)" % (kind, label, len(problems)))
            for p in problems:
                print("    - %s" % p)
        else:
            print("%-12s %s: OK" % (kind, label))
    print("doclint: %d problem(s)%s" % (total_problems, " (strict)" if strict else ""))
    return 1 if total_problems else 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
