"""Spec lint + traceability (lecture 'EARS lint': pattern keyword + shall + a measured number).

lint(path)   -> list of problems: every AC line must carry an id, one of the 5 EARS pattern keywords, the word "shall",
                and at least one digit (the measured number)
trace(specs, tests) -> (ac ids without any test, test-referenced ids missing from the spec)
all_patterns_covered(path) -> whole-document coverage gate: a line can be individually well-shaped yet
                the document as a whole never use one of the 5 EARS patterns; returns the pattern
                keywords with 0 occurrences anywhere in the file (empty list means all 5 are covered)
"""
from __future__ import annotations

import os
import re
from typing import Dict, List, Set, Tuple

PATTERNS: Tuple[str, ...] = ("Ubiquitous", "Event", "State", "Optional", "Unwanted")
AC_LINE = re.compile(r"^- (BSA-AC-\d+) \[(Ubiquitous|Event|State|Optional|Unwanted)\] (.*)$")
ANY_AC = re.compile(r"^- (BSA-AC-\d+)\b")
REF = re.compile(r"AC:\s*((?:BSA-AC-\d+(?:\s*,\s*)?)+)")


def parse(path: str) -> Dict[str, str]:
    acs: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            m = AC_LINE.match(line.rstrip("\n"))
            if m:
                acs[m.group(1)] = m.group(3)
    return acs


def lint(path: str) -> List[str]:
    problems: List[str] = []
    seen: Set[str] = set()
    with open(path, "r", encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not ANY_AC.match(line):
                continue
            m = AC_LINE.match(line)
            if not m:
                problems.append("line %d: not in the form '- BSA-AC-n [Pattern] ...'" % n)
                continue
            ident, _pat, body = m.groups()
            if ident in seen:
                problems.append("line %d: duplicate id %s" % (n, ident))
            seen.add(ident)
            if not re.search(r"\bshall\b", body):
                problems.append("%s: no 'shall'" % ident)
            if not re.search(r"\d", body):
                problems.append("%s: no measured number" % ident)
    return problems


def trace(spec_path: str, tests_dir: str) -> Tuple[List[str], List[str]]:
    acs = set(parse(spec_path))
    refs: Set[str] = set()
    for dp, _, fns in os.walk(tests_dir):
        for fn in fns:
            if fn.endswith(".py"):
                with open(os.path.join(dp, fn), "r", encoding="utf-8") as fh:
                    for m in REF.finditer(fh.read()):
                        refs.update(x.strip() for x in m.group(1).split(","))
    return sorted(acs - refs, key=lambda s: int(s.split("-")[-1])), sorted(refs - acs)


def all_patterns_covered(path: str) -> List[str]:
    """Whole-document gate: an individual AC line can be correctly shaped (lint() passes) while the
    document as a whole never uses one of the 5 EARS pattern keywords. Return the keywords (in the
    canonical order) with 0 occurrences anywhere in `path`; an empty list means all 5 are covered."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    return [p for p in PATTERNS if not re.search(r"\[%s\]" % re.escape(p), text)]


if __name__ == "__main__":
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = os.path.join(root, "specs", "bts_sbom_app_features.md")
    probs = lint(spec)
    missing, extra = trace(spec, os.path.join(root, "tests"))
    missing_patterns = all_patterns_covered(spec)
    for p in probs:
        print("LINT", p)
    print("ACs without a test:", missing)
    print("test references to unknown ACs:", extra)
    print("EARS patterns with 0 occurrences in the spec:", missing_patterns)
    sys.exit(1 if probs or missing or extra or missing_patterns else 0)
