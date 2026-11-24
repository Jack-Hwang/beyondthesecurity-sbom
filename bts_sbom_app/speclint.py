"""Spec lint + traceability (lecture 'EARS lint': pattern keyword + shall + a measured number).

lint(path)   -> list of problems: every AC line must carry an id, one of the 5 EARS pattern keywords, the word "shall",
                and at least one digit (the measured number)
trace(specs, tests) -> (ac ids without any test, test-referenced ids missing from the spec)
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Set, Tuple

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


# Requirement-kind tagging (the lecture's 6-way split of a requirement set): SFR functional, DAR data, PER performance,
# SIR interface, SECR security, CONR constraint. Deterministic keyword rules, FIRST match wins in the order below
# (security beats performance: "the approval token shall arrive within 2s" is a security requirement with a deadline),
# and SFR is the default: an unclassifiable requirement is a functional one, never silently dropped. The result is
# informational - it shows which KINDS of requirements the spec carries, it gates nothing.
REQ_KINDS = ("SFR", "DAR", "PER", "SIR", "SECR", "CONR")
_KIND_RULES = (
    ("SECR", re.compile(r"approval token|access token|인증 토큰|접근 토큰|secret|api key|credential|인증|인가|보안|주입|escap|csp|cors|"
                        r"host 헤더|host header|allowlist|allow-list|approval|승인|신뢰 불가|untrusted|권한|inject|dns rebinding|"
                        r"리바인딩|서명|digest", re.I)),
    ("PER", re.compile(r"\bp95\b|latency|지연|속도|\btimeout\b|타임아웃|within \d|초 이내|초 안|이내에|밀리초|\bms\b|first token|첫 토큰|"
                       r"\b\d+\s*(?:s|sec|seconds)\b", re.I)),
    ("CONR", re.compile(r"stdlib|표준 라이브러리|의존성 없|zero.depen|python \d|windows|linux|macos|플랫폼|offline|오프라인|"
                        r"네트워크 없|no network|without network|메모리|용량|크기 제한|바이트", re.I)),
    ("SIR", re.compile(r"\bapi\b|endpoint|route|/api/|\bcli\b|명령|sse|event stream|export\b|import\b|인터페이스|web|화면|"
                       r"\bui\b|렌더|render|브라우저|console|stdout|다운로드|download", re.I)),
    ("DAR", re.compile(r"schema|계약|contract|데이터|dataset|record|jsonl|캐시|cache|저장|evidence|필드|ledger|장부|버전 기록|"
                       r"원본|baseline|이력", re.I)),
)


def reqmap(path: str) -> Dict[str, Any]:
    """Tag every AC with one requirement kind. Returns {kinds: {kind: count}, ids: {kind: [ac ids]}, total, defaults}."""
    by: Dict[str, List[str]] = dict((k, []) for k in REQ_KINDS)
    defaults = 0
    for ident, body in parse(path).items():
        kind = next((k for k, rx in _KIND_RULES if rx.search(body)), None)
        if kind is None:
            kind, defaults = "SFR", defaults + 1
        by[kind].append(ident)
    return {"kinds": {k: len(v) for k, v in by.items()}, "ids": by, "total": sum(len(v) for v in by.values()), "defaults": defaults}


if __name__ == "__main__":
    import sys
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = os.path.join(root, "specs", "bts_sbom_app_features.md")
    probs = lint(spec)
    missing, extra = trace(spec, os.path.join(root, "tests"))
    rm = reqmap(spec)
    for p in probs:
        print("LINT", p)
    print("ACs without a test:", missing)
    print("test references to unknown ACs:", extra)
    print("REQ-KINDS " + " ".join("%s=%d" % (k, rm["kinds"][k]) for k in REQ_KINDS) + " total=%d sfr_default=%d" % (rm["total"], rm["defaults"]))
    sys.exit(1 if probs or missing or extra else 0)
