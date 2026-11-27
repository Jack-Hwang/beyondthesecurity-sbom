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


# --------------------------------------------------------------------------- reverse traceability (C63): surfaces with zero spec mention

_CLI_RE = re.compile(r'add_parser\(\s*"([a-z0-9][a-z0-9\-]*)"?')
_ROUTE_RE = re.compile(r'["\'](/(?:api|healthz|readyz|\.well-known)/[^"\']*)["\']')
_GENERIC_SEGMENTS = {"api", "jobs", "arch", "v1", "v2"}


def _norm_route(path: str) -> str:
    """A route literal as the spec would name it: keep the first two segments, strip a trailing slash and query."""
    p = path.split("?")[0].strip("/")
    segs = [s for s in p.split("/") if s]
    keep = segs[:2] if segs and segs[0] == "api" else segs[:1]
    return "/" + "/".join(keep)


def surface_trace(spec_path: str, app_root: str) -> Dict[str, Any]:
    """Every registered CLI subcommand and HTTP route the app exposes, checked against the spec TEXT: a surface
    is 'mentioned' when its name (or its route's first distinguishing segment) appears anywhere in the spec file.
    A surface with zero mention can still work - it just cannot be traced to a requirement, which is exactly the
    gap this report names. Report-only: the loop gate decides whether an unmentioned surface ships."""
    spec_text = open(spec_path, "r", encoding="utf-8").read().lower()
    rows: List[Dict[str, Any]] = []
    for fn in ("cli.py", "cli_ext.py"):
        p = os.path.join(app_root, fn)
        if not os.path.isfile(p):
            continue
        for m in _CLI_RE.finditer(open(p, "r", encoding="utf-8").read()):
            rows.append({"surface": m.group(1), "kind": "cli", "file": fn})
    seen: Set[str] = set()
    for fn in ("server.py", "oss_api.py", "arch_api.py", "books_api.py", "cra_api.py"):
        p = os.path.join(app_root, fn)
        if not os.path.isfile(p):
            continue
        for m in _ROUTE_RE.finditer(open(p, "r", encoding="utf-8").read()):
            r = _norm_route(m.group(1))
            if r in ("/healthz", "/readyz"):
                continue                                        # probes are named in the deployment docs, not the spec
            if r not in seen:
                seen.add(r)
                rows.append({"surface": r, "kind": "route", "file": fn})
    unmentioned: List[str] = []
    for row in rows:
        s = row["surface"].lower()
        if s in spec_text:
            row["mentioned"], row["via"] = True, "literal"
        else:
            seg = s.strip("/").split("/")
            token = next((x for x in seg if x not in _GENERIC_SEGMENTS and len(x) >= 3), seg[-1] if seg else s)
            if token and token in spec_text:
                row["mentioned"], row["via"] = True, "segment:" + token
            else:
                row["mentioned"], row["via"] = False, ""
                unmentioned.append(row["surface"])
    return {"schema": "bts-sbom.surface-trace.v1", "surfaces": rows,
            "total": len(rows), "mentioned": sum(1 for r in rows if r["mentioned"]),
            "unmentioned": unmentioned,
            "note": "report-only reverse trace: a working surface with zero spec mention cannot be traced to a requirement (C63)"}


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
