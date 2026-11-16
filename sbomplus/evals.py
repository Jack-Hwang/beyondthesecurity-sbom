"""Evaluation harness: retrieval quality (golden set) and chatbot grounding (synthetic project, no network)."""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from . import chat, rag
from .util import read_json


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_index(root: Optional[str] = None, extra_chunks: Optional[List[Dict[str, Any]]] = None) -> rag.Index:
    root = root or repo_root()
    chunks = rag.load_dir(os.path.join(root, "knowledge"), kind="knowledge")
    return rag.Index(chunks + list(extra_chunks or []))


def rag_eval(root: Optional[str] = None, golden_path: Optional[str] = None, k: int = 5) -> Dict[str, Any]:
    root = root or repo_root()
    golden = read_json(golden_path or os.path.join(root, "evals", "rag_golden.json"), [])
    idx = build_index(root)
    out = rag.evaluate(idx, golden, k=k)
    out["chunks"] = len(idx.chunks)
    return out


RAG_SETS = ("rag_golden", "rag_dev", "rag_test")


def rag_sets_eval(root: Optional[str] = None, k: int = 5) -> Dict[str, Dict[str, Any]]:
    """Golden (regression), dev (tuned on) and test (written BEFORE tuning, never tuned on) retrieval sets."""
    root = root or repo_root()
    idx = build_index(root)
    out: Dict[str, Dict[str, Any]] = {}
    for name in RAG_SETS:
        g = read_json(os.path.join(root, "evals", name + ".json"), None)
        if g is not None:
            out[name] = rag.evaluate(idx, g, k=k)
    return out


def synthetic_project() -> Dict[str, Any]:
    """A fixed project record exercising every chat tool (offline, deterministic)."""
    v = {"id": "CVE-2018-18074", "aliases": ["GHSA-x84v-xcm2-53pg"], "osv_ids": ["GHSA-x84v-xcm2-53pg"], "package": "requests", "version": "2.19.1",
         "ecosystem": "PyPI", "purl": "pkg:pypi/requests@2.19.1", "severity": "HIGH", "cvss": 7.5, "fixed_version": "2.20.0",
         "summary": "Insecure credential handling on redirect", "files": ["requirements.txt"]}
    comps = [{"name": "requests", "version": "2.19.1", "ecosystem": "PyPI", "license": "Apache-2.0", "license_source": "deps.dev", "license_category": "permissive", "vulns": 1, "files": ["requirements.txt"]},
             {"name": "leftpad", "version": "1.0.0", "ecosystem": "npm", "license": "", "license_source": "", "license_category": "unknown", "vulns": 0, "files": ["package.json"]}]
    plan = {"component": "requests", "ecosystem": "PyPI", "current_version": "2.19.1", "safe_version": "2.20.0", "status": "upgrade", "clears": ["CVE-2018-18074"],
            "uncleared": [], "cve_count": 1, "major_bump": False, "breaking_risk": "low", "files": ["requirements.txt"], "max_severity": "HIGH", "max_cvss": 7.5,
            "verification": {"clean": True, "method": "osv_recheck", "rounds": 1, "residual": []}}
    return {"name": "demo", "components": comps, "vulns": [v], "plans": [plan],
            "license": {"stats": {"resolved": 1, "total": 2, "resolved_rate": 0.5, "by_source": {"deps.dev": 1}}, "project_license": "MIT",
                        "project_license_source": "root license file", "policy": []},
            "patch": {"status": "applied", "approved": True, "branch": "sbomplus/auto-fix"},
            "arch": {"stack": {"files": 12, "loc": 900}, "graph": {"import_edges": 20, "cycle_count": 1}, "hotspots": [{"file": "app/core.py", "commits": 30, "loc": 400, "score": 91.0}],
                     "runtime_eol": [{"product": "python", "cycle": "3.8", "status": "eol", "source": "endoflife.date"}]},
            "sectors": {"finance": {"sector_title": "Finance OSS guidance", "verdict": "gaps", "summary": {"pass": 3, "gap": 1, "not_evidence": 0}}}}


CHAT_CASES = [
    {"q": "CVE-2018-18074 는 어떤 취약점이야", "found": True, "tool": "vuln_lookup"},
    {"q": "requests 컴포넌트 라이선스는 뭐야", "found": True, "tool": "component_lookup"},
    {"q": "취약점 현황 요약해줘", "found": True, "tool": "top_vulns"},
    {"q": "라이선스 분포와 정책 판정 알려줘", "found": True, "tool": "license"},
    {"q": "패치 계획은 어떻게 돼 있어", "found": True, "tool": "patch"},
    {"q": "아키텍처 핫스팟과 런타임 EOL 은", "found": True, "tool": "architecture"},
    {"q": "금융 규제 준수 상태는", "found": True, "tool": "sector"},
    {"q": "오늘 점심 메뉴 추천해줘", "found": False},
    {"q": "비트코인 시세 알려줘", "found": False},
]


def chat_eval(root: Optional[str] = None) -> Dict[str, Any]:
    idx = build_index(root)
    bot = chat.Chatbot(idx, {"demo": synthetic_project()})
    ok_found = 0
    ok_tool = 0
    n_tool = 0
    acc: List[float] = []
    bad: List[Dict[str, Any]] = []
    for c in CHAT_CASES:
        r = bot.ask(c["q"], project="demo")
        if r["found"] == c["found"]:
            ok_found += 1
        else:
            bad.append({"q": c["q"], "why": "found=%s expected %s" % (r["found"], c["found"])})
        if c.get("tool"):
            n_tool += 1
            if c["tool"] in r.get("tools", []):
                ok_tool += 1
            else:
                bad.append({"q": c["q"], "why": "tool %s not used (%s)" % (c["tool"], r.get("tools"))})
        if r["found"]:
            acc.append(r["citation_accuracy"])
    return {"cases": len(CHAT_CASES), "found_correct": ok_found, "found_rate": round(ok_found / len(CHAT_CASES), 3),
            "tool_routing_rate": round(ok_tool / n_tool, 3) if n_tool else None,
            "citation_accuracy": round(sum(acc) / len(acc), 3) if acc else None, "misses": bad}
