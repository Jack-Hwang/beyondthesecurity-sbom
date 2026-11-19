"""Routing evaluation of the governance and action tools of the chatbot (license risks, proposals, patch plan, VEX decision, conformance,
changes, cross-project lookup): paraphrased questions with the tool each should reach, measured for the regex router and for the LLM planner.

Kept apart from ``evals.py`` so the pinned paraphrase baseline of the first nine tools (BSA-AC-93) does not move. The numbers are a
measurement, not a target: the cases that the regex router misses are the reason the planner exists, and the planner is only credited for
a tool when its call survived ``chat.validate_calls`` (so a forged token or an invented reason can never score).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import changes, chat, conformance, evals, sbom

#: (question, tool that must be among the tools used). The first 6 share no keyword with the regex router.
CASES: List[Dict[str, str]] = [
    {"q": "우리 제품 SBOM 이 미국 정부가 말하는 기준을 맞추고 있어", "tool": "sbom_conformance"},
    {"q": "저번 검사 때보다 상황이 나아졌나", "tool": "what_changed"},
    {"q": "SaaS 로 서비스하면 쓰고 있는 오픈소스 조건이 괜찮아", "tool": "license_risks"},
    {"q": "해결책으로 뭐가 나와 있어", "tool": "proposals"},
    {"q": "고쳐도 되는 목록 먼저 보여줘 아직 건드리지 말고", "tool": "plan_patch"},
    {"q": "그 CVE-2018-18074 는 우리 쓰임새에선 문제 안 되니까 장부에 남겨줘", "tool": "record_decision"},
    {"q": "배포하면 copyleft 때문에 문제될 부품이 있나", "tool": "license_risks"},          # keyword hit: the regex router's own strength
    {"q": "NTIA 기준으로 SBOM 요건 충족하는지 알려줘", "tool": "sbom_conformance"},        # keyword hit
]


def governed_project() -> Dict[str, Any]:
    """The synthetic project plus the records the new tools read: conformance, an earlier analysis, a verified plan."""
    rec = evals.synthetic_project()
    rec["conformance"] = conformance.compact(conformance.evaluate(sbom.cyclonedx("demo", rec["components"], rec["vulns"])))
    before = {"name": "demo", "components": [dict(rec["components"][0], version="2.18.0")], "vulns": [dict(rec["vulns"][0], id="CVE-2017-1")]}
    rec["changes"] = changes.compact(changes.diff(before, rec))
    rec["proposals"] = {"source": "deterministic", "items": [{"action": "upgrade", "risk": "low", "title": "Upgrade requests", "rationale": "clears 1 advisory"}]}
    return rec


def governance_routing_eval(root: Optional[str] = None, client: Any = None) -> Dict[str, Any]:
    """Tool-routing rate on CASES: the regex router when ``client`` is None, the LLM planner (regex fallback) otherwise."""
    bot = chat.Chatbot(evals.build_index(root), {"demo": governed_project()}, client)
    hit = 0
    routing: Dict[str, int] = {}
    misses: List[Dict[str, Any]] = []
    for c in CASES:
        r = bot.ask(c["q"], project="demo", use_llm=client is not None)
        routing[r["routing"]] = routing.get(r["routing"], 0) + 1
        if c["tool"] in r.get("tools", []):
            hit += 1
        else:
            misses.append({"q": c["q"], "expected": c["tool"], "tools": r.get("tools"), "routing": r["routing"]})
    return {"cases": len(CASES), "tool_routing_rate": round(hit / len(CASES), 3), "router": "llm" if client is not None else "regex", "routing": routing,
            "misses": misses}
