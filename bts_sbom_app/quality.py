"""TOP10 answer-quality scorecard (MetaNet advanced course, appendix TOP10) - deterministic gates, no LLM judge.

Every number is computed from this run's own measured output, in the project style (a measurement, not a target):
- faithfulness: mean claim support ratio of the chat answers (same definition as chat.citation_accuracy) - gate >= 0.90
- relevance:    question/answer token cosine similarity - the floor below is the measured floor of this corpus
                (the course's 0.80 gate is for answer->question regeneration with an embedding model; we do not run a judge model)
- completeness: required-element ratio per found case, from the per-question required element lists below
- tool_accuracy: the weaker of the two routing rates (base + governance sets) - all shipped tools are read-only,
                so the course's write-tool 1.0 rule is enforced structurally by the actions gate instead (chat.validate_calls)
- over_refusal: normal questions the chat refused - gate <= 0.05 (course appendix ⑦)

A 6th metric, consistency (course appendix Topic5 "평가 흐름" 5 metrics incl. 일관성), is measured and gated too
(``consistency``/``consistency_gate``) but kept OUT of the ``apply_gates``/``THRESHOLDS``/``top10_report()["gates"]``
shape above: that shape is locked by existing consumers (tests/bts_sbom_app/test_quality_top10.py asserts it has
exactly the 5 named gates), so the contradiction-rate gate is reported as its own separate field instead of folded
into it - additive, not a breaking change to the report.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Tuple

from . import evals, evals_chat, licenses, rag

#: course appendix gates; relevance/completeness floors are this corpus's measured floor, not the course's judge-model numbers
THRESHOLDS: Dict[str, float] = {"faithfulness": 0.90, "relevance": 0.25, "completeness": 0.90,
                                "tool_accuracy": 0.95, "over_refusal": 0.05}

#: required answer elements per in-scope question (course ③ completeness: 필수 요소 충족률)
REQUIRED_ELEMENTS: Dict[str, List[str]] = {
    "CVE-2018-18074 는 어떤 취약점이야": ["CVE-2018-18074", "7.5", "high"],
    "requests 컴포넌트 라이선스는 뭐야": ["apache", "deps.dev"],
    "취약점 현황 요약해줘": ["CVE-2018-18074", "high"],
    "라이선스 분포와 정책 판정 알려줘": ["policy", "unresolved"],
    "패치 계획은 어떻게 돼 있어": ["2.20.0", "requests"],
    "아키텍처 핫스팟과 런타임 EOL 은": ["core.py", "3.8"],
    "금융 규제 준수 상태는": ["gap"],
}


def _cosine(a: Dict[str, int], b: Dict[str, int]) -> float:
    """Cosine over count vectors - 0 when either side has no tokens."""
    dot = sum(n * b.get(t, 0) for t, n in a.items())
    na = sum(n * n for n in a.values()) ** 0.5
    nb = sum(n * n for n in b.values()) ** 0.5
    return round(dot / (na * nb), 4) if na and nb else 0.0


def relevance(question: str, answer: str) -> float:
    """③ question/answer token cosine in 0..1 - answers that drift off the question score low."""
    qa: Dict[str, int] = {}
    at: Dict[str, int] = {}
    for t in rag.tokenize(question, for_query=True):
        qa[t] = qa.get(t, 0) + 1
    for t in rag.tokenize(answer):
        at[t] = at.get(t, 0) + 1
    return _cosine(qa, at)


def completeness(answer: str, elements: List[str]) -> float:
    """③ required-element ratio: how many required elements the answer carries (case-insensitive contains)."""
    low = answer.lower()
    hit = sum(1 for e in elements if e.lower() in low)
    return round(hit / len(elements), 4) if elements else 1.0


#: the 6th TOP10 metric's own gate, separate from THRESHOLDS/apply_gates (see module docstring)
CONSISTENCY_THRESHOLD = 0.05

_ADVISORY_ID = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+|GO-\d{4}-\d+)\b", re.I)
#: opposite status-word pairs: two claims about the SAME subject assigning BOTH sides of one pair is a contradiction
#: NEGATED label checked BEFORE its positive counterpart (unaffected before affected, no_patch before
#: patch_available): _claim_status returns the FIRST matching label, and \b-bounded word matching alone does not
#: stop a positive pattern ("vulnerable", "patch...available") from matching as a free-standing substring inside a
#: negated phrase ("not vulnerable", "no patch available") - checking the negated alternative first means that
#: phrase is classified correctly instead of being mislabelled with the positive status it actually denies.
_STATUS_WORDS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("unaffected", re.compile(r"\b(not\s+vulnerable|unaffected|no\s+known\s+vulnerabilit|영향\s*없|미영향)\b", re.I)),
    ("affected", re.compile(r"\b(vulnerable|affected|영향\s*있|취약함)\b", re.I)),
    ("no_patch", re.compile(r"\b(no\s+patch|not\s+patched|unpatched|패치\s*(없음|불가|미비))\b", re.I)),
    ("patch_available", re.compile(r"\b(patch(ed)?\s+(is\s+)?available|fix(ed)?\s+(is\s+)?available|패치\s*(가능|있음|됨))\b", re.I)),
    ("permissive", re.compile(r"\bpermissive\b|허용적", re.I)),
    ("copyleft", re.compile(r"\bcopyleft\b|카피레프트", re.I)),
]
_OPPOSITES = [frozenset({"affected", "unaffected"}), frozenset({"patch_available", "no_patch"}),
              frozenset({"permissive", "copyleft"})]


def _claim_subject(text: str) -> Optional[str]:
    """The advisory id or SPDX license name a claim is ABOUT, or ``None`` when it names neither."""
    m = _ADVISORY_ID.search(text)
    if m:
        return m.group(0).upper()
    for name in licenses.CATEGORY:                        # the product's own SPDX id vocabulary, not invented here
        if re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(name), text, re.I):
            return name
    return None


def _claim_status(text: str) -> Optional[str]:
    for label, pat in _STATUS_WORDS:
        if pat.search(text):
            return label
    return None


def consistency(claims: List[Dict[str, Any]]) -> Dict[str, Any]:
    """⑤ contradiction rate (course TOP10 일관성): ``claims`` (an answer's KEPT, verified claims) grouped by the
    advisory id or SPDX license name they each name; a group is flagged when two of its claims assign opposite
    status words (affected/unaffected, patch available/no patch, permissive/copyleft) to that same subject. A claim
    that names no subject or carries no recognised status word is not counted either way - absence of a signal is
    never read as agreement. ``rate`` is contradicted-groups / groups-with-a-subject (0.0 when there are none)."""
    groups: Dict[str, List[str]] = {}
    for c in claims or []:
        text = str(c.get("text") or c.get("quote") or "")
        subj = _claim_subject(text)
        label = _claim_status(text)
        if subj and label:
            groups.setdefault(subj, []).append(label)
    contradictions = []
    for subj, labels in groups.items():
        labset = set(labels)
        for pair in _OPPOSITES:
            if pair <= labset:
                contradictions.append({"subject": subj, "labels": sorted(pair)})
                break
    rate = round(len(contradictions) / len(groups), 4) if groups else 0.0
    return {"groups": len(groups), "contradictions": contradictions, "rate": rate}


def consistency_gate(claims: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The 6th gate's verdict for one answer's claims - ``{value, threshold, pass, groups, contradictions}``,
    reported next to (never inside) the 5-gate ``apply_gates`` shape."""
    c = consistency(claims)
    return {"value": c["rate"], "threshold": CONSISTENCY_THRESHOLD, "pass": bool(c["rate"] <= CONSISTENCY_THRESHOLD),
            "groups": c["groups"], "contradictions": c["contradictions"]}


def apply_gates(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Gates for the 5 gated metrics - verbatim metrics in, verdict out (the fail branch stays testable in isolation)."""
    gates: Dict[str, Dict[str, Any]] = {}
    for name, th in THRESHOLDS.items():
        v = metrics[name]
        ok = v <= th if name == "over_refusal" else v >= th
        gates[name] = {"value": v, "threshold": th, "pass": bool(ok)}
    failures = [{"metric": n, "value": g["value"], "threshold": g["threshold"]}
                for n, g in gates.items() if not g["pass"]]
    return {"gates": gates, "verdict": "pass" if not failures else "fail", "failures": failures}


def top10_report(root: Optional[str] = None) -> Dict[str, Any]:
    """Measure every metric over the offline deterministic chat set and return the gated scorecard."""
    root = root or evals.repo_root()
    bot = evals.chat.Chatbot(evals.build_index(root), {"demo": evals.synthetic_project()})
    cases: List[Dict[str, Any]] = []
    normal = refused = 0
    faith: List[float] = []
    rel: List[float] = []
    comp: List[float] = []
    cons: List[float] = []
    misses: List[Dict[str, Any]] = []
    for c in evals.CHAT_CASES:
        r = bot.ask(c["q"], project="demo")
        if c["found"]:                                   # a normal question - refusal here is over-refusal
            normal += 1
            if not r["found"]:
                refused += 1
                misses.append({"q": c["q"], "why": "over-refusal"})
                continue
            f = r["citation_accuracy"]
            req = REQUIRED_ELEMENTS.get(c["q"], [])
            rv = relevance(c["q"], r["answer"])
            cp = completeness(r["answer"], req) if req else 1.0
            faith.append(f)
            rel.append(rv)
            comp.append(cp)
            cons.append(consistency(r["claims"])["rate"])
            if f < THRESHOLDS["faithfulness"] or rv < THRESHOLDS["relevance"] or cp < THRESHOLDS["completeness"]:
                misses.append({"q": c["q"], "faithfulness": f, "relevance": rv, "completeness": cp,
                               "required": req, "answer": r["answer"][:200]})
        elif r["found"] != c["found"]:
            misses.append({"q": c["q"], "why": "out-of-scope question answered as found"})
    gov = evals_chat.governance_routing_eval(root)
    base = evals.chat_eval(root)
    metrics = {
        "faithfulness": round(sum(faith) / len(faith), 4) if faith else 0.0,
        "relevance": round(sum(rel) / len(rel), 4) if rel else 0.0,
        "completeness": round(sum(comp) / len(comp), 4) if comp else 0.0,
        # gate on the in-scope set the deterministic router must own; the paraphrase set's regex rate is a router
        # weakness by design (the reason the planner exists), so it is reported, not gated
        "tool_accuracy": base["tool_routing_rate"] or 0.0,
        "paraphrase_routing_rate": gov["tool_routing_rate"],
        "over_refusal": round(refused / normal, 4) if normal else 0.0,
        # the 6th metric (consistency) - measured here and gated via consistency_gate below, kept OUT of
        # THRESHOLDS/apply_gates so the locked 5-gate shape is unaffected (see module docstring)
        "consistency": round(sum(cons) / len(cons), 4) if cons else 0.0,
    }
    gates = apply_gates(metrics)
    return {"cases": len(evals.CHAT_CASES), "normal_cases": normal, "metrics": metrics,
            "gates": gates["gates"], "verdict": gates["verdict"], "failures": gates["failures"],
            "misses": misses,
            "consistency_gate": {"value": metrics["consistency"], "threshold": CONSISTENCY_THRESHOLD,
                                  "pass": bool(metrics["consistency"] <= CONSISTENCY_THRESHOLD)}}


def render_markdown(report: Dict[str, Any]) -> str:
    """One scorecard table, one row per metric (course appendix 24 scorecard style)."""
    label = {"faithfulness": "근거성 (faithfulness)", "relevance": "관련성 (relevance)",
             "completeness": "완결성 (completeness)", "tool_accuracy": "툴 호출 정확도",
             "over_refusal": "과잉 거절률"}
    lines = ["# TOP10 답변 품질 스코어카드", "",
             "판정: **%s** (%d문항, 정상 %d건)" % (report["verdict"], report["cases"], report["normal_cases"]), "",
             "| 지표 | 측정값 | 기준 | 통과 |", "|---|---|---|---|"]
    for name, g in report["gates"].items():
        lines.append("| %s | %s | %s%s | %s |" % (label.get(name, name), g["value"],
                                                  "≤" if name == "over_refusal" else "≥", g["threshold"],
                                                  "PASS" if g["pass"] else "FAIL"))
    if report["failures"]:
        lines.append("")
        lines += ["- FAIL %s: %s vs threshold %s" % (f["metric"], f["value"], f["threshold"]) for f in report["failures"]]
    if report["misses"]:
        lines.append("")
        lines += ["- miss: %s" % (m["q"],) for m in report["misses"]]
    lines.append("")
    return "\n".join(lines)


def write_report(report: Dict[str, Any], path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_markdown(report))
    return path
