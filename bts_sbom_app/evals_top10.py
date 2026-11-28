"""TOP-10 quality scorecard (brief-5 plan A, AC-607/608): the chat answer quality gates - grounding, relevance/
completeness, tool-call accuracy, over-refusal rate - measured without an LLM judge (⑧ n/a: grounding is computed
from quote-in-document verification, never from a model's opinion).

Two honest lanes, and every number says which one it came from:
- the deterministic lane (in-process, no network): the extractive answer path over the synthetic and governed
  projects. This is the FLOOR: the regex router answers only what its keywords can reach, and the planner-only
  questions (the whole reason the planner exists, BSA-AC-93) count as its misses.
- the live lane: `evidence/chat_features/report.json`, the 26-row suite that ran against the real service with the
  LLM planner on. The system's real router is planner-first-with-regex-fallback, so the GATED read-accuracy and
  over-refusal numbers come from this artifact when it exists (and passed); the floor is reported beside them.

Metrics (별첨1 mapping):
- A1 근거성 F >= 0.90: per answer, precision = claim support (chat.verify_claims, AC-40/41), recall = the share of the
  fired tools' fact sources the answer cites; F = harmonic mean. Deterministic lane (extractive answers are the
  contract: an LLM answer must itself clear the 0.8 citation gate or it is discarded, chat.py).
- A2 관련성 + 완결성: the brief's >= 0.80 cos assumes an embedding/역생성 estimator (judge lane). Here relevance is the
  deterministic token cosine, tracked with the regression rule (>= -0.02 against the stored run); the GATE is
  completeness - every golden row names the content an honest answer must contain, coverage >= 0.90.
- A3 툴 호출 정확도: read >= 0.95 from the live gate log (the suite report: expected tool fired per row), floor from
  the regex lane; write = 1.0 - every forged authorising value dropped AND a read-only session offering no write
  tool (the same block the HTTP action runner proves end-to-end).
- A4 과잉 거절률 <= 5%: in-scope questions answered with the bare "could not find" refusal and no tool fired. Live lane
  from the suite (rows that found nothing), floor from the deterministic pool. The two deliberate out-of-scope
  CHAT_CASES are negative controls, never in the denominator.
- A5 스코어카드: write_report() renders evals/top10_report.md and stores the scores; deltas follow the loop.gate rule
  (>= -0.02) - the regression gate of ⑩, now with per-metric numbers attached.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from . import chat, evals, evals_chat, evalguard, rag

GATES = {"grounding_f": 0.90, "completeness": 0.90, "tool_accuracy_read": 0.95,
         "tool_accuracy_write": 1.0, "over_refusal_rate": 0.05}
REPORT_PATH = os.path.join("evals", "top10_report.md")
SCORES_PATH = os.path.join("evals", "top10_scores.json")
SUITE_REPORT = os.path.join("evidence", "chat_features", "report.json")
DELTA_FLOOR = -0.02                    # the loop.gate regression rule, per metric

#: procedure/policy questions with the elements an honest answer must carry (A2; verified against the extractive path).
A2_ROWS: List[Dict[str, Any]] = [
    {"q": "배포하면 copyleft 때문에 문제될 부품이 있나", "project": "gov", "must": ["unresolved"]},
    {"q": "NTIA 기준으로 SBOM 요건 충족하는지 알려줘", "project": "gov", "must": ["NTIA"]},
    {"q": "취약점 현황 요약해줘", "project": "demo", "must": ["CVE-"]},
    {"q": "requests 를 2.20.0 으로 올리면 어떻게 돼", "project": "demo", "must": ["requests", "2.20.0"]},
    {"q": "CVE-2018-18074 는 어떤 취약점이야", "project": "demo", "must": ["requests", "severity"]},
    {"q": "쓰고 있는 오픈소스 이용 조건에 문제될 만한 게 있어", "project": "demo", "must": ["license"]},
]

#: one stock question per read tool (the deterministic A4 pool; also a per-tool smoke of the honest availability states).
STOCK_QUESTIONS: List[Tuple[str, str]] = [          # (question, project)
    ("프로젝트 요약해줘", "demo"), ("취약점 상위 5개 보여줘", "demo"),
    ("requests 컴포넌트 상세를 보여줘", "demo"), ("라이선스 통계 보여줘", "demo"),
    ("패치 현황 알려줘", "gov"), ("아키텍처 핫스팟 알려줘", "demo"), ("금융 규제 판정 보여줘", "demo"),
    ("CVE-2018-18074 조사해줘", "demo"), ("requests 를 2.19.2 로 올리면 어떻게 돼", "demo"),
    ("공급망 혼동 위험은 없어", "gov"), ("SBOM conformance 결과 보여줘", "gov"), ("what changed 결과 보여줘", "gov"),
    ("결정 커버리지 알려줘", "gov"), ("SaaS 배포 시 라이선스 리스크 보여줘", "gov"),
    ("수정 가능한 패치 계획 보여줘", "gov"), ("OpenVEX 내보내기 보여줘", "gov"),
    ("이 결정을 장부에 남겨줘: CVE-2018-18074 는 not_affected, 우리는 영향받는 버전을 안 쓴다", "gov"),
    ("component 다이어그램 그려줘", "demo"), ("지금 상황으로 어떤 행동을 해야 해", "gov"),
    ("clean architecture 책에서 관련 내용을 찾아줘", "demo"), ("생태계별 취약점 수 알려줘", "demo"),
    ("최신 아키텍처 분석 결과 보여줘", "demo"), ("requests 를 쓰는 프로젝트가 어디 있어", "demo"),
    ("CVE-2018-18074 는 우리 전체에서 어디 영향이야", "demo"),
]


def _both_projects(root: Optional[str] = None) -> Tuple[Any, Dict[str, Dict[str, Any]]]:
    """One bot over the synthetic project (demo) and the governed one (gov) - the two golden worlds."""
    projects = {"demo": evals.synthetic_project(), "gov": evals_chat.governed_project()}
    return chat.Chatbot(evals.build_index(root), projects), projects


def _cos(a: List[str], b: List[str]) -> float:
    if not a or not b:
        return 0.0
    sa: Dict[str, int] = {}
    sb: Dict[str, int] = {}
    for t in a:
        sa[t] = sa.get(t, 0) + 1
    for t in b:
        sb[t] = sb.get(t, 0) + 1
    dot = sum(n * sb.get(t, 0) for t, n in sa.items())
    na = sum(n * n for n in sa.values()) ** 0.5
    nb = sum(n * n for n in sb.values()) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


def _tok(text: str) -> List[str]:
    return rag.tokenize(text, for_query=True)


# ------------------------------------------------------------------ A1 grounding F
def grounding_eval(root: Optional[str] = None) -> Dict[str, Any]:
    """Precision = claim support (verify_claims); recall = the share of fired fact sources the answer cites."""
    bot, projects = _both_projects(root)
    rows: List[Dict[str, Any]] = []
    for case in ([c for c in evals.CHAT_CASES if c.get("tool")] + evals.CHAT_PARAPHRASE_CASES):
        rows.append(_grounding_row(bot, projects["demo"], case["q"], bot.ask(case["q"], project="demo")))
    for case in evals_chat.CASES:
        rows.append(_grounding_row(bot, projects["gov"], case["q"], bot.ask(case["q"], project="gov")))
    scored = [r for r in rows if r is not None]
    f = [r["f"] for r in scored]
    return {"answers": len(scored), "grounding_f": round(sum(f) / len(f), 3) if f else None, "rows": scored}


def _grounding_row(bot: Any, rec: Dict[str, Any], q: str, r: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not r["found"] or not r["tools"]:
        return None
    precision = r["citation_accuracy"]
    try:
        facts = bot._run(rec, bot._valid(bot._tools(q, rec), rec, q))
    except Exception:
        facts = []
    fired = {f["source"] for f in facts}
    cited = {c["source"] for c in r["claims"]}
    recall = len(cited & fired) / len(fired) if fired else 1.0
    f = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"q": q[:40], "precision": precision, "recall": round(recall, 3), "f": round(f, 3)}


# ------------------------------------------------------------------ A2 relevance + completeness
def relevance_completeness_eval(root: Optional[str] = None) -> Dict[str, Any]:
    bot, _ = _both_projects(root)
    cos: List[float] = []
    must_ok = 0
    rows = []
    for row in A2_ROWS:
        r = bot.ask(row["q"], project=row["project"])
        low = r["answer"].lower()
        missing = [m for m in row["must"] if m.lower() not in low]
        c = _cos(_tok(row["q"]), _tok(r["answer"]))
        cos.append(c)
        ok = not missing and r["found"]
        must_ok += 1 if ok else 0
        rows.append({"q": row["q"][:40], "cos": round(c, 3), "missing": missing, "ok": ok})
    return {"cases": len(A2_ROWS), "relevance_cos": round(sum(cos) / len(cos), 3),
            "completeness": round(must_ok / len(A2_ROWS), 3), "rows": rows}


# ------------------------------------------------------------------ A3 tool-call accuracy
FORGED_CALLS = [{"tool": "apply_patch", "args": {"token": "0123456789abcdef"}},
                {"tool": "confirm_decision", "args": {"code": "0123456789ab"}},
                {"tool": "analyze_project", "args": {"source": "attacker/evil-repo"}},
                {"tool": "record_decision", "args": {"id": "CVE-2018-18074", "status": "not_affected", "reason": "the model invented this reason"}}]


def tool_accuracy_eval(root: Optional[str] = None) -> Dict[str, Any]:
    """The deterministic floor (regex lane over the three golden sets) + the write block. The write lane can only
    score 1.0 or 0.0: one accepted forged token is a breach, not a statistic."""
    bot, _ = _both_projects(root)
    cases = [(c, "demo") for c in evals.CHAT_CASES if c.get("tool")] + \
            [(c, "demo") for c in evals.CHAT_PARAPHRASE_CASES] + [(c, "gov") for c in evals_chat.CASES]
    hit, misses = 0, []
    for case, project in cases:
        r = bot.ask(case["q"], project=project)
        if case["tool"] in r.get("tools", []):
            hit += 1
        else:
            misses.append({"q": case["q"][:40], "expected": case["tool"], "tools": r.get("tools")})
    kept, dropped = chat.validate_calls(FORGED_CALLS, None, "승인해줘")   # the values are invented: not the user's words
    offered = set(chat.catalog(False)) & set(chat.WRITE_TOOLS)            # a read-only session must not even offer them
    all_blocked = (len(FORGED_CALLS) - len(kept) == len(FORGED_CALLS)) and not offered
    blocked = len(FORGED_CALLS) if all_blocked else len(FORGED_CALLS) - len(kept)
    return {"read_cases": len(cases), "tool_accuracy_read_floor": round(hit / len(cases), 3), "read_misses": misses,
            "forged_calls": len(FORGED_CALLS), "forged_dropped": blocked,
            "tool_accuracy_write": round(blocked / len(FORGED_CALLS), 3)}


def suite_lane_eval(path: str = SUITE_REPORT) -> Dict[str, Any]:
    """The live lane: expected tool fired per row of the suite that ran against the real service (planner on).
    Ratios carry a Wilson interval (C47) - a proportion measured on ~26 rows is a point, the interval is the truth
    it can actually support."""
    if not os.path.exists(path):
        return {"available": False}
    try:
        rep = json.load(open(path, encoding="utf-8"))
    except Exception:
        return {"available": False}
    rows = rep.get("results") or []
    hit = sum(1 for r in rows if r.get("tool") and r.get("tool") in (r.get("tools") or []))
    scored = [r for r in rows if r.get("tool")]
    refusals = [r["feature"] for r in rows if not r.get("found") and not (r.get("tools") or [])]
    return {"available": True, "passed": rep.get("passed"), "rounds": rep.get("rounds"),
            "tool_accuracy_read": round(hit / len(scored), 3) if scored else None,
            "tool_accuracy_read_ci": evalguard.wilson_interval(hit, len(scored)),
            "over_refusal_rate": round(len(refusals) / len(rows), 3) if rows else None,
            "over_refusal_rate_ci": evalguard.wilson_interval(len(refusals), len(rows)), "refusals": refusals}


# ------------------------------------------------------------------ C61: the answer-correctness grader
def reference_eval(root: Optional[str] = None) -> Dict[str, Any]:
    """The answer-correctness grader against the reference (C61, distinct from A2 completeness): a case is correct
    only when the answer was FOUND, carries every reference element, carries none of the row's FORBIDDEN content
    (a fabricated value fails the case even when the must-list matched), and is more than the bare refusal."""
    bot, _ = _both_projects(root)
    ok, rows = 0, []
    for row in A2_ROWS:
        r = bot.ask(row["q"], project=row["project"])
        low = r["answer"].lower()
        missing = [m for m in row["must"] if m.lower() not in low]
        forbidden = [f for f in row.get("forbid") or [] if f.lower() in low]
        bare = (not r["found"]) or low.strip().startswith("i could not find")
        correct = not bare and not missing and not forbidden
        ok += 1 if correct else 0
        rows.append({"q": row["q"][:40], "correct": correct, "missing": missing, "forbidden": forbidden})
    return {"cases": len(A2_ROWS), "answer_correctness": round(ok / len(A2_ROWS), 3), "rows": rows}


# ------------------------------------------------------------------ C62: the 3-way miss classification
def miss_quadrant(path: str = SUITE_REPORT, golden_path: str = "evals/chat_features.json") -> Dict[str, Any]:
    """Every failing suite row is classified into ONE of three observable misses (C62): ``tool_miss`` - the expected
    tool never fired (a routing problem); ``empty_result`` - the tool fired and the turn honestly reported nothing
    found (a retrieval/lookup problem); ``content_miss`` - found=true but the answer lacks the golden row's expected
    content (a grounding/generation problem; only classifiable where the golden row carries ``expect``). A row that
    fits none is ``unclassified`` - named, never force-fitted."""
    if not os.path.exists(path):
        return {"available": False}
    try:
        rep = json.load(open(path, encoding="utf-8"))
    except Exception:
        return {"available": False}
    rows = rep.get("results") or []
    try:
        golden = {g.get("feature"): g for g in json.load(open(golden_path, encoding="utf-8"))}
    except Exception:
        golden = {}
    classes: Dict[str, List[str]] = {"tool_miss": [], "empty_result": [], "content_miss": [], "unclassified": []}
    for r in rows:
        g = golden.get(r.get("feature")) or {}
        # content_miss is checked BEFORE the issues gate: the runner only flags a missing tool or a bare refusal,
        # so an answer that was "found" but lacks the golden content is a failure ONLY this classifier can see.
        if r.get("found") and g.get("expect") and any(str(x).lower() not in (r.get("answer_head") or "").lower() for x in g["expect"]):
            classes["content_miss"].append(r.get("feature"))
            continue
        issues = r.get("issues") or []
        if not issues:
            continue
        fired, found, expected = r.get("tools") or [], bool(r.get("found")), r.get("tool")
        if expected and expected not in fired:
            classes["tool_miss"].append(r.get("feature"))
        elif expected and fired and not found:
            classes["empty_result"].append(r.get("feature"))
        else:
            classes["unclassified"].append(r.get("feature"))
    n = sum(len(v) for v in classes.values())
    return {"available": True, "fails": n,
            "classes": {k: {"n": len(v), "features": v[:6]} for k, v in classes.items()},
            "rate": {k: (round(len(v) / n, 3) if n else None) for k, v in classes.items()}}


# ------------------------------------------------------------------ C74: did the fired tool call carry the RIGHT values?
def tool_arg_eval(path: str = SUITE_REPORT, golden_path: str = "evals/chat_features.json") -> Dict[str, Any]:
    """Tool-call accuracy so far checked only that a tool FIRED (C74); this checks the ARGUMENT VALUES: each golden
    row may carry ``expect_args`` ({tool: {arg: value}}) and the live row's echoed ``tool_args`` must contain that
    exact value. A tool that fires with a wrong id answered nothing - this is where that shows."""
    if not os.path.exists(path):
        return {"available": False}
    try:
        rep = json.load(open(path, encoding="utf-8"))
    except Exception:
        return {"available": False}
    rows = rep.get("results") or []
    try:
        golden = {g.get("feature"): g for g in json.load(open(golden_path, encoding="utf-8"))}
    except Exception:
        golden = {}
    checked, correct, misses = 0, 0, []
    for r in rows:
        g = golden.get(r.get("feature")) or {}
        exp = g.get("expect_args") or {}
        if not exp:
            continue
        actual = r.get("tool_args") or {}
        for tool, want in exp.items():
            for k, v in want.items():
                checked += 1
                got = (actual.get(tool) or {}).get(k)
                if got == v:
                    correct += 1
                else:
                    misses.append({"feature": r.get("feature"), "tool": tool, "arg": k, "want": v, "got": got})
    return {"available": True, "checked": checked, "correct": correct,
            "arg_accuracy": round(correct / checked, 3) if checked else None, "misses": misses}


# ------------------------------------------------------------------ C75: which stage ate the turn?
def stage_bottleneck(path: str = SUITE_REPORT) -> Dict[str, Any]:
    """Per-stage medians over the suite rows that carry ``stage_ms`` (C75), and the bottleneck: the stage with the
    largest MEDIAN share of the turn - weighted by share, not by one noisy outlier row."""
    if not os.path.exists(path):
        return {"available": False}
    try:
        rep = json.load(open(path, encoding="utf-8"))
    except Exception:
        return {"available": False}
    rows = [r for r in (rep.get("results") or []) if isinstance(r.get("stage_ms"), dict) and r.get("stage_ms")]
    if not rows:
        return {"available": True, "rows": 0, "note": "no stage_ms in this report (run the suite against a service with C75 timings)"}
    shares: Dict[str, List[float]] = {}
    for r in rows:
        sm = r["stage_ms"]
        total = sum(v for v in sm.values() if isinstance(v, (int, float))) or 1
        for stage, ms in sm.items():
            if isinstance(ms, (int, float)):
                shares.setdefault(stage, []).append(ms / total)
    med = {k: round(sorted(v)[len(v) // 2], 3) for k, v in sorted(shares.items())}
    top = max(med, key=med.get) if med else None
    return {"available": True, "rows": len(rows), "median_share": med, "bottleneck": top}


# ------------------------------------------------------------------ C04: the rolling baseline
SCORES_HIST = os.path.join("evidence", "chat_features", "top10_history.jsonl")


def rolling_baseline(current: Dict[str, Any], path: str = SCORES_HIST, window: int = 5) -> Dict[str, Any]:
    """Drift against the ROLLING median of the last ``window`` recorded runs (C04) - a single stored previous run
    makes every comparison a two-point story; the rolling median is the baseline a slow slide cannot hide from.
    A metric below median + DELTA_FLOOR is named. An empty history is an honest zero-shape, not a pass."""
    hist: List[Dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                try:
                    rec = json.loads(ln)
                except ValueError:
                    continue
                if isinstance(rec, dict) and isinstance(rec.get("scores"), dict):
                    hist.append(rec["scores"])
    except OSError:
        pass
    hist = hist[-window:]
    drift: List[str] = []
    med: Dict[str, Optional[float]] = {}
    for k, v in current.items():
        if not isinstance(v, (int, float)):
            continue
        vals = sorted(h[k] for h in hist if isinstance(h.get(k), (int, float)))
        if not vals:
            med[k] = None
            continue
        m = vals[len(vals) // 2]
        med[k] = round(m, 3)
        if v - m < DELTA_FLOOR - 1e-9:
            drift.append("%s: %.3f is below the rolling median %.3f by more than %.2f" % (k, v, m, abs(DELTA_FLOOR)))
    return {"history_runs": len(hist), "median": med, "drift": drift,
            "pass": bool(hist) and not drift}          # no history yet: not a pass, an honest "cannot tell yet"


# ------------------------------------------------------------------ A4 over-refusal (deterministic pool)
def over_refusal_eval(root: Optional[str] = None) -> Dict[str, Any]:
    """In-scope questions must never come back as the bare "could not find" refusal with no tool fired (regex floor)."""
    bot, _ = _both_projects(root)
    pool = [(c["q"], "demo") for c in evals.CHAT_CASES if c.get("tool")] + \
           [(c["q"], "demo") for c in evals.CHAT_PARAPHRASE_CASES] + \
           [(c["q"], "gov") for c in evals_chat.CASES] + list(STOCK_QUESTIONS)
    refusals = []
    for q, project in pool:
        r = bot.ask(q, project=project)
        if (not r["found"]) and not r.get("tools"):
            refusals.append(q[:60])
    return {"in_scope": len(pool), "refusals": len(refusals),
            "over_refusal_rate_floor": round(len(refusals) / len(pool), 3), "refusal_questions": refusals}


# ------------------------------------------------------------------ scorecard
def top10(root: Optional[str] = None, suite_report: str = SUITE_REPORT) -> Dict[str, Any]:
    """Scores + gate verdicts. The gated read-accuracy and over-refusal numbers come from the live suite artifact when
    it exists and passed; otherwise the deterministic floor stands in and the gate verdict honestly reflects it."""
    g = grounding_eval(root)
    rc = relevance_completeness_eval(root)
    ta = tool_accuracy_eval(root)
    orr = over_refusal_eval(root)
    lane = suite_lane_eval(suite_report)
    live_ok = bool(lane.get("available")) and lane.get("passed") == lane.get("rounds") and lane.get("rounds")
    scores = {"grounding_f": g["grounding_f"], "relevance_cos": rc["relevance_cos"], "completeness": rc["completeness"],
              "tool_accuracy_read": lane["tool_accuracy_read"] if live_ok else ta["tool_accuracy_read_floor"],
              "tool_accuracy_write": ta["tool_accuracy_write"],
              "over_refusal_rate": lane["over_refusal_rate"] if live_ok else orr["over_refusal_rate_floor"]}
    prev = {}
    if os.path.exists(SCORES_PATH):
        try:
            prev = json.load(open(SCORES_PATH, encoding="utf-8"))
        except Exception:
            prev = {}
    deltas = {k: (round(scores[k] - prev[k], 3) if isinstance(scores.get(k), (int, float)) and k in prev else None)
              for k in scores}

    def _verdict(k: str) -> bool:
        v, d = scores.get(k), deltas.get(k)
        if v is None:
            return False
        if k == "over_refusal_rate":
            return v <= GATES[k]
        if d is not None and d < DELTA_FLOOR:            # regression rule rides on top of every gate
            return False
        if k == "relevance_cos":                          # tracked, not gated: the >=0.80 path is the judge lane
            return True
        return v >= GATES[k]

    return {"scores": scores, "gates": GATES, "pass": {k: _verdict(k) for k in scores}, "deltas": deltas,
            "delta_rule": "regression gate: a metric may drop by at most %.2f against the stored previous run" % abs(DELTA_FLOOR),
            "lane": {"live_suite": lane, "live_used": bool(live_ok),
                     "read_floor": ta["tool_accuracy_read_floor"], "refusal_floor": orr["over_refusal_rate_floor"]},
            "grounding": g, "relevance": rc, "tool_accuracy": ta, "over_refusal": orr,
            "reference": reference_eval(root),              # C61: answer correctness vs the reference content
            "miss_quadrant": miss_quadrant(suite_report),   # C62: 3-way miss classification
            "tool_args": tool_arg_eval(suite_report),       # C74: fired calls carry the RIGHT values
            "bottleneck": stage_bottleneck(suite_report),   # C75: which stage ate the turn
            "rolling": rolling_baseline(scores)}            # C04: drift vs the rolling median


def append_history(result: Optional[Dict[str, Any]] = None, path: str = SCORES_HIST) -> None:
    """One scores line per recorded run (C04): the rolling baseline needs history, so write_report leaves it."""
    r = result or {}
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps({"scores": r.get("scores") or {}}, ensure_ascii=False) + "\n")


def write_report(result: Optional[Dict[str, Any]] = None, path: str = REPORT_PATH, scores_path: str = SCORES_PATH) -> str:
    """A5: the TOP-10 scorecard as markdown; every number carries its gate, its lane and its delta."""
    r = result or top10()
    s, gates, p, lane = r["scores"], r["gates"], r["pass"], r["lane"]
    def _line(k: str, label: str, lower_is_better: bool = False) -> str:
        v, d = s.get(k), r["deltas"].get(k)
        dtxt = " (Δ %+.3f)" % d if d is not None else ""
        return "| %s | %s | %s | %s |%s |" % (label, "—" if v is None else v,
                                              (("<= %s" % gates[k]) if lower_is_better else (">= %s" % gates[k])) if k in gates else "추적(Δ 규칙)",
                                              "PASS" if p[k] else "FAIL", dtxt)
    lines = [
        "# Chat 품질 TOP-10 스코어카드", "",
        "측정: 합성·거버넌스 프로젝트 위 결정론 추출 답변 경로 (LLM 판정자 없음 — 근거성은 인용-원문 대조 계산, ⑈ 해당 없음).",
        "읽기 정확도·과잉 거절의 게이트 값은 라이브 스위트(%d행, 플래너 on)%s에서 왔다; 결정론 floor(정규식 라우터만)는 참고치." % (
            lane["live_suite"].get("rounds") or 0, "" if lane["live_used"] else " — **현재 없어 floor로 대산(게이트 FAIL은 정직)**"), "",
        "| 지표 | 측정값 | 게이트 | 판정 | 이전 대비 |",
        "|---|---|---|---|---|",
        _line("grounding_f", "A1 근거성 F (claim 지지율×출처 커버리지)"),
        _line("relevance_cos", "A2 관련성 (결정론 토큰 cos — 역생성 cos ≥0.80은 판정 레인)"),
        _line("completeness", "A2 완결성 (필수요소 충족률)"),
        _line("tool_accuracy_read", "A3 툴 호출 정확도 — 읽기"),
        _line("tool_accuracy_write", "A3 툴 호출 정확도 — 쓰기 (위조 차단)"),
        _line("over_refusal_rate", "A4 과잉 거절률", lower_is_better=True), "",
        "- A1 근거: %d개 답변(골든셋 전부). A3 쓰기 근거: 위조 호출 %d/%d 차단 + 읽기 전용 세션이 쓰기 도구를 아예 제공하지 않음." % (
            r["grounding"]["answers"], r["tool_accuracy"]["forged_dropped"], r["tool_accuracy"]["forged_calls"]),
        "- A3 읽기 floor(정규식만): %s — 플래너 전용 질문은 정규식이 답하지 못하는 게 설계 목표(BSA-AC-93)." % r["lane"]["read_floor"],
        "- A4 floor(정규식만, 범위 내 %d건): %s. 라이브 레인에서 과잉 거절: %s" % (
            r["over_refusal"]["in_scope"], r["lane"]["refusal_floor"], lane.get("refusals") or "없음"),
        "- Δ 규칙: 저장된 이전 점수 대비 -%.2f 이상 하락 금지(loop.gate ⑩과 동일). 첫 실행은 Δ 없음." % abs(DELTA_FLOOR), "",
    ]
    if r["over_refusal"]["refusal_questions"]:
        lines.append("- floor에서 과잉 거절된 질문(플래너가 답하는 영역): %s" %
                     "; ".join("「%s」" % q for q in r["over_refusal"]["refusal_questions"][:8]) + (" ..." if len(r["over_refusal"]["refusal_questions"]) > 8 else ""))
    misses = r["tool_accuracy"]["read_misses"]
    if misses:
        lines.append("- floor 읽기 미발동: %s" % "; ".join("「%s」→ %s (기대 %s)" % (m["q"], m["tools"], m["expected"]) for m in misses[:8]) +
                     (" ..." if len(misses) > 8 else ""))
    misses = r["tool_accuracy"]["read_misses"]
    if misses:
        lines.append("- floor 읽기 미발동: %s" % "; ".join("「%s」→ %s (기대 %s)" % (m["q"], m["tools"], m["expected"]) for m in misses[:8]) +
                     (" ..." if len(misses) > 8 else ""))
    ref = r.get("reference") or {}
    if ref:
        lines.append("- C61 답변 정답률(reference grader): %s (%d케이스) — 발견+필수요소 충족+금지값 부재+공거 아님을 전부 충족한 케이스만 정답." % (ref.get("answer_correctness"), ref.get("cases")))
    mq = r.get("miss_quadrant") or {}
    if mq.get("available") and mq.get("fails"):
        lines.append("- C62 실패 3분류: tool_miss %s / empty_result %s / content_miss %s / 미분류 %s" % (
            mq["classes"]["tool_miss"]["n"], mq["classes"]["empty_result"]["n"], mq["classes"]["content_miss"]["n"], mq["classes"]["unclassified"]["n"]))
    ta_args = r.get("tool_args") or {}
    if ta_args.get("available") and ta_args.get("checked"):
        lines.append("- C74 인자값 정확도: %s (%d/%d) %s" % (ta_args.get("arg_accuracy"), ta_args.get("correct"), ta_args.get("checked"),
                                                            ("; " + "; ".join("%s.%s은 %s이어야 하는데 %s" % (m["feature"], m["arg"], m["want"], m["got"]) for m in ta_args["misses"][:4])) if ta_args.get("misses") else ""))
    bo = r.get("bottleneck") or {}
    if bo.get("available") and bo.get("rows"):
        lines.append("- C75 병목(중앙값 점유율): %s — %s" % (bo.get("bottleneck"), bo.get("median_share")))
    ro = r.get("rolling") or {}
    if ro:
        lines.append("- C04 롤링 베이스라인: 최근 %d회 중앙값 대비 %s" % (ro.get("history_runs"), ("이탈: " + "; ".join(ro["drift"])) if ro.get("drift") else "이탈 없음"))
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    with open(scores_path, "w", encoding="utf-8") as fh:            # the stored run the next Δ compares against
        json.dump(r["scores"], fh, ensure_ascii=False, indent=1, sort_keys=True)
    append_history(r)                                               # C04: the rolling baseline reads this history
    return path


if __name__ == "__main__":                              # python -m bts_sbom_app.evals_top10 [report-path]
    import sys
    print("wrote", write_report(path=sys.argv[1] if len(sys.argv) > 1 else REPORT_PATH))
