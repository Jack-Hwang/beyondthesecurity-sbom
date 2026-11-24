"""Arch Intel insights: book-grounded, deterministic architecture readings of the measured structure.

Every insight here is derived ONLY from the deterministic facts ``arch_intel.structure`` already measured
(import graph, cycles, clusters, coupling, hotspots, manifests) - no LLM, no network, nothing executed. The
concepts behind the heuristics come from the team's reading of the architecture canon, summarised in
``knowledge/domain/``: flow blockers and bounded contexts (Kaiser, Architecture for Flow), bad smells as
architecture signals (Fowler, Refactoring), architecture characteristics/styles/risks (Richards/Ford/
Gandhi), and decision framing (Perera). Each insight is honest about being a heuristic: an insight names its
signals and never claims certainty.

Insight families:
  flow_blockers              what slows a change down: import cycles, unstable hubs, hidden change coupling
                             (files that change together without an import edge), hotspot concentration
  bounded_context_candidates cohesive, weakly-inbound modules that read as a seam to split along
  style_hypothesis           layered / modular-monolith / distributed signals from layout + manifests
  antipattern_signals        big-ball-of-mud signals (tangle, cycles, cohesion collapse, root sprawl)
  modularity_summary         per-cluster cohesion/coupling plus overall fitness numbers
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

SCHEMA = "bts-sbom.arch-flow-insights.v1"

_LAYER_GROUPS = {
    "presentation": ("controllers", "views", "routes", "ui", "web", "handlers", "endpoints", "apis", "presentation"),
    "business": ("services", "usecases", "application", "domain", "core", "business", "workflows"),
    "persistence": ("repositories", "repo", "dao", "models", "entities", "storage", "db", "persistence", "gateways"),
}
_DISTRIBUTED_MANIFESTS = ("docker-compose.yml", "compose.yml", "docker-compose.yaml")
_ENTRY_MANIFESTS = ("Dockerfile", "dockerfile")


def _dom_of(path: str, depth: int = 2) -> str:
    parts = path.strip("/").split("/")
    return "/".join(parts[:depth]) if len(parts) > depth else ("/".join(parts[:-1]) or ".")


# --------------------------------------------------------------------------- flow blockers
def flow_blockers(st: Dict[str, Any]) -> Dict[str, Any]:
    """What slows a change down (Kaiser; Fowler). Every item cites the measurement it came from."""
    g = st.get("graph") or {}
    blockers: List[Dict[str, Any]] = []
    for cyc in (g.get("cycles") or [])[:8]:
        blockers.append({"kind": "cycle", "why": "순환 의존 - 한 쪽 수정이 다른 쪽으로 되돌아온다(변경 파장 무한화)",
                         "what": " → ".join(cyc[:5]) + (" → …" if len(cyc) > 5 else ""), "evidence": "import graph SCC"})
    hubs = g.get("unstable_hubs") or []
    for hub in hubs[:5]:
        name = hub[0] if isinstance(hub, (list, tuple)) else str(hub)
        inst = hub[1] if isinstance(hub, (list, tuple)) and len(hub) > 1 else None
        blockers.append({"kind": "unstable_hub", "why": "불안정 허브 - 많이 의존받으면서 자주 외부에 의존(수정 파장 최대)",
                         "what": "%s (instability %s)" % (name, inst if inst is not None else "?"), "evidence": "fan-in ≥ 5, instability > 0.5"})
    coupling = st.get("coupling") or {}
    hidden = [p for p in (coupling.get("pairs") or []) if p.get("hidden")]
    for p in hidden[:8]:
        blockers.append({"kind": "hidden_change_coupling",
                         "why": "은닉 변경 결합 - 임포트로 연결되지 않는데 항상 함께 바뀌는 파일 쌍(숨은 의존)",
                         "what": "%s + %s (shared %s)" % (p.get("a"), p.get("b"), p.get("shared")), "evidence": "git change coupling"})
    hot = st.get("hotspots") or []
    if len(hot) >= 3 and hot[0].get("score") and hot[0]["score"] >= 3 * (hot[2].get("score") or 1):
        blockers.append({"kind": "hotspot_concentration",
                         "why": "핫스팟 집중 - 변경의 대부분이 극소 파일에 몰린다(기술 부채가 성장을 제한)",
                         "what": "%s (%s commits)" % (hot[0].get("file"), hot[0].get("commits")), "evidence": "git history"})
    tangle = g.get("tangle_ratio")
    if isinstance(tangle, (int, float)) and tangle >= 0.25:
        blockers.append({"kind": "high_tangle", "why": "높은 엉킴 - 그래프 노드 중 순환에 묶인 비중이 크다",
                         "what": "tangle_ratio %s" % tangle, "evidence": "import graph"})
    return {"count": len(blockers), "blockers": blockers[:12],
            "note": "흐름 차단자는 측정값 기반 휴리스틱이다 - 가장 큰 차단자부터 다루라(제약 이론)."}


# --------------------------------------------------------------------------- bounded context candidates
def bounded_context_candidates(st: Dict[str, Any], members_by_domain: Dict[str, List[str]]) -> Dict[str, Any]:
    """Cohesive, weakly-inbound modules that read as a seam (Kaiser; Fowler's Divergent Change inverse)."""
    out: List[Dict[str, Any]] = []
    for c in st.get("clusters") or []:
        if not c.get("extraction_candidate"):
            continue
        members = (members_by_domain.get(c["domain"]) or [])[:6]
        out.append({"name": c["domain"], "cohesion": c.get("cohesion"), "inbound": c.get("inbound"),
                    "outbound": c.get("outbound"), "modules": c.get("modules"),
                    "files": members,
                    "why": "응집 높음 + 유입 낮음 - 잘라내기 좋은 절리면(바운디드 컨텍스트 후보)"})
    out.sort(key=lambda x: (-(x.get("cohesion") or 0), x["name"]))
    return {"count": len(out), "candidates": out[:8],
            "note": "후보는 코드 경계의 힌트일 뿐이다 - 도메인 지식과 함께 확정하라(하위 도메인 유형 판단 필요)."}


# --------------------------------------------------------------------------- style hypothesis
def style_hypothesis(st: Dict[str, Any], manifests: Dict[str, Any]) -> Dict[str, Any]:
    """Layout + manifest signals -> a STYLE HYPOTHESIS (never a verdict)."""
    files = st.get("files_all") or []
    layer_hits: Dict[str, List[str]] = {}
    for f in files:
        segs = [s.lower() for s in f.split("/")[:-1]]
        stem = f.rsplit("/", 1)[-1].split(".")[0].lower()
        for group, names in _LAYER_GROUPS.items():
            if any(s in names for s in segs) or stem in names:
                layer_hits.setdefault(group, []).append(f)
                break
    distinct = sorted(layer_hits)
    if len(distinct) >= 2 and sum(len(v) for v in layer_hits.values()) >= 3:
        style = "layered"
        why = "프레젠테이션/비즈니스/퍼시스턴스 계층 이름이 관측된다"
        signals = ["%s: %s" % (k, len(layer_hits[k])) for k in distinct]
    else:
        entries = st.get("entry_points") or []
        domains = len({c["domain"] for c in st.get("clusters") or [] if (c.get("modules") or 0) >= 2})
        dist_signals = sum(1 for m in _DISTRIBUTED_MANIFESTS if manifests.get(m))
        if dist_signals >= 1 or len(entries) >= 3:
            style = "distributed"
            why = "복수의 배포 매니페스트/엔트리포인트가 관측된다"
            signals = ["docker-compose/service manifests: %d" % dist_signals, "entry points: %d" % len(entries)]
        elif entries and domains >= 2:
            style = "modular_monolith"
            why = "단일 진입점에 응집된 도메인 디렉터리가 여럿"
            signals = ["entry points: %d" % len(entries), "cohesive domains: %d" % domains]
        else:
            style = ""
            why = ""
            signals = []
    return {"style": style, "why": why, "signals": signals[:6],
            "note": "스타일은 가설이다 - 신호일 뿐이며 트레이드오프 판단은 사람의 몫이다."}


# --------------------------------------------------------------------------- antipattern signals
def antipattern_signals(st: Dict[str, Any]) -> Dict[str, Any]:
    """Big-ball-of-mud-style risk signals from the measurements (never a verdict)."""
    g = st.get("graph") or {}
    clusters = st.get("clusters") or []
    coh = [c.get("cohesion") for c in clusters if isinstance(c.get("cohesion"), (int, float))]
    avg_coh = round(sum(coh) / len(coh), 3) if coh else None
    signals: List[Dict[str, Any]] = []
    tangle, cycles = g.get("tangle_ratio"), g.get("cycle_count")
    if isinstance(tangle, (int, float)) and tangle >= 0.25 and isinstance(cycles, int) and cycles >= 3:
        signals.append({"code": "big_ball_of_mud", "why": "엉킴(tangle %s)과 순환(%s개)이 함께 크다 - 경계가 무너진 신호" % (tangle, cycles),
                        "measured": {"tangle_ratio": tangle, "cycles": cycles}})
    if avg_coh is not None and avg_coh <= 0.35 and len(clusters) >= 3:
        signals.append({"code": "low_cohesion", "why": "모듈 평균 응집이 낮다(%s) - 관련 동작이 흩어져 있다" % avg_coh,
                        "measured": {"avg_cohesion": avg_coh, "clusters": len(clusters)}})
    files_all = st.get("files_all") or []
    if files_all:
        root_share = sum(1 for f in files_all if "/" not in f) / len(files_all)
        if root_share >= 0.4 and len(files_all) >= 20:
            signals.append({"code": "root_sprawl", "why": "파일의 %d%%가 루트에 있다 - 구조 없이 평평하게 퍼졌다" % round(root_share * 100),
                            "measured": {"root_share": round(root_share, 2), "files": len(files_all)}})
    hubs = len(g.get("unstable_hubs") or [])
    if hubs >= 2:
        signals.append({"code": "hub_pressure", "why": "불안정 허브 %d개 - 수정 파장이 큰 지점이 여럿" % hubs,
                        "measured": {"unstable_hubs": hubs}})
    return {"count": len(signals), "signals": signals,
            "note": "안티패턴 '판정'이 아니라 위험 신호 목록이다."}


# --------------------------------------------------------------------------- modularity summary
def modularity_summary(st: Dict[str, Any]) -> Dict[str, Any]:
    """Per-cluster cohesion/coupling plus overall fitness numbers (Fundamentals of Software Architecture)."""
    rows = []
    for c in st.get("clusters") or []:
        rows.append({"domain": c["domain"], "modules": c.get("modules"), "cohesion": c.get("cohesion"),
                     "inbound": c.get("inbound"), "outbound": c.get("outbound"),
                     "bounded_context_candidate": bool(c.get("extraction_candidate"))})
    g = st.get("graph") or {}
    acyclic = 100.0
    nodes = g.get("nodes_in_graph")
    if isinstance(nodes, int) and nodes and isinstance(g.get("modules_in_cycles"), int):
        acyclic = round(100.0 * (1 - g["modules_in_cycles"] / nodes), 1)
    coh = [c.get("cohesion") for c in st.get("clusters") or [] if isinstance(c.get("cohesion"), (int, float))]
    return {"clusters": rows[:12], "avg_cohesion": round(sum(coh) / len(coh), 3) if coh else None,
            "acyclic_percent": acyclic, "tangle_ratio": g.get("tangle_ratio"),
            "note": "모듈리티는 복합 특성이다 - 한 지표로 정의되지 않는다."}


# --------------------------------------------------------------------------- code smells (function level)
def code_smells(st: Dict[str, Any]) -> Dict[str, Any]:
    """Function-level smell signals from the Code Intel measurements (complexity outliers, dead code, clones).
    Understand's metrics/CodeCheck lane, reimplemented deterministically - a signal list, never a verdict."""
    code = st.get("code") or {}
    m = code.get("metrics") or {}
    smells: List[Dict[str, Any]] = []
    mx = m.get("max_complexity") or {}
    if isinstance(mx.get("cc"), int) and mx["cc"] >= 9:
        smells.append({"code": "complexity_outlier", "why": "%s의 인지 복잡도가 %d - 분기 폭탄, 분해 후보" % (mx.get("name"), mx["cc"]),
                       "measured": {"function": mx.get("name"), "file": mx.get("file"), "cyclomatic": mx["cc"]}})
    avg = m.get("avg_complexity")
    if isinstance(avg, (int, float)) and avg >= 6.0 and m.get("functions"):
        smells.append({"code": "high_avg_complexity", "why": "함수 평균 복잡도 %s - 코드베이스 차원의 과분기 신호" % avg,
                       "measured": {"avg_complexity": avg, "functions": m.get("functions")}})
    dead = code.get("dead_code") or []
    if len(dead) >= 10:
        names = [d.get("name") for d in dead[:5]]
        smells.append({"code": "dead_code", "why": "호출부가 없는 함수 %d개 - 제거·부활 판단은 사람이" % len(dead),
                       "measured": {"dead_count": len(dead), "examples": names}})
    clones = code.get("clones") or []
    if clones:
        smells.append({"code": "duplicate_code", "why": "정규화 토큰이 동일한 함수 묶음 %d그룹 - 한쪽 수정이 다른 쪽을 놓치는 부식 경로" % len(clones),
                       "measured": {"clone_groups": len(clones), "largest": max(c.get("count", 0) for c in clones)}})
    return {"count": len(smells), "smells": smells,
            "note": "Python 함수 레벨 실측(다른 언어는 모듈 레벨만) - 목록이며 판정이 아니다."}


def build_insights(st: Dict[str, Any], manifests: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The whole insight pack over one measured structure (all deterministic)."""
    members: Dict[str, List[str]] = {}
    for f in st.get("files_all") or []:
        members.setdefault(_dom_of(f), [])
        if len(members[_dom_of(f)]) <= 6:
            members[_dom_of(f)].append(f)
    return {"schema": SCHEMA,
            "flow_blockers": flow_blockers(st),
            "bounded_context_candidates": bounded_context_candidates(st, members),
            "style_hypothesis": style_hypothesis(st, manifests or {}),
            "antipattern_signals": antipattern_signals(st),
            "modularity": modularity_summary(st),
            "code_smells": code_smells(st)}
