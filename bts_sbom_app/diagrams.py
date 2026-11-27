"""Diagram catalog: the diagram kinds of Sparx Enterprise Architect 17.2, reimplemented natively over the data
this tool already measures (ADR-0024). The catalog itself is REA evidence from the shipped artefact, not from
marketing pages: easetup_x64.msi (ProductVersion 17.2.1721.15, 3,744 files extracted, all digests verifiable)
carries the New-Diagram registry inside EA.exe as an embedded technology XML - one ``<Stereotype>`` per diagram
with its official one-line description and an ``<Apply type="Diagram_*">`` ribbon binding - plus per-technology
MDG XMLs (BPMN 1.0/1.1/2.0, ArchiMate 3.1/2, DFD, MindMapping, Kanban, Whiteboard, Executable State Machines,
Wireframing, ...) under ``MDGTechnologies``. Each kind below names the EA artefact it mirrors and the MEASURED
data source it draws from; a kind whose inputs this tool does not measure says so and draws nothing (the same
honest-coverage contract as the Code Intel lane, ADR-0023).

Output: Mermaid text. The web UI renders it with the already-vendored mermaid (see NOTICE.md) and falls back to
the source text; chat tools return the same structure so a diagram can be drawn mid-conversation. Deterministic:
the same record always yields the same diagram - no LLM, no sampling, caps recorded in notes when hit.
"""
from __future__ import annotations

import datetime as _dt
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from . import decision as dmn

MAX_NODES = 30                       # nodes per diagram (measured cap, reported in the note when hit)
MAX_EDGES = 60
MAX_LABEL = 60
_TODAY = None                        # injectable today for tests (None -> real date)


def _today() -> _dt.date:
    return _TODAY or _dt.date.today()


# ---------------------------------------------------------------------------- catalog (the REA enumeration)
# group = the EA 17.2 New-Diagram group the kind appears in (verbatim names from the embedded technology XML);
# ea = the EA diagram name as EA prints it; src = the measured data the builder consumes.
CATALOG: Dict[str, Dict[str, Any]] = {
    # --- UML Structural
    "package":     {"group": "UML Structural", "ea": "Package", "title": "패키지 다이어그램", "src": "import graph", "fn": "_pkg"},
    "class":       {"group": "UML Structural", "ea": "Class", "title": "클래스 다이어그램", "src": "code intel classes", "fn": "_cls"},
    "object":      {"group": "UML Structural", "ea": "Object", "title": "오브젝트(인스턴스) 다이어그램", "src": "SBOM components", "fn": "_obj"},
    "composite":   {"group": "UML Structural", "ea": "Composite Structure", "title": "컴포지트 구조 다이어그램", "src": "code intel (one class)", "fn": "_composite", "target": True},
    "component":   {"group": "UML Structural", "ea": "Component", "title": "컴포넌트 다이어그램", "src": "domain clusters + import graph", "fn": "_component"},
    "deployment":  {"group": "UML Structural", "ea": "Deployment", "title": "배포 다이어그램", "src": "components + measured runtimes", "fn": "_deployment"},
    "logical":     {"group": "UML Structural", "ea": "Logical", "title": "논리/레이어 검증도", "src": "recorded layer_validation", "fn": "_logical"},
    # --- UML Behavioral
    "usecase":     {"group": "UML Behavioral", "ea": "Use Case", "title": "유스케이스 다이어그램", "src": "arch intel scenarios", "fn": "_usecase", "arch_doc": True},
    "activity":    {"group": "UML Behavioral", "ea": "Activity", "title": "액티비티 다이어그램", "src": "arch intel flows", "fn": "_activity", "arch_doc": True},
    "state":       {"group": "UML Behavioral", "ea": "State Machine", "title": "상태 머신(해결 수명주기)", "src": "vulns + plans", "fn": "_state"},
    "sequence":    {"group": "UML Behavioral", "ea": "Sequence", "title": "시퀀스 다이어그램", "src": "arch intel scenario", "fn": "_sequence", "arch_doc": True},
    "communication": {"group": "UML Behavioral", "ea": "Communication", "title": "커뮤니케이션 다이어그램", "src": "arch intel scenario", "fn": "_communication", "arch_doc": True},
    "interaction": {"group": "UML Behavioral", "ea": "Interaction Overview", "title": "인터랙션 오버뷰", "src": "arch intel scenario", "fn": "_interaction", "arch_doc": True},
    "timing":      {"group": "UML Behavioral", "ea": "Timing / Timeline (Roadmap)", "title": "타이밍·타임라인(측정 날짜)", "src": "vuln published + runtime EOL dates", "fn": "_timing"},
    # --- SysML (round-2 REA correction: EA 17.2 carries "MDG Technology for SysML" + SysMLSim natively;
    #     the first-pass "SysML 0건" claim was an extraction-encoding miss, corrected in EA_REA_FINDINGS.md)
    "bdd":         {"group": "SysML", "ea": "SysML Block Definition Diagram", "title": "블록 정의 다이어그램", "src": "code intel classes (blocks + generalization)", "fn": "_bdd"},
    "ibd":         {"group": "SysML", "ea": "SysML Internal Block Diagram", "title": "내부 블록 다이어그램", "src": "code intel (one block's parts + connectors)", "fn": "_ibd", "target": True},
    "parametric":  {"group": "SysML", "ea": "SysML Parametric Diagram", "title": "파라메트릭(정책 제약망)", "src": "measured facts + policy rules as constraints", "fn": "_parametric"},
    "robustness":  {"group": "SysML", "ea": "Robustness Diagram (ICONIX)", "title": "러스트니스(경계·제어·개체)", "src": "entry points + class call degree (heuristic, rules stated)", "fn": "_robustness", "arch_doc": True},
    # --- Extended (EA core extensions, verbatim group name)
    "requirements": {"group": "Extended", "ea": "Requirements", "title": "요구사항 다이어그램", "src": "recorded conformance", "fn": "_requirements"},
    "maintenance": {"group": "Extended", "ea": "Maintenance", "title": "유지보수(변경) 다이어그램", "src": "recorded changes", "fn": "_maintenance"},
    "dashboard":   {"group": "Extended", "ea": "Dashboard", "title": "대시보드(심각도 파이)", "src": "vuln severities", "fn": "_dashboard"},
    "erd":         {"group": "Extended", "ea": "Data Modeling", "title": "데이터 모델링(ERD)", "src": "this tool's evidence schema + counts", "fn": "_erd"},
    "business":    {"group": "Extended", "ea": "Business Modeling", "title": "비즈니스 모델링(라이선스 조직)", "src": "license resolution", "fn": "_business"},
    "business_interaction": {"group": "Extended", "ea": "Business Interaction", "title": "비즈니스 인터랙션", "src": "arch intel scenario", "fn": "_binter", "arch_doc": True},
    "custom":      {"group": "Extended", "ea": "Custom", "title": "커스텀(대화에서 바로 그리기)", "src": "the user's arrow spec", "fn": "_custom", "spec": True},
    "ui":          {"group": "Extended", "ea": "User Interface", "title": "와이어프레이밍", "src": "- (not derivable: no measured UI model)", "fn": "_nodata"},
    "xml":         {"group": "Extended", "ea": "XML Transform", "title": "XML 트랜스폼(SBOM 아티팩트 흐름)", "src": "generated CDX/SPDX/VEX documents", "fn": "_xml"},
    # --- Data & Process (EA per-technology diagram families)
    "dfd":         {"group": "Data & Process", "ea": "Data Flow (DFD technology)", "title": "데이터 흐름 다이어그램", "src": "entry points + import graph + data files", "fn": "_dfd", "arch_doc": True},
    "flowchart":   {"group": "Data & Process", "ea": "Flowchart", "title": "플로우차트(해결 파이프라인)", "src": "plans + verification", "fn": "_flowchart"},
    "bpmn":        {"group": "Data & Process", "ea": "BPMN 2.0 Process", "title": "BPMN 프로세스", "src": "arch intel flow, BPMN notation", "fn": "_bpmn", "arch_doc": True},
    "decision":    {"group": "Data & Process", "ea": "DMN Decision (DMN-Sim)", "title": "DMN 의사결정 테이블", "src": "measured facts + policy table", "fn": "_decision"},
    "kanban":      {"group": "Data & Process", "ea": "Kanban (Kanban technology)", "title": "칸반 보드(해결 작업)", "src": "plans + verification", "fn": "_kanban"},
    # --- Enterprise & Strategy (EA per-technology diagram families)
    "archimate":   {"group": "Enterprise", "ea": "ArchiMate 3.1 (layered view)", "title": "아키타메이트 계층 뷰", "src": "components + runtimes + policy", "fn": "_archimate"},
    "mindmap":     {"group": "Enterprise", "ea": "Mind Mapping", "title": "마인드맵", "src": "stack + measured counts", "fn": "_mindmap"},
    # --- Code Intel (the Understand lane, ADR-0023 - EA has no code-level graphs; ours does)
    "call":        {"group": "Code Intel", "ea": "- (Code Intel lane)", "title": "콜 그래프", "src": "resolved function calls", "fn": "_call"},
    "butterfly":   {"group": "Code Intel", "ea": "- (Code Intel lane)", "title": "버터플라이(한 함수의 이웃)", "src": "resolved calls around one function", "fn": "_butterfly", "target": True},
    "cluster":     {"group": "Code Intel", "ea": "- (Code Intel lane)", "title": "클러스터 콜(클래스 단위 집계)", "src": "calls aggregated by class", "fn": "_cluster"},
}
_NEEDS_PROJECT = ("arch_doc", "target", "spec")


def catalog_doc() -> List[Dict[str, Any]]:
    """The catalog as plain data for the API/pane: id, EA group/name, Korean title, measured source, needs."""
    out = []
    for k, v in CATALOG.items():
        out.append({"kind": k, "group": v["group"], "ea": v["ea"], "title": v["title"], "src": v["src"],
                    "needs_target": bool(v.get("target")), "needs_spec": bool(v.get("spec")),
                    "needs_arch_doc": bool(v.get("arch_doc"))})
    return out


def catalog_lines() -> List[str]:
    """Chat-readable catalog, grouped in EA's New-Diagram order."""
    out: List[str] = []
    last = None
    for k, v in CATALOG.items():
        if v["group"] != last:
            last = v["group"]
            out.append("%s:" % last)
        need = " (대상 지정: target)" if v.get("target") else (" (직접 지정: spec)" if v.get("spec") else "")
        out.append("  %s - %s [%s]%s" % (k, v["title"], v["ea"], need))
    out.append("모든 다이어그램은 분석 기록의 측정값에서만 그린다. 데이터가 없는 종류는 거짓 도식 대신 그 이유를 말한다.")
    return out


# --------------------------------------------------------------------------- helpers (mermaid discipline)
def _esc(s: Any, limit: int = MAX_LABEL) -> str:
    """A safe Mermaid double-quoted label: quotes, backslashes and shape syntax stripped, newlines flattened.
    Truncation never leaves an unbalanced paren behind - a label cut mid-``(...)`` broke the decision diagram's
    dotted-arrow edges (caught by lint_mermaid, C27)."""
    t = re.sub(r"\s+", " ", str(s or "?")).strip()
    t = t.replace("\\", "\\\\").replace('"', "'").replace("[", "(").replace("]", ")").replace("{", "(").replace("}", ")")
    if len(t) > limit:
        t = t[:limit]
        while t.count("(") > t.count(")"):
            t += ")"
    return t


def _pid(prefix: str, seen: Dict[str, str], raw: str) -> str:
    key = str(raw).strip().lower()
    if key not in seen:
        seen[key] = "%s%d" % (prefix, len(seen) + 1)
    return seen[key]


def _edge_note(n: int, cap: int = MAX_EDGES) -> Optional[str]:
    return ("%d edges drawn (cap %d)" % (n, cap)) if n >= cap else None


def _arch(rec: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return (rec or {}).get("arch") or {}


def _code(rec: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return _arch(rec).get("code") or {}


def _need_project(rec: Optional[Dict[str, Any]], what: str) -> Optional[Tuple[str, str]]:
    if not rec or not (rec.get("components") or rec.get("vulns") or _arch(rec)):
        return ("", "이 다이어그램은 분석된 프로젝트 기록이 필요합니다 (%s가 그리려는 데이터입니다) - 먼저 프로젝트를 분석하세요." % what)
    return None


def _dir_of(mod: str, depth: int = 2) -> str:
    parts = str(mod).replace("\\", "/").strip("/").split("/")
    return "/".join(parts[:depth]) if len(parts) > depth else ("/".join(parts[:-1]) or "(root)")


def _dir_edges(rec: Dict[str, Any], depth: int = 2) -> Dict[Tuple[str, str], int]:
    """Pairwise directory-level edges aggregated from the recorded import edges (measured, never invented)."""
    agg: Dict[Tuple[str, str], int] = {}
    for e in _arch(rec).get("edges") or []:
        a, b = e if isinstance(e, (list, tuple)) else (e.get("a"), e.get("b"))
        da, db = _dir_of(a, depth), _dir_of(b, depth)
        if da != db:
            agg[(da, db)] = agg.get((da, db), 0) + 1
    return agg


def latest_arch_doc(arch_dir: Optional[str]) -> Optional[Dict[str, Any]]:
    """Newest finished Arch Intel result in the evidence folder (same selection rule as the chat's latest_arch)."""
    if not arch_dir:
        return None
    from .arch_intel import load_result                    # local import: keep the module graph light
    best: Optional[Tuple[str, Dict[str, Any]]] = None
    try:
        names = sorted(os.listdir(arch_dir))
    except OSError:
        return None
    for n in names:
        doc = load_result(os.path.join(arch_dir, n))
        if not doc:
            continue
        fin = str((doc.get("meta") or {}).get("finished") or "")
        if best is None or fin >= best[0]:
            best = (fin, doc)
    return best[1] if best else None


def facts_from_record(rec: Optional[Dict[str, Any]], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """DMN input facts measured from the record (worst severity, malware presence, license category of the
    project license, worst fix availability) plus caller-supplied overrides. Unknown facts stay absent - the
    engine treats absence honestly instead of guessing a default."""
    facts: Dict[str, Any] = {}
    vulns = (rec or {}).get("vulns") or []
    if vulns:
        order = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        worst = max(vulns, key=lambda v: order.get(str(v.get("severity")).upper(), 0))
        facts["severity"] = str(worst.get("severity")).lower()
        facts["malicious"] = any(v.get("malicious") for v in vulns)
        facts["fixed_available"] = any(v.get("fixed_version") for v in vulns)
    lic = (rec or {}).get("license") or {}
    if lic.get("project_license"):
        try:
            from . import licenses as _lic
            facts["license_category"] = _lic.category(lic["project_license"])
        except Exception:                                      # noqa: BLE001 - a category lookup must never break a diagram
            pass
    if extra:
        for k, v in extra.items():
            facts[k] = v
    return facts


# --------------------------------------------------------------------------------------------------- builders
def _pkg(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "import graph")
    if bad:
        return bad
    agg = _dir_edges(rec, 2)
    if not agg:
        raw = len(_arch(rec).get("edges") or [])
        why = ("엣지 %d개가 모두 같은 도메인 내부라 경계 엣지가 없습니다" % raw) if raw else \
              "기록된 import 엣지가 없습니다 (엣지 수집 이전 스캔이거나 평탄한 구조입니다)"
        return "", why + " - 다시 분석하면 그려집니다."
    seen: Dict[str, str] = {}
    lines = ["flowchart TD"]
    dirs: List[str] = []
    for (a, b) in list(agg)[:MAX_EDGES]:
        for d in (a, b):
            if d not in seen:
                seen[d] = _pid("d", seen, d)
                dirs.append(d)
        lines.append('  %s["%s"] -->|%d| %s["%s"]' % (seen[a], _esc(a), min(agg[(a, b)], 99), seen[b], _esc(b)))
    note = "디렉터리(2단계) 단위로 집계한 실측 import 엣지 %d개 중 %d개 그림 (레코드의 arch.edges)." % (len(agg), min(len(agg), MAX_EDGES))
    if len(agg) > MAX_EDGES:
        note += " 상위 %d개만 그렸다 (cap)." % MAX_EDGES
    return "\n".join(lines), note


def _cls(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "code intel classes")
    if bad:
        return bad
    classes = _code(rec).get("classes") or []
    if not classes:
        return "", "이 트리에는 측정된 Python 클래스가 없습니다 (Code Intel 레인은 Python-only입니다)."
    pick = classes[:MAX_NODES]
    names = {c["name"] for c in pick}
    lines = ["classDiagram"]
    for c in pick:
        lines.append('  class %s["%s"]' % (re.sub(r"\W", "_", c["name"]), _esc(c["name"] + " - " + os.path.basename(c.get("file") or ""))))
        for m in (c.get("methods") or [])[:8]:
            lines.append("  %s: +%s()" % (re.sub(r"\W", "_", c["name"]), _esc(m, 40)))
    inh = 0
    for c in pick:
        for b in c.get("bases") or []:
            bn = re.split(r"[<\[( ]", str(b))[0]
            if bn in names and bn != c["name"]:
                lines.append("  %s --|> %s" % (re.sub(r"\W", "_", c["name"]), re.sub(r"\W", "_", bn)))
                inh += 1
    note = "측정된 클래스 %d개 중 %d개, 메서드는 클래스당 최대 8개, 상속 %d건 (bases가 측정된 클래스 안에서만 연결)." % (len(classes), len(pick), inh)
    if len(classes) > MAX_NODES:
        note += " 상위 %d개만 (cap)." % MAX_NODES
    return "\n".join(lines), note


def _bdd(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    """SysML Block Definition Diagram over the measured classes: every class is a «block», the measured
    bases are the generalization tree, methods are operations. Part/association ends are NOT invented -
    the note says what a BDD would add that this tool does not measure."""
    bad = _need_project(rec, "code intel classes")
    if bad:
        return bad
    classes = _code(rec).get("classes") or []
    if not classes:
        return "", "측정된 Python 클래스가 없어 블록 정의 다이어그램을 그릴 수 없습니다."
    pick = classes[:MAX_NODES]
    names = {c["name"] for c in pick}
    lines = ["classDiagram"]
    for c in pick:
        cid = re.sub(r"\W", "_", c["name"])
        members = ["    <<block>>"] + ["    +%s()" % _esc(m, 40) for m in (c.get("methods") or [])[:8]]
        lines.append('  class %s["%s"]{' % (cid, _esc(c["name"] + " - " + os.path.basename(c.get("file") or ""), 50)))
        lines.extend(members)
        lines.append("  }")
    gen = 0
    for c in pick:
        for b in c.get("bases") or []:
            bn = re.split(r"[<\[( ]", str(b))[0]
            if bn in names and bn != c["name"]:
                lines.append("  %s --|> %s : generalization" % (re.sub(r"\W", "_", c["name"]), re.sub(r"\W", "_", bn)))
                gen += 1
    note = "«블록» %d개(측정 클래스), 일반화 %d건(bases). part/association 단은 이 도구가 측정하지 않아 그리지 않는다." % (len(pick), gen)
    if len(classes) > MAX_NODES:
        note += " 상위 %d개만 (cap)." % MAX_NODES
    return "\n".join(lines), note


def _ibd(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    """SysML Internal Block Diagram: one block's internal structure - the same measured facts as the
    composite-structure builder (parts = methods, connectors = resolved calls), SysML notation on top."""
    src, note = _composite(rec, doc, target, spec)
    if not src:
        return src, note
    lines = src.splitlines()
    lines[0] = lines[0].replace("flowchart", "flowchart")            # notation stays a flowchart; the title carries the kind
    return "\n".join(lines), "IBD 뷰: " + note


def _parametric(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    """SysML Parametric notation over the constraint network we genuinely run: the remediation-policy
    decision table. Each rule is a «constraint» block; measured facts bind to input pins, the fired rule's
    result pin is marked. The note states the mapping - this draws OUR policy, not a measured SysML model."""
    facts = facts_from_record(rec)
    table = dmn.remediation_policy()
    res = dmn.evaluate(table, facts)
    lines = ["flowchart LR"]
    seen: Dict[str, str] = {}
    for k in sorted(facts):
        lines.append('  %s["«value» %s = %s"]' % (_pid("p", seen, k), _esc(k, 22), _esc(str(facts[k]), 20)))
    for r in table.rules:
        cid = _pid("c", seen, r.rid)
        cond = "; ".join("%s %s" % (k, r.conditions.get(k, "*")) for k in table.inputs)
        fired = r.rid in res.get("matched", [])
        lines.append('  %s{"«constraint» %s: %s"}' % (cid, r.rid, _esc(cond, 56)))
        for k in sorted(facts):
            lines.append("  %s -. %s .-> %s" % (_pid("p", seen, k), _esc(k, 16), cid))
        lines.append('  %s ==>|"result: %s %s"| %s' % (cid, r.outputs.get("priority", ""), "FIRE" if fired else "-",
                                                       'out["«output» %s"]' % _esc(str(r.outputs.get("action", "")), 48) if fired else "out%d" % len(seen)))
        if not fired:
            lines.append('  out%d[?"%s"]' % (len(seen), _esc(str(r.outputs.get("action", "")), 44)))
    lines.append('  out --> done([결정])')
    note = "파라메트릭 표기 매핑: «constraint»=정책 규칙 %d개, «value»=측정 팩트 %d개, 발화=%s. SysML 모델이 아니라 우리 정책 제약망이다." % (
        len(table.rules), len(facts), ",".join(res["matched"]) or "없음")
    return "\n".join(lines), note


def _robustness(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    """ICONIX Robustness notation with the classification rules stated up front: boundary = measured entry
    points, control = the classes with the highest measured call degree, entity = the remaining classes.
    The classification is a stated heuristic reading of measured degrees - never presented as fact."""
    bad = _need_project(rec, "entry points + classes")
    if bad:
        return bad
    entries = [e.get("path") for e in ((doc or {}).get("structure") or {}).get("entry_points") or [] if e.get("path")][:5]
    classes = _code(rec).get("classes") or []
    fns = _code(rec).get("functions") or []
    if not classes:
        return "", "클래스가 측정되지 않아 러스트니스 분류를 할 수 없습니다."
    degree: Dict[str, int] = {}
    for f in fns:
        c = f.get("cls")
        if c:
            degree[c] = degree.get(c, 0) + (f.get("fan_in", 0) + f.get("fan_out", 0))
    ranked = sorted(degree, key=lambda c: -degree[c])
    controls, entities = set(ranked[:2]), set(ranked[2:8])
    lines = ["flowchart LR"]
    for e in entries:
        lines.append('  b_%s[["«boundary» %s"]]' % (re.sub(r"\W", "_", _dir_of(e, 1)), _esc(_dir_of(e, 1), 24)))
    for c in sorted(controls):
        lines.append('  k_%s(["«control» %s"])' % (re.sub(r"\W", "_", c), _esc(c, 24)))
    for c in sorted(entities):
        lines.append('  n_%s[("«entity» %s")]' % (re.sub(r"\W", "_", c), _esc(c, 24)))
    drawn = 0
    for e in entries:
        for c in sorted(controls):
            lines.append("  b_%s --> k_%s" % (re.sub(r"\W", "_", _dir_of(e, 1)), re.sub(r"\W", "_", c)))
            drawn += 1
    for c in sorted(controls):
        for n in sorted(entities):
            lines.append("  k_%s --> n_%s" % (re.sub(r"\W", "_", c), re.sub(r"\W", "_", n)))
            drawn += 1
    note = ("분류 규칙(경계=entry point %d개, 제어=호출 차수 상위 %s, 개체=나머지 클래스 %d개)은 측정 차수에 대한 "
            "명시적 휴리스틱이다 - ICONIX 의미론의 자동 판정이 아니다." % (len(entries), ",".join(sorted(controls)) or "없음", len(entities)))
    return "\n".join(lines), note


def _obj(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "SBOM components")
    if bad:
        return bad
    comps = (rec.get("components") or [])[:MAX_NODES]
    if not comps:
        return "", "기록된 컴포넌트가 없습니다."
    blocks: List[str] = ["flowchart LR"]
    cur_eco: Optional[str] = None
    count = 0
    for c in comps:
        eco = str(c.get("ecosystem") or "?")
        if eco != cur_eco:
            if cur_eco is not None:
                blocks.append("  end")
            cur_eco = eco
            blocks.append('  subgraph p_%s["%s"]' % (re.sub(r"\W", "_", eco), _esc(eco)))
        blocks.append('    o_%s_%s["%s : %s"]' % (re.sub(r"\W", "_", eco), re.sub(r"\W", "_", str(c.get("name"))), _esc(c.get("name"), 40), _esc(c.get("version"), 20)))
        count += 1
    if cur_eco is not None:
        blocks.append("  end")
    note = "SBOM 인스턴스 %d개 (컴포넌트:버전). 인스턴스 간 측정된 엣지는 없다 - SBOM은 관계가 아니라 존재를 기록한다 (거짓 관계는 그리지 않는다)." % count
    if len(rec.get("components") or []) > MAX_NODES:
        note += " 상위 %d개만 (cap)." % MAX_NODES
    return "\n".join(blocks), note


def _composite(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    code = _code(rec)
    fns = code.get("functions") or []
    if not fns:
        return "", "함수 수준 분석이 없습니다 (Code Intel 레인은 Python-only)."
    cls = target or next((c.get("name") for c in sorted((code.get("classes") or []), key=lambda c: -len(c.get("methods") or []))), None)
    if not cls:
        return "", "컴포지트 구조를 그릴 클래스가 없습니다. target으로 클래스를 지정하세요."
    members = [f for f in fns if f.get("cls") == cls][:12]
    if not members:
        return "", "클래스 %s의 측정된 메서드가 없습니다." % cls
    edges = code.get("call_edges") or []
    ids = {f["id"] for f in members}
    lines = ["flowchart TD", '  subgraph C["%s (composite structure)"]' % _esc(cls)]
    for f in members:
        lines.append('    m_%s["%s() cc%s"]' % (re.sub(r"\W", "_", f["name"]), _esc(f["name"], 30), f.get("complexity", "?")))
    out_targets: Dict[str, str] = {}
    for e in edges[:400]:
        a = e["from"] if isinstance(e, dict) else e[0]
        b = e["to"] if isinstance(e, dict) else e[1]
        fa = str(a).split("::")[-1]
        if str(a) not in ids:
            continue
        if str(b) in ids:
            lines.append('    m_%s --- m_%s' % (re.sub(r"\W", "_", fa), re.sub(r"\W", "_", str(b).split("::")[-1])))
        else:
            out_cls = next((f.get("cls") or str(b).split("::")[0] for f in fns if f["id"] == str(b)), None)
            if out_cls and out_cls != cls:
                out_targets.setdefault(out_cls, re.sub(r"\W", "_", out_cls))
                lines.append('    m_%s -->|call| O_%s' % (re.sub(r"\W", "_", fa), out_targets[out_cls]))
    lines.append("  end")
    for out_cls, pid in out_targets.items():
        lines.append('  O_%s["%s"]' % (pid, _esc(out_cls)))
    note = "클래스 %s 내부 구조: 측정된 메서드 %d개, 내부 호출과 외부 클래스로의 해결된 호출을 표시." % (cls, len(members))
    return "\n".join(lines), note


def _component(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    """Domain-cluster component graph. Prefers the Arch Intel bounded-context components when a doc exists
    (they carry role labels), falls back to measured directory domains over the recorded import edges."""
    if doc and ((doc.get("analysis") or {}).get("components")):
        comps = (doc["analysis"]["components"] or [])[:MAX_NODES]
        agg: Dict[Tuple[str, str], int] = {}
        owner: Dict[str, int] = {}
        for i, c in enumerate(comps):
            for f in c.get("files") or []:
                owner.setdefault(str(f), i)
        for e in (doc.get("structure") or {}).get("edges") or []:
            ia, ib = owner.get(str(e[0] if isinstance(e, (list, tuple)) else e.get("a"))), \
                owner.get(str(e[1] if isinstance(e, (list, tuple)) else e.get("b")))
            if ia is not None and ib is not None and ia != ib:
                agg[(min(ia, ib), max(ia, ib))] = agg.get((min(ia, ib), max(ia, ib)), 0) + 1
        lines = ["flowchart TD"]
        for i, c in enumerate(comps):
            lines.append('  c%d["%s"]' % (i, _esc("%s - %s" % (c.get("name"), c.get("role") or ""), 70)))
        drawn = 0
        for (a, b), n in sorted(agg.items())[:MAX_EDGES]:
            lines.append("  c%d -->|%d| c%d" % (a, n, b))
            drawn += 1
        return "\n".join(lines), "Arch Intel 경계 컨텍스트 %d개, 실측 엣지 %d개." % (len(comps), drawn)
    bad = _need_project(rec, "import graph")
    if bad:
        return bad
    agg = _dir_edges(rec, 2)
    if not agg:
        return "", "기록된 import 엣지가 없어 도메인 클러스터를 연결할 수 없습니다."
    lines = ["flowchart TD"]
    seen: Dict[str, str] = {}
    for (a, b), n in list(sorted(agg.items(), key=lambda kv: -kv[1]))[:MAX_EDGES]:
        for d in (a, b):
            if d not in seen:
                seen[d] = _pid("k", seen, d)
        lines.append('  %s["%s"] -->|%d| %s["%s"]' % (seen[a], _esc(a), min(n, 99), seen[b], _esc(b)))
    return "\n".join(lines), "디렉터리 도메인을 컴포넌트로 봤다 (bounded-context 후보가 기록되지 않은 레코드)."


def _deployment(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "components + runtimes")
    if bad:
        return bad
    rts = _arch(rec).get("runtime_eol") or []
    comps = (rec.get("components") or [])[:12]
    lines = ["flowchart TD"]
    lines.append('  dev[("개발/분석 워크스테이션")]')
    for i, r in enumerate(rts[:6]):
        eol = str(r.get("eol_date") or "?")
        st = str(r.get("status") or "?")
        lines.append('  dev --> rt%d["%s %s (EOL %s, %s)"]' % (i, _esc(r.get("product"), 20), _esc(r.get("cycle"), 10), _esc(eol, 12), _esc(st, 10)))
    if not rts:
        lines.append('  dev --> rt0["선언된 런타임 없음 (매니페스트에서 측정 안 됨)"]')
    for i, c in enumerate(comps):
        lines.append('  art%d["%s : %s"] --> dev' % (i, _esc(c.get("name"), 40), _esc(c.get("version"), 16)))
    note = "아티팩트=SBOM 컴포넌트 %d개, 실행 노드=측정된 런타임 %d개 (EOL은 endoflife.date 또는 내장 표 기준)." % (len(comps), len(rts))
    return "\n".join(lines), note


def _logical(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "layer validation")
    if bad:
        return bad
    lv = (rec or {}).get("layer_validation")
    if not lv:
        return "", "기록된 layer_validation이 없습니다 - arch CLI에 --layers로 규칙을 선언해 검증하면 이 다이어그램이 채워집니다."
    groups: Dict[str, List[str]] = {}
    lines = ["flowchart TD"]
    illegal = lv.get("violations") or []
    bypassed = lv.get("bypassed") or []
    for v in illegal[:MAX_EDGES]:
        a, b = v["edge"]
        la, lb = v.get("from_layer", "?"), v.get("to_layer", "?")
        for l, m in ((la, a), (lb, b)):
            if l not in groups:
                groups[l] = []
                lines.insert(len(lines), '  subgraph L_%s["layer: %s"]' % (re.sub(r"\W", "_", l), _esc(l)))
            if m not in groups[l]:
                groups[l].append(m)
                lines.append('    n_%s["%s"]' % (re.sub(r"\W", "_", m), _esc(_dir_of(m, 2))))
        lines.append("  end")
        lines.append('  n_%s -. "%s" .-> n_%s' % (re.sub(r"\W", "_", a), _esc("illegal: " + v.get("why", ""), 50), re.sub(r"\W", "_", b)))
    for v in bypassed[:20]:
        a, c = v["edge"]
        lines.append('  n_%s -. "bypassed via %s" .-> n_%s' % (re.sub(r"\W", "_", a), _esc(v.get("through_layer", "?"), 20), re.sub(r"\W", "_", c)))
    if not lines[1:]:
        lines.append('  ok["위반 없음 (verdict: %s)"]' % _esc(lv.get("verdict"), 14))
    note = "선언 레이어 %d개, 검증 엣지 %d개: 위반 %d, 우회 %d, 미분류 %d (verdict %s)." % (
        lv.get("layers_declared", 0), lv.get("checked", 0), len(illegal), len(bypassed), lv.get("unknown_layer_edges", 0), lv.get("verdict", "?"))
    return "\n".join(lines), note


def _usecase(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    scen = ((doc or {}).get("analysis") or {}).get("scenarios") or []
    if not scen:
        return "", "Arch Intel 시나리오가 없습니다 - Arch Intel 탭에서 분석을 먼저 실행하세요 (아키텍처 시나리오는 SBOM 스캔이 수집하지 않는다)."
    lines = ["flowchart LR"]
    drawn = 0
    for s in scen[:3]:
        sid = _pid("u", {}, s.get("name") or "scenario")
        actors = sorted({str(st.get("actor")) for st in s.get("steps") or []})
        for a in actors:
            aid = _pid("a", {}, a)
            lines.append('  %s(["%s"]) --> %s["%s"]' % (aid, _esc(a, 30), sid, _esc(s.get("name"), 50)))
            drawn += 1
        for st in (s.get("steps") or [])[:6]:
            lines.append('  %s -.->|"%s"| %s["%s"]' % (sid, _esc(st.get("action"), 40), _pid("s", {}, str(st.get("target"))), _esc(st.get("target"), 30)))
            drawn += 1
    return "\n".join(lines), "시나리오 %d개의 액터-유스케이스-대상 관계 (Arch Intel 분석 결과에서)." % min(len(scen), 3)


def _activity(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    flows = ((doc or {}).get("analysis") or {}).get("activity") or []
    if not flows:
        return "", "Arch Intel 활동 흐름이 없습니다 - Arch Intel 탭에서 분석을 먼저 실행하세요."
    from .arch_intel import mermaid_activity                  # the existing deterministic builder (single source of truth)
    f = flows[0]
    src, note = mermaid_activity(f)
    if not src:
        return "", note or "그릴 흐름이 없습니다 (2단계 미만)."
    return src, "흐름 '%s': %s" % (f.get("name"), note or "단계 %d개" % len(f.get("steps") or []))


def _state(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "vulns + plans")
    if bad:
        return bad
    vulns = rec.get("vulns") or []
    mal = sum(1 for v in vulns if v.get("malicious"))
    fix = sum(1 for v in vulns if v.get("fixed_version") and not v.get("malicious"))
    nofix = len(vulns) - fix - mal
    plans = rec.get("plans") or []
    up = [p for p in plans if p.get("status") == "upgrade"]
    clean = [p for p in up if (p.get("verification") or {}).get("clean") is True]
    dirty = [p for p in up if (p.get("verification") or {}).get("clean") is False]
    lines = ["stateDiagram-v2", "  [*] --> Detected: 악성/취약 발견 (측정 %d건)" % len(vulns)]
    if mal:
        lines.append("  Detected --> Quarantine: 악성 패키지 %d건" % mal)
    lines.append("  Detected --> Triaged: 분류 완료")
    if fix:
        lines.append("  Triaged --> FixAvailable: 수정판 존재 %d건" % fix)
    if nofix:
        lines.append("  Triaged --> NoFix: 수정판 없음 %d건" % nofix)
    lines.append("  FixAvailable --> Planned: 해결 계획 %d건" % len(up))
    lines.append("  Planned --> VerifiedClean: 재스캔 통과 %d건" % len(clean))
    if dirty:
        lines.append("  Planned --> Regression: 재스캔 실패 %d건" % len(dirty))
    lines.append("  VerifiedClean --> [*]")
    lines.append('  state "검역 (malware)" as Quarantine')
    note = "발견된 취약 %d건의 실측 수명주기: 악성 %d, 수정판 있음 %d, 없음 %d, 계획 %d(통과 %d/실패 %d)." % (
        len(vulns), mal, fix, nofix, len(up), len(clean), len(dirty))
    return "\n".join(lines), note


def _sequence(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    scen = ((doc or {}).get("analysis") or {}).get("scenarios") or []
    if not scen:
        return "", "Arch Intel 시나리오가 없습니다 - Arch Intel 탭에서 먼저 분석하세요."
    from .arch_intel import mermaid_sequence
    s = next((x for x in scen if (target or "").lower() in str(x.get("name")).lower()), scen[0]) if target else scen[0]
    return mermaid_sequence(s), "시나리오 '%s' (%d단계%s)." % (s.get("name"), len(s.get("steps") or []), ", 추론 표시" if s.get("inferred") else "")


def _communication(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    scen = ((doc or {}).get("analysis") or {}).get("scenarios") or []
    if not scen:
        return "", "Arch Intel 시나리오가 없습니다."
    s = scen[0]
    msgs: Dict[Tuple[str, str], int] = {}
    for st in s.get("steps") or []:
        key = (str(st.get("actor")), str(st.get("target")))
        msgs[key] = msgs.get(key, 0) + 1
    lines = ["flowchart LR"]
    seen: Dict[str, str] = {}
    seq = 0
    for (a, b), n in msgs.items():
        for x in (a, b):
            if x not in seen:
                seen[x] = _pid("p", seen, x)
        seq += 1
        lines.append('  %s(["%s"]) -->|%d. x%d| %s["%s"]' % (seen[a], _esc(a, 30), seq, n, seen[b], _esc(b, 30)))
    return "\n".join(lines), "시나리오 '%s'의 참가자 %d개, 메시지 %d건을 집계해 그렸다 (시퀀스를 무향 그래프로 재표현)." % (s.get("name"), len(seen), sum(msgs.values()))


def _interaction(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    scen = ((doc or {}).get("analysis") or {}).get("scenarios") or []
    flows = ((doc or {}).get("analysis") or {}).get("activity") or []
    if not scen and not flows:
        return "", "Arch Intel 분석 결과가 없습니다."
    lines = ["flowchart TD"]
    f = flows[0] if flows else None
    if f:
        steps = f.get("steps") or []
        for i, s in enumerate(steps[:12]):
            lines.append('  i%d["%s"]' % (i, _esc("%d. %s" % (i + 1, s), 60)))
        for i in range(min(len(steps), 12) - 1):
            lines.append("  i%d --> i%d" % (i, i + 1))
        for j, d in enumerate(f.get("decisions") or []):
            q = d.get("question") or "condition"
            lines.append('  g%d{"%s"}' % (j, _esc(q, 50)))
            lines.append("  i%d -.-> g%d" % (min(int(d.get("after_step", 0)), 11), j))
            lines.append("  g%d -- yes --> i%d" % (j, min(int(d.get("then_step", 0)), 11)))
            lines.append("  g%d -- no --> i%d" % (j, min(int(d.get("else_step", 0)), 11)))
    if scen:
        lines.append('  seq0(["%s 이후: 시퀀스 %d개로 세분화"])' % (_esc(scen[0].get("name"), 30), len(scen)))
    return "\n".join(lines), "흐름 '%s'의 단계를 인터랙션 발생으로, 분기를 게이트웨이로 그린 오버뷰." % (f.get("name") if f else scen[0].get("name"))


def _timing(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "측정 날짜")
    if bad:
        return bad
    today = _today()
    tasks: List[Tuple[str, str, str, int]] = []                # (section, name, start, days)
    date_rx = re.compile(r"^\d{4}-\d{2}-\d{2}")
    for v in (rec.get("vulns") or [])[:12]:
        pub = str(v.get("published") or "")[:10]
        if date_rx.match(pub):
            try:
                d0 = _dt.date.fromisoformat(pub)
                days = max(1, (today - d0).days)
                tasks.append(("공개 이후 노출", "%s %s (%s)" % (v.get("package"), v.get("id"), v.get("severity")), pub, min(days, 999)))
            except ValueError:
                pass
    for r in (_arch(rec).get("runtime_eol") or []):
        eol = str(r.get("eol_date") or "")
        if date_rx.match(eol):
            try:
                d1 = _dt.date.fromisoformat(eol)
                d0 = min(d1, today)
                days = max(1, (today - d0).days) or 1
                tasks.append(("런타임 EOL", "%s %s (%s)" % (r.get("product"), r.get("cycle"), r.get("status")), d0.isoformat(), min(days, 999)))
            except ValueError:
                pass
    if not tasks:
        return "", "그릴 측정 날짜가 없습니다 (공개일이 있는 취약점이나 EOL 날짜가 있는 런타임이 이 기록에 없다)."
    lines = ["gantt", "  title 측정된 날짜 (공개일·EOL; 오늘 기준 %s)" % today.isoformat(), "  dateFormat YYYY-MM-DD", "  axisFormat %Y-%m"]
    secs: Dict[str, bool] = {}
    for sec, name, start, days in tasks[:MAX_NODES]:
        if sec not in secs:
            secs[sec] = True
            lines.append("  section %s" % _esc(sec, 30))
        lines.append('  "%s" :%s, %s, %dd' % (_esc(name, 50), "crit," if "EOL" in sec else "", start, days))
    return "\n".join(lines), "취약 공개 이후 경과일 %d건, 런타임 EOL %d건을 실측 날짜로 그렸다." % (
        sum(1 for t in tasks if t[0].startswith("공개")), sum(1 for t in tasks if t[0].startswith("런타임")))


def _requirements(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "conformance")
    if bad:
        return bad
    conf = rec.get("conformance") or {}
    regimes = conf.get("regimes") or {}
    if not regimes:
        return "", "기록된 적합성 검사가 없습니다 (이 레코드는 conformance 단계를 건너뛰었다)."
    lines = ["requirementDiagram"]
    for k, v in list(regimes.items())[:8]:
        verdict = str(v.get("verdict") or "?")
        risk = "High" if verdict == "fail" else ("Medium" if verdict == "partial" else "Low")
        lines.append('  requirement req_%s {' % re.sub(r"\W", "_", k))
        lines.append('    id: %s' % re.sub(r"\W", "_", k))
        lines.append('    text: %s (pass %s/partial %s/gap %s)' % (_esc(v.get("title") or k, 60), v.get("pass", "?"), v.get("partial", "?"), v.get("gap", "?")))
        lines.append('    risk: %s' % risk)
        lines.append('    verifymethod: Analysis')
        lines.append('  }')
        lines.append('  requirement req_%s - traces - element sbom_doc' % re.sub(r"\W", "_", k))
    lines.append('  element sbom_doc {')
    lines.append('    type: %s' % _esc(conf.get("format") or "SBOM document", 30))
    lines.append('  }')
    fails = sum(1 for v in regimes.values() if str(v.get("verdict")) == "fail")
    note = "적합성 체계 %d개 (fail %d)를 요구사항으로, 생성된 SBOM 문서를 대상 요소로 연결 (verdict 기준 risk)." % (len(regimes), fails)
    return "\n".join(lines), note


def _maintenance(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "changes")
    if bad:
        return bad
    ch = rec.get("changes")
    if not ch:
        return "", "기록된 변경 비교가 없습니다 - 같은 소스를 두 번 분석하면 이 다이어그램이 채워집니다."
    lines = ["flowchart LR"]
    for i, x in enumerate((ch.get("new") or [])[:10]):
        lines.append('  nw%d["신규: %s %s"] --> base' % (i, _esc(x.get("package", x.get("id", "?")), 30), _esc(x.get("id", ""), 20)))
    for i, x in enumerate((ch.get("resolved") or [])[:10]):
        lines.append('  base --> rs%d["해소: %s %s"]' % (i, _esc(x.get("package", x.get("id", "?")), 30), _esc(x.get("id", ""), 20)))
    for i, a in enumerate((ch.get("alerts") or [])[:8]):
        lines.append('  base -. "%s" .-> al%d["경보: %s %s"]' % (_esc(a.get("severity"), 10), i, _esc(a.get("kind"), 16), _esc(a.get("package"), 24)))
    lines.append('  base["%s 기준점 (%s)"]' % (_esc(rec.get("name", "project"), 24), _esc(ch.get("compared_at", "?"), 20)))
    s = ch.get("summary") or {}
    note = "이전 분석 대비: 신규 %d, 해소 %d, 재채점 %d, 경보 %d (verdict %s)." % (
        s.get("vulns_new", len(ch.get("new") or [])), s.get("vulns_resolved", len(ch.get("resolved") or [])),
        s.get("vulns_rescored", 0), s.get("alerts", len(ch.get("alerts") or [])), ch.get("verdict", "?"))
    return "\n".join(lines), note


def _dashboard(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "vuln severities")
    if bad:
        return bad
    counts: Dict[str, int] = {}
    for v in rec.get("vulns") or []:
        s = str(v.get("severity") or "UNKNOWN")
        counts[s] = counts.get(s, 0) + 1
    if not counts:
        return "", "심각도 분포를 그릴 취약점이 없습니다 (0건은 '없음'이고, 그 사실은 라인으로 말한다)."
    lines = ["pie title 심각도 분포 (측정 %d건)" % sum(counts.values())]
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        if counts.get(s):
            lines.append('  "%s" : %d' % (s, counts[s]))
    note = "취약 %d건: %s." % (sum(counts.values()), ", ".join("%s %d" % kv for kv in sorted(counts.items())))
    return "\n".join(lines), note


def _erd(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "evidence counts")
    if bad:
        return bad
    nc, nv = len(rec.get("components") or []), len(rec.get("vulns") or [])
    plans = rec.get("plans") or []
    ch = rec.get("changes") or {}
    lines = ["erDiagram"]
    lines.append('  PROJECT ||--o{ COMPONENT : "contains (%d)"' % nc)
    lines.append('  COMPONENT ||--o{ ADVISORY : "affected by (%d)"' % nv)
    lines.append('  ADVISORY |o--o| PLAN : "remediated by (%d plans)"' % len(plans))
    lines.append('  PROJECT ||--o| CHANGESET : "compared against (%s)"' % ("yes" if ch else "none"))
    lines.append('  PROJECT {')
    lines.append('    string name "%s"' % _esc(rec.get("name", "?"), 40))
    lines.append('    string project_license "%s"' % _esc((rec.get("license") or {}).get("project_license") or "unresolved", 30))
    lines.append('  }')
    lines.append('  COMPONENT {')
    lines.append('    string name "e.g. %s"' % _esc((rec.get("components") or [{}])[0].get("name", "?"), 30))
    lines.append('    string version')
    lines.append('    string license')
    lines.append('  }')
    lines.append('  ADVISORY {')
    lines.append('    string id "e.g. %s"' % _esc(((rec.get("vulns") or [{}])[0].get("id", "?")), 24))
    lines.append('    string severity')
    lines.append('  }')
    note = "이 도구가 이 프로젝트에 대해 기록한 증거 스키마(컴포넌트 %d, 취약 %d, 계획 %d)를 ERD로 그렸다 - 분석 대상 코드의 스키마가 아니다." % (nc, nv, len(plans))
    return "\n".join(lines), note


def _business(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "license resolution")
    if bad:
        return bad
    fams: Dict[str, List[str]] = {}
    from . import licenses as _lic
    for c in (rec.get("components") or [])[:200]:
        lic = c.get("license") or c.get("license_raw") or "unknown"
        try:
            cat = _lic.category(str(lic))
        except Exception:                                      # noqa: BLE001
            cat = "unknown"
        fams.setdefault(cat or "unknown", []).append(str(c.get("name")))
    if not fams:
        return "", "라이선스 카테고리를 그릴 컴포넌트가 없습니다."
    lines = ["classDiagram"]
    shown = 0
    for cat, members in sorted(fams.items()):
        cid = re.sub(r"\W", "_", cat)
        lines.append('  class %s["%s (family)"]' % (cid, _esc(cat, 30)))
        for m in members[:6]:
            lines.append("  %s: +%s()" % (cid, _esc(m, 36)))
            shown += 1
    note = "라이선스 카테고리 %d개를 비즈니스 객체(패밀리)로, 구성원 컴포넌트를 조작으로 표기 (%d개 표시, 200개까지 집계)." % (len(fams), shown)
    return "\n".join(lines), note


def _binter(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    scen = ((doc or {}).get("analysis") or {}).get("scenarios") or []
    if not scen:
        return "", "Arch Intel 시나리오가 없습니다."
    from .arch_intel import mermaid_sequence
    s = scen[0]
    return mermaid_sequence(s), "비즈니스 인터랙션 뷰: 시나리오 '%s'를 확장 시퀀스로 표기 (EA Business Interaction 정의에 따른다)." % s.get("name")


def _nodata(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    return "", "이 다이어그램(EA User Interface/Wireframing)은 사용자가 직접 꾸미는 목업이며, 이 도구가 측정하는 데이터에 UI 모델이 없다 - 거짓 와이어프레임은 그리지 않는다."


_CUSTOM_RX = re.compile(r"([^\s]+)\s*(?:->|-->)\s*([^\s]+)")


def parse_custom_spec(spec: str) -> Tuple[List[str], List[Tuple[str, str]], List[str]]:
    """Parse the conversational arrow grammar: ``A -> B -> C`` chains and ``A -> B`` pairs, one per line,
    ``#`` starts a comment. Returns (nodes in first-seen order, edges, problems)."""
    nodes: List[str] = []
    edges: List[Tuple[str, str]] = []
    problems: List[str] = []
    seen: Dict[str, None] = {}

    def add(x: str) -> str:
        x = x.strip()
        if x and x not in seen:
            seen[x] = None
            nodes.append(x)
        return x

    for ln in (spec or "").splitlines():
        line = ln.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("->")]
        parts = [p for p in parts if p]
        if len(parts) >= 2 and all(re.fullmatch(r"[\w가-힣.\-/: ]{1,40}", p) for p in parts):
            for a, b in zip(parts, parts[1:]):
                edges.append((add(a), add(b)))
        else:
            problems.append(line[:60])
    return nodes, edges, problems


def _custom(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    if not spec or not spec.strip():
        return "", "커스텀 다이어그램은 화살표 문장이 필요합니다. 예: `사용자 -> 게이트웨이 -> 스캐너 -> 리포트`"
    nodes, edges, problems = parse_custom_spec(spec)
    if not edges:
        return "", "화살표(->)를 해석하지 못했습니다: %s" % "; ".join(problems[:3]) if problems else "화살표(->)를 해석하지 못했습니다."
    lines = ["flowchart LR"]
    seen: Dict[str, str] = {}
    for n in nodes[:MAX_NODES]:
        lines.append('  %s["%s"]' % (_pid("n", seen, n), _esc(n, 40)))
    for a, b in edges[:MAX_EDGES]:
        lines.append("  %s --> %s" % (_pid("n", seen, a), _pid("n", seen, b)))
    note = "질문 문장에서 화살표 %d개, 노드 %d개를 그대로 옮겨 그렸다 (노드는 발견 순)." % (len(edges), len(nodes))
    if problems:
        note += " 해석 못한 줄 %d개는 버렸다: %s" % (len(problems), problems[0])
    return "\n".join(lines), note


def _xml(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "generated SBOM documents")
    if bad:
        return bad
    chk = rec.get("sbom_check") or {}
    lines = ["flowchart LR"]
    lines.append('  rec["분석 기록 (components + vulns)"]')
    lines.append('  rec --> cdx["CycloneDX (%s)"]' % ("valid" if chk.get("cyclonedx_valid") else "errors %s" % len(chk.get("cyclonedx_errors") or [])))
    lines.append('  rec --> spd["SPDX (%s)"]' % ("valid" if chk.get("spdx_valid") else "not built/errors"))
    lines.append('  rec --> vex["OpenVEX (vulns %d)"]' % chk.get("vulnerabilities", len(rec.get("vulns") or [])))
    lines.append('  cdx --> conf["conformance regimes"]')
    note = "생성된 SBOM 아티팩트 3종(CDX/SPDX/VEX)의 실측 흐름: 변환 결과의 유효성은 기록된 검증값 그대로."
    return "\n".join(lines), note


def _dfd(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "import graph")
    if bad:
        return bad
    agg = _dir_edges(rec, 2)
    entries = [e.get("path") for e in ((doc or {}).get("structure") or {}).get("entry_points") or [] if e.get("path")][:6]
    stores: List[str] = []
    for c in (rec.get("components") or []):
        n = str(c.get("name")).lower()
        if any(k in n for k in ("sqlite", "mysql", "postgres", "mongo", "redis", "sql")) and n not in stores:
            stores.append(n)
    if not agg and not entries:
        return "", "기록된 import 엣지와 entry point가 없어 데이터 흐름을 그릴 수 없습니다."
    lines = ["flowchart TD"]
    for i, e in enumerate(entries):
        lines.append('  ext%d["[%s]"] -->|input| proc0' % (i, _esc(_dir_of(e, 1), 30)))
    top = sorted(agg.items(), key=lambda kv: -kv[1])[:12]
    seen: Dict[str, str] = {}
    if not top:
        lines.append('  proc0[("처리: (엣지 없음)")]')
    for (a, b), n in top:
        for d in (a, b):
            if d not in seen:
                seen[d] = _pid("pr", seen, d)
        lines.append('  %s[("%s")] -->|%d| %s[("%s")]' % (seen[a], _esc(a, 26), min(n, 99), seen[b], _esc(b, 26)))
    for i, s in enumerate(stores[:5]):
        lines.append('  %s[("처리")] --> db%d[("DB: %s")]' % (list(seen.values())[:1] or ["proc0"], i, _esc(s, 26)))
    note = "외부 실체=entry point %d개, 처리=도메인 %d개, 데이터 저장소=이름 매칭 DB 컴포넌트 %d개 (매핑 규칙은 노트에 명시)." % (len(entries), len(seen) or 1, len(stores[:5]))
    return "\n".join(lines), note


def _flowchart(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "plans")
    if bad:
        return bad
    plans = rec.get("plans") or []
    up = [p for p in plans if p.get("status") == "upgrade"]
    clean = [p for p in up if (p.get("verification") or {}).get("clean") is True]
    dirty = [p for p in up if (p.get("verification") or {}).get("clean") is False]
    unv = len(up) - len(clean) - len(dirty)
    lines = ["flowchart TD"]
    lines.append('  s([스캔 완료]) --> p["계획: %d개 (업그레이드 %d, 수정판 없음 %d)"]' % (len(plans), len(up), len(plans) - len(up)))
    lines.append('  p --> g{"승인?"}')
    lines.append('  g -- 사용자 승인 --> a["패치 적용 (격리 작업복사본)"]')
    lines.append('  g -- 보류 --> stop["대기"]')
    lines.append('  a --> r{"재스캔 검증"}')
    lines.append('  r -- 통과 %d --> ok([완료])' % len(clean))
    lines.append('  r -- 실패 %d --> rev["자동 복귀 후 재계획"]' % len(dirty))
    lines.append('  rev --> p')
    if unv:
        lines.append('  a -. 미검증 %d .-> u["검증 대기"]' % unv)
    note = "해결 파이프라인 실측: 계획 %d, 승인·적용은 기록에 남은 검증 결과로 표시 (통과 %d/실패 %d/미검증 %d)." % (len(plans), len(clean), len(dirty), unv)
    return "\n".join(lines), note


def _bpmn(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    flows = ((doc or {}).get("analysis") or {}).get("activity") or []
    if not flows:
        return "", "Arch Intel 활동 흐름이 없습니다 - BPMN 표기는 Arch Intel 흐름 데이터에서 그린다."
    f = flows[0]
    steps = f.get("steps") or []
    if len(steps) < 2:
        return "", "2단계 미만 흐름은 그리지 않는다."
    lines = ["flowchart LR"]
    lines.append('  e0((시작))')
    for i, s in enumerate(steps[:10]):
        lines.append('  t%d["%s"]' % (i, _esc(s, 44)))
    lines.append("  e0 --> t0")
    for i in range(min(len(steps), 10) - 1):
        lines.append("  t%d --> t%d" % (i, i + 1))
    for j, d in enumerate((f.get("decisions") or [])[:3]):
        lines.append('  g%d{%s}' % (j, _esc(d.get("question") or "조건", 40)))
        lines.append("  t%d --> g%d" % (min(int(d.get("after_step", 0)), 9), j))
        lines.append("  g%d -- 예 --> t%d" % (j, min(int(d.get("then_step", 0)), 9)))
        lines.append("  g%d -- 아니오 --> t%d" % (j, min(int(d.get("else_step", 0)), 9)))
    lines.append('  t%d((종료))' % min(len(steps) - 1, 9))
    return "\n".join(lines), "BPMN 표기(이벤트 원, 태스크 상자, 게이트웨이 다이아몬드)로 흐름 '%s'를 그렸다 (%d단계)." % (f.get("name"), len(steps))


def _decision(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    facts = facts_from_record(rec)
    table = dmn.remediation_policy()
    res = dmn.evaluate(table, facts)
    lines = ["flowchart TD"]
    fk = sorted(facts)
    for i, k in enumerate(fk):
        lines.append('  in%d["%s = %s"]' % (i, _esc(k, 24), _esc(str(facts[k]), 24)))
    lines.append('  dt{"%s (hit policy %s)"}' % (_esc(table.name, 30), table.hit_policy))
    for i in range(len(fk)):
        lines.append("  in%d --> dt" % i)
    for r in table.rules:
        fired = "%s %s" % (r.outputs.get("priority", ""), r.outputs.get("action", ""))
        if r.rid in res.get("matched", []):
            lines.append('  dt ==>|"FIRE %s"| out["%s"]' % (r.rid, _esc(fired, 60)))
        else:
            lines.append('  dt -. %s: %s .-> sink["%s"]' % (r.rid, _esc(str(r.conditions) if r.conditions else "*", 40), _esc(fired, 50)))
    verdict = res.get("verdict")
    if verdict == "decided":
        lines.append('  out --> done([결정: %s])' % _esc(res["outputs"].get("action", ""), 60))
    elif verdict == "conflict":
        lines.append('  dt --> conf(["충돌: %s가 동시 발화 - 테이블이 잘못됐다"])' % _esc(",".join(res["matched"]), 20))
    else:
        lines.append('  dt --> none(["발화 없음: 측정 팩트가 부족하다 %s"])' % _esc(",".join(sorted(set(table.inputs) - set(facts)))[:60], 60))
    note = "추론 결과: %s (발화 규칙 %s; 팩트 %s). 테이블은 이 도구의 정책, 팩트는 기록의 측정값." % (
        verdict, ",".join(res["matched"]) or "없음", ", ".join("%s=%s" % (k, facts[k]) for k in fk) or "없음")
    lines_out = dmn.table_lines(table)
    return "\n".join(lines), note + "\n" + "\n".join(lines_out)


def _kanban(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "plans")
    if bad:
        return bad
    plans = rec.get("plans") or []
    up = [p for p in plans if p.get("status") == "upgrade"]
    nofix = [p for p in plans if p.get("status") == "no_fix"]
    clean = [p for p in up if (p.get("verification") or {}).get("clean") is True]
    dirty = [p for p in up if (p.get("verification") or {}).get("clean") is False]
    pending = [p for p in up if (p.get("verification") or {}).get("clean") is None]
    lines = ["flowchart LR"]
    cols = [("Backlog (수정판 없음)", nofix), ("Planned (계획됨)", pending), ("Review (재검토 필요)", dirty), ("Done (검증 통과)", clean)]
    for ci, (title, items) in enumerate(cols):
        lines.append('  subgraph col%d["%s (%d)"]' % (ci, _esc(title, 30), len(items)))
        for p in items[:6]:
            lines.append('    k_%s["%s %s -> %s"]' % (re.sub(r"\W", "_", "%s_%s" % (p.get("component"), p.get("current_version"))),
                                                      _esc(p.get("component"), 26), _esc(p.get("current_version"), 14), _esc(p.get("safe_version") or "?", 14)))
        if not items:
            lines.append("    k_empty[\"-\"]")
        lines.append("  end")
    note = "칸반 열 = 해결 상태의 실측 분류: 수정판 없음 %d, 계획(미검증) %d, 재검토(재스캔 실패) %d, 완료(통과) %d." % (len(nofix), len(pending), len(dirty), len(clean))
    return "\n".join(lines), note


def _archimate(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "components + runtimes")
    if bad:
        return bad
    rts = _arch(rec).get("runtime_eol") or []
    comps = (rec.get("components") or [])[:10]
    pol = (rec.get("license") or {}).get("policy") or {}
    lines = ["flowchart TD"]
    lines.append('  subgraph L_mot["동기 (Motivation)"]')
    lines.append('    m0["정책 판정 %d건, 프로젝트 라이선스 %s"]' % (len(pol if isinstance(pol, list) else (pol or {}).get("findings") or []),
                                                       _esc((rec.get("license") or {}).get("project_license") or "미해결", 24)))
    lines.append("  end")
    lines.append('  subgraph L_biz["비즈니스"]')
    scen = ((doc or {}).get("analysis") or {}).get("scenarios") or []
    lines.append('    b0["시나리오/서비스 %d개"]' % len(scen))
    lines.append("  end")
    lines.append('  subgraph L_app["애플리케이션"]')
    for i, c in enumerate(comps):
        lines.append('    a_%d["%s"]' % (i, _esc(str(c.get("name")), 28)))
    lines.append("  end")
    lines.append('  subgraph L_tech["기술"]')
    for i, r in enumerate(rts[:4]):
        lines.append('    t_%d["%s %s (%s)"]' % (i, _esc(r.get("product"), 16), _esc(r.get("cycle"), 8), _esc(r.get("status"), 10)))
    lines.append("  end")
    lines.append("  L_mot -. 제약 .-> L_app")
    lines.append("  b0 -. 서비스 .-> L_app")
    lines.append("  L_app -. 배치 .-> L_tech")
    note = "아키타메이트 계층 뷰: 동기=정책 판정, 비즈니스=시나리오, 애플리케이션=컴포넌트 %d개, 기술=측정 런타임 %d개 (계층 배치는 이 도구의 매핑 규칙)." % (len(comps), len(rts))
    return "\n".join(lines), note


def _mindmap(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "stack")
    if bad:
        return bad
    st = _arch(rec).get("stack") or {}
    lines = ["mindmap"]
    lines.append("  root((%s))" % _esc(rec.get("name", "project"), 30))
    langs = st.get("languages") or {}
    if langs:
        lines.append("    언어")
        for k, v in list(langs.items())[:5]:
            lines.append("      %s %d파일" % (_esc(k, 18), v.get("files", 0)))
    sev: Dict[str, int] = {}
    for v in rec.get("vulns") or []:
        sev[str(v.get("severity"))] = sev.get(str(v.get("severity")), 0) + 1
    if sev:
        lines.append("    취약 %d건" % sum(sev.values()))
        for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev.get(k):
                lines.append("      %s %d" % (k, sev[k]))
    rts = _arch(rec).get("runtime_eol") or []
    if rts:
        lines.append("    런타임")
        for r in rts[:4]:
            lines.append("      %s %s %s" % (_esc(r.get("product"), 14), _esc(r.get("cycle"), 8), _esc(r.get("status"), 10)))
    lic = (rec.get("license") or {}).get("stats") or {}
    top_lic = (lic.get("top") or lic.get("categories") or None)
    if isinstance(top_lic, dict) and top_lic:
        lines.append("    라이선스")
        for k in list(top_lic)[:5]:
            lines.append("      %s" % _esc(k, 20))
    elif isinstance(top_lic, list) and top_lic:
        lines.append("    라이선스")
        for x in top_lic[:5]:
            lines.append("      %s" % _esc(x.get("license") or x.get("spdx") or "?", 20))
    if len(lines) <= 2:
        return "", "마인드맵 가지를 만들 측정값이 이 기록에 없습니다."
    note = "스택·취약·런타임·라이선스 측정값을 마인드맵 가지로 재배열 (새 정보가 아니라 재표현이다)."
    return "\n".join(lines), note


def _call(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    bad = _need_project(rec, "code intel calls")
    if bad:
        return bad
    code = _code(rec)
    if not (code.get("call_edges") or []):
        return "", "해결된 함수 호출이 없습니다 (Code Intel 레인은 Python-only이며 이름 기반 해석이다)."
    from .arch_intel import mermaid_callgraph
    src, note = mermaid_callgraph(code)
    return src, note or ""


def _butterfly(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    code = _code(rec)
    if not (code.get("functions") or []):
        return "", "함수 수준 분석이 없습니다."
    from .code_intel import butterfly as _bf
    name = target or ((code.get("metrics") or {}).get("max_complexity") or {}).get("name")
    if not name:
        return "", "target으로 함수를 지정하세요."
    b = _bf(code, name)
    if b is None:
        return "", "함수 %r가 측정된 함수 목록에 없습니다 (추측으로 그리지 않는다)." % name
    lines = ["flowchart LR"]
    lines.append('  subgraph callers["호출자 (fan-in %d)"]' % b.get("fan_in", 0))
    for c in (b.get("callers") or [])[:10]:
        lines.append('    ci_%s["%s"]' % (re.sub(r"\W", "_", str(c.get("name"))), _esc(str(c.get("name")), 30)))
    lines.append("  end")
    lines.append('  center["%s (cc %s)"]' % (_esc(name, 30), b.get("complexity", "?")))
    lines.append('  subgraph callees["피호출 (fan-out %d)"]' % b.get("fan_out", 0))
    for c in (b.get("callees") or [])[:10]:
        lines.append('    co_%s["%s"]' % (re.sub(r"\W", "_", str(c.get("name"))), _esc(str(c.get("name")), 30)))
    lines.append("  end")
    for c in (b.get("callers") or [])[:10]:
        lines.append("  ci_%s --> center" % re.sub(r"\W", "_", str(c.get("name"))))
    for c in (b.get("callees") or [])[:10]:
        lines.append("  center --> co_%s" % re.sub(r"\W", "_", str(c.get("name"))))
    return "\n".join(lines), "함수 %s의 이웃: 호출자 %d, 피호출 %d (즉시 이웃만, 10개씩 cap)." % (name, len(b.get("callers") or []), len(b.get("callees") or []))


def _cluster(rec: Optional[Dict], doc: Optional[Dict], target: Optional[str], spec: Optional[str]) -> Tuple[str, str]:
    code = _code(rec)
    fns = code.get("functions") or []
    edges = code.get("call_edges") or []
    if not edges:
        return "", "해결된 함수 호출이 없습니다."
    owner: Dict[str, str] = {}
    for f in fns:
        owner[f["id"]] = f.get("cls") or f.get("file") or "?"
    agg: Dict[Tuple[str, str], int] = {}
    for e in edges[:2000]:
        a = e["from"] if isinstance(e, dict) else e[0]
        b = e["to"] if isinstance(e, dict) else e[1]
        ga, gb = owner.get(str(a), "?"), owner.get(str(b), "?")
        if ga != gb:
            agg[(ga, gb)] = agg.get((ga, gb), 0) + 1
    lines = ["flowchart TD"]
    top = sorted(agg.items(), key=lambda kv: -kv[1])[:MAX_EDGES]
    seen: Dict[str, str] = {}
    for (a, b), n in top:
        for x in (a, b):
            if x not in seen:
                seen[x] = _pid("cl", seen, x)
        lines.append('  %s["%s"] -->|%d| %s["%s"]' % (seen[a], _esc(_short_owner(a), 34), min(n, 99), seen[b], _esc(_short_owner(b), 34)))
    if not top:
        return "", "클래스 경계를 넘는 호출이 없습니다 (호출이 모두 같은 클래스/파일 안이다)."
    return "\n".join(lines), "클래스(없으면 파일) 단위로 집계한 호출 %d관계 중 상위 %d관계." % (len(agg), len(top))


def _short_owner(o: str) -> str:
    o = str(o)
    return o.split("::")[-1] if "::" in o else os.path.basename(o)


# ---------------------------------------------------------------------------------------------- entry points
_BUILDERS: Dict[str, Any] = {}


def _builder_of(kind: str) -> Any:
    fn = CATALOG[kind]["fn"]
    if fn not in _BUILDERS:
        _BUILDERS[fn] = globals()[fn]
    return _BUILDERS[fn]


def build(kind: str, rec: Optional[Dict[str, Any]] = None, arch_doc: Optional[Dict[str, Any]] = None,
          target: Optional[str] = None, spec: Optional[str] = None) -> Dict[str, Any]:
    """Draw one diagram kind from measured data. The reply always names its inputs; an unavailable kind returns
    ``mermaid: ""`` plus the honest reason - never a plausible-looking fake."""
    meta = CATALOG.get((kind or "").strip().lower())
    if meta is None:
        return {"kind": kind, "title": "?", "group": "?", "ea": "?", "mermaid": "",
                "note": "알 수 없는 다이어그램 종류입니다. catalog 종류를 보려면 draw_diagram(kind='catalog')."}
    src, note = _builder_of(kind)(rec, arch_doc, (target or "").strip() or None, (spec or "").strip() or None)
    lines: List[str] = []
    if "\n" in (note or ""):                                   # the decision kind appends its table below the summary line
        first, rest = note.split("\n", 1)
        note, lines = first, rest.split("\n")
    return {"kind": kind, "title": meta["title"], "group": meta["group"], "ea": meta["ea"],
            "mermaid": src or "", "note": note or "", "lines": lines}


# --------------------------------------------------------------------------- generic Mermaid well-formedness lint (C27)

MERMAID_HEADERS = ("flowchart", "graph", "sequenceDiagram", "classDiagram", "stateDiagram-v2", "stateDiagram",
                   "erDiagram", "journey", "gantt", "mindmap", "timeline", "quadrantChart", "gitGraph", "pie",
                   "requirementDiagram", "C4Context", "C4Container", "C4Component", "sankey-beta", "xychart-beta")
_EDGE_ARROWS = ("-.->", "==>", "-->", "---", "-.-", "===")     # longest first so ".-->" never matches "-->" twice
_PAIRS = {"(": ")", "[": "]", "{": "}"}


def lint_mermaid(src: str) -> List[str]:
    """Generic well-formedness lint for ANY Mermaid source (all 37 catalog kinds and third-party text alike):
    a known diagram header on the first line, balanced quotes and bracket pairs (per line, quotes respected),
    and every arrow edge carrying text on BOTH ends. Returns the problem strings; ``[]`` = no structural finding.
    This is a structural check only - it cannot judge whether the drawn semantics are right."""
    problems: List[str] = []
    text = str(src or "")
    stripped = [ln for ln in text.splitlines() if ln.strip()]
    if not stripped:
        return ["empty diagram"]
    first = stripped[0].strip()
    if not any(first.startswith(h) or first.split(" ")[0] == h for h in MERMAID_HEADERS):
        problems.append("first line is not a known Mermaid header: %r" % first[:40])
    brace_depth = 0                                          # entity blocks span lines: brace balance is document-scoped
    brace_line: List[str] = []
    for ln in stripped:
        if ln.count('"') % 2:
            problems.append("unbalanced quotes: %s" % ln.strip()[:60])
        work = ln.replace("o{", "").replace("}o", "")         # crow's-foot cardinality markers, not blocks (erDiagram)
        depth_bal = {"(": 0, "[": 0}
        in_q = False
        for ch in work:
            if ch == '"':
                in_q = not in_q
                continue
            if in_q:
                continue
            if ch in depth_bal:
                depth_bal[ch] += 1
            elif ch in _PAIRS.values() and ch != "}":
                opener = {v: k for k, v in _PAIRS.items()}[ch]
                if depth_bal[opener] <= 0:
                    problems.append("unbalanced %s: %s" % (ch, ln.strip()[:60]))
                    depth_bal[opener] = 0                    # report once per line, keep scanning
                else:
                    depth_bal[opener] -= 1
            elif ch == "{":
                brace_depth += 1
            elif ch == "}":
                brace_depth -= 1
                if brace_depth < 0:
                    problems.append("unbalanced }: %s" % ln.strip()[:60])
                    brace_depth = 0
        for o, n in depth_bal.items():
            if n:
                problems.append("unbalanced %s...%s: %s" % (o, _PAIRS[o], ln.strip()[:60]))
    if brace_depth > 0:
        problems.append("unbalanced {...}: %d unclosed entity block(s)" % brace_depth)
    for ln in stripped:                                        # edge lines need both endpoints
        s = ln.strip()
        for arrow in _EDGE_ARROWS:
            i = s.find(arrow)
            while i >= 0:
                if not s[:i].strip() or not s[i + len(arrow):].strip():
                    problems.append("edge without both endpoints: %s" % s[:60])
                i = s.find(arrow, i + len(arrow))
    # de-duplicate, keep order - the same broken line pattern can repeat across lines
    seen: set = set()
    out: List[str] = []
    for p in problems:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def draw_for_chat(kind: str, rec: Optional[Dict[str, Any]], arch_dir: Optional[str] = None,
                  target: Optional[str] = None, spec: Optional[str] = None) -> Dict[str, Any]:
    """chat.run_tool entry: builds the diagram, loading the newest Arch Intel doc when the kind needs one."""
    doc = latest_arch_doc(arch_dir) if CATALOG.get(kind, {}).get("arch_doc") else None
    out = build(kind, rec, doc, target, spec)
    if out["mermaid"]:
        out["diagram"] = {"name": out["title"], "mermaid": out["mermaid"], "note": out["note"]}
    return out
