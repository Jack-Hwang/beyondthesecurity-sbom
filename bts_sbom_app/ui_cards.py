"""BTS UI Cards - an A2UI-inspired component catalog for chat tool results (spec-level clean-room adoption,
see docs/A2UI_INTEGRATION.md; A2UI is Apache-2.0 and no code was taken from it).

The four A2UI principles adopted, at our scale:
1. UI is DATA, never code - a card is a strictly validated JSON object; the renderer builds DOM with
   textContent only, so nothing in a card can execute.
2. A closed catalog with per-kind schemas - unknown kinds, undeclared fields, oversized values and
   non-scalar entries are DROPPED by the validator (never sent malformed), and prose lines always ride
   along as the fallback, so a dropped card never loses the answer.
3. Catalog negotiation - GET /api/ui/catalog hands the renderer the supported kinds; a renderer that
   does not know a kind ignores it (the prose still answers).
4. Execution boundary - the agent (LLM) NEVER writes cards. They are produced only by the deterministic
   tool post-processor from measured record data, and there is deliberately no click-action channel:
   our approval gates require values the USER typed (approval token / confirm code), so an agent-driven
   action surface would weaken them. This is a documented deviation from A2UI's callRendererFunction.

Determinism: the same tool result over the same record yields the same cards. Caps (4 cards/turn,
8 table rows, 6 list items, 90-char strings) are enforced by the validator, not by hope.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

MAX_CARDS = 4
MAX_ROWS = 8
MAX_ITEMS = 6
MAX_STR = 90
MAX_MERMAID = 4000
_SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
_TOKEN16 = re.compile(r"^[0-9a-f]{16}$")
_TOKEN12 = re.compile(r"^[0-9a-f]{12}$")

# kind -> declared fields: name -> type tag (the closed catalog; extra/unknown fields are rejected,
# mirroring the spec's additionalProperties: false discipline)
CATALOG: Dict[str, Dict[str, Any]] = {
    "stat_row": {"doc": "counts strip", "fields": {"items": "stat_list"}, "max_items": 6},
    "table": {"doc": "measured rows", "fields": {"head": "str_list", "rows": "row_list"}, "max_rows": MAX_ROWS, "max_cols": 6},
    "kv": {"doc": "key facts", "fields": {"items": "kv_list"}, "max_items": MAX_ITEMS},
    "decision": {"doc": "decision-table verdict", "fields": {"verdict": "str", "rule": "str", "priority": "str", "action": "str"}},
    "approval_request": {"doc": "HITL gate preview (patch token / decision code)", "fields": {"gate": "str", "summary": "str", "code": "hex"}},
    "progress": {"doc": "pass/partial/fail checklist", "fields": {"items": "progress_list"}, "max_items": MAX_ITEMS},
    "findings_badges": {"doc": "severity counts", "fields": {"counts": "sev_counts"}},
    "diagram_ref": {"doc": "a Mermaid diagram drawn from measured data", "fields": {"name": "str", "mermaid": "mermaid"}},
}


def _clip(s: Any, limit: int = MAX_STR) -> str:
    return re.sub(r"\s+", " ", str(s or "")).strip()[:limit]


def _clean_list(items: Any, limit: int = MAX_ITEMS) -> List[str]:
    if not isinstance(items, (list, tuple)):
        return []
    return [_clip(x) for x in items[:limit] if x is not None and str(x).strip()]


def validate_cards(cards: Any) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Strict validator (the A2UI 'validator compliance' role): every card must be a dict with a known
    kind, a non-empty title and EXACTLY the declared fields of that kind, scalar/list-of-string values
    only, within caps. Anything else is dropped and named - malformed UI is never shipped; the prose
    lines that always accompany cards carry the answer."""
    clean: List[Dict[str, Any]] = []
    dropped: List[str] = []
    if not isinstance(cards, list):
        return [], ["cards가 목록이 아닙니다 - 전부 폐기"]
    for c in cards[:MAX_CARDS * 2]:
        if len(clean) >= MAX_CARDS:
            dropped.append("카드 상한 %d 초과 - 나머지 폐기" % MAX_CARDS)
            break
        if not isinstance(c, dict):
            dropped.append("카드가 객체가 아님 - 폐기")
            continue
        kind = c.get("kind")
        spec = CATALOG.get(kind) if isinstance(kind, str) else None
        if spec is None:
            dropped.append("카탈로그에 없는 kind %r - 폐기" % (kind,))
            continue
        title = _clip(c.get("title"))
        if not title:
            dropped.append("%s: 제목 없음 - 폐기" % kind)
            continue
        unknown = sorted(set(c) - {"kind", "title"} - set(spec["fields"]))
        if unknown:
            dropped.append("%s: 선언되지 않은 필드 %s - 폐기 (additionalProperties: false)" % (kind, ",".join(unknown)))
            continue
        out: Dict[str, Any] = {"kind": kind, "title": title}
        bad = False
        for fname, ftype in spec["fields"].items():
            v = c.get(fname)
            if ftype == "str":
                if not isinstance(v, str) or not v.strip():
                    bad = True
                else:
                    out[fname] = _clip(v)
            elif ftype == "hex":
                if not isinstance(v, str) or not (_TOKEN16.match(v) or _TOKEN12.match(v)):
                    bad = True
                else:
                    out[fname] = v
            elif ftype == "mermaid":
                if not isinstance(v, str) or not v.strip():
                    bad = True
                else:
                    out[fname] = v[:MAX_MERMAID]
            elif ftype == "str_list":
                lv = _clean_list(v)
                if not lv:
                    bad = True
                else:
                    out[fname] = lv
            elif ftype == "row_list":
                rows = []
                if isinstance(v, list):
                    for r in v[:spec.get("max_rows", MAX_ROWS)]:
                        if isinstance(r, list):
                            rows.append([_clip(x, 40) for x in r[:spec.get("max_cols", 6)]])
                if not rows:
                    bad = True
                else:
                    out[fname] = rows
            elif ftype == "stat_list":
                items = []
                if isinstance(v, list):
                    for it in v[:spec.get("max_items", MAX_ITEMS)]:
                        if isinstance(it, dict) and isinstance(it.get("label"), str) and isinstance(it.get("value"), (str, int, float, bool)):
                            item = {"label": _clip(it["label"], 24), "value": _clip(it["value"], 20)}
                            if it.get("sev") in _SEVS:
                                item["sev"] = it["sev"]
                            items.append(item)
                if not items:
                    bad = True
                else:
                    out[fname] = items
            elif ftype == "kv_list":
                items = []
                if isinstance(v, list):
                    for it in v[:spec.get("max_items", MAX_ITEMS)]:
                        if isinstance(it, dict) and isinstance(it.get("k"), str) and isinstance(it.get("v"), (str, int, float, bool)):
                            items.append({"k": _clip(it["k"], 28), "v": _clip(it["v"], 60)})
                if not items:
                    bad = True
                else:
                    out[fname] = items
            elif ftype == "progress_list":
                items = []
                if isinstance(v, list):
                    for it in v[:spec.get("max_items", MAX_ITEMS)]:
                        if isinstance(it, dict) and isinstance(it.get("label"), str) and it.get("state") in ("pass", "partial", "fail", "gap"):
                            items.append({"label": _clip(it["label"], 40), "state": it["state"]})
                if not items:
                    bad = True
                else:
                    out[fname] = items
            elif ftype == "sev_counts":
                counts = {}
                if isinstance(v, dict):
                    for k in _SEVS:
                        n = v.get(k)
                        if isinstance(n, int) and n > 0:
                            counts[k] = n
                if not counts:
                    bad = True
                else:
                    out[fname] = counts
            if bad:
                dropped.append("%s: 필드 %s가 스키마에 맞지 않음 - 폐기" % (kind, fname))
                break
        if not bad:
            clean.append(out)
    return clean, dropped


def _sev_counts(rec: Optional[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for v in (rec or {}).get("vulns") or []:
        s = str(v.get("severity") or "UNKNOWN").upper()
        counts[s] = counts.get(s, 0) + 1
    return counts


# --------------------------------------------------------------------------- deterministic builders
def cards_for(tool: str, args: Dict[str, Any], rec: Optional[Dict[str, Any]], result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Tool result -> validated cards. Called ONLY from the chatbot's deterministic post-processor - the
    model never supplies card content. Unknown tools simply produce no cards."""
    if tool == "draw_diagram":                                  # a drawn diagram IS a diagram_ref card - the
        d = (result.get("diagrams") or [{}])[0]                 # catalog kind replaces the ad-hoc payload
        if d.get("mermaid"):
            return validate_cards([{"kind": "diagram_ref", "title": d.get("name") or "diagram",
                                    "name": d.get("name") or "diagram", "mermaid": d["mermaid"]}])[0]
        return []
    builders = {
        "overview": _c_overview, "top_vulns": _c_top_vulns, "vuln_lookup": _c_vuln,
        "component_lookup": _c_component, "decide": _c_decision, "decision": _c_decision,
        "plan_patch": _c_plan, "record_decision": _c_decision_preview,
        "coverage": _c_coverage, "sbom_conformance": _c_conformance,
        "license": _c_license, "what_if_upgrade": _c_whatif, "architecture": _c_arch,
        "license_risks": _c_license_risks, "proposals": _c_proposals, "what_changed": _c_changed,
        "export_vex": _c_vex, "supply_chain": _c_supply, "nl2sql": _c_nl2sql,
    }
    fn = builders.get(tool)
    if fn is None:
        return []
    try:
        raw = fn(args, rec or {}, result)
    except Exception:                                          # noqa: BLE001 - a card must never break a turn
        return []
    clean, _ = validate_cards(raw)
    return clean


def _c_overview(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    counts = _sev_counts(rec)
    ncomp = len(rec.get("components") or [])
    return [{"kind": "stat_row", "title": _clip(rec.get("name", "project") + " 현황"), "items": [
        {"label": "컴포넌트", "value": str(ncomp)},
        {"label": "취약점", "value": str(sum(counts.values()))},
        {"label": "CRITICAL", "value": str(counts.get("CRITICAL", 0)), "sev": "CRITICAL"} if counts.get("CRITICAL") else None,
        {"label": "HIGH", "value": str(counts.get("HIGH", 0)), "sev": "HIGH"} if counts.get("HIGH") else None,
        {"label": "MEDIUM", "value": str(counts.get("MEDIUM", 0)), "sev": "MEDIUM"} if counts.get("MEDIUM") else None,
    ]}]


def _c_top_vulns(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    vulns = sorted(rec.get("vulns") or [], key=lambda v: str(v.get("severity")))[:MAX_ROWS]
    if not vulns:
        return []
    rows = [[str(v.get("id", "?")), _clip(v.get("package", "?"), 40), str(v.get("severity", "?")),
             str(v.get("fixed_version") or "-")] for v in vulns]
    return [{"kind": "table", "title": "최악 발견 (심각도 순)", "head": ["Advisory", "Package", "Severity", "Fixed in"], "rows": rows}]


def _c_vuln(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    vid = _clip(args.get("id", ""), 24).upper()
    v = next((x for x in rec.get("vulns") or [] if str(x.get("id")).upper() == vid), None)
    if v is None:
        return []
    return [{"kind": "kv", "title": str(v.get("id")), "items": [
        {"k": "package", "v": "%s %s" % (v.get("package"), v.get("version"))},
        {"k": "severity", "v": str(v.get("severity"))},
        {"k": "cvss", "v": str(v.get("cvss") if v.get("cvss") is not None else "-")},
        {"k": "fixed in", "v": str(v.get("fixed_version") or "수정판 미확인")},
        {"k": "published", "v": str(v.get("published") or "-")[:10]},
    ]}]


def _c_component(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    name = _clip(args.get("name", ""), 40).lower()
    c = next((x for x in rec.get("components") or [] if str(x.get("name")).lower() == name), None)
    if c is None:
        return []
    return [{"kind": "kv", "title": "%s %s" % (c.get("name"), c.get("version")), "items": [
        {"k": "ecosystem", "v": str(c.get("ecosystem"))},
        {"k": "license", "v": str(c.get("license") or "unresolved")},
        {"k": "vulns", "v": str(c.get("vulns", 0))},
    ]}]


def _c_decision(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    lines = result.get("lines") or []
    head = next((ln for ln in lines if "verdict=" in ln), "")
    m = re.search(r"verdict=(\w+).*?발화 규칙=([^.]*)", head)
    out = [{"kind": "decision", "title": "의사결정 테이블 추론",
            "verdict": m.group(1) if m else "?",
            "rule": _clip(m.group(2)) if m else "-",
            "priority": "", "action": ""}]
    fired = next((ln for ln in lines if ln.startswith("결정:")), "")
    if fired:
        m2 = re.match(r"결정: \[(P\d)\] (.+)$", fired)
        if m2:
            out[0]["priority"], out[0]["action"] = m2.group(1), _clip(m2.group(2))
    return out


def _c_plan(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    plans = rec.get("plans") or []
    up = [p for p in plans if p.get("status") == "upgrade"]
    # the approval covers the SHOWN selection: when the plan line names a component subset, the card
    # must count that subset - not every upgrade plan in the record (live-measured overstatement)
    import re as _re
    head = next((ln for ln in result.get("lines") or [] if ln.startswith("Patch plan for")), "")
    m = _re.search(r"for ([\w., -]+): (\d+) upgrade", head)
    shown: Optional[int] = None
    scope = ""
    if m:
        scope = _clip(m.group(1), 40)
        shown = int(m.group(2))
        up = up[:shown] if shown else up
    if not up:
        return []
    tok = result.get("approval_token") or ""
    import re as _re
    m = _re.search(r"Approval token ([0-9a-f]{16})", "\n".join(result.get("lines") or []))
    out: Dict[str, Any] = {"kind": "approval_request", "title": "패치 승인 대기" + (" - " + scope if scope else ""),
                           "gate": "patch",
                           "summary": _clip("이 승인이 다루는 선택: 업그레이드 %d건 (검증 통과 %d건)%s" % (
                               len(up), sum(1 for p in up if (p.get("verification") or {}).get("clean") is True),
                               "" if not shown else " - 계획 전체 %d건이 아니다" % (len([p for p in plans if p.get("status") == "upgrade"]))))}
    if m:
        out["code"] = m.group(1)
    return [out]


def _c_decision_preview(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    m = re.search(r"confirm code ([0-9a-f]{12})", "\n".join(result.get("lines") or []), re.I)
    if not m:
        return []
    return [{"kind": "approval_request", "title": "VEX 결정 승인 대기", "gate": "decision",
             "summary": _clip("VEX 결정 기록 대기: %s" % args.get("id", "?")), "code": m.group(1)}]


def _c_coverage(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    cov = result.get("coverage") if isinstance(result.get("coverage"), dict) else None
    lines = result.get("lines") or []
    if cov is None and lines:
        return []
    items = []
    for ln in lines[:MAX_ITEMS]:
        m = re.match(r"^-?\s*(.+?):\s*(\d+)%", _clip(ln, 60))
        if m:
            pct = int(m.group(2))
            items.append({"label": m.group(1), "state": "pass" if pct >= 90 else ("partial" if pct >= 50 else "fail")})
    if not items:
        return []
    return [{"kind": "progress", "title": "결정 커버리지", "items": items}]


def _c_conformance(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    regimes = ((rec.get("conformance") or {}).get("regimes")) or {}
    items = [{"label": _clip(v.get("title") or k, 40), "state": {"pass": "pass", "partial": "partial", "fail": "fail"}.get(str(v.get("verdict")), "gap")}
             for k, v in list(regimes.items())[:MAX_ITEMS]]
    if not items:
        return []
    return [{"kind": "progress", "title": "SBOM 적합성 체계", "items": items}]


def _c_license(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    lic = rec.get("license") or {}
    stats = lic.get("stats") or {}
    resolved = stats.get("resolved", stats.get("resolved_count"))
    total = stats.get("total", len(rec.get("components") or []))
    if resolved is None and total == 0:
        return []
    return [{"kind": "kv", "title": "라이선스 해결 현황", "items": [
        {"k": "project license", "v": _clip(lic.get("project_license") or "unresolved", 30)},
        {"k": "resolved / total", "v": "%s / %s" % (resolved if resolved is not None else "?", total)},
    ]}]


def _c_whatif(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    target = _clip(args.get("component", "?"), 30)
    ver = _clip(args.get("version", "?"), 20)
    cleared = next((ln for ln in result.get("lines") or [] if "clear" in ln.lower() or "해소" in ln), None)
    return [{"kind": "kv", "title": "업그레이드 시뮬레이션", "items": [
        {"k": "대상", "v": "%s -> %s" % (target, ver)},
        {"k": "판정", "v": _clip(cleared or (result.get("lines") or ["-"])[0], 58)},
    ]}]


def _c_arch(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    g = (rec.get("arch") or {}).get("graph") or {}
    if not g:
        return []
    return [{"kind": "kv", "title": "구조 실측", "items": [
        {"k": "modules", "v": str(g.get("modules", "?"))},
        {"k": "import edges", "v": str(g.get("import_edges", "?"))},
        {"k": "cycles", "v": str(g.get("cycle_count", "?"))},
        {"k": "max depth", "v": str(g.get("max_depth", "?"))},
    ]}]


def _c_license_risks(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    comps = rec.get("components") or []
    if not comps:
        return []
    from . import licenses as _lic
    cats: Dict[str, int] = {}
    for c in comps[:200]:
        lic = str(c.get("license") or c.get("license_raw") or "unknown")
        try:
            cat = _lic.category(lic)
        except Exception:                                      # noqa: BLE001
            cat = "unknown"
        cats[cat or "unknown"] = cats.get(cat or "unknown", 0) + 1
    return [{"kind": "kv", "title": "라이선스 리스크 (배포 모델: %s)" % _clip(args.get("distribution") or "binary", 16), "items": [
        {"k": "copyleft", "v": str(cats.get("copyleft", 0))},
        {"k": "weak-copyleft", "v": str(cats.get("weak-copyleft", 0))},
        {"k": "unknown/미해결", "v": str(cats.get("unknown", 0) + cats.get("none", 0))},
        {"k": "permissive", "v": str(cats.get("permissive", 0))},
    ]}]


def _c_proposals(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    pr = rec.get("proposals") or {}
    items = pr.get("items") or []
    if not items:
        return []
    rows = [[_clip(i.get("action"), 14), _clip(i.get("risk"), 12), _clip(i.get("title"), 44)] for i in items[:MAX_ROWS]]
    return [{"kind": "table", "title": "수정 제안 (%s 생성, 증거 검증 통과)" % _clip(pr.get("source") or "deterministic", 14),
             "head": ["action", "risk", "제목"], "rows": rows}]


def _c_changed(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    ch = rec.get("changes")
    if not ch:
        return []
    return [{"kind": "stat_row", "title": "이전 분석 대비 (%s)" % _clip(ch.get("compared_at", "?"), 16), "items": [
        {"label": "신규", "value": str(len(ch.get("new") or []))},
        {"label": "해소", "value": str(len(ch.get("resolved") or []))},
        {"label": "재채점", "value": str(len(ch.get("rescored") or []))},
        {"label": "경보", "value": str(len(ch.get("alerts") or []))},
    ]}]


def _c_vex(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    written = next((ln for ln in result.get("lines") or [] if "Written to" in ln), None)
    if not written:
        return []
    return [{"kind": "kv", "title": "OpenVEX 내보내기", "items": [{"k": "결과", "v": _clip(written, 70)}]}]


def _c_supply(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    fs = rec.get("supply_chain") or []
    if not fs:
        return []
    rows = [[_clip(f.get("package"), 22), _clip(f.get("kind"), 18), _clip(f.get("resembles"), 18),
             _clip(f.get("recommendation"), 40)] for f in fs[:MAX_ROWS]]
    return [{"kind": "table", "title": "공급망 대체 리스크 %d건" % len(fs), "head": ["패키지", "종류", "유사 대상", "권고"], "rows": rows}]


def _c_nl2sql(args: Dict, rec: Dict, result: Dict) -> List[Dict[str, Any]]:
    lines = result.get("lines") or []
    status = next((ln for ln in lines if ln.startswith("status:")), "")
    sql = next((ln for ln in lines if ln.startswith("sql:")), "")
    nrows = sum(1 for ln in lines if ln and not ln.startswith(("status:", "sql:")))
    if not status and not sql:
        return []
    return [{"kind": "kv", "title": "로컬 OSV DB 질의", "items": [
        {"k": "상태", "v": _clip(status.replace("status: ", ""), 24)},
        {"k": "SQL", "v": _clip(sql.replace("sql: ", ""), 60)},
        {"k": "행", "v": str(nrows)},
    ]}]


def catalog_doc() -> List[Dict[str, Any]]:
    """The negotiation payload for GET /api/ui/catalog: every kind with its declared fields - a renderer
    that speaks a subset ignores what it does not know and keeps the prose."""
    return [{"kind": k, "doc": v["doc"], "fields": sorted(v["fields"])} for k, v in sorted(CATALOG.items())]
