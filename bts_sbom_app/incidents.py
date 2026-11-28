"""The incident-response lane (KISA 침해사고 원인분석 RFP 매핑, docs/INCIDENT_RESPONSE_PLAN.md).

One incident = one JSON record under ``<evidence>/incidents/``. The stage machine walks forward only
(intake 접수 -> interview 초동 -> evidence 증거수집 -> analysis 원인분석 -> report 보고서 -> closed 종결);
every stage move is stamped, so the SLA clocks the RFP asks for are pure reads:

  - intake: an assignee must be named within 1 day of receipt (1영업일 근사 - 달력일, 법정휴일 달력은 후속)
  - evidence: leaving the evidence stage stamps the 7-day cause-analysis + report due date
    (증거수집 완료 후 7일 이내, 법정휴일 제외의 근사)

The HTTP surface (server.py routes it through ``Handler._incidents``):
  GET  /api/incidents                          -> incident summaries + the stage/SLA roll-up (진척관리)
  POST /api/incidents                          -> open an incident (org/title required; source/envs validated)
  GET  /api/incidents/<id>                     -> the full record
  POST /api/incidents/<id>/advance             -> move one stage forward (optionally naming the assignee,
                                                  marking evidence collection complete, closing)
  POST /api/incidents/<id>/delay               -> record a delay reason + new ETA (지연사유 사전 보고)
  POST /api/incidents/<id>/iocs                -> attach an IoC (hash/ip/c2/domain/package)
  GET  /api/incidents/<id>/sbom-impact         -> cross-check the incident's IoCs against every scanned
                                                  project's components (supply-chain surface of the RFP's IoC)
  GET  /api/incidents/<id>/report?kind=...     -> 초동보고서(intake) / 원인분석 보고서(cause) as Markdown
                                                  downloads; unknown fields render as 미확인, never invented
  GET  /api/incidents/<id>/checklist?env=...   -> the evidence-collection checklist for the damaged target
                                                  (web/db/app/mobile-iot/other - the RFP's 피해 대상별 예시)
  GET  /api/incidents/playbook                 -> 대응방안 모음집: the response notes of every incident, accumulated
  POST /api/incidents/<id>/close               -> close with an optional satisfaction survey (사후관리)

Honesty contract: the builders never invent facts. A report line whose input is absent says 미확인; a
hash IoC with no component checksum to compare against says so instead of claiming a match.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .oss_api import Response, _err, _host_allowed, _ok, _same_origin

STAGES = ("intake", "interview", "evidence", "analysis", "report", "closed")
STAGE_KO = {"intake": "접수", "interview": "초동", "evidence": "증거수집", "analysis": "원인분석",
            "report": "보고서", "closed": "종결"}
ASSIGN_SLA_DAYS = 1.0            # 접수 후 1영업일 이내 담당자 지정 (달력일 근사 - 문서에 명시)
ANALYSIS_SLA_DAYS = 7.0          # 증거수집 완료 후 7일 이내 원인분석·보고서
LONG_STALL_DAYS = 14.0           # 장기 미완료 경계
ENVS = ("web", "db", "app", "mobile-iot", "other")
SOURCES = ("ioc", "report", "agency", "customer", "other")
IOC_TYPES = ("hash", "ip", "c2", "domain", "package")
IOC_CAP = 50                                  # per incident: the cross-check is O(IoCs x components), keep it bounded
_LIMITS = {"org": 120, "title": 200, "assignee": 80, "reason": 500, "eta": 40, "ioc": 256,
           "field": 4000, "score_max": 5}

CHECKLISTS: Dict[str, List[str]] = {
    "web": ["웹 접근 로그·에러 로그 확보 (침투 경로 파악)", "웹셸 잔존 여부 점검 (업로드 경로·실행 흔적)",
            "웹 취약점 점검 (파일 업로드·인젝션 등)", "WAF·웹서버 설정 변경 이력 확인"],
    "db": ["DB 접근·감사 로그 확보", "DB 덤프로 중요자료(개인·민감정보) 유출 여부 확인",
           "DB 스키마·데이터 변조 여부 점검", "DB 계정·권한 변경 이력 확인"],
    "app": ["어플리케이션 로그 확보 (동작 방식·악용 경로 파악)", "공격자가 악용한 취약점 식별 (입력 검증·인증 우회)",
            "특이 어플리케이션(SMS 발송 서버 등)은 동작 원리 유선 인터뷰·조사 후 기록", "앱 설정·배포 이력 확인"],
    "mobile-iot": ["메모리 덤프 확보 후 분석", "이미지(펌웨어) 덤프 확보 후 분석",
                   "악성코드 감염 기기 식별·격리", "침투 경로(네트워크·설치 경로) 조사"],
    "other": ["각종 시스템 로그 확보", "시스템 증거자료(프로세스·autorun·예약작업) 확보",
              "침투 원인·경로 분석", "악성코드 제거·조치 방안 확인"],
}


# --------------------------------------------------------------------------- storage
def _folder(evidence: str) -> str:
    return os.path.join(evidence, "incidents")


def _path(evidence: str, iid: str) -> str:
    return os.path.join(_folder(evidence), iid + ".json")


def _valid_id(iid: str) -> bool:
    return bool(re.fullmatch(r"IR-\d{8}-[0-9a-f]{4}", iid or ""))


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _load(evidence: str, iid: str) -> Optional[Dict[str, Any]]:
    try:
        with open(_path(evidence, iid), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _save(evidence: str, rec: Dict[str, Any]) -> None:
    os.makedirs(_folder(evidence), exist_ok=True)
    with open(_path(evidence, rec["id"]), "w", encoding="utf-8") as fh:
        json.dump(rec, fh, ensure_ascii=False, indent=1, sort_keys=True)


def all_incidents(evidence: str) -> List[Dict[str, Any]]:
    """Every incident record, oldest receipt first (the panel shows the newest first; this is the raw order)."""
    d = _folder(evidence)
    if not os.path.isdir(d):
        return []
    out = []
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".json"):
            continue
        try:
            with open(os.path.join(d, fn), "r", encoding="utf-8") as fh:
                out.append(json.load(fh))
        except (OSError, ValueError):
            continue                                       # a torn file is skipped, never invented
    out.sort(key=lambda r: r.get("received_at", ""))
    return out


# --------------------------------------------------------------------------- SLA clocks
def _parse(ts: Optional[str]) -> Optional[datetime.datetime]:
    try:
        return datetime.datetime.fromisoformat(ts) if ts else None
    except ValueError:
        return None


def sla_view(rec: Dict[str, Any], now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """A torn/hand-edited record degrades to all-false clocks (the row stays listed, never crashes the list)."""
    try:
        return _sla_view(rec, now)
    except (TypeError, ValueError):
        return {"assign_breach": False, "analysis_breach": False, "long_stalled": False,
                "due_at": rec.get("due_at"), "assignee": rec.get("assignee") or ""}


def _sla_view(rec: Dict[str, Any], now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """The RFP's clocks for one incident, computed - never remembered:
    assign_breach  접수 후 1일 내 담당자 미지정
    analysis_breach 증거수집 완료 후 7일 내 보고서 단계 미도달
    long_stalled   종결 아닌 사고가 마지막 단계 이동 후 14일 경과
    due_at         증거수집 완료 시각 + 7일 (분석·보고서 처리기한)"""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    received = _parse(rec.get("received_at"))
    assignee = bool(rec.get("assignee"))
    assign_breach = bool(received and not assignee and
                         (now - received).total_seconds() > ASSIGN_SLA_DAYS * 86400)
    due = _parse(rec.get("due_at"))
    report_reached = STAGES.index(rec.get("stage", "intake")) >= STAGES.index("report")
    analysis_breach = bool(due and now > due and not report_reached)
    stamps = [(_parse(t), s) for s, t in (rec.get("stage_at") or {}).items()]
    stamps = [(t, s) for t, s in stamps if t]
    last_move = max(stamps)[0] if stamps else received
    long_stalled = bool(rec.get("stage") != "closed" and last_move and
                        (now - last_move).total_seconds() > LONG_STALL_DAYS * 86400)
    return {"assign_breach": assign_breach, "analysis_breach": analysis_breach,
            "long_stalled": long_stalled, "due_at": rec.get("due_at"),
            "assignee": rec.get("assignee") or ""}


def sla_rollup(records: List[Dict[str, Any]], now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """진척관리 roll-up: 단계별 건수 + SLA 위반·장기 미완료·미착수·준수율 (the RFP's 처리기준 table)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    by_stage: Dict[str, int] = {s: 0 for s in STAGES}
    assign_breach = analysis_breach = long_stalled = not_started = 0
    open_n = 0
    for r in records:
        by_stage[r.get("stage", "intake")] = by_stage.get(r.get("stage", "intake"), 0) + 1
        v = sla_view(r, now)
        assign_breach += v["assign_breach"]
        analysis_breach += v["analysis_breach"]
        long_stalled += v["long_stalled"]
        if r.get("stage") != "closed":
            open_n += 1
            if not r.get("assignee"):
                not_started += 1
    return {"total": len(records), "open": open_n, "closed": by_stage.get("closed", 0),
            "by_stage": by_stage, "assign_sla_breach": assign_breach,
            "analysis_sla_breach": analysis_breach, "long_stalled": long_stalled,
            "not_started": not_started}


def _summary(rec: Dict[str, Any], now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    v = sla_view(rec, now)
    return {"id": rec["id"], "org": rec.get("org", ""), "title": rec.get("title", ""),
            "source": rec.get("source", ""), "stage": rec.get("stage", "intake"),
            "assignee": rec.get("assignee", ""), "received_at": rec.get("received_at", ""),
            "due_at": v["due_at"], "iocs": len(rec.get("iocs") or []),
            "sla": {k: v[k] for k in ("assign_breach", "analysis_breach", "long_stalled")}}

# --------------------------------------------------------------------------- create / advance
def create_incident(evidence: str, body: Dict[str, Any], now: Optional[datetime.datetime] = None) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    org = str(body.get("org") or "").strip()
    title = str(body.get("title") or "").strip()
    if not org or not title:
        return None, "org과 title은 필수다"
    if len(org) > _LIMITS["org"] or len(title) > _LIMITS["title"]:
        return None, "org/title 길이 한도 초과"
    source = str(body.get("source") or "other")
    if source not in SOURCES:
        return None, "source는 %s 중 하나다" % (SOURCES,)
    envs = body.get("envs") or []
    if not isinstance(envs, list) or any(e not in ENVS for e in envs):
        return None, "envs는 %s 부분집합이어야 한다" % (ENVS,)
    assignee = str(body.get("assignee") or "").strip()[:_LIMITS["assignee"]]
    ts = now.isoformat(timespec="seconds")
    iid = "IR-%s-%s" % (now.strftime("%Y%m%d"), uuid.uuid4().hex[:4])
    rec: Dict[str, Any] = {"id": iid, "received_at": ts, "source": source, "org": org,
                           "title": title, "assignee": assignee, "assigned_at": ts if assignee else None,
                           "stage": "intake", "stage_at": {"intake": ts}, "envs": envs,
                           "evidence_done_at": None, "due_at": None, "delay": [], "notes": [],
                           "iocs": [], "findings": {}, "closed_at": None, "satisfaction": None}
    _save(evidence, rec)
    return rec, None


def advance_incident(evidence: str, iid: str, body: Dict[str, Any], now: Optional[datetime.datetime] = None) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    rec = _load(evidence, iid)
    if rec is None:
        return None, "unknown incident"
    stage = str(body.get("stage") or "").strip()
    if stage not in STAGES:
        return None, "stage는 %s 중 하나다" % (STAGES,)
    cur = STAGES.index(rec["stage"])
    nxt = STAGES.index(stage)
    if nxt != cur + 1:
        return None, "단계는 한 칸씩만 앞으로 간다 (현재 %s)" % rec["stage"]
    ts = now.isoformat(timespec="seconds")
    prev_stage = rec["stage"]
    rec["stage"] = stage
    rec.setdefault("stage_at", {})[stage] = ts
    assignee = str(body.get("assignee") or "").strip()[:_LIMITS["assignee"]]
    if assignee and not rec.get("assignee"):
        rec["assignee"] = assignee
        rec["assigned_at"] = ts
    if prev_stage == "evidence":
        # 증거수집 완료 후 7일 이내: the clock starts when the lane leaves the evidence stage (the RFP default)
        rec["evidence_done_at"] = ts
        due = now + datetime.timedelta(days=ANALYSIS_SLA_DAYS)
        rec["due_at"] = due.isoformat(timespec="seconds")
    if stage == "closed":
        rec["closed_at"] = ts
        sat = body.get("satisfaction")
        if isinstance(sat, dict):
            score = sat.get("score")
            rec["satisfaction"] = {"score": int(score) if type(score) is int and 0 <= score <= _LIMITS["score_max"] else None,
                                   "comments": str(sat.get("comments") or "")[:_LIMITS["field"]]}
    note = str(body.get("note") or "").strip()[:_LIMITS["reason"]]
    if note:
        rec.setdefault("notes", []).append({"at": ts, "stage": stage, "text": note})
    _save(evidence, rec)
    return rec, None


def record_delay(evidence: str, iid: str, body: Dict[str, Any], now: Optional[datetime.datetime] = None) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """지연사유 사전 보고 (RFP: 기한 도래 전 지연사유·잔여업무·완료예정일 보고)."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    rec = _load(evidence, iid)
    if rec is None:
        return None, "unknown incident"
    reason = str(body.get("reason") or "").strip()
    if len(reason) < 5:
        return None, "지연사유는 5자 이상이어야 한다"
    rec.setdefault("delay", []).append({"at": now.isoformat(timespec="seconds"), "stage": rec.get("stage", "intake"),
                                        "reason": reason[:_LIMITS["reason"]],
                                        "eta": str(body.get("eta") or "").strip()[:_LIMITS["eta"]]})
    _save(evidence, rec)
    return rec, None


# --------------------------------------------------------------------------- IoC + supply-chain cross-check
FINDING_KEYS = ("interview", "initial", "plan", "entry", "actions", "scope", "cause", "response", "detection")


def record_findings(evidence: str, iid: str, body: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """보고서 입력란 기록: 알려진 키만 반영(부분 갱신), 값은 길이 한도 안에서 그대로 저장 - 빈 칸은 미확인으로 렌더된다."""
    rec = _load(evidence, iid)
    if rec is None:
        return None, "unknown incident"
    changed = 0
    f = rec.setdefault("findings", {})
    for k, v in (body or {}).items():
        if k not in FINDING_KEYS:
            continue
        f[k] = str(v or "").strip()[:_LIMITS["field"]]
        changed += 1
    if not changed:
        return None, "반영할 필드가 없다 - %s 중 하나로 보내야 한다" % (FINDING_KEYS,)
    _save(evidence, rec)
    return rec, None


def add_ioc(evidence: str, iid: str, body: Dict[str, Any], now: Optional[datetime.datetime] = None) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    rec = _load(evidence, iid)
    if rec is None:
        return None, "unknown incident"
    typ = str(body.get("type") or "").strip()
    value = str(body.get("value") or "").strip()
    if typ not in IOC_TYPES:
        return None, "type는 %s 중 하나다" % (IOC_TYPES,)
    if not value or len(value) > _LIMITS["ioc"]:
        return None, "value는 1..%d 자여야 한다" % _LIMITS["ioc"]
    if typ == "hash" and not re.fullmatch(r"[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32}", value):
        return None, "hash IoC는 md5(32)/sha1(40)/sha256(64) 16진수다"
    if typ in ("ip",) and not re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{2,45}", value):
        return None, "ip IoC는 IPv4/IPv6 형태다"
    entry = {"type": typ, "value": value, "added_at": now.isoformat(timespec="seconds")}
    existing = rec.get("iocs") or []
    if len(existing) >= IOC_CAP:
        return None, "사고당 IoC는 %d개까지다" % IOC_CAP
    if any(x.get("type") == typ and str(x.get("value") or "").lower() == value.lower() for x in existing):
        return rec, None                                        # idempotent duplicate: keep the first stamp
    rec.setdefault("iocs", []).append(entry)
    _save(evidence, rec)
    return rec, None


def _component_hashes(c: Dict[str, Any]) -> List[str]:
    """Every recorded checksum of one component, prefix-stripped (sha256:... -> the bare hex)."""
    out = []
    for h in c.get("hashes") or []:
        v = str(h.get("content") or "") if isinstance(h, dict) else str(h)
        v = v.split(":", 1)[1] if ":" in v else v
        if v:
            out.append(v.lower())
    if c.get("checksum"):
        v = str(c["checksum"])
        out.append((v.split(":", 1)[1] if ":" in v else v).lower())
    return out


def sbom_impact(evidence: str, iid: str) -> Dict[str, Any]:
    """교차조회: 등록된 IoC가 스캔된 프로젝트의 공급망(SBOM 컴포넌트)에 존재하는가.
    - package IoC  -> 컴포넌트 이름 정규화 대조 + 그 컴포넌트가 연결된 advisory
    - hash IoC     -> 컴포넌트 체크섬이 기록된 경우에만 대조 (없으면 '해시 불가'로 정직 응답)
    - ip/c2/domain -> SBOM 표면이 없다 - 프로젝트 대조 불가를 사실로 응답 (지어내지 않음)"""
    rec = _load(evidence, iid)
    if rec is None:
        return {"error": "unknown incident"}
    try:
        from .server import project_records                   # local import: server imports this module's siblings
        from .fleet import canon_name
        projects = {n: r for n, (f, r) in project_records(evidence).items()}
    except Exception as exc:                                  # noqa: BLE001 - degrade honestly, never 500
        return {"id": rec["id"], "iocs": len(rec.get("iocs") or []), "matches": [], "unmatched": [],
                "error": "교차조회 불가: %s" % exc}
    comps: List[Dict[str, Any]] = []                          # canon-indexed once per call, not per IoC
    for pname, rec2 in projects.items():
        for c in rec2.get("components") or []:
            comps.append({"project": pname, "record": rec2, "component": c,
                          "canon": canon_name(str(c.get("name") or "").lower())})
    hashes: Dict[str, Dict[str, Any]] = {}
    for e in comps:
        for hv in _component_hashes(e["component"]):
            hashes[hv] = e
    hits: List[Dict[str, Any]] = []
    unmatched: List[Dict[str, str]] = []
    for ioc in rec.get("iocs") or []:
        typ, value = ioc.get("type"), str(ioc.get("value") or "")
        matched = False
        if typ == "package":
            canon = canon_name(value.lower())
            for e in comps:
                if e["canon"] != canon:
                    continue
                adv = sorted({str(v.get("id")) for v in (e["record"].get("vulns") or [])
                              if canon_name(str(v.get("package") or "").lower()) == canon})
                hits.append({"ioc": value, "type": typ, "project": e["project"],
                             "component": e["component"].get("name"), "version": e["component"].get("version"),
                             "advisories": adv})
                matched = True
            if not matched:
                unmatched.append({"type": typ, "value": value, "reason": "스캔된 프로젝트의 컴포넌트에 없다"})
        elif typ == "hash":
            e = hashes.get(value.lower())
            if e is not None:
                hits.append({"ioc": value, "type": typ, "project": e["project"],
                             "component": e["component"].get("name"), "version": e["component"].get("version"),
                             "advisories": []})
                matched = True
            elif not hashes:
                unmatched.append({"type": typ, "value": value,
                                  "reason": "스캔 기록에 비교 가능한 컴포넌트 해시가 없어 대조 불가"})
            else:
                unmatched.append({"type": typ, "value": value, "reason": "기록된 컴포넌트 해시와 일치하지 않는다"})
        else:
            unmatched.append({"type": typ, "value": value,
                              "reason": "IP/C2/도메인은 SBOM 표면이 없다 - 로그·방화벽 대상이며 프로젝트 대조 불가"})
        if not matched and all(u.get("value") != value or u.get("type") != typ for u in unmatched):
            unmatched.append({"type": typ, "value": value, "reason": "대조 결과 없음"})
    return {"id": rec["id"], "iocs": len(rec.get("iocs") or []), "projects": len(projects),
            "matches": hits, "unmatched": unmatched}

# --------------------------------------------------------------------------- reports (루프 2)
def _md_safe(text: str) -> str:
    """Neutralize markdown-active line starts (#/!/[) and control chars in user text so a report stays prose."""
    out = []
    for ln in text.replace("\r", "").split("\n"):
        ln = ln.lstrip()
        if ln.startswith(("#", "!", "[")):
            ln = "\\" + ln                       # a backslash escape keeps the character, kills the markup meaning
        out.append(ln)
    return "\n".join(out)


def _f(rec: Dict[str, Any], key: str) -> str:
    v = str((rec.get("findings") or {}).get(key) or "").strip()
    return _md_safe(v) if v else "미확인"


def intake_report(rec: Dict[str, Any]) -> str:
    """초동보고서: 사고개요·주요 확인사항·초기 판단·증거데이터 수집대상·향후 분석계획 (입력 없는 칸은 미확인)."""
    envs = ", ".join(rec.get("envs") or []) or "미확인"
    items: List[str] = CHECKLISTS.get((rec.get("envs") or ["other"])[0], CHECKLISTS["other"])
    lines = [
        "# 초동보고서 - %s" % rec["id"],
        "",
        "- 접수 시각: %s" % rec.get("received_at", "미확인"),
        "- 접수 경로: %s" % rec.get("source", "미확인"),
        "- 피해기업: %s" % rec.get("org", "미확인"),
        "- 담당자: %s" % (rec.get("assignee") or "미지정"),
        "",
        "## 사고 개요",
        rec.get("title", "미확인"),
        "",
        "## 주요 확인 사항 (초동 인터뷰)",
        _f(rec, "interview"),
        "",
        "## 초기 판단",
        _f(rec, "initial"),
        "",
        "## 증거데이터 수집 대상 (대상 환경: %s)" % envs,
    ]
    lines += ["- %s" % i for i in items]
    lines += ["", "## 향후 분석 계획", _f(rec, "plan")]
    delays = rec.get("delay") or []
    if delays:
        lines += ["", "## 수집 지연 기록"]
        lines += ["- %s (%s, ETA %s)" % (d["reason"], d.get("stage", ""), d.get("eta") or "미정") for d in delays]
    return "\n".join(lines) + "\n"


def cause_report(rec: Dict[str, Any]) -> str:
    """결과보고서: 사고개요·침투경로·공격행위·피해범위·IoC·원인분석결과·대응방안. 입력 없는 칸은 미확인."""
    iocs = rec.get("iocs") or []
    lines = [
        "# 침해사고 원인분석 결과보고서 - %s" % rec["id"],
        "",
        "## 사고 개요",
        "- 피해기업: %s" % rec.get("org", "미확인"),
        "- 접수: %s (%s)" % (rec.get("received_at", "미확인"), rec.get("source", "미확인")),
        "- 현재 단계: %s" % STAGE_KO.get(rec.get("stage", ""), "미확인"),
        "",
        "## 침투 경로", _f(rec, "entry"),
        "", "## 공격 행위", _f(rec, "actions"),
        "", "## 피해 범위", _f(rec, "scope"),
        "", "## 침해지표(IoC)",
    ]
    if iocs:
        lines += ["- %s: %s" % (x.get("type"), x.get("value")) for x in iocs]
    else:
        lines.append("- 미확인")
    lines += ["", "## 원인 분석 결과", _f(rec, "cause"),
              "", "## 대응 방안", _f(rec, "response"),
              "", "## 유사·추가 침해사고 식별을 위한 위협행위 식별기준", _f(rec, "detection")]
    return "\n".join(lines) + "\n"


def checklist_md(env: str) -> str:
    items = CHECKLISTS.get(env)
    if not items:
        return ""
    ko = {"web": "웹서버", "db": "DB서버", "app": "어플리케이션 서버", "mobile-iot": "모바일 및 IoT 기기", "other": "기타 시스템"}
    lines = ["# 증거데이터 수집 체크리스트 - %s" % ko.get(env, env), ""]
    lines += ["- [ ] %s" % i for i in items]
    return "\n".join(lines) + "\n"


def playbook_md(records: List[Dict[str, Any]]) -> str:
    """대응방안 모음집: 진행·종결 사고의 대응방안을 누적 (진행 중 자료 갱신)."""
    lines = ["# 침해사고 대응방안 모음집", "", "누적 기준시각: " + _now(), ""]
    n = 0
    for rec in records:
        resp = str((rec.get("findings") or {}).get("response") or "").strip()
        if not resp:
            continue
        n += 1
        lines += ["## %s (%s)" % (rec.get("title", rec["id"]), rec.get("org", "미확인")),
                  "- 단계: %s · 기록: %s" % (STAGE_KO.get(rec.get("stage", ""), ""), rec.get("received_at", "미확인")),
                  resp, ""]
    if not n:
        lines.append("- 아직 기록된 대응방안이 없다 - 대응 방안은 사고별로 직접 기록해야 모음집에 누적된다.")
    return "\n".join(lines) + "\n"

# --------------------------------------------------------------------------- route
def _body_str(body: Dict[str, Any], key: str, limit: int) -> str:
    return str(body.get(key) or "").strip()[:limit]


def route(method: str, path: str, query: Dict[str, List[str]], body: Dict[str, Any], headers: Any, st: Any,
          bind: Optional[Tuple[Any, ...]] = None) -> Optional[Response]:
    """Return a response for /api/incidents/... or None when the path is not ours (server.py keeps routing)."""
    if not path.startswith("/api/incidents"):
        return None
    if headers is not None and not _host_allowed(headers.get("Host", "") or "", bind):
        return _err(403, "unexpected Host header (the service answers only at its own address)")
    if method == "POST" and not _same_origin(headers, bind):
        return _err(403, "cross-origin request refused")
    evidence = st.evidence
    rest = path[len("/api/incidents"):]
    if method == "GET":
        if rest in ("", "/"):
            recs = all_incidents(evidence)
            return _ok({"incidents": [_summary(r) for r in reversed(recs)], "rollup": sla_rollup(recs)})
        if rest == "/playbook":
            md = playbook_md(all_incidents(evidence))
            return _ok({"markdown": md}, 200)
        m = re.fullmatch(r"/(IR-\d{8}-[0-9a-f]{4})", rest)
        if m:
            rec = _load(evidence, m.group(1))
            return _ok(rec) if rec else _err(404, "unknown incident")
        m = re.fullmatch(r"/(IR-\d{8}-[0-9a-f]{4})/sbom-impact", rest)
        if m:
            out = sbom_impact(evidence, m.group(1))
            return _err(404, "unknown incident") if out.get("error") == "unknown incident" else _ok(out)
        m = re.fullmatch(r"/(IR-\d{8}-[0-9a-f]{4})/findings", rest)
        if m:
            rec, why = record_findings(evidence, m.group(1), body)
            if rec is None:
                return _err(400, why or "invalid")
            return _ok(rec)
        m = re.fullmatch(r"/(IR-\d{8}-[0-9a-f]{4})/report", rest)
        if m:
            rec = _load(evidence, m.group(1))
            if rec is None:
                return _err(404, "unknown incident")
            kind = (query.get("kind") or ["intake"])[0]
            if kind == "intake":
                md = intake_report(rec)
            elif kind == "cause":
                md = cause_report(rec)
            else:
                return _err(400, "kind는 intake|cause 중 하나다")
            return 200, {"markdown": md}, "text/markdown; charset=utf-8", {
                "Content-Disposition": 'attachment; filename="%s_%s.md"' % (rec["id"], kind)}
        m = re.fullmatch(r"/(IR-\d{8}-[0-9a-f]{4})/checklist", rest)
        if m:
            env = (query.get("env") or ["other"])[0]
            md = checklist_md(env)
            if not md:
                return _err(400, "env는 %s 중 하나다" % (ENVS,))
            return 200, {"markdown": md}, "text/markdown; charset=utf-8", {
                "Content-Disposition": 'attachment; filename="evidence_checklist_%s.md"' % env}
        return _err(404, "not found")
    if method == "POST":
        if not isinstance(body, dict):
            return _err(400, "JSON object body required")
        if rest in ("", "/"):
            rec, why = create_incident(evidence, body)
            if rec is None:
                return _err(400, why or "invalid")
            return _ok(rec, 201)
        m = re.fullmatch(r"/(IR-\d{8}-[0-9a-f]{4})/(advance|delay|iocs|close)", rest)
        if not m:
            return _err(404, "not found")
        iid, action = m.group(1), m.group(2)
        if action == "advance":
            rec, why = advance_incident(evidence, iid, body)
            if rec is None:
                return _err(400, why or "invalid")
            return _ok(rec)
        if action == "delay":
            rec, why = record_delay(evidence, iid, body)
            if rec is None:
                return _err(400, why or "invalid")
            return _ok(rec)
        if action == "iocs":
            rec, why = add_ioc(evidence, iid, body)
            if rec is None:
                return _err(400, why or "invalid")
            return _ok(rec)
        if action == "close":                                   # close = advance to closed with a survey
            body = dict(body)
            body["stage"] = "closed"
            rec, why = advance_incident(evidence, iid, body)
            if rec is None:
                return _err(400, why or "invalid")
            return _ok(rec)
        return _err(404, "not found")
    return _err(405, "method not allowed")
