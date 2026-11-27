"""EU Cyber Resilience Act (Regulation (EU) 2024/2847) compliance lane.

The K-OSSC practitioner's guide (v1.0, 2026-11-23, CC BY-NC 4.0) turns the CRA obligations a manufacturer must
evidence into concrete artifacts: the machine-readable SBOM with its five ledgers (guide annex J), the RFC 9116
security.txt contact behind the coordinated-vulnerability-disclosure policy (Annex I Part II (5)·(6)), the declared
support period with its >= 5 years minimum (Article 13(8), Annex II 7), and the Article 14 reporting clock
(in force since 2026-09-11: awareness -> 24 h early warning -> 72 h notification -> 14 days / 1 month final report).
This module computes each artifact from the app's own records and scores the project's readiness (guide annex I,
the automatable subset) — the SBOM document part of the score is delegated to conformance.py, which already checks
the EU CRA and BSI TR-03183-2 SBOM regimes per element.

Honesty rules (the same contract as the rest of the app):
  * no actively-exploited-verdict is computed here - CISA KEV / EUVD feeds are not wired into this workflow, so
    "actively exploited" stays a recorded human decision (Article 14(1) awareness) with its evidence, never an
    automatic pass, and the vuln ledger marks the exploitation column "not assessed" instead of guessing;
  * upstream EOL dates are not measured by the scan, so the EOL ledger ships its columns and the 4-band priority
    rule (guide template 3 is a management sheet) and leaves the dates to the team;
  * every check carries the CRA article / guide section it maps to, and "not computed" is a gap, not a pass.
"""
from __future__ import annotations

import calendar
import csv
import datetime
import io
import json
import os
import re
import threading
from typing import Any, Dict, List, Optional

from . import __version__, sbom

SCHEMA = "bts-sbom.cra.v1"
MIN_SUPPORT_YEARS = 5                                        # Article 13(8): 최소 5년 (예상 사용 기간 반영)
NOT_COMPUTED = ("CISA KEV / EUVD exploitation feeds and upstream EOL dates are not wired into this workflow - "
                "those fields are recorded by the team, not inferred by the scan.")
AEV_KINDS = ("aev", "incident")                              # Article 14(1) vs (3): 악용 취약점 / 심각한 사고
_LEDGER_LOCK = threading.Lock()

# ---------------------------------------------------------------- dates (RFC 3339 UTC, py310-safe Z handling)

def _now(now: Optional[Any] = None) -> datetime.datetime:
    if now is None:
        return datetime.datetime.now(datetime.timezone.utc)
    return now if isinstance(now, datetime.datetime) else _parse_dt(now)


def _parse_dt(s: str) -> datetime.datetime:
    t = datetime.datetime.fromisoformat(str(s).strip().replace("Z", "+00:00"))
    if t.tzinfo is None:
        t = t.replace(tzinfo=datetime.timezone.utc)          # date-only / naive input is read as UTC, never local
    return t


def _iso(t: datetime.datetime) -> str:
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _add_months(d: datetime.datetime, months: int) -> datetime.datetime:
    y, m = d.year + (d.month - 1 + months) // 12, (d.month - 1 + months) % 12 + 1
    day = min(d.day, calendar.monthrange(y, m)[1])
    return d.replace(year=y, month=m, day=day)


def _support_floor(today: datetime.datetime) -> datetime.date:
    """The earliest support end a declaration today may name: today + MIN_SUPPORT_YEARS (Feb-29 clamped)."""
    t = today.date()
    try:
        return t.replace(year=t.year + MIN_SUPPORT_YEARS)
    except ValueError:                                       # 02-29 -> 02-28 of the target year
        return t.replace(month=2, day=28, year=t.year + MIN_SUPPORT_YEARS)

# ---------------------------------------------------------------- security.txt (RFC 9116) - Annex I Part II (5)·(6)

def security_txt(contact: Any, *, expires_days: int = 90, preferred_languages: str = "ko, en",
                 policy: str = "", csaf: str = "", now: Optional[Any] = None) -> str:
    """RFC 9116 security.txt for the CVD contact point. ``contact`` may be one or more mailto:/URL values -
    the generator never invents one (the operator supplies it via BTS_SBOM_CVD_CONTACT). Expires is the
    90-day renewal convention the guide marks as a 사내 정책 예시."""
    contacts = contact if isinstance(contact, (list, tuple)) else [contact]
    contacts = [str(c).strip() for c in contacts if str(c).strip()]
    if not contacts:
        raise ValueError("no CVD contact configured - set BTS_SBOM_CVD_CONTACT (a mailto: or a URL), never a guessed address")
    exp = (_now(now) + datetime.timedelta(days=expires_days)).date().isoformat()
    lines = ["# security.txt - RFC 9116 (CRA Annex I Part II (5)/(6): coordinated vulnerability disclosure contact)"]
    lines += ["Contact: %s" % c for c in contacts]
    lines.append("Expires: %sT23:59:59Z" % exp)
    if preferred_languages:
        lines.append("Preferred-Languages: %s" % preferred_languages)
    if policy:
        lines.append("Policy: %s" % policy)
    if csaf:
        lines.append("CSAF: %s" % csaf)
    lines.append("# generated by bts_sbom %s" % __version__)
    return "\n".join(lines) + "\n"

# ---------------------------------------------------------------- support period (Article 13(8), Annex II 7)

def validate_support_period(declared: Optional[str], today: Optional[Any] = None) -> Dict[str, Any]:
    """A declared support end must be at least year·month (Annex II 7) and must not sit inside the 5-year
    minimum floor (Article 13(8)); the shortfall is measured in months, not asserted."""
    floor = _support_floor(_now(today))
    out = {"declared": declared, "minimum_end": floor.isoformat(), "ref": "Article 13(8) · Annex II 7 (CRA)"}
    if not declared:
        return dict(out, status="not_declared",
                    note="지원 기간 미선언 - 최소 연·월 형식으로 선언해야 한다 (예: %s)" % floor.isoformat()[:7])
    m = re.match(r"^(\d{4})-(\d{2})$", str(declared).strip())
    if not m:
        return dict(out, status="invalid", note="형식 불일치 - 지원 기간은 최소 연·월 (YYYY-MM)로 선언한다 (Annex II 7)")
    y, mo = int(m.group(1)), int(m.group(2))
    end = datetime.date(y, mo, calendar.monthrange(y, mo)[1])
    out["declared_end"] = end.isoformat()
    if end < floor:
        short = (floor.year - end.year) * 12 + (floor.month - end.month)
        return dict(out, status="below_minimum", shortfall_months=short,
                    note="지원 기간이 최소 5년에 %d개월 미달 (Article 13(8): 최소 %s)" % (short, floor.isoformat()))
    return dict(out, status="ok", note="선언됨 - 최소 5년 충족")

# ---------------------------------------------------------------- EOL priority bands (guide annex J template 3, 사내 정책 예시)

def eol_priority(days: Optional[int]) -> str:
    """The 4-band priority of the EOL ledger from the days a component's upstream EOL overshoots the product's
    support end (negative = already past it). The bands are the guide's 사내 정책 예시, not a legal number."""
    if days is None:
        return "unknown"
    if days < 0:
        return "immediate"                                   # 이미 EOL 초과: 즉시 조치
    if days <= 180:
        return "urgent"                                      # 다음 릴리스에 반드시 포함
    if days <= 365:
        return "planned"                                     # 로드맵에 반영
    return "monitor"                                         # 정기 재검토

# ---------------------------------------------------------------- Article 14 clock (2026-09-11부터 적용 중)

_AEV_REFS = {"early": "Article 14(2)(a) (24h 조기 경보)", "notify": "Article 14(2)(b) (72h 통보)",
             "final": "Article 14(2)(c) (시정 조치 가용 후 14일 최종 보고)"}
_INC_REFS = {"early": "Article 14(4)(a) (24h 조기 경보)", "notify": "Article 14(4)(b) (72h 사고 통보)",
             "final": "Article 14(4)(c) (통보 후 1개월 최종 보고)"}


def article14_clock(kind: str, aware_at: Any, *, mitigation_available: Optional[Any] = None,
                    now: Optional[Any] = None) -> Dict[str, Any]:
    """The two clocks of Article 14, computed from the recorded awareness moment T0 (the guide is explicit that
    T0 is the moment of reasonable certainty about the exploitation/incident, and that the 24 h early warning
    does not wait for complete information). ``aev`` final report runs from the mitigation-availability moment;
    ``incident`` final report runs from the notification moment."""
    if kind not in AEV_KINDS:
        raise ValueError("kind must be one of %s (Article 14(1) vs (3))" % "|".join(AEV_KINDS))
    aware = _parse_dt(aware_at)
    nowt = _now(now)
    refs = _AEV_REFS if kind == "aev" else _INC_REFS
    mit = _parse_dt(mitigation_available) if mitigation_available else None
    final: Optional[datetime.datetime] = mit + datetime.timedelta(days=14) if (kind == "aev" and mit) \
        else (_add_months(aware + datetime.timedelta(hours=72), 1) if kind == "incident" else None)

    def slot(due: Optional[datetime.datetime], ref: str) -> Dict[str, Any]:
        if due is None:
            return {"ref": ref, "status": "awaiting_input",
                    "note": "시정·완화 조치 가용 시점을 기록하면 산출된다" if ref is refs["final"] else ""}
        return {"ref": ref, "due": _iso(due),
                "status": "overdue" if nowt > due else "open",
                "hours_left": round((due - nowt).total_seconds() / 3600.0, 1) if nowt <= due else 0.0}
    return {"kind": kind, "aware_at": _iso(aware), "now": _iso(nowt),
            "early_warning": slot(aware + datetime.timedelta(hours=24), refs["early"]),
            "notification": slot(aware + datetime.timedelta(hours=72), refs["notify"]),
            "final_report": slot(final, refs["final"]) if final else
            {"ref": refs["final"], "status": "awaiting_input", "note": "시정·완화 조치 가용 시점 기록 후 14일 산출"}}

# ---------------------------------------------------------------- per-project CRA store + awareness ledger

def _store_file(folder: str) -> str:
    return os.path.join(folder, "cra", "store.json")


def _aware_file(folder: str) -> str:
    return os.path.join(folder, "cra", "article14.json")


def _read_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    os.replace(tmp, path)


def load_store(folder: str) -> Dict[str, Any]:
    return _read_json(_store_file(folder), {}) or {}


def declare_support(folder: str, declared: str, *, today: Optional[Any] = None) -> Dict[str, Any]:
    """Record (or clear with "") the product's declared support end and keep the validation verdict beside it."""
    res = validate_support_period(declared or None, today=today)
    with _LEDGER_LOCK:
        store = load_store(folder)
        store["support_end"] = declared or ""
        store["support_validation"] = res
        store["updated_at"] = _iso(_now(today))
        _write_json(_store_file(folder), store)
    return res


def set_ledger_maintained(folder: str, which: str, maintained: bool) -> None:
    """Mark a generated ledger as the team's maintained copy (readiness checks it; the scan cannot)."""
    if which not in ("3",):
        raise ValueError("only the EOL ledger (3) carries a maintained flag - the others are regenerated from records")
    with _LEDGER_LOCK:
        store = load_store(folder)
        store["eol_maintained"] = bool(maintained)
        _write_json(_store_file(folder), store)


def record_awareness(folder: str, entry: Dict[str, Any], *, now: Optional[Any] = None) -> Dict[str, Any]:
    """Append one Article 14 awareness record (T0 = reasonable certainty). The exploitation/incident verdict is
    the reporter's, stored with its evidence reference - never inferred by the scan."""
    kind = str(entry.get("kind") or "aev")
    if kind not in AEV_KINDS:
        raise ValueError("kind must be one of %s" % "|".join(AEV_KINDS))
    vid = str(entry.get("id") or "").strip()
    if not vid:
        raise ValueError("id required (CVE id, or an incident id for kind=incident)")
    aware = entry.get("aware_at") or now
    mit = entry.get("mitigation_available") or None
    rec = {"id": vid, "kind": kind, "aware_at": _iso(_parse_dt(aware)), "mitigation_available": _iso(_parse_dt(mit)) if mit else "",
           "products": [str(p) for p in (entry.get("products") or [])][:8],
           "evidence": str(entry.get("evidence") or "").strip()[:400],
           "recorded_at": _iso(_now(now))}
    rec["clock"] = article14_clock(kind, rec["aware_at"], mitigation_available=rec["mitigation_available"] or None, now=now)
    with _LEDGER_LOCK:
        log = _read_json(_aware_file(folder), []) or []
        log = [e for e in log if not (e.get("id") == vid and e.get("kind") == kind)]   # re-recording replaces, never duplicates
        log.append(rec)
        _write_json(_aware_file(folder), log)
    return rec


def load_awareness(folder: str, *, now: Optional[Any] = None) -> List[Dict[str, Any]]:
    entries = _read_json(_aware_file(folder), []) or []
    for e in entries:
        try:
            e["clock"] = article14_clock(e["kind"], e["aware_at"], mitigation_available=e.get("mitigation_available") or None, now=now)
        except ValueError:
            e["clock"] = {"error": "unparsable entry"}
    return entries

# ---------------------------------------------------------------- readiness scorecard (guide annex I, automatable subset)

CHECKS = (
    ("sbom_machine_readable", "기계 판독 SBOM (EU CRA·BSI TR-03183-2 regime)", "Annex I Part II(1) · BSI TR-03183-2"),
    ("security_txt_deployed", "security.txt (CVD 연락처 공개)", "Annex I Part II(5)·(6) · RFC 9116"),
    ("support_period", "지원 기간 선언·최소 5년", "Article 13(8) · Annex II 7"),
    ("eol_ledger_maintained", "EOL 컴포넌트 관리 대장 유지", "Article 13(5) · guide annex J template 3"),
    ("vex_document", "기계 판독 취약점 공시 (OpenVEX)", "Annex I Part II(4)"),
    ("reporting_process", "Article 14 보고 체계 기록", "Article 14(2) (2026-09-11부터 적용 중)"),
    ("sbom_refresh_history", "릴리스별 SBOM 갱신 이력", "Article 31(2) · guide annex J template 4"),
    ("triage_disclosure", "취약점 처분 결정 기록 (not_affected 근거)", "Annex I Part II(4) · VEX"),
)


def readiness(rec: Dict[str, Any], *, folder: str, doc: Optional[Dict[str, Any]] = None, triage: Optional[Dict[str, Any]] = None,
              security_txt_deployed: bool = False, history_rows: int = 0, today: Optional[Any] = None) -> Dict[str, Any]:
    """Score the automatable subset of the guide's annex-I checklist for one project. A check that needs data
    the scan does not produce reports a gap with the fix, never a pass."""
    store = load_store(folder)
    awareness = load_awareness(folder, now=today)
    vulns = rec.get("vulns") or []
    from . import conformance
    out: Dict[str, Any] = {"schema": SCHEMA, "status": "OK", "project": rec.get("name", ""), "checks": [], "note": NOT_COMPUTED,
                           "regulations": "Regulation (EU) 2024/2847 · K-OSSC CRA 실무 가이드 v1.0 (2026-11)"}

    def add(cid: str, status: str, basis: str, fix: str = "") -> None:
        title, ref = next((t, r) for i, t, r in CHECKS if i == cid)
        out["checks"].append({"id": cid, "title": title, "ref": ref, "status": status, "basis": basis, "fix": fix})

    # 1 - machine-readable SBOM against the CRA and BSI regimes (delegated: conformance.py owns that matrix)
    if isinstance(doc, dict) and str(doc.get("bomFormat", "")).lower() == "cyclonedx":
        conf = conformance.compact(conformance.evaluate(doc, regimes=("eu-cra-annex-i", "bsi-tr-03183-2")))
        regimes = conf.get("regimes") or {}
        verdicts = [r.get("verdict") for r in regimes.values()]
        n_ok = sum(1 for v in verdicts if v == "conformant")
        status = "pass" if n_ok == len(verdicts) and verdicts else ("partial" if n_ok else "gap")
        detail = ", ".join("%s=%s" % (k, r.get("verdict")) for k, r in regimes.items())
        add("sbom_machine_readable", status,
            "%d components - %s" % (conf.get("components", 0), detail or "no verdicts"),
            "" if status == "pass" else "conformance 탭의 fix-once 목록으로 빠진 필드를 메운다")
    else:
        add("sbom_machine_readable", "gap", "이 프로젝트의 CycloneDX 문서가 없다", "스캔을 다시 실행해 SBOM을 생성한다")

    # 2 - security.txt (service-level: the operator configures the contact, the server serves /.well-known/)
    add("security_txt_deployed", "pass" if security_txt_deployed else "gap",
        "deployed at /.well-known/security.txt" if security_txt_deployed else "미배포",
        "" if security_txt_deployed else "BTS_SBOM_CVD_CONTACT 환경변수에 mailto: 또는 URL을 설정한다 (주소를 추측하지 않는다)")

    # 3 - support period declared and inside the 5-year minimum
    sup = store.get("support_validation")
    if not sup:
        sup = validate_support_period(store.get("support_end") or None, today=today)
    add("support_period", {"ok": "pass", "below_minimum": "gap", "invalid": "gap", "not_declared": "gap"}[sup["status"]],
        str(sup.get("note") or sup["status"]),
        "" if sup["status"] == "ok" else "CRA 판에서 지원 기간을 YYYY-MM로 선언한다 (Article 13(8): 최소 5년)")

    # 4 - EOL ledger maintained by the team (the scan cannot measure upstream EOL dates)
    add("eol_ledger_maintained", "pass" if store.get("eol_maintained") else "gap",
        "maintained copy flagged" if store.get("eol_maintained") else "미유지",
        "" if store.get("eol_maintained") else "EOL 대장(대장 3)을 내려받아 상류 EOL일을 조사·기입하고 유지 플래그를 켠다")

    # 5 - machine-readable disclosure exists (OpenVEX with decisions applied)
    try:
        vex = sbom.openvex(rec.get("name", ""), vulns, triage=triage)
        n = len(vex.get("statements") or [])
        add("vex_document", "partial" if n == 0 else "pass",
            "%d statements" % n, "" if n else "알려진 취약점이 없어 공시 대상이 없다 (빈 문서는 정직한 상태)")
    except Exception:                                        # noqa: BLE001 - never guess: report the gap
        add("vex_document", "gap", "OpenVEX 생성 실패", "VEX · Decisions 탭에서 재생성한다")

    # 6 - Article 14 reporting process has a recorded runbook or at least one awareness entry
    if awareness:
        add("reporting_process", "pass", "%d awareness entries recorded" % len(awareness))
    elif store.get("article14_runbook"):
        add("reporting_process", "pass", "runbook flagged in the project store")
    else:
        add("reporting_process", "gap", "인지 기록·런북 플래그 없음", "CRA 팬에서 Article 14 인지 시점을 기록하고 24h 런북을 마련한다")

    # 7 - SBOM refreshed per release (template 4 needs > one run)
    add("sbom_refresh_history", "pass" if history_rows >= 2 else ("partial" if history_rows == 1 else "gap"),
        "%d recorded analysis runs" % history_rows,
        "" if history_rows >= 2 else "같은 프로젝트를 재분석하면 갱신 이력 대장이 채워진다")

    # 8 - disposition decisions recorded (Part II(4) disclosure evidence, not_affected needs a justification)
    n_dec = len(triage or {})
    add("triage_disclosure", "pass" if n_dec else "gap", "%d decisions recorded" % n_dec,
        "" if n_dec else "VEX · Decisions 탭에서 처분 결정(근거 포함)을 기록한다")

    n_pass = sum(1 for c in out["checks"] if c["status"] == "pass")
    n_partial = sum(1 for c in out["checks"] if c["status"] == "partial")
    out["score"] = {"pass": n_pass, "partial": n_partial, "gap": len(out["checks"]) - n_pass - n_partial,
                    "total": len(out["checks"]), "pct": round((n_pass + 0.5 * n_partial) / len(out["checks"]) * 100, 1)}
    return out

# ---------------------------------------------------------------- the five SBOM ledgers (guide annex J)

_LEDGER_NAMES = {"1": ("SBOM 제품 등록 대장", "cra-ledger-1-product.csv"),
                 "2": ("SBOM 컴포넌트 취약점 추적 대장", "cra-ledger-2-vulns.csv"),
                 "3": ("SBOM EOL 컴포넌트 관리 대장", "cra-ledger-3-eol.csv"),
                 "4": ("SBOM 갱신 이력 대장", "cra-ledger-4-updates.csv"),
                 "5": ("SBOM 시장 감시 당국 제출 대장", "cra-ledger-5-submissions.csv")}


def _csv(header: List[str], rows: List[List[Any]], tail: str = "") -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for r in rows:
        w.writerow(r)
    if tail:
        w.writerow([])
        w.writerow([tail])
    return buf.getvalue()


def ledgers(rec: Dict[str, Any], *, folder: str, doc: Optional[Dict[str, Any]] = None, triage: Optional[Dict[str, Any]] = None,
            history_rows: Optional[List[Dict[str, Any]]] = None, today: Optional[Any] = None) -> Dict[str, str]:
    """Build the guide's five SBOM ledgers from what the records actually hold. Columns the scan cannot measure
    stay blank or carry the not-computed marker - a ledger with invented dates would be worse than an empty one."""
    name = rec.get("name", "")
    nowt = _now(today)
    store = load_store(folder)
    meta = ((doc or {}).get("metadata") or {})
    ts = str(meta.get("timestamp") or rec.get("analysed_at") or _iso(nowt))
    lifecycles = meta.get("lifecycles") or []
    ctx = ", ".join(str(l.get("phase", l)) if isinstance(l, dict) else str(l) for l in lifecycles) or "post-build (분석 시점 생성)"
    sup = store.get("support_validation") or {}
    support_end = sup.get("declared_end") or ""
    out: Dict[str, str] = {}

    # template 1 - the SBOM master registry: what exists, in which format, where
    out["1"] = _csv(
        ["항목", "값"],
        [["대상 제품", name],
         ["SBOM 형식·형식버전", "CycloneDX %s" % (doc or {}).get("specVersion", "1.5")],
         ["SBOM 작성자", "bts_sbom_app (도구 생성 - 담당자 미기록: 채워 넣을 것)"],
         ["SBOM 타임스탬프 (UTC)", ts],
         ["생성도구·버전", "bts_sbom %s" % __version__],
         ["생성맥락", ctx],
         ["상세수준", "전체 컴포넌트 (CRA 최저선: 최상위 의존성 이상 충족)"],
         ["서명여부", "아니오 (서명 파이프라인 미구현)"],
         ["다음점검예정일", (nowt + datetime.timedelta(days=90)).date().isoformat()],
         ["기술문서포함여부", "예 (/api/doc/%s Markdown 보고서)" % name],
         ["지원기간(선언)", support_end or "미선언"],
         ["보관기한", "시장 출시 후 10년 또는 지원 기간 중 더 긴 기간 (Article 13(13))"]],
        tail="매 릴리스마다 새 SBOM을 생성하고 이 대장을 갱신한다 (guide annex J template 1)")

    # template 2 - the vulnerability tracking ledger: VEX status per finding, exploitation NOT assessed
    vex = sbom.openvex(name, rec.get("vulns") or [], triage=triage)
    vexmap: Dict[tuple, Dict[str, str]] = {}
    for s in vex.get("statements") or []:
        pid = ((s.get("products") or [{}])[0].get("@id") or "")
        note = s.get("action_statement") or ""
        if s.get("status_notes"):
            note = (note + " — " + " / ".join(str(n) for n in s["status_notes"])).strip(" —")
        vexmap[(s.get("vulnerability", {}).get("name", ""), pid)] = {"status": s.get("status", ""), "note": note}
    aware_ids = {e["id"] for e in (load_awareness(folder, now=today) or [])}
    rows2: List[List[Any]] = []
    for v in rec.get("vulns") or []:
        pid = v.get("purl") or "pkg:generic/%s@%s" % (v["package"], v["version"])
        vx = vexmap.get((v["id"], pid)) or {}
        rows2.append([v["id"], pid, v["package"], v.get("version", ""), v.get("severity", ""),
                      "affected", "미판정 (KEV·EUVD 미연동)", vx.get("status", "affected"),
                      vx.get("note", ""), "기록됨" if v["id"] in aware_ids else "미기록", "", ""])
    out["2"] = _csv(
        ["취약점식별자", "PURL", "패키지", "버전", "심각도", "영향여부", "악용여부", "VEX상태", "VEX근거/조치",
         "Article14보고여부", "조치완료일", "비고"],
        rows2,
        tail="악용여부·조치완료일은 팀이 기입한다 (scan이 KEV/EUVD를 계산하지 않음 - guide annex J template 2)")

    # template 3 - the EOL ledger: the full component list, upstream EOL columns left to the team
    rows3 = []
    for c in rec.get("components") or []:
        rows3.append([c["name"], c.get("version", ""), c.get("purl") or "", c.get("license", ""),
                      "", "", "unknown", ""])
    out["3"] = _csv(
        ["컴포넌트명", "버전", "PURL", "라이선스", "상류EOL일", "불일치기간(일)", "우선순위", "대응전략"],
        rows3,
        tail="상류 EOL일 조사 후 기입 - 우선순위 구간(사내 정책 예시): 음수=즉시·0~180일=긴급·180~365일=계획·365일+=모니터링 (guide annex J template 3)")

    # template 4 - the SBOM update history: one row per recorded analysis run
    rows4 = [[(h.get("analysed_at") or ""), "릴리스", "프로젝트 재분석", "SBOM 갱신 (%s)" % h.get("name", name)]
             for h in (history_rows or [])]
    if not rows4:
        rows4.append([ts, "릴리스", "첫 분석", "SBOM 생성 (%s)" % name])
    out["4"] = _csv(["일시(UTC)", "갱신유형", "트리거", "결과SBOM"], rows4,
                    tail="오류 정정·정보 추가 시 같은 버전의 개정 SBOM을 발행하고 여기에 기록한다 (guide annex J template 4)")

    # template 5 - the submissions ledger: honestly empty until a reasoned request arrives
    out["5"] = _csv(["제출일시", "요청당국", "근거(reasoned request 요지)", "제출한 SBOM 버전", "제출 파일 해시", "법무 통보"],
                    [], tail="제출 이력 없음 - 시장 감시 당국의 reasoned request 접수 시 기입 (Annex VII 8 · Article 13(25))")
    return out


def ledger(which: str, rec: Dict[str, Any], *, folder: str, **kw: Any) -> Optional[Dict[str, str]]:
    """One ledger: {"title", "filename", "csv"} — or None for an unknown template number."""
    if which not in _LEDGER_NAMES:
        return None
    title, fname = _LEDGER_NAMES[which]
    return {"title": title, "filename": fname, "csv": ledgers(rec, folder=folder, **kw)[which]}
