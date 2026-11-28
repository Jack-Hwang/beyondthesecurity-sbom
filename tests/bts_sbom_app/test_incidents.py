"""The incident-response lane (KISA 침해사고 대응 RFP 매핑): stage machine, SLA clocks, roll-up,
the four report builders, IoC registration and the supply-chain cross-check - unit tests on pure
functions plus the HTTP security contract (Host pinning, cross-origin refusal, input limits)."""
from __future__ import annotations

import datetime
import json
import re
import os
import types
import urllib.parse

from bts_sbom_app import incidents

HOST = {"Host": "127.0.0.1:8800"}
BIND = ("127.0.0.1", 8800)
NOW = datetime.datetime(2026, 11, 28, 9, 0, 0, tzinfo=datetime.timezone.utc)


def _st(tmp_path):
    return types.SimpleNamespace(evidence=str(tmp_path), jobs={}, buses={})


def _req(st, method, path, body=None, headers=None, query=None):
    h = dict(HOST)
    h.update(headers or {})
    code, obj, ctype, hdr = incidents.route(method, path, query or {}, body or {}, h, st, BIND)
    return code, obj


def _rec(tmp_path, **kw):
    body = {"org": "피해기업", "title": "랜섬웨어 감염 신고", "source": "ioc"}
    body.update(kw)
    rec, why = incidents.create_incident(str(tmp_path), body, now=NOW)
    assert rec is not None, why
    return rec


# ------------------------------------------------------------------ stage machine + SLA clocks
def test_create_defaults_and_stage_walk(tmp_path):
    """AC: BSA-AC-1261"""
    st = _st(tmp_path)
    rec = _rec(tmp_path)
    assert re.fullmatch(r"IR-\d{8}-[0-9a-f]{4}", rec["id"]) and rec["stage"] == "intake"
    assert rec["stage_at"]["intake"] == rec["received_at"] and rec["due_at"] is None
    # forward one step at a time; evidence completion stamps the 7-day clock
    for stage, kw in (("interview", {"assignee": "김분석"}),
                      ("evidence", {}),
                      ("analysis", {"collection_complete": True}),
                      ("report", {}), ("closed", {})):
        rec, why = incidents.advance_incident(str(tmp_path), rec["id"], dict(stage=stage, **kw), now=NOW)
        assert rec is not None, why
    assert rec["assignee"] == "김분석" and rec["assigned_at"]
    assert rec["evidence_done_at"] and rec["due_at"] == (NOW + datetime.timedelta(days=7)).isoformat(timespec="seconds")
    assert rec["closed_at"]
    code, obj = _req(st, "GET", "/api/incidents")
    assert code == 200 and obj["rollup"]["closed"] == 1 and obj["incidents"][0]["stage"] == "closed"


def test_advance_without_stage_auto_advances_one_step(tmp_path):
    """AC: BSA-AC-1261 — the 다음 단계 ▶ button sends no stage: the lane auto-advances exactly one step."""
    st = _st(tmp_path)
    rec = _rec(tmp_path)
    import bts_sbom_app.incidents as _m
    print("DBG module:", _m.__file__)
    code, obj = _req(st, "POST", "/api/incidents/%s/advance" % rec["id"], {})
    print("DBG resp:", code, obj.get("stage"), obj.get("error"))
    assert code == 200 and obj["stage"] == "interview"
    code, obj = _req(st, "POST", "/api/incidents/%s/advance" % rec["id"], {})
    assert code == 200 and obj["stage"] == "evidence"
    for stg in ("analysis", "report", "closed"):
        code, obj = _req(st, "POST", "/api/incidents/%s/advance" % rec["id"], {})
        assert code == 200, (stg, obj.get("error"))
        assert obj["stage"] == stg
    code, obj = _req(st, "POST", "/api/incidents/%s/advance" % rec["id"], {})
    assert code == 400 and "종결" in obj["error"]


def test_findings_route_takes_post_and_refuses_wrong_method(tmp_path):
    """AC: BSA-AC-1262 — findings는 POST 전용 (GET 분기에 잘못 붙었던 리뷰 결함 수선)."""
    st = _st(tmp_path)
    rec = _rec(tmp_path)
    code, obj = _req(st, "POST", "/api/incidents/%s/findings" % rec["id"], {"cause": "웹셸 경로 확인"})
    assert code == 200 and obj["findings"]["cause"] == "웹셸 경로 확인"
    code, obj = _req(st, "GET", "/api/incidents/%s/findings" % rec["id"])
    assert code == 404                                            # findings answers POST only; GET is a flat 404


def test_advance_rejects_skips_backwards_and_unknown(tmp_path):
    """AC: BSA-AC-1261"""
    st = _st(tmp_path)
    rec = _rec(tmp_path)
    code, obj = _req(st, "POST", "/api/incidents/%s/advance" % rec["id"], {"stage": "analysis"})
    assert code == 400 and "한 칸씩" in obj["error"]
    code, obj = _req(st, "POST", "/api/incidents/IR-20260101-dead/advance", {"stage": "interview"})
    assert code == 400 and "unknown incident" in obj["error"]
    code, obj = _req(st, "POST", "/api/incidents/%s/advance" % rec["id"], {"stage": "nonsense"})
    assert code == 400


def test_sla_view_flags_assign_and_analysis_breach_and_long_stall(tmp_path):
    """AC: BSA-AC-1261"""
    rec = _rec(tmp_path)
    v = incidents.sla_view(rec, now=NOW)
    assert v["assign_breach"] is False and v["analysis_breach"] is False
    late = NOW + datetime.timedelta(days=2)                                   # 1-day assign SLA has passed
    v = incidents.sla_view(rec, now=late)
    assert v["assign_breach"] is True and v["long_stalled"] is False
    rec2, _ = incidents.advance_incident(str(tmp_path), rec["id"],
                                         {"stage": "interview", "assignee": "김분석"}, now=NOW)
    rec3, _ = incidents.advance_incident(str(tmp_path), rec["id"], {"stage": "evidence"}, now=NOW)
    rec4, _ = incidents.advance_incident(str(tmp_path), rec["id"], {"stage": "analysis", "collection_complete": True}, now=NOW)
    way_late = NOW + datetime.timedelta(days=30)
    v = incidents.sla_view(rec4, now=way_late)
    assert v["analysis_breach"] is True and v["long_stalled"] is True and v["assign_breach"] is False


def test_rollup_counts_stages_and_breaches(tmp_path):
    """AC: BSA-AC-1261"""
    rec = _rec(tmp_path)
    _rec(tmp_path, org="두번째", title="피싱 대응 요청")
    late = NOW + datetime.timedelta(days=3)                                   # both are unassigned -> assign breach
    ru = incidents.sla_rollup(incidents.all_incidents(str(tmp_path)), now=late)
    assert ru["total"] == 2 and ru["open"] == 2 and ru["by_stage"]["intake"] == 2
    assert ru["assign_sla_breach"] == 2 and ru["not_started"] == 2


# ------------------------------------------------------------------ intake validation (limits)
def test_create_refuses_missing_fields_bad_source_and_oversized(tmp_path):
    """AC: BSA-AC-1261"""
    st = _st(tmp_path)
    code, obj = _req(st, "POST", "/api/incidents", {"title": "x"})
    assert code == 400 and "org" in obj["error"]
    code, obj = _req(st, "POST", "/api/incidents", {"org": "A", "title": "B", "source": "twitter"})
    assert code == 400 and "source" in obj["error"]
    code, obj = _req(st, "POST", "/api/incidents", {"org": "A", "title": "B", "envs": ["web", "satellite"]})
    assert code == 400 and "envs" in obj["error"]
    code, obj = _req(st, "POST", "/api/incidents", {"org": "A" * 300, "title": "B"})
    assert code == 400 and "길이" in obj["error"]


def test_delay_requires_a_real_reason(tmp_path):
    """AC: BSA-AC-1261"""
    st = _st(tmp_path)
    rec = _rec(tmp_path)
    code, obj = _req(st, "POST", "/api/incidents/%s/delay" % rec["id"], {"reason": "짧"})
    assert code == 400 and "5자" in obj["error"]
    code, obj = _req(st, "POST", "/api/incidents/%s/delay" % rec["id"],
                     {"reason": "피해기업 자료제공 지연", "eta": "2026-12-05"})
    assert code == 200 and obj["delay"][0]["reason"] == "피해기업 자료제공 지연"


# ------------------------------------------------------------------ IoC + supply-chain cross-check
def test_ioc_registration_validates_and_dedupes(tmp_path):
    """AC: BSA-AC-1263"""
    st = _st(tmp_path)
    rec = _rec(tmp_path)
    code, obj = _req(st, "POST", "/api/incidents/%s/iocs" % rec["id"], {"type": "yara", "value": "x"})
    assert code == 400 and "type" in obj["error"]
    code, obj = _req(st, "POST", "/api/incidents/%s/iocs" % rec["id"], {"type": "hash", "value": "zz"})
    assert code == 400 and "md5" in obj["error"]
    code, obj = _req(st, "POST", "/api/incidents/%s/iocs" % rec["id"], {"type": "package", "value": "requests"})
    assert code == 200
    code, obj = _req(st, "POST", "/api/incidents/%s/iocs" % rec["id"], {"type": "package", "value": "REQUESTS"})
    assert code == 200 and len(obj["iocs"]) == 1                               # duplicate is idempotent
    code, obj = _req(st, "POST", "/api/incidents/%s/iocs" % rec["id"],
                     {"type": "hash", "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"})
    assert code == 200 and len(obj["iocs"]) == 2


def _project_fixture(tmp_path, name="projx", components=None, vulns=None):
    rec = {"schema": "sbomplus.project.v1", "name": name, "components": components or [],
           "vulns": vulns or [], "version": "1.0"}
    d = tmp_path / name
    d.mkdir()
    (d / (name + ".json")).write_text(json.dumps(rec), encoding="utf-8")


def test_sbom_impact_matches_package_and_is_honest_about_hashes(tmp_path):
    """AC: BSA-AC-1263"""
    st = _st(tmp_path)
    _project_fixture(tmp_path, components=[{"name": "Django", "version": "1.8.3"}],
                     vulns=[{"id": "CVE-2018-7537", "package": "django"}])
    rec = _rec(tmp_path)
    _req(st, "POST", "/api/incidents/%s/iocs" % rec["id"], {"type": "package", "value": "django"})
    _req(st, "POST", "/api/incidents/%s/iocs" % rec["id"],
         {"type": "hash", "value": "a" * 64})
    _req(st, "POST", "/api/incidents/%s/iocs" % rec["id"], {"type": "c2", "value": "203.0.113.9"})
    code, obj = _req(st, "GET", "/api/incidents/%s/sbom-impact" % rec["id"])
    assert code == 200
    assert obj["matches"] and obj["matches"][0]["component"] == "Django"
    assert "CVE-2018-7537" in obj["matches"][0]["advisories"]
    reasons = {u["type"]: u["reason"] for u in obj["unmatched"]}
    assert "대조 불가" in reasons["hash"] and "SBOM 표면이 없" in reasons["c2"]


# ------------------------------------------------------------------ reports: honest placeholders
def test_reports_mark_unknown_fields_and_never_invent(tmp_path):
    """AC: BSA-AC-1262"""
    st = _st(tmp_path)
    rec = _rec(tmp_path, envs=["web"])
    code, obj = _req(st, "GET", "/api/incidents/%s/report" % rec["id"], query={"kind": ["intake"]})
    assert code == 200 and "초동보고서" in obj["markdown"] and "미확인" in obj["markdown"]
    assert "증거데이터 수집 대상" in obj["markdown"] and "웹 접근 로그" in obj["markdown"]
    code, obj = _req(st, "GET", "/api/incidents/%s/report" % rec["id"], query={"kind": ["cause"]})
    assert code == 200 and "침투 경로" in obj["markdown"] and "미확인" in obj["markdown"]
    code, obj = _req(st, "GET", "/api/incidents/%s/report" % rec["id"], query={"kind": ["bogus"]})
    assert code == 400
    code, obj = _req(st, "GET", "/api/incidents/%s/checklist" % rec["id"], query={"env": ["mobile-iot"]})
    assert code == 200 and "메모리 덤프" in obj["markdown"]
    code, obj = _req(st, "GET", "/api/incidents/%s/checklist" % rec["id"], query={"env": ["satellite"]})
    assert code == 400


def test_playbook_accumulates_only_recorded_responses(tmp_path):
    """AC: BSA-AC-1262"""
    st = _st(tmp_path)
    _rec(tmp_path)                                                            # no response recorded yet
    code, obj = _req(st, "GET", "/api/incidents/playbook")
    assert code == 200 and "아직 기록된 대응방안이 없다" in obj["markdown"]
    rec = incidents.all_incidents(str(tmp_path))[0]
    rec["findings"]["response"] = "웹셸 제거 후 WAF 규칙을 추가했다."
    incidents._save(str(tmp_path), rec)
    code, obj = _req(st, "GET", "/api/incidents/playbook")
    assert code == 200 and "웹셸 제거 후 WAF 규칙을 추가했다." in obj["markdown"]


# ------------------------------------------------------------------ security contract
def test_security_host_pinning_cross_origin_and_paths(tmp_path):
    """AC: BSA-AC-1263"""
    st = _st(tmp_path)
    evil = {"Host": "evil.example:8800"}
    code, obj = incidents.route("GET", "/api/incidents", {}, {}, evil, st, BIND)[:2]
    assert code == 403 and "Host" in obj["error"]
    code, obj = incidents.route("POST", "/api/incidents", {}, {"org": "A", "title": "B"},
                                {"Host": "127.0.0.1:8800", "Origin": "https://evil.example"}, st, BIND)[:2]
    assert code == 403 and "cross-origin" in obj["error"]
    code, obj = _req(st, "GET", "/api/incidents/IR-99999999-dead")
    assert code == 404
    code, obj = _req(st, "GET", "/api/incidents/IR-20260101-dead/sbom-impact")
    assert code == 200 or code == 404                                         # impact on unknown id is an honest miss
    code, obj = incidents.route("PUT", "/api/incidents", {}, {}, HOST, st, BIND)[:2]
    assert code == 405
    code, obj = _req(st, "GET", "/api/incidents/../../server.py")
    assert code in (400, 404)

