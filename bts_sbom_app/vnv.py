"""V&V evidence report in the ISO/SAE TR 8477 8.1 shape (task 30) - stdlib only, deterministic.

Turns one analysis record into the evidence an assessor reads: traceability (target, plan/requirement refs, tool
and core versions, online/offline), scope with EXCLUSIONS AND REASONS (unreadable files, unsupported manifests,
packages that could not be queried, unresolved licenses), per-item results, proposed actions (the verified plan),
deviations from plan (stage errors), and a conclusion. Honesty rules, verbatim from the review:
  * offline, unqueried packages, or existence-only evidence => "pass with restrictions", never "pass";
  * "exploitability was not demonstrated - existence was checked by scanning" is a FIXED scope statement (TR 6.11);
  * no compliance verdict is ever issued (that is the assessor's independent judgement, TR annex A).
"""
from __future__ import annotations

from typing import Any, Dict, List

SCHEMA = "bts-sbom.vnv.v1"
DISCLAIMER = "엔지니어링 증거이며 법률·적합성 판정이 아닙니다 — 독립 평가(4-eyes)는 평가자의 몫입니다"
FIXED_SCOPE = "공격 실현 가능성(악용 입증)은 시험하지 않았습니다 — 취약점 스캐닝으로 존재만 확인했습니다 (exploitability was not demonstrated; existence was checked by scanning)"

_RESTRICTION_REASONS = {
    "offline": "오프라인 실행 — 권위 있는 조회를 하지 못했다",
    "unqueried": "권위 있는 조회를 하지 못한 패키지가 있다 — 건수는 하한일 수 있다",
    "version_unresolved": "버전을 확정하지 못한 패키지가 있다 — 범위가 불완전하다",
    "unresolved_license": "라이선스를 해소하지 못한 부품이 있다",
    "existence_only": "발견은 존재 확인까지만이다 — 악용 입증은 별도 시험의 몫이다",
    "no_data": "분석된 부품이 0개다 — 보고할 결과가 없다",
}


def _exclusions(rec: Dict[str, Any]) -> List[Dict[str, str]]:
    """Scope exclusions with reasons, from the record's own honest bookkeeping (never fabricated)."""
    out: List[Dict[str, str]] = []
    comps = rec.get("components") or []
    status = rec.get("status") or {}
    offline = bool(rec.get("engine", {}).get("offline")) or bool(status.get("network_fallback_offline")) or status.get("mode") == "offline"
    unqueried = [c for c in comps if str(c.get("query_status") or "") not in ("queried_online",)]
    bad_license = [c for c in comps if str(c.get("license_category") or "") == "unknown"]
    unsupported = rec.get("engine", {}).get("unsupported") or []
    if offline:
        out.append({"item": "network lookups", "reason": _RESTRICTION_REASONS["offline"]})
    if unqueried:
        out.append({"item": "%d package(s) not authoritatively queried" % len(unqueried), "reason": _RESTRICTION_REASONS["unqueried"]})
    if status.get("version_unresolved"):
        out.append({"item": "%s package(s) with unresolved version" % status.get("version_unresolved"), "reason": _RESTRICTION_REASONS["version_unresolved"]})
    if bad_license:
        out.append({"item": "%d component(s) with unresolved license" % len(bad_license), "reason": _RESTRICTION_REASONS["unresolved_license"]})
    if unsupported:
        out.append({"item": "%d unsupported file/manifest(s) skipped" % len(unsupported), "reason": "지원하지 않는 매니페스트·파일은 스캔에서 제외됐다"})
    if not comps:
        out.append({"item": "components", "reason": _RESTRICTION_REASONS["no_data"]})
    out.append({"item": "exploitability", "reason": _RESTRICTION_REASONS["existence_only"]})
    return out


def report(rec: Dict[str, Any], *, plan_ref: str = "", req_ref: str = "") -> Dict[str, Any]:
    """Deterministic V&V evidence report (TR 8.1 fields, this tool's honest mapping)."""
    from .jobstore import sanitize_source
    comps = rec.get("components") or []
    vulns = rec.get("vulns") or []
    plans = [p for p in rec.get("plans") or [] if p.get("status") == "upgrade"]
    metrics = rec.get("metrics") or {}
    status = rec.get("status") or {}
    offline = bool(rec.get("engine", {}).get("offline")) or bool(status.get("network_fallback_offline")) or status.get("mode") == "offline"
    restrictions = _exclusions(rec)
    stage_errors = rec.get("stage_errors") or {}
    if rec.get("error"):
        grade = "fail"
    elif not comps:
        grade = "pass with restrictions"
    elif restrictions[:-1]:                                    # every restriction except the fixed existence-only line
        grade = "pass with restrictions"
    else:
        grade = "pass"
    items = [{"id": v.get("id"), "package": v.get("package"), "version": v.get("version"),
              "severity": v.get("severity"), "cvss": v.get("cvss"), "fixed_version": v.get("fixed_version") or "",
              "evidence": "existence (vulnerability scanning)"} for v in vulns]
    conclusion = {
        "fail": "분석이 실패했다 — 산출물을 산출하지 못했으므로 증거로 쓸 수 없다.",
        "pass": "제한 없이 통과: 조회 실패·미해결 항목이 없고 정책 기준을 만족한다(존재 확인 기준).",
        "pass with restrictions": "제한 있는 통과: 범위의 제외 사유를 읽고 증거를 판단하라. 악용 가능성은 입증되지 않았다.",
    }[grade]
    return {"schema": SCHEMA, "disclaimer": DISCLAIMER,
            "traceability": {"target": rec.get("name"), "source": sanitize_source(rec.get("source")), "commit": (rec.get("lineage") or {}).get("commit", ""),
                             "plan_ref": plan_ref, "req_ref": req_ref, "tool": "bts_sbom_app", "workflow_version": rec.get("engine", {}).get("core", ""),
                             "online": not offline, "record_schema": rec.get("schema")},
            "scope": {"integration_layer": "component level (SBOM / SCA)", "access": "white-box for source manifests; black-box string evidence for binaries",
                      "acceptance": "license policy + verified remediation plan", "exploitability": FIXED_SCOPE,
                      "exclusions": restrictions},
            "results": {"grade": grade, "components": len(comps), "findings": len(vulns),
                        "per_item": items[:40], "proposed_actions": [{"component": p.get("component"), "to": p.get("safe_version")} for p in plans[:20]]},
            "measures": {"license_resolved_rate": metrics.get("license_resolved_rate"), "plans_verified_clean": metrics.get("plans_verified_clean")},
            "deviations": [{"stage": k, "error": str(v)[:160]} for k, v in stage_errors.items()],
            "conclusion": conclusion}


def render_md(rep: Dict[str, Any]) -> str:
    L = ["# V&V evidence report — %s" % rep["traceability"]["target"], "", "_" + rep["disclaimer"] + "_", ""]
    tr = rep["traceability"]
    L += ["- target: `%s` (commit `%s`)" % (tr.get("source"), (tr.get("commit") or "")[:10]),
          "- plan/req refs: %s / %s" % (tr.get("plan_ref") or "-", tr.get("req_ref") or "-"),
          "- tool: %s (core %s), online=%s" % (tr.get("tool"), tr.get("workflow_version") or "?", tr.get("online")), ""]
    sc = rep["scope"]
    L += ["## Scope", "", "- " + sc["integration_layer"], "- " + sc["access"], "- acceptance: " + sc["acceptance"],
          "- **" + sc["exploitability"] + "**", "", "| excluded | reason |", "|---|---|"]
    L += ["| %s | %s |" % (x["item"], x["reason"]) for x in sc["exclusions"]]
    rs = rep["results"]
    L += ["", "## Results — **%s**" % rs["grade"], "", "components: %d, findings: %d" % (rs["components"], rs["findings"]), ""]
    if rs["per_item"]:
        L += ["| id | package | severity | fixed in | evidence |", "|---|---|---|---|---|"]
        L += ["| %s | %s | %s | %s | %s |" % (i.get("id"), i.get("package"), i.get("severity"), i.get("fixed_version") or "-", i["evidence"]) for i in rs["per_item"]]
    if rs["proposed_actions"]:
        L += ["", "## Proposed actions", ""] + ["- %s → %s" % (a["component"], a["to"]) for a in rs["proposed_actions"]]
    if rep["deviations"]:
        L += ["", "## Deviations from plan"] + ["- %s: %s" % (d["stage"], d["error"]) for d in rep["deviations"]]
    L += ["", "## Conclusion", "", rep["conclusion"], ""]
    return "\n".join(L)
