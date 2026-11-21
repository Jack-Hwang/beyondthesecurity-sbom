"""AI proposal lane (LG EXAONE): evidence -> prompt -> response validated in four layers -> or honest downgrade.

Validation layers (a proposal must pass all four, otherwise it is dropped and counted in ``dropped``):
  1 schema       JSON object/array with title, action, refs, rationale
  2 rule         action / risk from closed sets, bounded lengths, target_version string-or-null
  3 semantic     every ref names something that exists in the evidence (advisory id/alias, component, file, domain...)
  4 cross-field  upgrade -> target equals the verified plan's safe version; replace/accept_risk only where no clean
                 fix exists; review_license only for components that really lack/violate a license; refactor only
                 for measured architecture entities
When EXAONE is unavailable (no key, local budget, provider day limit, network, invalid output) the lane falls back to
DETERMINISTIC proposals and says so (``source="deterministic"`` + the cause in ``llm_note``) - it never reports an
LLM success it did not have. Responses are cached by prompt hash so identical evidence never costs a second call.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from . import router
from .llm import ChatClient, LLMError, LLMUnavailable
from .util import clip

PROMPT_VERSION = "ai-v2"
ACTIONS = {"upgrade", "replace", "pin", "remove", "review_license", "refactor", "monitor", "accept_risk",
           "upgrade_runtime", "extract_module"}
RISKS = {"low", "medium", "high"}
_SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

SYSTEM = ("You are a software supply-chain and legacy-modernization engineer. Use ONLY the evidence JSON. "
          "Return one JSON object: {\"summary\": string (max 3 sentences, plain statement of the main risks), "
          "\"proposals\": [{\"title\", \"action\", \"refs\": [ids/names/files copied exactly from the evidence], "
          "\"target_version\": string or null, \"rationale\", \"risk\": \"low|medium|high\"}]}. "
          "action must be one of " + ", ".join(sorted(ACTIONS)) + ". At most 8 proposals, highest impact first. "
          "Never invent ids, versions, packages, files or numbers. For upgrade use the plan's target version.")


def evidence(rec: Dict[str, Any]) -> Dict[str, Any]:
    vul = sorted(rec.get("vulns") or [], key=lambda v: (-_SEV.get(v["severity"], 0), -(v.get("cvss") or 0), v["package"]))[:12]
    plans = (rec.get("plans") or [])[:12]
    arch = rec.get("arch") or {}
    g = arch.get("graph") or {}
    lic = rec.get("license") or {}
    return {"project": rec.get("name"),
            "totals": {"components": len(rec.get("components") or []), "vulns": len(rec.get("vulns") or [])},
            "vulns": [{"id": v["id"], "package": v["package"], "version": v["version"], "severity": v["severity"],
                       "cvss": v.get("cvss"), "fixed_version": v.get("fixed_version")} for v in vul],
            "plans": [{"component": p["component"], "from": p["current_version"], "to": p.get("safe_version"),
                       "status": p["status"], "major_bump": p.get("major_bump"),
                       "verified_clean": p["verification"].get("clean")} for p in plans],
            "license": {"unresolved": [c["name"] for c in rec.get("components") or [] if not c.get("license")][:12],
                        "policy": [{"category": f["category"], "verdict": f["verdict"], "components": f["components"][:6]}
                                   for f in (lic.get("policy") or [])[:4]],
                        "project_license": lic.get("project_license") or None},
            "architecture": {"hotspots": [h["file"] for h in (arch.get("hotspots") or [])[:5]],
                             "cycles": [c[:4] for c in (g.get("cycles") or [])[:3]],
                             "runtime_eol": ["%s %s" % (r["product"], r["cycle"]) for r in (arch.get("runtime_eol") or [])
                                             if r.get("status") == "eol"][:4],
                             "extraction_candidates": [c["domain"] for c in (arch.get("clusters") or [])
                                                       if c.get("extraction_candidate")][:4]}}


def allowed_refs(ev: Dict[str, Any], rec: Dict[str, Any]) -> Set[str]:
    ids: Set[str] = set()
    for v in rec.get("vulns") or []:
        ids.add(v["id"])
        ids.update(v.get("aliases") or [])
        ids.add(v["package"].lower())
    ids.update(c["name"].lower() for c in rec.get("components") or [])
    a = ev["architecture"]
    for h in a["hotspots"]:
        ids.add(h)
    for c in a["cycles"]:
        ids.update(c)
    for r in a["runtime_eol"]:
        ids.add(r)
        ids.add(r.split()[0])
    ids.update(a["extraction_candidates"])
    # evidence anchors that a model legitimately cites alongside entities: versions that occur in the plans/findings, the project
    # name, the evidence section names, license categories and the license ids present in the SBOM (measured on real EXAONE
    # answers: ~half of the "semantic" drops were refs like ['4.0.5', '4.7.10'] or ['vulns'], not invented entities)
    for p in rec.get("plans") or []:
        ids.update(str(x).lower() for x in (p.get("current_version"), p.get("safe_version")) if x)
    for v in rec.get("vulns") or []:
        ids.add(str(v["version"]).lower())
        ids.update(str(x).lower() for x in v.get("fixed_candidates") or [])
    ids.add(str(rec.get("name") or "").lower())
    ids.update(SECTION_REFS)
    ids.update(LICENSE_CATEGORIES)
    ids.update(c["license"].lower() for c in rec.get("components") or [] if c.get("license"))
    ids.discard("")
    return ids


SECTION_REFS = {"vulns", "totals", "plans", "license", "architecture", "hotspots", "cycles", "runtime_eol", "extraction_candidates",
                "unresolved", "policy", "components"}
LICENSE_CATEGORIES = {"permissive", "public-domain", "weak-copyleft", "strong-copyleft", "network-copyleft", "restricted", "unknown"}


def _repair_refs(title: str, refs: List[str], entities: Set[str]) -> Tuple[List[str], bool]:
    """If no ref names an entity, bind the proposal to the ONE evidence component its own title names (re-validated afterwards)."""
    if any(r.split("@")[0].lower() in entities for r in refs):
        return refs, False
    low = str(title).lower()
    hits = sorted({e for e in entities if len(e) >= 3 and re.search(r"(?<![\w.-])%s(?![\w-])" % re.escape(e), low)})
    return ([hits[0]] + refs, True) if len(hits) == 1 else (refs, False)


def deterministic(rec: Dict[str, Any], lang: str = "ko") -> List[Dict[str, Any]]:
    ko = lang == "ko"
    out: List[Dict[str, Any]] = []
    for p in (rec.get("plans") or [])[:8]:
        if p["status"] == "upgrade" and p.get("safe_version"):
            clean = p["verification"].get("clean")
            out.append({"title": "%s %s -> %s" % (p["component"], p["current_version"], p["safe_version"]), "action": "upgrade",
                        "refs": [p["component"]], "target_version": p["safe_version"],
                        "rationale": ("OSV 재조회 결과 %s: %d개 취약점 해소%s" % ({True: "후보 버전 깨끗함", False: "후보 버전에 잔여 취약점", None: "후보 미검증"}[clean],
                                                                       len(p["clears"]), " (메이저 업그레이드 - 호환성 검토 필요)" if p["major_bump"] else "")
                                      if ko else "%d advisories cleared (candidate verification: %s)%s" % (len(p["clears"]), clean, "; major bump - check compatibility" if p["major_bump"] else "")),
                        "risk": "high" if p["major_bump"] else "low"})
        else:
            out.append({"title": "%s: %s" % (p["component"], "수정 버전 없음" if ko else "no fixed version known"), "action": "replace",
                        "refs": [p["component"]], "target_version": None,
                        "rationale": "알려진 수정 버전이 없다 - 대체 라이브러리 검토 또는 위험 수용 승인이 필요하다" if ko else "no fixed release exists - evaluate a replacement or document risk acceptance",
                        "risk": "high"})
    unres = [c["name"] for c in rec.get("components") or [] if not c.get("license")]
    if unres:
        out.append({"title": ("라이선스 미식별 %d개 확인" if ko else "identify %d unlicensed components") % len(unres), "action": "review_license",
                    "refs": [u.lower() for u in unres[:8]], "target_version": None,
                    "rationale": "라이선스가 식별되지 않으면 의무 이행 여부를 판단할 수 없다" if ko else "without a license the obligations cannot be assessed",
                    "risk": "medium"})
    arch = rec.get("arch") or {}
    for r in arch.get("runtime_eol") or []:
        if r.get("status") == "eol":
            out.append({"title": "%s %s 런타임 업그레이드" % (r["product"], r["cycle"]) if ko else "upgrade %s %s runtime" % (r["product"], r["cycle"]),
                        "action": "upgrade_runtime", "refs": ["%s %s" % (r["product"], r["cycle"])], "target_version": None,
                        "rationale": "지원 종료(%s) - 보안 수정이 더 이상 나오지 않는다" % r.get("eol_date") if ko else "end of life %s - no further security fixes" % r.get("eol_date"),
                        "risk": "medium"})
    for cyc in ((arch.get("graph") or {}).get("cycles") or [])[:2]:
        out.append({"title": "순환 의존 분리" if ko else "break dependency cycle", "action": "refactor", "refs": cyc[:4], "target_version": None,
                    "rationale": "모듈 순환은 변경 영향 분석과 점진적 교체를 막는다" if ko else "cycles block impact analysis and incremental replacement",
                    "risk": "medium"})
    for c in arch.get("clusters") or []:
        if c.get("extraction_candidate"):
            out.append({"title": "%s 도메인 분리 후보" % c["domain"] if ko else "extraction candidate %s" % c["domain"], "action": "extract_module",
                        "refs": [c["domain"]], "target_version": None,
                        "rationale": "응집도 %s, 유입 의존 %d개로 점진적 분리(strangler) 후보" % (c["cohesion"], c["inbound"]) if ko else "cohesion %s, %d inbound edges" % (c["cohesion"], c["inbound"]),
                        "risk": "low"})
            break
    return out[:14]


def validate(obj: Any, rec: Dict[str, Any], ev: Dict[str, Any]) -> Dict[str, Any]:
    items = obj.get("proposals") if isinstance(obj, dict) else obj
    ids = {x.lower() for x in allowed_refs(ev, rec)}
    plan = {p["component"].lower(): p for p in rec.get("plans") or []}
    unresolved = {c["name"].lower() for c in rec.get("components") or [] if not c.get("license")}
    lic_bad = {x.split("@")[0].lower() for f in (rec.get("license") or {}).get("policy") or [] for x in f.get("components", [])}
    comp_set = {c["name"].lower() for c in rec.get("components") or []}
    entities = comp_set | {v["id"].lower() for v in rec.get("vulns") or []} | {x.lower() for x in ev["architecture"]["hotspots"]} \
        | {x.lower() for x in ev["architecture"]["extraction_candidates"]}
    ok: List[Dict[str, Any]] = []
    repaired = 0
    dropped = {"schema": 0, "rule": 0, "semantic": 0, "cross_field": 0}
    for it in items if isinstance(items, list) else []:
        if not (isinstance(it, dict) and all(k in it for k in ("title", "action", "refs", "rationale"))):
            dropped["schema"] += 1
            continue
        tv = it.get("target_version")
        if (it["action"] not in ACTIONS or not isinstance(it["refs"], list) or not it["refs"] or
                str(it.get("risk", "medium")) not in RISKS or not (tv is None or isinstance(tv, str)) or
                len(str(it["title"])) > 160 or len(str(it["rationale"])) > 600):
            dropped["rule"] += 1
            continue
        refs = [str(r) for r in it["refs"]]
        refs, fixed = _repair_refs(str(it["title"]), refs, entities)
        repaired += 1 if fixed else 0
        if any(r.lower() not in ids and r.split("@")[0].lower() not in ids for r in refs):
            dropped["semantic"] += 1
            continue
        names = [r.split("@")[0].lower() for r in refs]
        act = it["action"]
        bad = False
        if act == "upgrade":
            p = next((plan[n] for n in names if n in plan), None)
            bad = p is None or p["status"] != "upgrade" or (tv is not None and tv != p.get("safe_version"))
        elif act in ("replace", "accept_risk"):
            bad = not any(n in plan and (plan[n]["status"] == "no_fix" or plan[n]["verification"].get("clean") is False) for n in names)
        elif act == "review_license":
            comp_refs = [n for n in names if n in comp_set]
            bad = not comp_refs or not all(n in unresolved or n in lic_bad for n in comp_refs)
        elif act in ("refactor", "extract_module", "upgrade_runtime"):
            bad = any(r.lower() in plan or r.lower() in unresolved for r in refs) and not any("/" in r or " " in r for r in refs)
        if bad:
            dropped["cross_field"] += 1
            continue
        ok.append({"title": clip(it["title"], 160), "action": act, "refs": refs, "target_version": tv,
                   "rationale": clip(it["rationale"], 600), "risk": str(it.get("risk", "medium"))})
    summ = obj.get("summary") if isinstance(obj, dict) else None
    return {"items": ok[:12], "dropped": dropped, "repaired": repaired, "summary": clip(summ, 900) if isinstance(summ, str) else ""}


def _parse_json(text: str) -> Any:
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t)
    try:
        return json.loads(t)
    except ValueError:
        m = re.search(r"\{.*\}", t, re.S)
        if m:
            return json.loads(m.group(0))
        m = re.search(r"\[.*\]", t, re.S)
        if m:
            return json.loads(m.group(0))
        raise


def propose(rec: Dict[str, Any], *, client: Optional[ChatClient] = None, cache_dir: Optional[str] = None,
            use_llm: bool = True, lang: str = "ko") -> Dict[str, Any]:
    ev = evidence(rec)
    prompt = json.dumps(ev, ensure_ascii=False, sort_keys=True)
    sys_prompt = SYSTEM + (" Write title, rationale and summary in Korean." if lang == "ko" else " Write in English.")
    key = hashlib.sha256((PROMPT_VERSION + sys_prompt + prompt).encode()).hexdigest()[:20]
    cpath = os.path.join(cache_dir, "ai_" + key + ".json") if cache_dir else None
    note = ""
    raw: Optional[str] = None
    cached = False
    if cpath and os.path.isfile(cpath):
        try:
            raw = open(cpath, encoding="utf-8").read()
            cached = True
            note = "cached EXAONE response for identical evidence (no new call)"
        except OSError:
            raw = None
    if raw is None and use_llm and client is not None:
        # the router decides (data sovereignty / budget / throttling); a refused route is an honest downgrade with a reason
        reasons: List[str] = []
        budget = getattr(client, "daily_budget", 0) or 0
        ratio = (client.calls_today() / budget) if budget else 1.0
        backend = router.choose_backend(data_class="private" if rec.get("private") else "public",
                                        daily_budget_ratio=ratio, throttled=False, cloud_llm_allowed=client.available,
                                        providers={"primary": "exaone", "fallback": getattr(client, "provider", "") != "exaone" and "azure-openai"},
                                        reasons=reasons)
        if backend == "deterministic":
            note = "router refused the LLM route -> deterministic: " + "; ".join(reasons)
        else:
            try:
                raw = client.complete(sys_prompt, prompt, max_tokens=8192, json_mode=True)    # reasoning tokens count against this
            except LLMUnavailable as exc:
                note = "EXAONE unavailable -> deterministic proposals: " + clip(str(exc), 220)
            except LLMError as exc:
                note = "EXAONE error -> deterministic proposals: " + clip(str(exc), 220)
    elif raw is None:
        note = "use_llm=false" if not use_llm else "no LLM client configured"
    if raw is not None:
        try:
            v = validate(_parse_json(raw), rec, ev)
            if v["items"]:
                if cpath and not cached:                      # cache only responses that survived validation (a truncated or
                    os.makedirs(cache_dir, exist_ok=True)     # invalid answer must never be replayed for identical evidence)
                    with open(cpath, "w", encoding="utf-8") as fh:
                        fh.write(raw)
                return {"source": "exaone", "model": getattr(client, "model", "") if client else "cached", "items": v["items"],
                        "summary": v["summary"], "dropped": v["dropped"], "repaired": v["repaired"], "llm_note": note, "cached": cached,
                        "cache_key": key, "prompt_version": PROMPT_VERSION}
            note = (note + " | " if note else "") + "no proposal survived validation (dropped=%s) -> deterministic" % v["dropped"]
        except (ValueError, TypeError) as exc:
            note = (note + " | " if note else "") + "unparseable EXAONE output -> deterministic: " + type(exc).__name__
    return {"source": "deterministic", "model": "", "items": deterministic(rec, lang), "summary": "", "dropped": {},
            "llm_note": note, "cached": False, "cache_key": key, "prompt_version": PROMPT_VERSION}
