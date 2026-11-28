"""AI Impact Assessment export + staleness gate (backlog C85; course week 5 lesson 4: the AI 기본법 duties are proven
by the artifacts a project already produces, and audit response is an EXPORT of those - never a second bookkeeping
track that drifts). Three parts, all offline:

* :func:`assess`    - resolve the live evidence: which control map / eval corpora / escalation health / runbook / spec
                      artifacts exist RIGHT NOW, with measured detail (row counts, composition, version stamps). Every
                      path in the payload is verified to exist before it is listed - the assessment cannot cite a ghost.
* :func:`render`    - the 영향평가서 markdown: the 8 required sections, each evidence as a repo-relative path with its
                      measured note and the AC ids that pin it. A slot with no artifact says 미확인 - never invented.
* :func:`gate`      - the staleness machine-check on the COMMITTED document: all sections present, every backticked
                      repo path still exists, every BSA-AC id still resolves in specs/, the version stamp still matches
                      the package, and each governance gate names evidence or says 미확인 out loud. An artifact that
                      moved or an AC that was renumbered makes the doc rot - this gate is what notices.

The risk classification is declared, with its reasoning: this service INFORMS human supply-chain decisions (scan,
license, patch-PLAN output); effectful actions stay behind explicit approval gates (ENFORCEMENT_MAP rows AC-14/15),
legal judgments and certifications are escalated to humans (escalation.py policy_gap), so it is not a high-risk
automated-decision system - and the assessment says why instead of asserting it.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from . import __version__, evalguard, evals

SCHEMA = "bts-sbom.ai-impact.v1"
DOC_PATH = os.path.join("docs", "AI_IMPACT_ASSESSMENT.md")
SECTIONS = ("용도·대상·사용 맥락", "위험 분류", "데이터 출처", "모델·버전", "통제 매핑", "사전 검증", "모니터링·사람 감독", "거버넌스 6게이트")
GATES = ("Spec", "AI-Review", "Security", "Compliance", "Observability", "Agent Access")
_PATHY = re.compile(r"`((?:bts_sbom_app|tests|docs|evals|specs|scripts|knowledge|evidence|\.github)/[A-Za-z0-9_./\-]+\.(?:py|md|yml|yaml|json|jsonl|toml))`")
_AC = re.compile(r"BSA-AC-(\d{2,4})")
_AC_IN_SPECS = re.compile(r"BSA-AC-(\d{2,4})")


def _jsonl_rows(path: str) -> int:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return sum(1 for ln in fh if ln.strip())
    except OSError:
        return 0


def _evidence(root: str, rel: str, detail: str, acs: Tuple[str, ...] = ()) -> Optional[Dict[str, Any]]:
    """An evidence row only when the path exists - a moved or deleted artifact cannot be cited."""
    p = os.path.join(root, *rel.split("/"))
    if not os.path.exists(p):
        return None
    return {"path": rel, "detail": detail, "acs": list(acs)}


def assess(root: Optional[str] = None) -> Dict[str, Any]:
    """Resolve the live evidence payload (every listed path exists; measured numbers come from the artifacts)."""
    root = root or evals.repo_root()
    rows: List[Dict[str, Any]] = []
    add = lambda rel, detail, acs=(): rows.append(e) if (e := _evidence(root, rel, detail, acs)) else None

    add("bts_sbom_app/escalation.py", "에스컬레이션 3트리거·구조화 인계 페이로드·사람 승인 경계 (정책 공백은 법률·인증 심사로 이관)", ())
    add("docs/ENFORCEMENT_MAP.md", "강제장치 지도: 승인 게이트·원본 무손상·근거 인용 등 통제와 검증 테스트의 1:1 대응표", ())
    add("bts_sbom_app/pii_guard.py", "인계·기록 경로의 개인정보 마스킹", ())
    add("bts_sbom_app/conformance.py", "규제 적합도(NTIA·CRA·TR-03183-2 등): 6개월 지난 검토 표는 '검토 필요'로 정직 표시", ("BSA-AC-210",))

    inv = evals.eval_inventory(root)
    for name, c in sorted(inv["sets"].items()):
        ext = ".jsonl" if name in evalguard.ADVERSARIAL_SETS else ".json"
        k = c["kinds"]
        add("evals/%s%s" % (name, ext), "n=%d, 전형 %d/경계 %d/적대 %d" % (c["n"], k.get("typical", 0), k.get("boundary", 0), k.get("adversarial", 0)), ())
    try:
        reg = json.loads(open(os.path.join(root, "evals", "prompt_registry.json"), encoding="utf-8").read())
        add("evals/prompt_registry.json", "프롬프트 레지스트리: %d개 등록 프롬프트, schema %s" % (len(reg.get("prompts") or []), reg.get("schema")), ())
    except (OSError, ValueError):
        pass

    try:
        from . import escalation_report
        rep = escalation_report.report(os.path.join(root, "evidence"))
        add("bts_sbom_app/escalation_report.py", "에스컬레이션 롤업: status %s, 총 %d건" % (rep.get("status"), (rep.get("totals") or {}).get("all", 0)), ())
    except Exception:
        pass
    add(".github/workflows/nightly-drift.yml", "야간 드리프트 배터리(스캔·평가·구성표·링크·스펙 게이트) - 시계 트리거", ())
    add("docs/RUNBOOK.md", "운영 런북(롤백 절차 포함)", ())
    add("bts_sbom_app/loop.py", "루프 회귀 게이트: 후보가 기준 대비 지표를 깎으면 accept가 아니라 rollback", ("BSA-AC-42",))
    add("bts_sbom_app/speclint.py", "스펙 게이트: AC 없는 표면·미지정 AC를 기계 검출", ())
    add("bts_sbom_app/review.py", "독립 리뷰어: 계획기의 내부 상태 없이 산출물만으로 재검토 (ADR-0012)", ())
    add("bts_sbom_app/chat.py", "도구 호출 검증: 사용자가 실제 입력한 토큰·출처·사유만 수용 (validate_calls)", ("BSA-AC-203",))
    add("bts_sbom_app/actions.py", "효과 동작의 승인·감사 경계 (approval digest, fail-closed 결정)", ("BSA-AC-14", "BSA-AC-15"))
    return {"schema": SCHEMA, "app_version": __version__, "evidence": rows,
            "risk": {"classification": "high-risk 아님 (사람 결정 보조)",
                     "reason": "스캔·라이선스·패치 계획은 사람의 결정을 돕는 증거를 생산한다; 적용은 명시 승인(AC-14/15) 뒤에만, "
                               "법적 판단·인증은 policy_gap 에스컬레이션으로 사람에게 이관하며, 감정·자기신고 신뢰도는 트리거 입력에서 배제한다.",
                     "acs": ["BSA-AC-14", "BSA-AC-15"]}}


def render(payload: Dict[str, Any]) -> str:
    """The assessment markdown - every evidence row with its measured note; no row is invented for an empty slot."""
    ev = payload.get("evidence") or []
    L: List[str] = ["# AI 영향평가서 — bts-sbom", "",
                    "app_version: %s | schema: %s" % (payload.get("app_version"), payload.get("schema")), "",
                    "AI 기본법(2026-01-22 시행) 4대 의무의 증빙은 이 저장소가 이미 생산하는 산출물의 export다 - 감사 시 새로 쓰는 것이 아니라 현행을 가리킨다.",
                    "각 근거는 실제 존재가 확인된 경로와 측정값만 담는다; 없는 칸은 미확인으로 남는다(지어내지 않는다).", ""]
    by = {r["path"]: r for r in ev}
    def _row(rel: str) -> str:
        r = by.get(rel)
        return ("- `%s` — %s%s" % (rel, r["detail"], (" (AC %s)" % ", ".join(r["acs"])) if r.get("acs") else "")) if r else "- 미확인 (기록된 근거 없음)"

    L += ["## 1. 용도·대상·사용 맥락", "",
          "오픈소스 공급망 보안 서비스: 저장소·바이너리 스캔으로 SBOM·취약점·라이선스 증거를 생산하고, 챗 인터페이스로 사람의 "
          "수용 여부 판단(수용/보류/대체)을 돕는다. 대상은 보안·오픈소스 거버넌스 담당자이며, 모든 효과 동작(패치 적용 등)은 "
          "사람 승인 게이트 뒤에 있다.", ""]
    L += ["## 2. 위험 분류", "",
          "- 분류: %s" % payload["risk"]["classification"],
          "- 근거: %s" % payload["risk"]["reason"],
          _row("bts_sbom_app/actions.py"), _row("bts_sbom_app/escalation.py"), ""]
    L += ["## 3. 데이터 출처", "", "- 분석 입력은 사용자가 지정한 로컬 저장소·SBOM이고, 지식 코퍼스와 평가셋은 저장소 안에 버전 고정된다.", ""]
    eval_rows = [_row(rel) for rel in sorted(by) if rel.startswith("evals/")]
    L += eval_rows if eval_rows else ["- 미확인 (기록된 근거 없음)"]
    L.append("")
    L += ["## 4. 모델·버전", "", "- app_version: %s (버전이 바뀌면 이 문서는 스테일로 판정된다)" % payload.get("app_version"),
          _row("evals/prompt_registry.json"),
          "- LLM은 다운그레이드 경로를 가진다: 키·예산·제공자 한도 문제 시 결정적(stdlib) 경로로 정직 강등된다.", ""]
    L += ["## 5. 통제 매핑", "", _row("docs/ENFORCEMENT_MAP.md"), _row("bts_sbom_app/pii_guard.py"), ""]
    L += ["## 6. 사전 검증", "", _row("bts_sbom_app/loop.py"),
          "- 평가셋 구성표(전형/경계/적대)와 누출 검사는 `python -m bts_sbom_app evalsets`로 기계 판정한다.", ""]
    L += ["## 7. 모니터링·사람 감독", "", _row("bts_sbom_app/escalation_report.py"), _row(".github/workflows/nightly-drift.yml"), _row("docs/RUNBOOK.md"), ""]
    L += ["## 8. 거버넌스 6게이트", "", "| 게이트 | 근거 |", "|---|---|",
          "| Spec | `bts_sbom_app/speclint.py` (AC 없는 표면·미지정 AC 기계 검출) |",
          "| AI-Review | `bts_sbom_app/review.py` (독립 리뷰어 — 생성 세션의 내부 상태 없이 재검토) |",
          "| Security | `docs/ENFORCEMENT_MAP.md` + `bts_sbom_app/pii_guard.py` |",
          "| Compliance | 이 문서 + `bts_sbom_app/conformance.py` (규제 적합도, 6개월 스테일 표시) |",
          "| Observability | `bts_sbom_app/escalation_report.py` + `.github/workflows/nightly-drift.yml` |",
          "| Agent Access | `bts_sbom_app/chat.py` validate_calls + `bts_sbom_app/actions.py` 승인 게이트 |", ""]
    L += ["## 스테일니스 게이트", "",
          "이 문서의 모든 역따옴표 경로는 존재해야 하고, 인용된 BSA-AC id는 specs/에 살아 있어야 하며, app_version은 패키지와 일치해야 한다 —",
          "`python -m bts_sbom_app ai-impact --check` 가 기계 판정한다(하나라도 어긋나면 exit 1).", ""]
    return "\n".join(L)


def gate(root: Optional[str] = None, doc_path: Optional[str] = None) -> Dict[str, Any]:
    """Staleness machine-check of the COMMITTED assessment: sections present, every cited repo path exists, every cited
    BSA-AC id resolves in specs/, the version stamp matches the package, and every governance gate row names evidence
    or says 미확인. Findings are named, never aggregated into a bare boolean."""
    root = root or evals.repo_root()
    doc = doc_path or os.path.join(root, DOC_PATH)
    findings: List[str] = []
    if not os.path.exists(doc):
        return {"schema": SCHEMA, "ok": False, "findings": ["assessment document missing: %s" % DOC_PATH]}
    text = open(doc, encoding="utf-8", errors="replace").read()
    for s in SECTIONS:
        if not re.search(r"^## (?:\d+\. )?%s\s*$" % re.escape(s), text, re.M):
            findings.append("required section missing: %s" % s)
    for m in _PATHY.finditer(text):
        rel = m.group(1)
        if not os.path.exists(os.path.join(root, *rel.replace("\\", "/").split("/"))):
            findings.append("cited artifact is gone (stale): %s" % rel)
    specs = os.path.join(root, "specs", "bts_sbom_app_features.md")
    live = set()
    try:
        live = set(_AC_IN_SPECS.findall(open(specs, encoding="utf-8", errors="replace").read()))
    except OSError:
        findings.append("specs file missing: specs/bts_sbom_app_features.md")
    for m in _AC.finditer(text):
        if m.group(1) not in live:
            findings.append("cited AC BSA-AC-%s resolves to nothing in specs/ (stale or renumbered)" % m.group(1))
    m = re.search(r"^app_version:\s*(\S+)", text, re.M)
    if not m:
        findings.append("version stamp missing (app_version:)")
    elif m.group(1) != __version__:
        findings.append("version stamp %s != package %s - the assessment predates the current release" % (m.group(1), __version__))
    gates_block = text.split("## 8.")[1] if "## 8." in text else ""
    for g in GATES:
        row = [ln for ln in gates_block.splitlines() if ln.startswith("| %s |" % g)]
        if not row:
            findings.append("governance gate row missing: %s" % g)
        elif "미확인" not in row[0] and not _PATHY.search(row[0]):
            findings.append("governance gate %s names no evidence and does not say 미확인" % g)
    return {"schema": SCHEMA, "ok": not findings, "findings": findings}
