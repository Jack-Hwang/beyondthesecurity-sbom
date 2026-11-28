# AI 영향평가서 — bts-sbom

app_version: 0.6.0 | schema: bts-sbom.ai-impact.v1

AI 기본법(2026-01-22 시행) 4대 의무의 증빙은 이 저장소가 이미 생산하는 산출물의 export다 - 감사 시 새로 쓰는 것이 아니라 현행을 가리킨다.
각 근거는 실제 존재가 확인된 경로와 측정값만 담는다; 없는 칸은 미확인으로 남는다(지어내지 않는다).

## 1. 용도·대상·사용 맥락

오픈소스 공급망 보안 서비스: 저장소·바이너리 스캔으로 SBOM·취약점·라이선스 증거를 생산하고, 챗 인터페이스로 사람의 수용 여부 판단(수용/보류/대체)을 돕는다. 대상은 보안·오픈소스 거버넌스 담당자이며, 모든 효과 동작(패치 적용 등)은 사람 승인 게이트 뒤에 있다.

## 2. 위험 분류

- 분류: high-risk 아님 (사람 결정 보조)
- 근거: 스캔·라이선스·패치 계획은 사람의 결정을 돕는 증거를 생산한다; 적용은 명시 승인(AC-14/15) 뒤에만, 법적 판단·인증은 policy_gap 에스컬레이션으로 사람에게 이관하며, 감정·자기신고 신뢰도는 트리거 입력에서 배제한다.
- `bts_sbom_app/actions.py` — 효과 동작의 승인·감사 경계 (approval digest, fail-closed 결정) (AC BSA-AC-14, BSA-AC-15)
- `bts_sbom_app/escalation.py` — 에스컬레이션 3트리거·구조화 인계 페이로드·사람 승인 경계 (정책 공백은 법률·인증 심사로 이관)

## 3. 데이터 출처

- 분석 입력은 사용자가 지정한 로컬 저장소·SBOM이고, 지식 코퍼스와 평가셋은 저장소 안에 버전 고정된다.

- `evals/chat_features.json` — n=27, 전형 27/경계 0/적대 0
- `evals/injection_holdout.jsonl` — n=46, 전형 24/경계 0/적대 22
- `evals/injection_samples.jsonl` — n=50, 전형 25/경계 0/적대 25
- `evals/prompt_registry.json` — 프롬프트 레지스트리: 15개 등록 프롬프트, schema 1
- `evals/rag_dev.json` — n=20, 전형 15/경계 5/적대 0
- `evals/rag_golden.json` — n=25, 전형 20/경계 5/적대 0
- `evals/rag_test.json` — n=16, 전형 12/경계 4/적대 0

## 4. 모델·버전

- app_version: 0.6.0 (버전이 바뀌면 이 문서는 스테일로 판정된다)
- `evals/prompt_registry.json` — 프롬프트 레지스트리: 15개 등록 프롬프트, schema 1
- LLM은 다운그레이드 경로를 가진다: 키·예산·제공자 한도 문제 시 결정적(stdlib) 경로로 정직 강등된다.

## 5. 통제 매핑

- `docs/ENFORCEMENT_MAP.md` — 강제장치 지도: 승인 게이트·원본 무손상·근거 인용 등 통제와 검증 테스트의 1:1 대응표
- `bts_sbom_app/pii_guard.py` — 인계·기록 경로의 개인정보 마스킹

## 6. 사전 검증

- `bts_sbom_app/loop.py` — 루프 회귀 게이트: 후보가 기준 대비 지표를 깎으면 accept가 아니라 rollback (AC BSA-AC-42)
- 평가셋 구성표(전형/경계/적대)와 누출 검사는 `python -m bts_sbom_app evalsets`로 기계 판정한다.

## 7. 모니터링·사람 감독

- `bts_sbom_app/escalation_report.py` — 에스컬레이션 롤업: status no_data, 총 0건
- `.github/workflows/nightly-drift.yml` — 야간 드리프트 배터리(스캔·평가·구성표·링크·스펙 게이트) - 시계 트리거
- `docs/RUNBOOK.md` — 운영 런북(롤백 절차 포함)

## 8. 거버넌스 6게이트

| 게이트 | 근거 |
|---|---|
| Spec | `bts_sbom_app/speclint.py` (AC 없는 표면·미지정 AC 기계 검출) |
| AI-Review | `bts_sbom_app/review.py` (독립 리뷰어 — 생성 세션의 내부 상태 없이 재검토) |
| Security | `docs/ENFORCEMENT_MAP.md` + `bts_sbom_app/pii_guard.py` |
| Compliance | 이 문서 + `bts_sbom_app/conformance.py` (규제 적합도, 6개월 스테일 표시) |
| Observability | `bts_sbom_app/escalation_report.py` + `.github/workflows/nightly-drift.yml` |
| Agent Access | `bts_sbom_app/chat.py` validate_calls + `bts_sbom_app/actions.py` 승인 게이트 |

## 스테일니스 게이트

이 문서의 모든 역따옴표 경로는 존재해야 하고, 인용된 BSA-AC id는 specs/에 살아 있어야 하며, app_version은 패키지와 일치해야 한다 —
`python -m bts_sbom_app ai-impact --check` 가 기계 판정한다(하나라도 어긋나면 exit 1).
