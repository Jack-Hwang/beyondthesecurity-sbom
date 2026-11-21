# AI 영향평가서 (AI Impact Assessment) — BTS-SBOM

**자체 평가(self-assessment)이며 법률 자문이 아니다.** 첫 문단 명시: 이 문서는 저장소 코드·테스트를 직접 읽고 쓴
자기 평가이고, EU AI Act 등 규제의 법적 판단을 대신하지 않는다. 근거는 파일 경로·AC·테스트로 연결한다(존재하는 것만).

## 시스템 개요

BTS-SBOM 은 분석 대상 저장소의 SBOM·라이선스·취약점을 수집하고, 승인형 패치 계획을 만들고, 근거가 있는 챗 답변을 제공하는
표준 라이브러리 전용 파이썬 도구다(`bts_sbom_app/pipeline.py`). AI(EXAONE)는 세 곳에서만 쓰인다:
1. **제안(proposals)**: `ai.propose` — 증거의 구조적 사실만 전송하고, 검증 4계층을 통과한 답만 채택(실패 시 결정적 강등).
2. **챗 도구 계획**: `chat.plan_tools` — 어떤 도구를 부를지 결정(도구 인자는 질문에 있어야 하고 `validate_calls` 가 검증).
3. **라이선스 위원회**: `council.py` — 라이선스 판정의 참고 의견(사람이 최종 결정).

## 고영향 AI 여부 (판단과 근거)

**아니다 — 결정 지원(assistive)이며, 사람 승인 게이트가 있다.** 근거: ① 도구가 자동으로 수행하는 "위험한" 행위는
사람 승인 토큰 없이는 0 건(`patch.apply`, AC-14/15), ② AI 제안은 검증 4계층을 통과해야 채택되고(AC-34), ③ 모든 통과
판정은 코드로 계산되며 AI 는 근거 인용·요약만 돕는다. 이는 자체 판단이며 규제 분류의 법적 결론이 아니다.

## 이해관계자

- 분석 수행자(개발자·보안 담당): 챗·제안·패치 계획의 수요자.
- 승인자: 패치 적용·VEX 결정의 사람 게이트(클라우드 모드에서는 신원 기록, AC-447).
- 분석 대상 저장소 소유자: 원본 불변 계약의 보호 대상(AC-1).
- 정보원(OSV·deps.dev·레지스트리)과 LLM 제공사(LG EXAONE): 외부 데이터·서비스 제공자.

## 위험 식별과 완화

| 위험 | 완화(코드 위치·AC·테스트) |
|---|---|
| 환각(없는 권고·버전) | 검증 4계층 `ai.validate` (AC-34, test_ai_rag_loop::test_four_layer_validation_keeps_exactly_one) |
| 검증 우회(429를 성공으로 보고) | 결정적 강등 + 사유 기록 (AC-33, test_ai_rag_loop::test_http_429_day_limit_downgrades_after_one_call) |
| 키 노출 | 키 미반환·저장 파일 0600·gitignore (AC-216, AC-425~428, test_secret_hygiene.py) |
| 프롬프트 주입 | 결정적 입력 필터 + 권고 본문 표식 (AC-551~554, test_guardrail.py) |
| 클라우드 노출(공개 주소·로컬 경로·SSRF) | 클라우드 모드 스위치 + 소스 정책 (AC-465~470, AC-453~460, test_cloud_mode.py·test_source_policy.py) |
| 외부 LLM 전송(데이터 주권) | 기본 꺼짐 + 전송 미리보기 `GET /api/llm/outbound/<project>` + 라우터(사유 기록) (AC-541~549) |
| 분석 대상 변조 | 워크 복사본·원본 해시 불변 (AC-1, test_patch_delivery.py) |
| 감사 불가 | 감사 해시 체인 + 승인자 신원 (AC-448~449, AC-447) |

## 사람 감독 (human oversight)

- 패치: 16자리 다이제스트 토큰(사람이 플랜 검토 후 전달) — `patch.py` (AC-14/15).
- VEX 결정: 12자리 확인 코드 + 5개 상태 단어만 허용 — `console.valid_triage`.
- 클라우드 모드: 쓰기 동작은 신원 없으면 거부(AC-446), 신원은 `approved_by`·감사 줄에 기록(AC-447).
- 챗의 쓰기 도구는 `--chat-actions` 로 시작한 세션에서만(AC-207).

## 모니터링

- 루프 게이트(`loop.gate`, 회귀 ≥ -0.02), `evidence/loop/` 패스 기록(AC-43/44).
- evalrag/evalchat 지표(specs 고정, `run_bts_sbom_app.py`).
- `/metrics`(요청·작업·net 통계, AC-521~528), 감사 로그 `<evidence>/audit.jsonl`(해시 체인, AC-449).

## 잔여 위험

- 권고 본문(공개 DB 텍스트)의 우회 문장이 정확히 RAG 동의어와 겹치면 인용될 수 있다(가져온 테스트가 known_gap 3개로 문서화 — test_method_chat_redteam_injection.py).
- 클라우드 모드 소스 정책의 DNS TOCTOU 창(ADR-0018).
- Azure App Service 영속 저장소 동작은 미검증(ADR-0019 "확인 필요").
- AI 영향평가서 자체는 자기 평가다 — 제3자 검증 없음.
