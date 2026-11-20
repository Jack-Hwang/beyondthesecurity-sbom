# AI 영향평가서 (AI Impact Assessment) — bts_sbom_app

이 문서는 `bts_sbom_app/ai.py`, `llm.py`, `chat.py`, `actions.py`, `council.py`, `pipeline.py`, `evals.py`, `licenses.py`,
`net.py` 와 README.md 를 읽고 실제로 존재하는 AI 사용만 기술한다. 법률 자문이 아니며, 고영향 AI 여부 판단은 2절에 적은 대로
**자체 평가**다.

## 1. 시스템 개요 (System overview)

`bts_sbom_app` 은 로컬 전용(localhost) SBOM/취약점/라이선스 분석 도구이며, 다음 지점에서 선택적으로(opt-in, API 키 필요) LG
EXAONE(또는 임의의 OpenAI 호환 엔드포인트, 로컬 서버 포함)을 호출한다:

| 모듈 | 호출 함수 | 용도 |
|---|---|---|
| `ai.py` | `ai.propose()` | 업그레이드/교체/라이선스 검토/리팩터링 제안 생성 (4계층 검증, 결정적 강등) |
| `chat.py` | `plan_calls()`(→ `validate_calls()`) | 사용자의 질문에서 어떤 도구를 호출할지 계획(정규식 라우터로도 가능) |
| `actions.py` | (`chat.py` 의 계획을 실행) | 분석/패치/VEX 결정 — 모델은 계획만 하고, 실행은 사용자가 입력한 토큰·코드로만 승인됨 |
| `council.py` | `run_record()` 등 | 식별 안 된 라이선스 문자열에 대한 다중 모델 독립 투표 + 익명 동료 검토 + 의장 선택(제안만, 자동 반영 없음) |
| `loop.py` | `propose_variables()` | 측정된 실패 군집에서 다음 루프 실험 변수 후보 제안 |
| `llm.py` | `ChatClient` | 위 전부가 공유하는 EXAONE/호환 API 클라이언트(일일 호출 예산 원장 포함) |

AI 는 이 제품에서 **무엇도 자동으로 쓰거나 적용하지 않는다** — 분석 결과에 추가되는 "제안"·"계획"·"투표" 필드이며, 디스크에
쓰는 모든 동작(패치 적용, VEX 결정 기록)은 사용자가 직접 입력한 승인 토큰/확인 코드가 있어야 한다(6절).

## 2. 고영향 AI 여부 (High-impact AI determination)

**이 판단은 저자의 자체 평가이며 법률 자문이 아니다** (`bts_sbom_app/conformance.py` 의 규제 적합도 결과가 이미 "Not a
legal assessment" 문구를 붙이는 것과 같은 성격의 면책이다 — spec `BSA-AC-172`, `BSA-AC-227`).

**자체 평가: 낮은 영향(low-impact)으로 본다.** 근거:

- AI 의 출력이 사람의 승인 없이 쓰기 동작(패치 적용, VEX 결정 기록, 전달/푸시)으로 이어지는 경로가 코드에 없다 — 모든 쓰기
  동작은 사용자가 그 세션에서 직접 입력한 16자리 승인 토큰(계획의 다이제스트) 또는 12자리 확인 코드(결정 내용의 다이제스트)를
  요구한다(`actions.py`, spec `BSA-AC-14`, `BSA-AC-15`, `BSA-AC-201`, `BSA-AC-203`, `BSA-AC-204`).
- 규제 적합도 판정(`sectors.py`, `conformance.py`)은 결정적 코드로만 계산되며 AI 를 거치지 않는다. AI 제안(`ai.propose`)의
  "summary" 필드는 사람이 읽는 참고용 텍스트일 뿐, 어떤 적합도 verdict 에도 입력되지 않는다.
- 생체인식, 채용/신용/법집행 결정, 필수 인프라 제어 등 통상 "고영향"으로 분류되는 영역에 해당하지 않는다 — 대상은 소프트웨어
  의존성 메타데이터(패키지명·버전·라이선스 문자열·CVE)이지 개인 데이터가 아니다.

**그럼에도 남는 고려사항**: 이 도구의 산출물(SBOM/VEX/적합도 보고서)은 조직이 CRA·FDA 524B·금융 규제 보고에 사용할 수
있으므로, AI 가 생성한 "summary"·제안 텍스트를 사람이 결정적 수치와 구분하지 않고 그대로 신뢰해 보고서에 옮기면 간접적인
피해가 발생할 수 있다. 이 위험은 4절·5절에서 별도로 다룬다.

## 3. 이해관계자 (Stakeholders)

- **직접 사용자** — `bts-sbom-app scan|patch|chat|serve` 를 로컬에서 실행하는 개발자/보안 담당자. AI 제안·채팅 응답을
  읽고 승인 여부를 결정한다.
- **조직의 보안/컴플라이언스 담당자** — SBOM/VEX/적합도 보고서(결정적 산출물)와 AI 제안(참고용 산출물)을 함께 받는 사람.
  둘을 혼동하지 않아야 한다(2절).
- **분석 대상 저장소의 소유자/업스트림 오픈소스 프로젝트** — 승인된 패치가 작업 사본에 적용되고 `deliver_target` 에 따라
  브랜치/PR 로 전달될 수 있다(패치 자체는 ADR-0008 에 따라 사람 승인 없이는 발생하지 않는다).
- **LG EXAONE / 호환 공급자** — API 호출 시 분석 증거(프로젝트명·취약점·라이선스 등, `ai.evidence()` 가 구성)가 전송되는
  대상. 이 데이터의 공급자 측 보존 정책은 확인하지 못했다(`docs/governance/ORIGIN_LINEAGE.md` 의 "확인 필요" 참고).
- **이 저장소를 읽는 수강생/리뷰어** — 이 문서 자체의 독자.

## 4. 위험 식별 (Risk identification)

| # | 위험 | 구체적 실패 시나리오 |
|---|---|---|
| R1 | 환각(hallucination) | `ai.propose` 가 증거에 없는 컴포넌트 id·버전·파일을 인용 |
| R2 | 검증 우회 | 모델이 허용되지 않은 action/risk 값이나 비정상적으로 긴 텍스트를 반환해 하류 처리에 전달 |
| R3 | 키 노출 | EXAONE API 키가 응답, 로그, 캐시, 에러 메시지에 그대로 노출 |
| R4 | 프롬프트 인젝션 | 저장소의 라이선스 파일·소스 주석에 심어진 지시문이 모델 컨텍스트로 들어가 행동을 바꿈 |
| R5 | 권한 사칭(forged authority) | 모델이 계획한 도구 호출이 사용자가 입력하지 않은 승인 토큰·확인 코드·출처·사유를 스스로 지어냄 |
| R6 | 가용성/비용 폭주 | 재시도나 반복 호출이 공급자의 일일 한도를 소진시키거나 과금을 유발 |
| R7 | 라이선스 위원회 편향 | 모호한 라이선스 판정에서 다수결이 틀린 쪽으로 쏠림(동료 검토 단계의 집단사고) |
| R8 | 회귀 은폐 | 루프 엔지니어링이 반복 재시도로 실제 품질 저하를 "통과"로 둔갑시킴 |
| R9 | 참고용 텍스트의 오용 | AI "summary"/제안 텍스트가 결정적 적합도 verdict 와 구분 없이 규제 보고서에 인용됨(2절의 잔여 고려사항) |

## 5. 완화 조치 (Mitigation)

| 위험 | 완화 | 코드 위치 | AC | 테스트 |
|---|---|---|---|---|
| R1 | 4계층 검증(스키마/규칙/의미/교차필드), 실패 항목은 `dropped` 에 집계 | `bts_sbom_app/ai.py:validate` | BSA-AC-34 | `tests/bts_sbom_app/test_ai_rag_loop.py::test_four_layer_validation_keeps_exactly_one` |
| R2 | 닫힌 action/risk 집합, 길이 상한, ref 존재 확인 | `bts_sbom_app/ai.py:validate` | BSA-AC-34 | 위와 동일 |
| R3 | 키는 응답·로그·캐시·에러에 기록되지 않고 상태 조회는 마지막 4자만 노출 | `bts_sbom_app/server.py`, `bts_sbom_app/llm.py:ChatClient._post` | BSA-AC-216, BSA-AC-217, BSA-AC-218 | `tests/bts_sbom_app/test_server_cli.py::test_api_llm_connects_masks_the_key_and_plans_with_the_llm` |
| R4 | 저장소 텍스트는 전부 신뢰 불가로 표시, 지시문처럼 보이는 파일 플래그 및 CXML 이스케이프; 라이선스 위원회 입력은 JSON 인용된 데이터로만 전달(패키지명도 제외) | `bts_sbom_app/contextpack.py`, `bts_sbom_app/council.py` | BSA-AC-179 | `tests/bts_sbom_app/test_contextpack.py::test_cxml_escapes_repository_text_and_flags_instruction_like_files` |
| R5 | 모델이 제안한 토큰·소스·확인 코드·사유 중 사용자가 그 세션에서 타이핑하지 않은 값은 전부 드롭 | `bts_sbom_app/chat.py:validate_calls` | BSA-AC-203 | `tests/bts_sbom_app/test_chat_actions.py::test_tokens_sources_codes_and_reasons_must_be_the_users_own_text` |
| R6 | 로컬 일일 호출 예산 원장이 공급자보다 먼저 호출을 막음; 일일 한도 429 는 재시도 없이 즉시 강등 | `bts_sbom_app/llm.py:ChatClient._complete` | BSA-AC-33 | `tests/bts_sbom_app/test_ai_rag_loop.py::test_http_429_day_limit_downgrades_after_one_call` |
| R7 | 2/3 이상 동의, 1/3 미만 차점자·기권일 때만 `agreed`; 그 외 `needs_human`/`undetermined`; 결과는 `suggestions`일 뿐 `license` 필드에 자동 반영되지 않음 | `bts_sbom_app/council.py` | (council 모듈 docstring; 44건 수기 사례로 측정, 전용 AC 없음) | `tests/bts_sbom_app/test_council.py` |
| R8 | 회귀 게이트 Δ>=-0.02 미만 하락은 차단, 동일 지표 3회 연속이면 plateau 보고 | `bts_sbom_app/loop.py:gate`, `bts_sbom_app/loop.py:plateau` | BSA-AC-42, BSA-AC-43 | `tests/bts_sbom_app/test_ai_rag_loop.py::test_regression_gate_blocks_drop_over_delta` |
| R9 | 규제 적합도는 결정적 코드로만 계산되고 "Not a legal assessment" 문구를 동반; AI 제안은 별도 `proposals` 필드로 분리되어 SBOM/VEX/conformance 문서에 섞이지 않음 | `bts_sbom_app/conformance.py`, `bts_sbom_app/pipeline.py:run_project`(별도 `rec["conformance"]`/`rec["proposals"]` 필드) | BSA-AC-172, BSA-AC-227 | `tests/bts_sbom_app/test_sbom_conformance.py` |

## 6. 사람 감독 (Human oversight)

- **승인 토큰** — 패치는 `patch.approval_digest()` 가 계산한, 정확히 그 계획의 다이제스트와 일치하는 토큰이 있어야만
  적용된다. 토큰 불일치·미승인은 변경 0건을 보장한다(BSA-AC-14, BSA-AC-15).
- **확인 코드** — VEX 결정은 미리보기 후 그 결정 내용의 다이제스트(12자리)를 사용자가 입력해야 기록된다(BSA-AC-204,
  `bts_sbom_app/actions.py:decision_digest`).
- **읽기 전용 기본값** — `chat` 세션은 기본적으로 쓰기 도구(분석/패치/결정) 없이 시작하며, `--actions`(또는 서버의
  `--chat-actions`)로 명시적으로 켜야 한다(BSA-AC-207).
- **제안·투표는 적용되지 않는다** — `ai.propose`, `council` 의 결과는 어디에도 자동으로 쓰이지 않는 "제안"/"suggestions"
  필드다.
- **루프 수용도 사람의 검토 대상** — `loop.gate` 가 차단하지 않은 패스도 최종 수용 여부는 이 게이트의 수치를 사람이 보고
  판단하는 것을 전제로 하며, 코드가 "루프 패스를 자동으로 제품에 반영"하는 경로는 없다.

## 7. 모니터링 (Monitoring)

- **회귀 게이트 이력** — `loop.run_pass`/`loop.gate` 결과가 `evidence/loop/` 아래 패스별로 기록되어, 시간에 따른 지표
  추이를 사후에 검토할 수 있다.
- **드롭 사유 집계** — `ai.validate` 의 `dropped`(schema/rule/semantic/cross_field 별 건수), `chat.validate_calls` 의
  `dropped`(schema/tool/args/semantic/duplicate/over_limit 별 건수)가 매 응답·증거 파일에 포함되어, 모델 출력이 얼마나
  거부되고 있는지 운영 중에 바로 보인다.
- **호출 계측** — `llm.ChatClient.describe()` 가 `calls_this_run`/`calls_today`/`daily_budget`/`tokens` 를 노출한다.
- **검색/근거성 평가** — `evals.rag_eval`(검색 품질, nDCG@5), `evals.chat_eval`(채팅 근거성·인용 정확도)이 오프라인
  골든셋으로 회귀 없이 반복 측정 가능하다(`run_bts_sbom_app.py evalrag`, CI 의 "Retrieval + chatbot grounding eval" 단계).
- **연결 상태 가시성** — `GET /api/llm` 이 모델명·마스킹된 키 꼬리·연결 여부를 노출해 운영자가 AI 경로가 켜져 있는지 바로
  확인할 수 있다(BSA-AC-216).

## 8. 잔여 위험 (Residual risk)

- README 에 적힌 측정치("10개 GitHub 저장소, 2,478개 컴포넌트, 1,292개 발견, 라이선스 해소율 0.990")는 **표본 내
  수치**이며, 저자가 실제 EXAONE 응답을 보고 검증 규칙을 고친 뒤의 결과다 — 독립적인 held-out 벤치마크가 아니다
  (`docs/governance/MODEL_CARD.md` 4절에 동일하게 명시).
- `ai.validate` 의 의미 계층은 관측된 실제 응답에 맞춰 보강되는 방식(reactive)이라, 아직 보지 못한 새로운 표현은 과도하게
  드롭될 수 있다(안전한 방향의 실패이긴 하다) — `ai._repair_refs` 주석이 이 보강 이력을 그대로 기록하고 있다.
- 로컬 서버(`bts-sbom-app serve`)는 인증이 없다 — README: "no authentication... must stay on localhost". `--chat-actions`
  가 켜진 상태에서 그 포트에 접근할 수 있는 누구나 쓰기 흐름의 1단계(계획 보기)까지는 도달할 수 있다(토큰은 계획을 본
  사람과 같은 접근 권한을 이미 요구하므로 추가 인가 우회는 아니지만, 포트 노출 자체가 전제 조건이다).
- 라이선스 위원회의 합의 임계값(>=2/3 등)은 44건의 수기 사례로 측정된 것이며, 더 큰 모집단에서도 같은 비율로 맞는다는
  보장은 없다.
- 이 문서의 2절("고영향 AI 여부")은 자체 평가이며 법률 자문이 아니다 — 조직이 실제 규제 적용 대상인지는 별도로 법률
  검토가 필요하다.
