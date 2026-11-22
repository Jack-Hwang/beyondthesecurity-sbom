# BOOK IMPROVEMENT MAP — ai책모음 15권 → 우리 서비스 개선 전수 매핑 (2026-11-22)

규칙: 모든 행은 (a) 이미 구현(AC 인용), (b) 이번 재추론에서 신규 구현(AC 인용), (c) 부분, (d) 기각/비적용 —
둘 중 하나다. 책 제목은 축약했다. 근거는 knowledge_books/ 정제 노트 30개와 evidence/books 원문(12.02M자,
junk≤0.03)이다. "측정이 판정한다" 원칙에 따라 검색 품질 변경은 기준선 재측정을 수반했고 결과는 문서
맨 아래에 있다.

## 1. MCP / 에이전트 연결 (AI Agents with MCP, MCP Engineering Handbook)

| 기법 | 상태 | 근거 |
|---|---|---|
| JSON-RPC 2.0 + initialize 핸드셰이크 + tools/list,tools/call | **구현 (AC-534)** | mcp_server.py stdio, 4도구 |
| 도구 오류는 isError+메시지 (예외 은닉 금지) | **구현 (AC-534)** | 4상태 철학과 동일 |
| stdout 프로토콜 순수성 (배너는 stderr) | **구현 (AC-534)** | serve_stdio |
| **resources/list, resources/read** — "툴=행동, 리소스=카탈로그" | **신규 구현 (AC-545)** | bts://tools/catalog · bts://agent/card · bts://books/notes-index |
| sampling·elicitation (서버→호스트 역방향 요청) | **비적용** | 호스트 통합(IDE/오케스트레이터)이 없다 — 도입 시 G-단계 |
| 원격 MCP 서버 신뢰·전송 보안 | **비적용** | 로컬 stdio만 제공, 원격 서버 없음 |

## 2. 멀티에이전트 / A2A (Building Agentic AI Systems, Illustrated Guide)

| 기법 | 상태 | 근거 |
|---|---|---|
| Agent Card 발견(discovery) | **구현 (AC-535)** | /api/agent-card 7스킬·게이트 자기 서술 |
| 오케스트레이터 상태 소유 + 서브에이전트 명시 전달(비상속) | **구현** | council + handoff.v1 (AC-517) |
| 멤버 다수 + 결정론 집계 (self-consistency의 도메인형) | **구현** | council 3멤버 verdict |
| 실패 서브에이전트의 부분 결과+갭 주석 | **구현** | error envelope warning/recoverable/fatal |
| A2A 작업 수명주기(task submit→artifact) | **부분** | job+EventBus가 job 단위 수명주기 — 표준 A2A 와이어는 미도입(수요 측정 후) |
| sub-agent 격리 실행 프로세스 | **기각** | 단일 프로세스 도구 — 프로세스 분리는 capacity.md 스케일 축 문서화 |

## 3. SDD (Spec-Driven Development, AI-Native SWE)

| 기법 | 상태 | 근거 |
|---|---|---|
| specify→plan→tasks→implement 산출물의 기계 소비 | **구현** | spec(AC)+speclint trace+briefs |
| 프로젝트 헌법(constitution) | **구현** | ADR 체계(ADR-0007 stdlib 전용 등) + doclint |
| 명세↔구현 불일치의 기계 검출 | **구현** | speclint 양방향 AC↔테스트 trace (missing/extra) |
| AC의 측정 가능 동사(n-of-n 관례) | **구현** | speclint.lint |
| 책의 SDD 도구(/specify 등 슬래시 워크플로) 도입 | **기각** | 동일 기능이 이미 speclint+briefs로 존재 — 도구 이중화 회피 |

## 4. RAG / 컨텍스트 (Illustrated Guide, LLM Design Patterns)

| 기법 | 상태 | 근거 |
|---|---|---|
| lost-in-the-middle: 관련도 순 재배열 | **신규 구현 (AC-536)** | chat.order_passages_for_prompt |
| 컨텍스트 예산 + 절삭 보고 (조용한 손실 금지) | **신규 구현 (AC-544)** | llm_note "N of M passages (K trimmed)" |
| 하이브리드 검색(RRF) + 동의어 확장 + 종류 필터 | **구현** | rag.py (기준선 recall 1.0) |
| 리랭커 | **기각 (ADR-0016)** | 3변형 실측 후 기각 — 책도 "측정 전 도입 금지" 원칙 |
| 원문·노트·평가 코퍼스 3분리 | **구현 (ADR-0021)** | books 2계층 + eval 격리 실측 |
| HyDE, multi-query 분해 | **기각 (근거 0)** | 15권 원문 그리핑에서 언급 0건 — 책 기반 도입 아님 |
| 컨텍스트 회전(context rot) 완화: 근거 없는 첨부 금지 | **구현** | verified claims만 답변으로 |

## 5. 챗봇 / 루프·하니스 (Loop Engineering, Harness Engineering)

| 기법 | 상태 | 근거 |
|---|---|---|
| 자기교정 루프: 실패 원인 첨부 + 상한 + 동일오류 중단 | **신규 구현 (AC-543, 답변 레인)** | nl2sql(AC-512)의 루프를 LLM 답변에 확장 — 1회 재시도, 거절 사유 프롬프트 첨부 |
| 구조화 출력 실패의 결정론 폴백 | **구현** | json_mode + verify_claims + 추출 폴백 |
| 7종 이벤트 스트리밍 + HITL 승인 | **구현 (AC-517~520)** | chat_stream + awaiting_approval |
| 컴팩션(계층 요약) | **부분** | 목록 캡+trimmed 보고(AC-505~506)만 — 대화 이력 요약은 세션 장기화 수요 시 |
| 회로차단기·4상태 외부호출 보고 | **구현 (AC-301~315)** | resilience.py |

## 6. 품질·평가 (AI Agents Definitive Guide, Code Complete)

| 기법 | 상태 | 근거 |
|---|---|---|
| 코드 계산 품질 게이트 (LLM-as-judge 회피) | **구현 (AC-481~485)** | TOP10 스코어카드 전부 코드 계산 |
| 결정론 골든셋 + 실측 이중 평가 | **구현** | evalrag/evalchat/evallicense + live scorecard |
| 배포 가능성 세트(빌드·스캔·프로브·롤백) | **구현 (AC-514~516, 521)** | 게이트+RUNBOOK+capacity.md |

## 7. 파인튜닝 / GraphRAG / 기타

| 기법 | 상태 | 근거 |
|---|---|---|
| 파인튜닝 | **비적용** | API-only 환경 (Fine-Tuning AI의 "마지막 수단" 원칙과도 일치) |
| GraphRAG (CVE→CPE 그래프) | **기각** | 골든 Recall@5 이미 1.0 — 측정된 필요 없음 (브리프5) |
| KEDA/HPA/AI DBA | **기각** | 단일 프로세스·SQLite 규모 (브리프5) |

## 재추론이 잡아낸 기존 결함 (2026-11-22 2차)

- **"해결책"이 book_search로 오라우팅** (evalchat paraphrase miss): 책 라우팅 정규식의 `책`이 "해결책"의 부분문자열로 매칭 — 뒤어미 제외 `(?<!해결)(?<!대책)(?<!방책)책`으로 수정. 잘못된 도구 호출은 미스보다 나쁘다 (엉뚱한 근거를 준다).
- **`proposals?\b`의 단어경계가 제어바이트(0x08)로 변질**된 기존 손상도 함께 복구 — 이번 세션의 heredoc 사고가 아니라 더 이른 시점의 잔재였다. 정규식 3라인 전부 실측 재검증 (books 영문 라우팅 테스트 복귀, evalchat 오라우팅 해소).

## 이번 재추론 신규 구현의 검증 (2026-11-22)

- AC-543: 첫 답변이 인용 정확도 게이트 미달 → 거절 사유를 프롬프트에 첨부해 1회 재시도, 재거절 시
  추출 폴백+정직 노트 (TRANSPORT 스텁으로 두 경로 모두 테스트).
- AC-544: 신뢰 문서가 6개를 넘으면 "N of M passages (K trimmed)"를 llm_note로 보고.
- AC-545: resources/list 3건, resources/read 각 URI 본문 반환, 미지 URI는 isError+known 목록.
- 기준선 재측정: evalrag/evalchat — chat 경로 변경은 LLM 레인만 건드리므로 결정론 지표 불변이어야 한다.

## 챗봇·에이전트 고도화 — 웹 조사 라운드 (2025-26, AC-546~548)

2025-26 문헌(2026 multi-turn playbook, Rasa, Parlant, arXiv 2507.00355 쿼리 분해·2511.15759 인젝션
방어, Haystack/NVIDIA 분해, Fiddler 가드레일 계층론)에서 도출해 결정론 우선으로 구현한 3축:

| 기법 | 조사 근거 | 상태 |
|---|---|---|
| 다중 턴 대화 기억 + 후속질문 해소 | 2026 multi-turn playbook·Rasa·Parlant | **신규 구현 (AC-546)** — 서버 State 공유 ConversationMemory(3턴), 후속형 질문은 이전 질문을 문맥으로 합쳐 라우팅, 완전한 질문은 재작성 금지 |
| 복합질문 분해 → 도구 병합 | arXiv 2507.00355·Haystack·NVIDIA blueprint | **신규 구현 (AC-547)** — 명시 접속 항상 분해, 조사 분해는 우변 도구 의도로 검증("CVE-X와 관련된…" 미분해) |
| 컨텍스트 계층 인젝션 가드 | Fiddler 가드레일 계층·arXiv 2511.15759 | **신규 구현 (AC-548)** — 도구·검색 텍스트 스캔, attempts+주석 보고, 구조적 방어(validate_calls·신뢰 프롬프트·비신뢰 표기)와 병행 |
| 대화 요약 컴팩션 | 조사 공통 (sliding window+summarization) | **부분** — 3턴 슬라이딩 윈도우만; 장기 세션 요약은 수요 측정 후 |
| 멀티턴 전용 평가 지표(대화 관련성 등) | 조사 공통 | **부분** — followup 플래그로 관측점만; 전용 골든셋은 다음 라운드 |
