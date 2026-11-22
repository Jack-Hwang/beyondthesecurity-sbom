# 강의 방법론 -> BTS-SBOM 구현 매핑 (정직 판)

심화과정 1~2주차 6개 교안의 라운드별 분석·적용 결과는 `docs/METANET_ADVANCED_MAPPING.md` 에 기록된다.

출처: `강의자료/` 분석 결과(`knowledge/lecture/`)에서 도출한 기법을 실제로 구현했는지, 하지 않았다면 이유가 무엇인지 기록한다.
"구현"은 테스트와 측정값이 있는 것만 뜻한다.

| 기법 (강의 출처) | 상태 | 어디에 / 측정 |
|---|---|---|
| BM25 + TF-IDF -> RRF 융합, k=60 (HybridSearch_고급RAG) | 구현 | `rag.Index.search`, 골든 20문항 |
| 헤딩 인식 청킹 + 문맥 헤더 | 구현 | `rag.chunk_markdown` (섹션 경로가 청크 본문에 포함) |
| 쿼리 변환(동의어 확장) + 메타데이터 필터 | 구현 | `rag.SYNONYMS`, `filters={"kind": ...}` |
| 검색 지표 vs 생성 지표 분리, nDCG@5 | 구현 | `evals.rag_eval`(검색) / `evals.chat_eval`(근거성), AC-38~41 |
| 근거 없으면 `found=false` | 구현 | 신뢰도 게이트(`min_bm25`, `min_cover`), 범위 밖 5/5 거절 |
| claim-quote-source, 인용 포인터 검증(이번 검색 결과에 실재) | 구현 | `chat.verify_claims`: 이번 질문의 문서 집합에 없는 source 는 거절 (AC-40, AC-41) |
| 검증 4계층(스키마/규칙/의미/교차필드) | 구현 | `ai.validate`, AC-34 |
| 정직한 강등(LLM 불가 -> 결정적, 원인 기록) | 구현 | `ai.propose`, AC-33 |
| 프롬프트 버전 관리 | 구현 | `ai.PROMPT_VERSION`, 캐시 키에 포함 |
| 응답 캐시(호출 한도 보호) | 구현 | 프롬프트 해시 캐시 + 로컬 일일 장부, AC-35/36 |
| 회귀 게이트 Δ >= -0.02, 골든셋, 한 번에 한 변수 | 구현 | `loop.gate`, `loop.run_pass`, 패스 기록 `evidence/loop/` |
| 회귀율(개별 케이스 통과→실패, 2주차 1차시 정의) | 구현 | `loop.case_regressions` + `run_rag_pass` 차단: 평균이 평평해도 개별 질의 회귀는 롤백 (BSA-AC-496..500, ADR-0018) |
| 공회전(spinning) 탐지 | 구현 | 패치 계획 반복 시 중단, 최근 3패스 동일 지표 시 plateau (AC-43) |
| EARS + 측정값 AC, 린트, 양방향 추적 | 구현 | `specs/`, `bts_sbom_app.speclint`, `tests/test_specs.py` |
| 실패 군집화로 다음 변수 선택 | 구현 | `loop.cluster_failures`, EXAONE 가설은 실제 군집만 채택 (AC-44) |
| 툴 출력 트림 + trim 로그 | 구현 | `ai.evidence` `trimmed` 블록: 잘린 행 수를 프롬프트 안에서 보고 (BSA-AC-505..506, ADR-0019) |
| 계층(parent-child) 청킹 | **미구현** | 코퍼스가 작고(수백 청크) 골든 Recall@5 가 이미 높아 측정된 필요가 없었다. 라이선스 전문을 코퍼스에 넣을 때 재검토 |
| 리랭킹 | **측정 후 기각(관측만 유지)** | 3개 재정렬 변형 전부 게이트 실패(dev recall -0.067, OOD 1.0→0.8, 풀최고 BM25 게이트는 범위 밖 질의 통과). `lex` 정밀 신호는 주석으로만 보고 — 순서 불변 (BSA-AC-486..490, ADR-0016) |
| 정보원 상충 로그(`conflicts`) | 구현 | `rag.conflicts` + 챗 답변 `[conflict]` 주석: 같은 라벨 다른 수치 × 다른 출처 → rule=escalate, unresolved (BSA-AC-491..495, ADR-0017) |
| 형식 오류만 재시도, 정보 부재는 null | **미구현** | EXAONE 일일 한도 때문에 호출당 1회 + 결정적 강등을 택했다 |
| LLM-as-judge 의 Cohen's κ 보정 | 해당 없음 | 판정 모델을 쓰지 않는다(근거성은 코드로 계산) |
| Batches API (50% 비용) | 적용 불가 | EXAONE 은 동기 OpenAI 호환 API 뿐 |
| LoRA 파인튜닝 | 적용 불가 | API 호출만 가능 |
| 요구 6분류 태깅(SFR/DAR/PER/SIR/SECR/CONR) | 구현 | `speclint.reqmap` + speclint 출력 `REQ-KINDS` 줄: 359 AC 태깅(SFR=185 DAR=58 PER=3 SIR=75 SECR=32 CONR=6), 정보성 (BSA-AC-501..504, ADR-0019) |
| 서킷브레이커 3상태 + "없음의 4상태" (3주차 1·2차시) | 구현 | `resilience.py`, `net.fetch_json`, AC-301~315. 기존 호출부는 아직 래퍼를 써서 4상태를 따로 보고하지 않음 |
| 회귀 4분면 + 독립 리뷰 (3주차 3차시) | 구현 | `impact.py`, `review.py`, AC-316~335. 패치 루프에서는 fleet 부분이 항상 unverified |
| SSE 이벤트 스키마 + 발행 전 승인 이벤트 (4주차 3차시) | 구현 | `events.py`, `/api/jobs/<id>/events`, AC-336~357 |
| 프로브 3종·비루트·런북 4블록 (4주차 1·2차시) | 부분 | `/healthz`, `/readyz`, Dockerfile 정적 정책, `docs/RUNBOOK.md`. 실제 `docker build` 는 미실행, startup 프로브 없음 |
| ADR(기각 대안 필수)·영향평가서·model card·강제장치 지도 (1·5·6주차) | 구현 | `docs/adr/`, `docs/governance/`, `docs/ENFORCEMENT_MAP.md`, `doclint.py`, AC-361~380 |
| 추적성 매트릭스·증거 사이드카·포트폴리오 export | 구현 | `traceability.py`, `portfolio.py`, AC-381~400 |
| NL2SQL 가드 (3주차 2차시) | 구현 | `nl2sql.py`: 토크나이저 검증기 + 읽기전용 URI/query_only + 4상태 실행기 + 오류 첨부 자기교정 + EX 골든 30문항, AC-510~513 (2026-11-22, 브리프 5) |
| coordinator-subagent 재구조화 | **미구현** | 구조 변경 이득 불명 — 유지 (브리프 5 재평가와 동일 결론) |
| 오류 봉투·핸드오프·챗 SSE 7종·HITL (4주차 3차시) | 구현 | `handoff.py`, `chat_stream.py`, `POST /api/chat/stream`, 웹 단계 스트림 패널, AC-517~520 (2026-11-22, 브리프 5) |
| 공급망 게이트: 빌드→Trivy→SBOM→벤치 (4주차 1차시) | 구현 | `scripts/supply_chain_gate.py` — 첫 docker build 50.61 s, Trivy CRITICAL 0, 이미지 CycloneDX 122 컴포넌트, `/healthz` p50 0.54 ms·p95 18.11 ms, 컨테이너 HEALTHCHECK healthy, AC-514~516 (2026-11-22, 브리프 5) |
| SLO·용량 산정 근거 수식 (4주차 2차시) | 구현 | `docs/capacity.md` — 실측 원본 표 + Little's Law/처리량 수식, 미측정 항목은 "미측정"으로 명시 (2026-11-22, 브리프 5) |
| TOP10 답변 품질 게이트 (별첨 1) | 구현 | `quality.py` — 근거성 1.0·관련성 0.359·완결성 1.0·툴정확도 1.0·과잉거절 0.0 전 게이트 통과, AC-481~485 (2026-11-22, 브리프 5) |
| kind 매니페스트·롤백/프로브 계승 (4주차 2차시, G1) | 산출만 | `deploy/kind/` — 단일 노드용 Namespace+PVC+Deployment(replicas 1·Recreate·readiness /readyz)+Service(ClusterIP), kubectl client dry-run 파싱 통과·미배포(kind 부재), AC-522 (2026-11-22, 브리프 5) |
| ai책모음 15권 기법 통합: MCP 서버·A2A Agent Card·lost-in-the-middle (사용자 서재) | 구현 | `mcp_server.py`(stdio JSON-RPC 4도구), `/api/agent-card`(7스킬·게이트 선언), `chat.order_passages_for_prompt` — 정제 노트 30개(knowledge_books/), RAG 기준선 불변 실측, AC-534~536 (2026-11-22) |
| LLM·RAG·파인튜닝·에이전트 아키텍처 해설 (별첨 2) | 부분 | 이 표 상단의 회로차단기·SSE·검증된 인용 등으로 이미 반영; AI DBA·KEDA·LoRA·GraphRAG는 기각 (`docs/GLM_IMPLEMENTATION_BRIEF_5.md` 매핑표) |

저작권 메모: `knowledge/lecture/` 는 강의 내용을 **의역·요약**한 것이며 슬라이드 원문을 옮기지 않았다. 레포를 공개하기 전에
수강 약관/출처 표기 정책을 확인하고, 필요하면 해당 폴더를 제외하라.
