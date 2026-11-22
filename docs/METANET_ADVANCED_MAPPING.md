# 메타넷 심화과정 → BTS-SBOM 적용 맵 — 라운드 1 (1~2주차 6교안, 2026-11-22)

심화과정 1주차 1~3차시, 2주차 1~3차시의 전체 내용을 교안별로 추론 분석하고, 이 저장소에 실제로 적용한 것 /
이미 구현되어 있던 것 / 측정 후 기각한 것 / 적용하지 않은 것과 그 근거를 기록한다. "구현"은 테스트와 측정값이 있는
것만 뜻한다. 상태 갱신은 `docs/LECTURE_MAPPING.md` 의 해당 행과 함께 유지한다. 라운드 2(3주차 이후 교안)는 이
문서에 섹션을 추가하는 방식으로 기록한다.

이번 라운드 산출물: AC 486~509 (24건, `tests/bts_sbom_app/test_lecture_round1.py` 24 tests), ADR-0016~0019,
UI 채팅 답변 렌더러(근거 칩·라우팅·상충 노트), speclint `REQ-KINDS` 리포트.

---

## 1주차 1차시 — VM·App Services + OpenAI 통합 아키텍처 설계

| 교안 개념 | 상태 | 어디에 / 근거 |
|---|---|---|
| 6계층 참조 아키텍처(표현/애플리케이션/오케스트레이션/모델/데이터/운영) | 이미 구현 | `docs/ARCHITECTURE.md`, `server.py`(표현+API), `chat.py`(오케스트레이션), `rag.py`(데이터), `events.py`·RUNBOOK(운영) |
| 에이전틱 5대 결정(자율성·실행루프·작업구조·상태·신뢰성) | 이미 구현 | 자율성=툴 카탈로그 3계층(읽기/승인/쓰기), 루프=MAX_CALLS 4 + 검증 게이트, 신뢰성=`resilience.py` 서킷브레이커·4상태 (AC-301~315) |
| 종료 5종(end_turn·오류임계·예산·정지신호·공회전) | 이미 구현 | `loop.plateau`(공회전, AC-43), llm 일일 예산 장부(예산 소진), 스키마 실패 강등(오류임계) |
| 오류 4분류(도구-일시/도구-영구/추론/침묵실패) | 이미 구현 | `resilience.py` 백오프+서킷브레이커, 429 1회 후 강격(AC-33), `loop.gate` 침묵실패=미지원 지표는 undecidable |
| Well-Architected 5기둥 점검표 | 문서 수준 해당 | 이 문서의 ADR·측정 관행이 근거 기록을 대신함 — 별도 점검표는 미도입(중복 문서 방지) |
| ADR 템플릿(기각 대안 필수) | 이미 구현 | `docs/adr/` 0007~0019 전부 기각 대안 절 포함, doclint 검사 대상 아님(관행 강제) |
| APIM AI 게이트웨이·다중 리전 분산 | 적용 불가 | 단일 프로세스 stdlib 서버, 클라우드 인프라 계층 없음. llm 호출 한도 장부(AC-35/36)가 예산 게이트 역할 |

## 1주차 2차시 — Container+App Services AI 챗봇 구현

| 교안 개념 | 상태 | 어디에 / 근거 |
|---|---|---|
| stop_reason 기반 툴 루프, 종료 신호 안티패턴 금지 | 이미 구현 | `chat.plan_tools` JSON 플랜 + `validate_calls` 4계층(AC-93~96) — 응답 문구·블록 유무로 종료 판정하지 않음 |
| 공회전 감지(같은 호출·같은 결과 반복 → 런타임이 끊음) | 이미 구현 | `validate_calls` duplicate 버킷 + `loop.plateau` 3패스 동일 지표(AC-43). 이번 라운드 재검토: 챗 루프는 단일 플랜(≤4호출)이라 중복 제거가 이미 공회전을 끊음 — 추가 가드는 측정된 필요 없음 |
| SSE 이벤트 분리(token/tool/done/error) | 이미 구현 | `events.py` 스키마 + 발행 전 승인 이벤트(AC-336~357) |
| case facts 블록(원문 유지) | 이미 구현 | claim-quote가 원문 그대로(`verify_claims` 공백 정규화 substring, AC-40/41) — 사실이 요약을 거치지 않는 구조 |
| 컨테이너 4원칙(멀티스테이지·비루트·HEALTHCHECK·환경변수) | 이미 구현 | Dockerfile 정적 정책 + `/healthz` `/readyz` 프로브(AC-301~, ops probes), RUNBOOK 4블록 |
| 툴 출력 트림 + trim 로그 | **이번 라운드 구현** | `ai.evidence` `trimmed` 블록 — 잘린 행 수를 프롬프트 안에서 보고 (BSA-AC-505~506, ADR-0019) |
| 컨텍스트 예산 4층 / lost in the middle | 부분 | passages 상위 6개·1400자 컷(`chat.ask`) — 예산 계층은 명시적 상수, 사실 블록은 claim 원문 구조가 대체. trim 회계로 가시화됨 |

## 1주차 3차시 — 기업 요구사항 분석·프로젝트 주제 선정

| 교안 개념 | 상태 | 어디에 / 근거 |
|---|---|---|
| EARS 5패턴 AC + 측정 수치 | 이미 구현 | `specs/` 359 AC 전부 `[Pattern] shall 숫자`, `speclint.lint` |
| EARS 린트(패턴 키워드+shall+측정 수치) | 이미 구현 | `speclint.lint` — 이번 라운드 재검토: 교안 라인과 동일 구현 확인 |
| AC↔테스트 양방향 추적 | 이미 구현 | `speclint.trace`, `tests/test_specs.py` |
| 요구 6분류 태깅(SFR/DAR/PER/SIR/SECR/CONR) | **이번 라운드 구현** | `speclint.reqmap` + `REQ-KINDS` 출력: SFR=185 DAR=58 PER=3 SIR=75 SECR=32 CONR=6 — 정보성, 기각 없음 (BSA-AC-501~504, ADR-0019) |
| SDD 10섹션 정본 / Placement·Final-Only | 이미 구현 | `specs/bts_sbom_app_features.md` 단일 정본 + doclint --strict |
| 구체성 테스트(모호어 금지) | 관행으로 구현 | house 규칙이 측정 수치를 강제하므로 모호어("빠르게")는 AC 문장에 존재할 수 없음 — lint는 수치 부재로 이미 잡음. 별도 모호어 사전은 미도입(중복 검사) |
| todos.md 5섹션 | 적용 안 함 | 패스 기록 `evidence/loop/` + `LOOP_LOG.md` 가 동일 역할(현재 노트·최근 검증 포함) |

## 2주차 1차시 — DataOps & MLOps 응용/심화

| 교안 개념 | 상태 | 어디에 / 근거 |
|---|---|---|
| 4축 동시 결정(코드·데이터·모델·프롬프트) | 이미 구현 | `code_fingerprint`(코드) + PROMPT_VERSION(프롬프트) + evals 골든셋 버전(데이터) + core 버전 경고(`run_pass` confounded 경고) |
| 회귀율 = 통과→실패 개별 정의 | **이번 라운드 구현** | `loop.case_regressions` + `run_rag_pass` 차단 — 평균이 평평해도 개별 질의 회귀는 롤백 (BSA-AC-496~500, ADR-0018) |
| 검증 4계층 / 필드별 신뢰도·보정 / 검토 큐 | 이미 구현(해당 부분) | `ai.validate` 4계층(AC-34), `review.py` 독립 리뷰, `triage.py` 처분. 필드별 신뢰도는 판정 모델을 쓰지 않아 해당 없음(기존 기록 유지) |
| CI 헤드리스 리뷰(-p --output-format json) | 적용 불가 | 이 저장소는 Claude Code 게이트가 아니라 자체 proof 게이트(pytest/speclint/doclint/evalrag, `cli_ext.proof`)를 쓴다 — 개념은 동일(기계판독 findings → 머지 차단) |
| Batches API(50% 비용, custom_id) | 적용 불가(유지) | EXAONE 동기 OpenAI 호환 API 전용. azure provider 병합 시 재평가 |
| Evidence 규약(요약 덮어쓰기 + 원본 누적) | 이미 구현 | `evidence/loop/history.json`(요약) + `pass_NN_tag.json`(원본 누적), run 기록 `run_dir` |
| MLOps 성숙도 L0~2 진단 | 문서 수준 해당 | 레벨 1(측정 게이트 있는 자동 루프) 달성 상태 — `loop.py` 패스 이력이 증거. 별도 성숙도 문서는 미작성 |

## 2주차 2차시 — AI 학습 데이터 관리 파이프라인

| 교안 개념 | 상태 | 어디에 / 근거 |
|---|---|---|
| 구조화 출력 검증 4계층(스키마→규칙→의미→교차필드) | 이미 구현 | `ai.validate` (AC-34), `arch_intel.validate_arch` (AC-448~449) |
| 형식 오류만 재시도·정보 부재는 null | 유지(기각 기록) | 호출당 1회 + 결정적 강등 정책(AC-33) — 일일 한도 때문. ADR-0010 기록 유지 |
| 자가검증 필드(conflict_detected 등) | 부분 | `proposals`는 검증 계층이 대체, LLM 자가검증 필드는 미도입 — 모델 출력은 항상 코드가 재검증하므로 자가 보고의 가치가 낮음 |
| PII 비식별화·가명화 | 해당 없음 | 분석 대상은 저장소·매니페스트·라이선스 텍스트 — 개인정보 처리 면 없음. 이루다 사례는 governance 교육 자료로만 인용 |
| 층화 표집·Cohen's κ | 해당 없음 | LLM-as-judge 미사용(근거성은 코드 계산) — 기존 기록 유지 |
| 데이터 계약(schema.yaml)·계보 | 이미 구현 | `docs/governance/DATA_CONTRACT.md`(doclint 검사), `docs/governance/ORIGIN_LINEAGE.md` |

## 2주차 3차시 — VectorDB 기반 Hybrid Search 고급 RAG

| 교안 개념 | 상태 | 어디에 / 근거 |
|---|---|---|
| 하이브리드 BM25+벡터 RRF(k=60) | 이미 구현 | `rag.Index.search` — BM25 + TF-IDF 코사인 RRF 융합 |
| 헤딩 인식 청킹·컨텍스트 헤더 | 이미 구현 | `rag.chunk_markdown` |
| 쿼리 재작성(동의어·한↔영 확장) | 이미 구현 | `rag.SYNONYMS` |
| 근거 없으면 "찾지 못함" | 이미 구현 | 신뢰도 게이트 min_bm25=11 + found=false (범위 밖 5/5 거절) |
| claim-source 포인터 검증(quote ⊂ 원문) | 이미 구현 | `chat.verify_claims` — 이번 라운드 재검토: 교안의 인용 정확도 정의와 동일 |
| Recall@k·MRR·nDCG + OOD | 이미 구현 | `rag.evaluate`, `evalrag` |
| 리랭킹 | **측정 후 기각(관측만 유지)** | 3개 변형 전부 게이트 실패: ① 3번째 RRF 목록(bigram+헤딩) test MRR +0.104 but dev recall −0.067·OOD 0.8 ② 헤딩 전용 golden MRR −0.108 ③ 인접 스왑 캡 dev recall −0.067. `lex` 주석만 유지, 순서 불변 (BSA-AC-486~490, ADR-0016) |
| 정보원 상충 로그 | **이번 라운드 구현** | `rag.conflicts` + 챗 `[conflict]` 주석 + UI 경고 노트 — rule=escalate, unresolved (BSA-AC-491~495, ADR-0017) |
| 계층(parent-child) 청킹 | 미구현(유지) | 재검토 조건(코퍼스 수백 청크 초과·골든 Recall 하락) 미충족 — 기존 기록 유지 |
| 툴 설명 5요소 / 오라우팅 4종 | 이미 구현 | `TOOL_CATALOG` doc + `evals_chat` 오라우팅 측정(정상·오라우팅·미호출·폴백) |

## UI 고도화 (이번 라운드)

보안 화면 채팅 패널(`bts_console.js` ask)이 정답 본문 한 줄만 보여주던 것을 고도화:

- **근거 칩**: `retrieval.top` 의 섹션 제목·출처·rrf 를 칩으로 표시 (하이브리드 검색이 무엇을 근거로 골랐는지 가시화)
- **라우팅 라인**: `routing` + `routing_note`(LLM 플랜 실패 → 정규식 폴백 사유) 표시
- **비신뢰 인용 경고**: `contains_untrusted` 시 1개 경고 노트
- **상충 노트**: ADR-0017 의 `[conflict]` 를 경고 노트로 표시
- 렌더러는 순수 함수 `bts_ui.renderChatAnswer` 로 분리 — 노드 하니스(`tests/js/render_harness.js`)로 이스케이프·노트 수를 테스트 (BSA-AC-507~509). 모든 동적 값 esc(), 인라인 핸들러 없음(엄격 CSP) 규칙 준수.

## 측정값 (이번 라운드 게이트)

- 앱 스위트: 451 passed + 신규 24 = `python -X utf8 -m pytest` 결과 참고(아래 게이트 기록)
- speclint: 0 문제 / AC 359개 양방향 추적 0 누락 — REQ-KINDS SFR=185 DAR=58 PER=3 SIR=75 SECR=32 CONR=6
- doclint --strict: 0
- evalrag(리랭커 주석 전환 후, HEAD와 100% 동일 확인): golden 1.0/0.975/0.950 · dev 0.933/0.802/0.828 · test 0.917/0.757/0.769, OOD golden/test 1.0 (dev 0.8은 라운드 이전 코퍼스 성장 상태 — pass 4 기록과의 차이는 arch_flow 지식 문서 추가분)
- 참고: pass 4 기록(1.0/0.95/0.944 등)은 arch_flow 지식 문서 유입 이전 기준선이므로, 다음 `run_rag_pass` 가 현재 코퍼스의 새 기준선을 기록한다

## 라운드 2 (3주차 이후) 슬롯

- 교안 첨부 시 위 표 형식 그대로 섹션 추가, 미구현 항목 중 측정 가능한 것부터 게이트로 적용
- 재검토 대기 항목: 계층 청킹(코퍼스 성장 시), 리랭커(크로스인코더 대체 가능 시), Batches API(azure provider 병합 시), 형식 재시도 1회(호출 예산 여유 확인 시)
