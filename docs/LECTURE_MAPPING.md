# 강의 방법론 -> BTS-SBOM 구현 매핑 (정직 판)

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
| 공회전(spinning) 탐지 | 구현 | 패치 계획 반복 시 중단, 최근 3패스 동일 지표 시 plateau (AC-43) |
| EARS + 측정값 AC, 린트, 양방향 추적 | 구현 | `specs/`, `bts_sbom_app.speclint`, `tests/test_specs.py` |
| 실패 군집화로 다음 변수 선택 | 구현 | `loop.cluster_failures`, EXAONE 가설은 실제 군집만 채택 (AC-44) |
| 툴 출력 트림 | 부분 | `ai.evidence` 가 상위 N개만 전달. 버린 필드의 trim 로그는 **미구현** |
| 계층(parent-child) 청킹 | **미구현** | 코퍼스가 작고(수백 청크) 골든 Recall@5 가 이미 높아 측정된 필요가 없었다. 라이선스 전문을 코퍼스에 넣을 때 재검토 |
| 리랭킹 | **미구현** | stdlib 전용 제약. 외부 크로스인코더는 적용 불가 |
| 정보원 상충 로그(`conflicts`) | 구현 | `engine.detect_conflicts` 가 권고 레코드 묶음에서 수정 버전·CVSS 점수의 불일치를 `conflicts[]`(값·출처·날짜)로 기록하고 챗봇 `vuln_lookup` 이 양쪽 값을 보여 준다 (`tests/bts_sbom_app/test_advisory_conflicts.py`, AC-413~424). 한계: 수정 버전과 CVSS 점수만 비교하고 출처 레코드가 2개 이상일 때만 동작 |
| 형식 오류만 재시도, 정보 부재는 null | **미구현** | EXAONE 일일 한도 때문에 호출당 1회 + 결정적 강등을 택했다 |
| LLM-as-judge 의 Cohen's κ 보정 | 해당 없음 | 판정 모델을 쓰지 않는다(근거성은 코드로 계산) |
| Batches API (50% 비용) | 적용 불가 | EXAONE 은 동기 OpenAI 호환 API 뿐 |
| LoRA 파인튜닝 | 적용 불가 | API 호출만 가능 |
| 요구 6분류 태깅(SFR/DAR/...) | **미구현** | AC 를 기능 영역(모듈)별로만 묶었다 |

저작권 메모: `knowledge/lecture/` 는 강의 내용을 **의역·요약**한 것이며 슬라이드 원문을 옮기지 않았다. 레포를 공개하기 전에
수강 약관/출처 표기 정책을 확인하고, 필요하면 해당 폴더를 제외하라.
