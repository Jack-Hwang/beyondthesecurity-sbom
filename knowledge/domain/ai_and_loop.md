# AI 제안, 챗봇, 루프 엔지니어링 (AI proposals, chatbot, loop engineering)

## LG EXAONE 연결

K-EXAONE 는 OpenAI 호환 chat completions API 로 호출한다(`EXAONE_API_KEY`, `EXAONE_BASE_URL`, `EXAONE_MODEL`). 추론(reasoning) 모델이라 추론 토큰이 max_tokens 에 포함되므로 최소 1024 를 보장하고 reasoning_effort 는 low 로 보낸다.
무료 한도는 하루 100회 수준이라 로컬 호출 장부(daily budget 80)로 먼저 막고, 429 일일 한도 응답은 재시도하지 않는다. 로컬 Ollama 같은 OpenAI 호환 서버를 쓰면 일일 한도가 없다. API 키는 증거 파일, 로그, 캐시에 쓰지 않는다.

## 제안 4계층 검증

AI 제안은 (1) 스키마, (2) 규칙(action 과 risk 허용 집합, 길이), (3) 의미(refs 가 증거에 실재하는 취약점 ID, 컴포넌트, 파일, 도메인), (4) 교차 필드(upgrade 의 target_version 이 검증된 계획의 safe_version 과 일치, replace 와 accept_risk 는 깨끗한 수정이 없을 때만, review_license 는 실제 라이선스 문제가 있는 컴포넌트만)를 모두 통과해야 채택된다. 탈락한 제안은 `dropped` 로 개수를 남긴다.

## 정직한 강등 (deterministic fallback)

EXAONE 키가 없거나, 일일 한도, 네트워크 오류, 검증 통과 제안 0건이면 결정적 제안으로 강등하고 `source=deterministic` 과 원인(`llm_note`)을 남긴다. LLM 성공으로 위장하지 않는다. 같은 증거는 프롬프트 해시 캐시로 두 번 호출하지 않는다.

## 근거 있는 챗봇 (grounded chatbot)

답변은 claim 목록이며 각 claim 은 인용문(quote)과 출처(source)를 가진다. 인용문은 출처 문서의 verbatim 부분 문자열이어야 하고 출처 id 는 이번 질문에서 실제로 검색되거나 호출된 문서여야 한다. 질문이 프로젝트 도구에도, 지식베이스에도 근거가 없으면 `found=false` 로 모른다고 답한다.
프로젝트 질문(취약점 ID, 컴포넌트, 라이선스, 패치, 아키텍처, 산업 리포트)은 도구로 답하고, 일반 질문은 하이브리드 검색으로 답한다.

## 하이브리드 검색 (hybrid retrieval)

BM25 와 TF-IDF 코사인을 RRF(Reciprocal Rank Fusion, k=60)로 합친다. 한국어는 음절 바이그램과 조사 제거 토큰을 함께 쓴다. 질의 확장 동의어 표(한국어와 영어)와 메타데이터 필터(kind, project)를 쓴다. 신뢰도 게이트(최상위 청크가 질문의 핵심어를 충분히 덮는지)를 통과하지 못하면 범위 밖 질문으로 처리한다.
평가는 Recall@5, MRR, nDCG@5 와 범위 밖 질문 거절률로 한다.

## 루프 엔지니어링 (loop engineering)

한 패스는 하나의 변수만 바꾼다. 같은 골든셋에서 지표를 재측정하고 회귀 게이트 Δ = 후보 - 기준 >= -0.02 를 차단 지표에 적용해 채택(accept) 또는 롤백(rollback)한다. 최근 3패스의 지표가 같으면 plateau(공회전)로 멈춘다.
실패는 원인별로 군집화한다(라이선스 미해결 생태계, 미검증 계획, 차단된 패치, 미지원 매니페스트, import 분석 불가). 다음 변수는 이 군집에서 고르며, EXAONE 가설은 실제 군집 키를 인용한 것만 채택한다.
