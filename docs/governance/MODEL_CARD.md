# Model Card — LG EXAONE 사용 방식 (bts_sbom_app)

`bts_sbom_app/llm.py`, `ai.py`, `chat.py`, `council.py`, `loop.py` 와 README.md 를 읽고 실제 코드 동작만 기술한다.
이 문서는 EXAONE 모델 자체를 학습시키거나 배포하지 않는다(ADR-0010) — 이 패키지가 **호출하는 방식**을 설명하는 카드다.

## 1. 모델 개요 (Model details)

- **제공자/모델**: LG EXAONE (K-EXAONE), OpenAI 호환 chat-completions API. 기본 베이스 URL
  `https://api.exaone.ai/v1`(`llm.DEFAULT_BASE`), 기본 모델 `k-exaone_v2.5`(`llm.DEFAULT_MODEL`). 환경변수
  `EXAONE_API_KEY`/`EXAONE_BASE_URL`/`EXAONE_MODEL`, `BTS_SBOM_LLM_CONFIG` 가 가리키는 JSON 파일, 또는 범용
  `LLM_API_KEY`/`LLM_BASE_URL`/`LLM_MODEL` 로 임의의 OpenAI 호환 서버(로컬 Ollama 등)를 대신 지정할 수 있다
  (`llm.ChatClient.from_env`).
- **추론 모델 취급**: K-EXAONE 은 추론(reasoning) 모델이라 추론 토큰이 `max_tokens` 에 포함되고 끌 수 없으므로, 토큰
  하한을 `FLOOR_TOKENS = 1024` 로 두고 `reasoning_effort="low"` 를 함께 보낸다(`provider == "exaone"` 일 때만).
- **파라미터/직렬화**: 한 번에 요청 1건만 보냄(`ChatClient.complete` 가 락으로 직렬화) — "병렬 배치 워커가 같은 클라이언트를
  공유하면 공급자의 '바쁨' 429 를 유발한다(측정: 10개 프로젝트 중 2개가 그렇게 제안을 잃었다)"는 `llm.py` 자체 주석에
  따른 설계.
- **프롬프트 버전**: `ai.PROMPT_VERSION = "ai-v2"`, `council.PROMPT_VERSION = "council-v1"` — 캐시 키에 포함되어 프롬프트가
  바뀌면 이전 캐시가 자동으로 무효화된다.
- **검증·캐시·강등**: 모든 구조화 출력은 호출부마다 정의된 검증을 통과해야 쓰이고(`ai.validate` 4계층, `chat.validate_calls`,
  `council` 의 스키마/인용 검사), 검증을 통과한 응답만 프롬프트 해시 키로 캐시되며(검증 실패·파싱 실패 응답은 캐시하지
  않음 — 잘못된 응답이 재생되지 않도록), 키가 없거나 예산 소진·네트워크 오류·파싱 실패 시 결정적(rule-based) 경로로 강등하고
  그 원인을 `llm_note`/`routing_note` 에 남긴다(ADR-0010).

## 2. 사용 목적과 범위 (Intended use)

**의도된 사용**:
- `ai.propose` — 업그레이드/교체/라이선스 검토/아키텍처 리팩터링 "제안" 텍스트 생성(사람이 읽고 선택).
- `chat.py` — 고정된 도구 카탈로그(최대 21종, 그중 쓰기 도구 3종은 `--actions` 세션에서만 노출)에서 어떤 도구를 호출할지
  계획. 모델은 계획만 하고 토큰/코드는 절대 스스로 발급하지 못한다(검증기가 드롭).
- `council.py` — 식별되지 않은 라이선스 문자열에 대한 여러 모델의 독립적인 분류 "제안"(결과는 `suggestions`, 자동 반영
  없음).
- `loop.py` — 측정된 실패 군집을 근거로 다음에 시도할 실험 변수 "가설" 제안.

**의도된 범위 밖(out of scope)**:
- 규제 적합도 판정(`sectors.py`, `conformance.py`)은 AI 를 전혀 거치지 않는 결정적 계산이다 — 모델은 이 수치에 입력도
  출력도 아니다.
- 모델은 어떤 파일도 직접 쓰지 않는다 — 패치 적용·VEX 결정 기록은 사람이 타이핑한 토큰/코드 없이는 발생하지 않는다
  (`docs/governance/AI_IMPACT_ASSESSMENT.md` 6절).
- 개인 식별 정보(PII)를 다루거나 수집하지 않는다 — 입력은 소스 코드/매니페스트/SBOM 메타데이터(패키지명·버전·라이선스
  문자열·CVE)다.
- 인증/인가 결정에 쓰이지 않는다.

## 3. 데이터·평가 (Evaluation)

**README.md 가 보고하는 측정치(인용)**: "Measured on 10 real GitHub repositories (chosen by the author, several
deliberately vulnerable): 2,478 components, 1,292 findings, license resolution 0.990."

> **이 수치는 표본 내(in-sample) 수치이며, 저자가 실제 EXAONE 응답을 직접 보고 검증·매칭 규칙을 고친 뒤에 나온 결과다.**
> 독립적으로 분리해 둔(held-out) 벤치마크가 아니고, 규칙이 그 10개 저장소의 관측 결과에 맞춰 조정되었을 가능성을 배제하지
> 않는다. 다른 저장소 집합에서 같은 비율이 재현된다는 보장은 없다.

그 밖의 측정값(코드·spec 에서 확인):
- `evalchat`(라우팅 측정, README 인용): 정규식 라우터 2/8, LLM 플래너 8/8(`BSA-AC-209`). 사용자가 타이핑하지 않은 "사유"는
  신뢰되지 않아 7/8 로 채점됨(동일 AC).
- `evals.rag_eval`/`evals.chat_eval`: 검색 품질(nDCG@5)과 채팅 근거성(인용 정확도)을 오프라인 골든셋으로 측정
  (`docs/LECTURE_MAPPING.md`: "검색 지표 vs 생성 지표 분리, nDCG@5 | 구현").
- `BSA-AC-34`: 4개 제안 중 하나씩 결함이 있는 3개를 드롭하고 정확히 1개만 남기는 검증기 동작을 측정(가짜 EXAONE 응답).
- `council.score`: 라이선스 위원회는 44건의 수기 작성 사례로 측정됨(`docs/LECTURE_MAPPING.md` 해당 없음 — 이 카드가 직접
  명시).

## 4. 한계 (Limitations)

- **일일 호출 예산**: 기본 80회/일(`BTS_SBOM_LLM_DAILY_BUDGET`, 무료 티어 100회/일보다 낮게 설정) — 예산 소진 시 그
  실행에서는 더 이상 LLM 경로를 쓸 수 없고 결정적 경로로 전환된다.
- **직렬 호출**: 한 클라이언트는 한 번에 요청 1건만 보낸다 — 대량 배치 작업에서 처리량이 모델 자체 지연시간에 비례해서만
  늘어난다(병렬화 없음).
- **검색은 어휘 기반(lexical)**: `rag.py` 는 BM25+TF-IDF 융합이며 의미 임베딩/리랭킹이 없다(stdlib 제약, 이미
  `docs/LECTURE_MAPPING.md` 에 "리랭킹: 미구현 - stdlib 전용 제약"으로 기록됨).
- **파인튜닝 없음**: 이 모델은 이 프로젝트의 데이터로 학습되지 않는다(ADR-0010) — 모든 개선은 프롬프트·검증 규칙 수정으로
  이뤄진다.
- **의미 검증기는 사후 보강형**: `ai._repair_refs` 의 주석대로, 검증 규칙은 실제로 관측된 EXAONE 응답을 보고 나서야
  보강된 이력이 있다 — 아직 보지 못한 표현에 대해서는 과도하게 드롭될 수 있다.
- **Python 3.10 stdlib 제약**: 외부 JSON 스키마 검증기 없이 손으로 짠 검증만 사용한다(ADR-0007).

## 5. 윤리·위험 (Risks)

세부 위험 식별과 완화는 `docs/governance/AI_IMPACT_ASSESSMENT.md` 4·5절에 전부 기술되어 있다(환각, 검증 우회, 키 노출,
프롬프트 인젝션, 권한 사칭, 가용성/비용, 라이선스 위원회 편향, 회귀 은폐, 참고용 텍스트의 오용). 핵심만 다시 적으면: 이
모델의 출력은 **어디에서도 사람 승인 없이 쓰기 동작으로 이어지지 않으며**, 구조화 출력은 항상 재검증을 거치고, API 키는
응답·로그·캐시·에러에 결코 그대로 노출되지 않는다(`llm.py` 모듈 docstring: "The key is never written to evidence, logs,
caches or errors").
