# ADR-0010: 파인튜닝하지 않고 EXAONE API 호출만 사용한다

## Status
Accepted — 사후 기록. 근거 코드: `bts_sbom_app/ai.py`(검증 4계층·결정적 강등), `bts_sbom_app/llm.py`(직렬 호출·일일 장부), `docs/LECTURE_MAPPING.md` 의 "LoRA 파인튜닝: 적용 불가". AC: BSA-AC-33(정직한 강등), BSA-AC-34(검증 4계층). 테스트: `tests/bts_sbom_app/test_ai_rag_loop.py`.

## 근거 (Context)
EXAONE 은 API 로만 접근 가능하다(호스팅·파인튜닝 불가). 환각 답변이 SBOM 권고로 흘러가면 "근거 없는 통과"가 된다.

## 결정 (Decision)
모델은 프롬프트만으로 사용한다(LoRA 등 파인튜닝 없음). 모든 제안은 검증 4계층(스키마/규칙/의미/교차필드)을 통과해야 하고, 통과 못 하면 결정적 강등(deterministic)으로 정직하게 격하되어 사유가 기록된다.

## 기각 대안 (Rejected alternatives)
- LoRA 파인튜닝: API 전용 제약으로 불가능 — 애초에 시도하지 않는다.
- 모델 자체 호스팅: GPU·운영 비용이 이 과제의 규모를 넘고, 데이터 주권은 클라우드 모드의 스위치(작업 12·19)로 다룬다.

## 결과 (Consequences)
모델 품질 개선은 프롬프트 버전(PROMPT_VERSION)과 검증 규칙으로만 진행된다. 같은 증거는 캐시로 같은 결과를 얻는다.
