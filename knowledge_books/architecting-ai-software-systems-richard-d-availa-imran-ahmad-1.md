# architecting ai software systems richard d availa imran ahmad 1

출처: Architecting AI Software Systems (Availa & Ahmad) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- AI 시스템 아키텍처는 비결정 구성요소를 결정론 경계로 감싸는 일이다.
- 폴백·타임아웃·캐시는 예외 처리가 아니라 아키텍처 요소다.
- 데이터 흐름(수집→인덱스→검색→생성)을 파이프라인으로 그려야 비용이 보인다.

## 이 프로젝트 적용

- net.fetch_json + 회로차단기 + 4상태 보고가 비결정 외부호출의 결정론 경계다 (AC-301~315).
- books 2계층(원문 결정론 추출 / 정제 노트)이 데이터 파이프라인 분리의 실례다 (ADR-0021).
