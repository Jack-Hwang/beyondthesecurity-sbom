# technique sdd spec to code

출처: SDD (Martinelli) + AI-Native SWE (Graziano) 종합 (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- specify→plan→tasks→implement의 각 단계 산출물은 버전화되고 기계 판독 가능해야 한다.
- 에이전트는 명세를 읽는 것이 아니라 검사(테스트·린트)로 소비해야 한다.
- 구현 전 명세의 모호함을 잡는 린트가 가장 싼 품질 장치다.

## 이 프로젝트 적용

- speclint: AC 문법 검사+양방향 trace가 기계가 명세를 소비하는 구현이다.
- 브리프(작업 지시서)가 plan/tasks 산출물 역할이고 ADR이 헌법이다.
