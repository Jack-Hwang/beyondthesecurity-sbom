# fine tuning ai

출처: Fine-Tuning AI (Moroney) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 파인튜닝은 프롬프트·RAG·도구로 못 푼 문제의 마지막 수단이다.
- 데이터 품질이 학습률보다 중요하고 평가셋 분리가 필수다.

## 이 프로젝트 적용

- 프로젝트 판정: API-only 환경이라 적용 불가 — RAG+도구로 같은 문제를 푼다 (브리프5 매핑).
- 평가셋 분리는 golden/dev/test와 books의 eval 격리(ADR-0021)로 지켜진다.
