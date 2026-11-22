# technique harness compaction

출처: Harness Engineering + LLM Design Patterns 종합 (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 컨텍스트 예산 초과 시 계층적으로 압축한다: 원문→요약→포인터.
- 압축에서 무엇이 잘렸는지 반드시 보고한다 — 조용한 손실 금지.
- 세션 상태는 재시작 가능한 파일로 저장한다.

## 이 프로젝트 적용

- ai.evidence trimmed 보고·triage 스토어·evidence/runs 레코드가 이 원칙의 구현이다.
- handoff 스키마가 세션 간 상태 이관의 결정론 형식이다.
