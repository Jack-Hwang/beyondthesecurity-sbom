# technique eval driven quality

출처: AI Agents Definitive Guide + Code Complete 종합 (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 품질은 속성 목록이 아니라 측정 세트다: 성공률·지연·비용·안전을 함께 본다.
- 평가는 오프라인 골든셋(결정론)과 온라인 실측으로 나눈다.
- LLM-as-judge는 편향이 있어 코드 계산이 우선이다.

## 이 프로젝트 적용

- TOP10 게이트는 전부 코드 계산 — 판정 모델이 없다 (품질 철학 일치).
- evalrag/evalchat/evallicense 골든셋 + live 실측 스코어카드가 이중 평가다 (AC-481~485).
