# technique multi agent orchestration

출처: Building Agentic AI Systems + Illustrated Guide 종합 (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 오케스트레이터가 상태·예산·중단을 소유하고 서브에이전트는 작업에만 책임진다.
- 서브에이전트 결과는 명시 전달(비상속)이 원칙 — 암묵 컨텍스트 상속은 오류의 원천이다.
- 합의가 필요한 판정은 독립 멤버 다수+결정론 집계가 단일 LLM 판정을 이긴다.

## 이 프로젝트 적용

- council(3멤버+결정론 verdict)와 council_handoff(not_passed 명시)가 이 구조의 구현이다.
- 부분 결과+갭 주석(오류 봉투)은 오케스트레이터-서브 계약의 실례다 (AC-517).
