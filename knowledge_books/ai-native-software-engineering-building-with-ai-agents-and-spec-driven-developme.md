# ai native software engineering building with ai agents and spec driven developme

출처: AI-Native Software Engineering (Graziano) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- AI 네이티브 개발의 축은 명세가 곧 산출물이라는 것 — 코드는 명세의 파생물이다.
- 에이전트에게 자유를 주기 전에 검증 가능한 계약(테스트·AC)을 먼저 고정한다.
- 사람의 검토 지점을 명시적으로 설계해야 에이전트 자동화가 안전해진다.

## 이 프로젝트 적용

- 이 프로젝트는 이미 SDD다: BSA-AC-* 명세 + speclint 양방향 trace + doclint가 계약을 강제한다.
- patch 게이트(계획→토큰→승인)가 사람 검토 지점 명시의 구현이다.
