# spec driven development from specs to code with ai agents simon martinelli

출처: Spec-Driven Development (Martinelli) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- SDD 사이클: specify→plan→tasks→implement이고 에이전트가 각 단계 산출물을 소비한다.
- 프로젝트 헌법이 불변 원칙을 선언해 모든 생성물이 그 검사를 받는다.
- 명세와 구현의 불일치는 테스트보다 이른 시점에 기계로 잡는다.

## 이 프로젝트 적용

- 이 저장소의 헌법은 ADR + speclint(AC 문법) + doclint(문서 게이트) + 양방향 trace다.
- 갭 없음을 정직히 기록한다 — SDD는 구현돼 있고 책의 새 도구는 도입하지 않는다.
