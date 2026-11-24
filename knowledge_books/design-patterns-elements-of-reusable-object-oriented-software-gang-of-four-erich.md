# design patterns elements of reusable object oriented software gang of four erich

출처: Design Patterns (GoF) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 패턴은 재사용이 아니라 변화를 담을 자리를 미리 만드는 것이다.
- 인터페이스에 의존하고 구현에 의존하지 않는다 — 콤포지션으로 유연성을 산다.

## 이 프로젝트 적용

- llm.TRANSPORT 교체 가능 구조가 스트래티지 패턴의 실례다.
- events.EventBus의 구독자 분리는 옵저버 패턴 그 자체다.
