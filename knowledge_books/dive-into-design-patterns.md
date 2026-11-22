# Dive Into Design Patterns (Alexander Shvets) — 정제 노트

출처: 로컬 도서 "Dive Into Design Patterns" (EPUB, slug `dive-into-design-patterns`). 추출 원문을 읽고 우리 말로
정리한 종합 — 원문 인용이 아니다. 원문 검색은 `/api/books/search` 또는 채팅 `book_search`.

## 이 책의 논지

GoF 23패턴을 현대 언어로 다시 가르치는 학습서. 전반부는 설계 원칙(좋은 설계의 특징 → SOLID)을, 후반부는 생성·
구조·행동 패턴 카탈로그를 문제→나쁜 해법→좋은 해법→패턴 구조→의사코드 순으로 훈련시킨다. 핵심 서사: 패턴은
원칙의 결과물이며, 원칙(캡슐화·인터페이스·구성) 없이 패턴만 흉내내면 과설계가 된다.

## 핵심 개념 지도

- **설계 원칙의 사다리**: 변하는 것을 캡슐화 → 인터페이스에 프로그래밍 → 상속보다 구성 → SOLID(SRP·OCP·LSP·
  ISP·DIP). 각 원칙은 위 원칙의 도구.
- **SOLID**: SRP(클래스는 바꿀 이유 하나), OCP(확장에 열고 수정에 닫음 — Strategy/Decorator가 이를 실현), LSP
  (부모 계약을 깨는 자식 금지), ISP(뚱뚱한 인터페이스 분리), DIP(구체가 아닌 추상에 의존).
- **생성**: Factory Method(서브클래스가 무엇을 만들지 결정), Builder(복잡한 조립 단계 분리), Singleton(전역 하나 —
  테스트성 해치므로 주의), Prototype(복제).
- **구조**: Facade(복잡한 서브시스템의 단순 진입 — Proxy는 서비스 생명주기를 스스로 관리, Decorator 조합은
  클라이언트가 제어한다는 구분), Adapter, Composite, Bridge, Flyweight, Proxy.
- **행동**: Command(요청을 객체로 — 큐·실행취소), Observer, Strategy, Template Method, State, Memento 등.

## 이 프로젝트 적용

- **Facade 선례**: `report.project_md`·`console.build_view`가 복잡한 프로젝트 기록의 Facade — 화면과 채팅은
  Facade만 본다. 새 분석 기능도 Facade(함수 1개+문서 1개)로 노출하고 내부 구조를 새지 않는다.
- **OCP의 실현처**: conformance REGIMES·license council 멤버·sector 산업표는 "수정 없이 확장"(레지스트리에
  항목 추가) — 새 규제·산업·평가항목은 기존 코드 수정이 아니라 데이터 추가로 들어온다.
- **ISP → 도구 카탈로그**: chat TOOL_CATALOG의 도구 하나하나가 작은 계약 — "뚱뚱한 도구" 하나로 질의를 몰지
  않는다. 새 도구는 새 계약.
- **Singleton 경계**: 전역 상태를 만들지 않는다(모듈 상태조차 서킷브레이커처럼 테스트에서 리셋하는 autouse
  fixture 운용) — 책의 Singleton 경고와 일치.
- **과설계 경계**: stdlib-only 원칙에서 패턴은 3회 이상 반복될 때만 도입 — 원칙이 패턴보다 먼저다.
