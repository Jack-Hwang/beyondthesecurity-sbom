# 디자인 패턴 (GoF 및 Dive Into Design Patterns 개념 요약)

Erich Gamma·Richard Helm·Ralph Johnson·John Vlissides(GoF) 의『Design Patterns: Elements of Reusable Object-Oriented Software』(Addison-Wesley) 와 Alexander Shvets 의『Dive Into Design Patterns』(Refactoring.Guru) 에서 다루는 개념을 BTS-SBOM 팀이 정리한 요약이다(원문 인용이 아니라 개념의 재서술이다).

## 패턴이란 무엇인가

디자인 패턴은 반복되는 설계 문제에 대한 검증된 해법의 이름 붙은 청사진이다. 코드를 복사해 오는 게 아니라, 문제와 해법 구조에 공통 언어를 부여해 팀의 소통과 설계 판단을 돕는 도구다. 패턴은 만능 해법이 아니며 문맥(문제가 실제로 존재하는가) 없이 적용하면 불필요한 복잡도만 더한다. Shvets 는 패턴을 "설계 문제 해법의 카탈로그이자, 좋은 설계 원칙을 실천하는 방법"으로 소개하며 관계(패턴 간 조합·대체 관계)를 함께 다룬다.

## 좋은 설계의 세 원칙 (Shvets 정리)

- 변하는 것을 캡슐화하라: 자주 바뀌는 부분을 분리해 격리한다(우리의 "변경 이유 분리" — Divergent Change 제거와 같은 뿌리).
- 구현이 아니라 인터페이스에 프로그래밍하라: 구상 타입이 아닌 추상에 의존해 결합을 줄인다.
- 상속보다 구성을 선호하라: 런타임에 행동을 조립 가능하게 해 상속 계층 경직을 피한다.

## SOLID (Shvets 정리)

단일 책임(한 모듈·클래스는 한 가지 변경 이유만), 개방/폐쇄(확장에 열리고 수정에 닫힘), 리스코프 치환(파생 타입이 기반 계약을 깨지 않음), 인터페이스 분리(거대 인터페이스 대신 작은 계약), 의존성 역전(고수준 정책이 저수준 세부에 의존하지 않음). 아키텍처 관점에서 SRP 는 모듈 분리 판단의 근거가 되고, DIP 는 ports-and-adapters 스타일의 이론적 기반이 된다.

## GoF 23 패턴 분류

- 생성(Creational): Factory Method, Abstract Factory, Builder, Prototype, Singleton — 객체 생성 방식을 캡슐화.
- 구조(Structural): Adapter, Bridge, Composite, Decorator, Facade, Flyweight, Proxy — 구성과 인터페이스를 다룸. Facade 는 복잡한 하위 시스템 앞에 단순한 접점을 놓는 것으로, DDD 의 open-host service 와 통합 퍼사드의 원형이다.
- 행동(Behavioral): Chain of Responsibility, Command, Iterator, Mediator, Memento, Observer, State, Strategy, Template Method, Visitor — 책임 배분과 메시징. Observer 는 이벤트 기반 아키텍처, Mediator 는 서비스 간 직접 결합을 줄이는 오케스트레이션의 원형이다.

## 아키텍처 분석에서 패턴을 읽는 법

정적 분석으로 "패턴이 쓰였다"고 확정하는 건 어렵다(이름·구조 힌트일 뿐). 대신 다음 신호를 구조 힌트로 읽을 수 있다: 래퍼 클래스 뭉치(Adapter/Decorator), 단일 진입 퍼사드 클래스(Facade), 콜백·핸들러 등록(Observer/Command), `create*`/`new*Instance` 팩토리 함수, 전역 단일 인스턴스(Singleton — 테스트성·전역 상태 위험 신호). 패턴 남용은 Speculative Generality 악취와 같은 위험 신호로도 읽힌다.
