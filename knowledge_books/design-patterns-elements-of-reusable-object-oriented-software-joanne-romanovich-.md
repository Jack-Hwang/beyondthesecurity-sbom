# Design Patterns (GoF: Gamma, Helm, Johnson, Vlissides) — 정제 노트

출처: 로컬 도서 "Design Patterns, Elements of Reusable Object-Oriented Software" (EPUB, slug
`design-patterns-elements-of-reusable-object-oriented-software-joanne-romanovich-`). 추출 원문을 읽고 우리 말로
정리한 종합 — 원문 인용이 아니다. 원문 검색은 `/api/books/search` 또는 채팅 `book_search`.

## 이 책의 논지

재사용 가능한 객체지향 설계의 어휘 23개. 패턴은 이름·문제·해법·결과(트레이드오프)로 기술되며, 목적별로 생성
(Factory Method·Abstract Factory·Builder·Prototype·Singleton)·구조(Adapter·Bridge·Composite·Decorator·Facade·
Flyweight·Proxy)·행동(Chain of Responsibility·Command·Interpreter·Iterator·Mediator·Memento·Observer·State·
Strategy·Template Method·Visitor)으로 나뉜다. 책의 깊은 부분은 패턴 "선택"보다 패턴 "관계"를 다룬다 — 예컨대
Decorator와 Strategy는 둘 다 구성(composition)으로 만들어지지만, Decorator의 인터페이스는 컴포넌트에 일치해야
하고 Strategy는 자기 전용 경량 인터페이스를 가질 수 있다(무거운 컴포넌트에 가벼운 전략을 붙일 때 유리).
MacApp/Bedrock이 뷰 장식을 넘어 이벤트 핸들링 확장에 Strategy 리스트를 쓰는 사례가 이 구분을 보여준다.

## 핵심 개념 지도

- **생성 패턴**: 객체 생성을 캡슐화 — 구체 클래스에 대한 의존을 인터페이스 뒤로. (이 앱의 ChatClient.from_env/
  from_config가 팩토리 계열.)
- **구조 패턴**: 합성으로 큰 구조를 만든다. Decorator는 컴포넌트 인터페이스 준수가 강제, Strategy는 전용
  인터페이스 허용 — "꾸미는 것"과 "행동 교체"의 경계.
- **행동 패턴**: 책임 분배. Observer(다대일 통지), Strategy(알고리즘 교체), Template Method(뼈대 고정·단계 위임),
  Command(요청을 객체로 — 실행취소·큐잉 가능), Mediator(다대다를 다대一로).
- **원칙**: 변하는 것을 캡슐화, 인터페이스에 프로그래밍, 상속보다 구성 우선 — 23개 패턴의 공통 기반.

## 이 프로젝트 적용

- **이 저장소에 이미 있는 패턴**: events.EventBus=Observer, net.py 서킷브레이커=State(상태 전이)·Proxy(호출
  감싸기), ai.py 검증 계층=Chain of Responsibility(각 계층이 통과/드롭 판정), conformance REGIMES·policy 주입=
  Strategy, report.project_md=Facade(기록 전체의 단일 진입).
- **Decorator vs Strategy 선택 규칙**: 렌더러·분석기 확장 시 "같은 인터페이스를 겹쳐 감싸는가(Decorator)" vs
  "전용 계약의 알고리즘인가(Strategy)"를 명시 — 새 확장 제안 시 어느 쪽인지 ADR에 기록.
- **패턴 남용 경계**: stdlib-only·작은 모듈 원칙에서 패턴은 문제가 있을 때만. 23개 어휘는 리뷰 대화의 언어로
  쓰되, 코드는 가장 단순한 형태 우선(Fundamentals의 단순성 우선과 동일 방향).
