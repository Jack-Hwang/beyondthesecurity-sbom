# Refactoring, Improving the Design of Existing Code (Martin Fowler, 2판) — 정제 노트

출처: 로컬 도서 "Refactoring" (EPUB, slug `refactoring-improving-the-design-of-existing-code`). 추출 원문을 읽고
우리 말로 정리한 종합 — 원문 인용이 아니다. 원문 검색은 `/api/books/search` 또는 채팅 `book_search`.

## 이 책의 논지

리팩토링은 "겉보기 동작은 그대로 둔 채 내부 구조를 개선하는" 이름 붙은 소규모 변환의 카탈로그다. 안전장치는
테스트(행동 고정)와 작은 단계(한 변환마다 실행·검증), 그리고 냄새(smell)→변환 이름의 사전 대응이다. 2판은
JavaScript 예제와 새 냄새 분류로 갱신됐고, "준비된 코드에서 이름 붙은 동선으로 이동"하는 방식을 강조한다.

## 핵심 개념 지도

- **냄새 → 변환 사전**: 신비로운 이름(Rename), 중복 코드(Extract Function), 긴 함수(Extract/Inline), 긴 매개변수
  목록(Parameter Object), 전역 데이터(Encapsulate Variable — 접근자로 갱신 통제, 필요하면 Change Reference to
  Value), 가변 데이터, 뒤엉킨 변경(Split Module), 산탄총 수술(Move Function/Field), 기능 욕심, 메시지 체인
  (Hide Delegate), 중개자 자 제거, 잘못된 소속, 과대·과소 클래스 등.
- **캡슐화 계열**: Encapsulate Collection(컬렉션 getter/setter 대신 제어된 접근 — 큰 자료구조 전체를 캡슐화하는
  비용이 과할 때는 getter가 깊게 파고들어도 구조를 감싼 객체를 돌려주는 절충 가능), Replace Primitive with
  Object, Introduce Parameter Object.
- **이동 계열**: Move Function/Field(데이터와 그 데이터를 쓰는 로직의 소속 정렬), Extract Class(한 클래스가 두
  가지 일을 할 때).
- **조건 단순화 계열**: Replace Conditional with Polymorphism, Decompose Conditional, Introduce Assertion.
- **절차 규율**: 테스트 자동화 위에서 작은 단계 반복, 커밋 단위 변환, 실패 시 되돌림 — "이름 붙은 변환"이
  리뷰·회귀 대화를 가능하게 한다.

## 이 프로젝트 적용

- **패치 회귀 게이트 = 리팩토링 절차의 기계화**: patch.py의 계획→승인 토큰→적용→재스캔→회귀 시 원본 복원
  (regression_reverted) 파이프라인이 책의 "작은 단계+테스트+되돌림" 절차 그대로다. 재구현 작업도 같은 절차로
  한다 — 변환은 이름 붙여 기록하고, 검증 실패 시 되돌린다.
- **냄새→신호 사전**: arch.py hotspots/modernization(거대 함수·전역 데이터·반복 코드)이 냄새 탐지기. 새 냄새를
  추가할 때는 책의 냄새 정의+우리의 측정(파일 LOC·import 엣지·순환)을 함께 적는다.
- **Encapsulate Variable 원칙**: evidence 기록·트리아지 저장소가 set_* 메서드로만 갱신되는 이유 — 전역 데이터
  냄새의 처방. 새 전역 상태는 금지, 필요하면 접근자+잠금.
- **Change Reference to Value 절충**: 증거 문서가 클 때 전체 캡슐화 대신 "감싼 객체 반환" 절충을 허용하는 책의
  실용주의 — API 응답도 전체 원문 대신 감싼 스니펫(book_search snippet 240자)으로.
- **이름 붙은 변환 언어**: 코드 리뷰·채팅 제안이 "이 파일에서 Extract Class/Move Function" 같은 변환 이름으로
  말하게 — EXAONE 제안 검증기가 계획과 target_version을 대조하는 것과 같은 정밀성.
