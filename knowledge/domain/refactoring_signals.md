# 리팩터링 신호 (Refactoring 2판 개념 요약)

Martin Fowler 의『Refactoring: Improving the Design of Existing Code』2판(Addison-Wesley) 에서 다루는 개념을 BTS-SBOM 팀이 정리한 요약이다(원문 인용이 아니라 개념의 재서술이다).

## 리팩터링의 정의와 아키텍처에 대한 함의

리팩터링은 외부 동작은 그대로 둔 채 내부 구조를 개선하는 통제된 변경이다. 설계를 코딩 전에 완성해 두어야 한다는 선(先)설계 관점과 달리, 리팩터링은 "운영 중인 소프트웨어의 아키텍처를 유의미하게 바꿀 수 있다"는 진화적(evolutionary) 아키텍처 관점을 가능하게 한다. 미래 요구를 미리 맞추려 넣는 유연성 장치(무분별한 파라미터화, 추상화)는 대개 틀리기 때문에, 필요할 때 리팩터링으로 도입하는 편이 변경 비용이 낮다(YAGNI). 테스트가 없는 레거시는 구조 변경이 위험하므로 자동 테스트가 리팩터링의 전제다.

## 코드 악취 (bad smells) — 아키텍처 신호로 읽기

23개 코드 악취 중 아키텍처 분석에서 특히 중요한 것들:

- **Divergent Change**(한 클래스가 서로 다른 이유로 자주 바뀜): 하나의 모듈이 여러 변경 이유를 품고 있다는 신호 — 모듈을 나눌(바운디드 컨텍스트로 갈라낼) 절리면의 힌트.
- **Shotgun Surgery**(한 변경이 여러 곳을 고쳐야 함): 변경 커플링이 강하다는 신호 — 응집이 낮고 결합이 강한 구조.
- **Feature Envy**(다른 모듈의 데이터를 주로 사용하는 함수): 함수가 소속된 모듈을 옮겨야 한다는 신호 — 잘못 배치된 책임.
- **Duplicated Code**: 로직이 흩어져 있다는 신호 — 공유 모듈 추출 또는 통합의 근거.
- **Large Class / Long Function / Long Parameter List**: 책임 과다·인터페이스 비대 — 추출(Extract Function/Class) 대상.
- **Primitive Obsession / Data Clumps**: 도메인 개념이 원시 타입으로 흩어져 있다는 신호 — 값 객체 도입.
- **Repeated Switches / Loops**: 조건 분기·루프 중복 — 다형성/파이프라인으로 대체.
- **Insider Trading / Message Chains / Middle Man**: 모듈 간 과도한 참조(지나친 직접 의존 또는 불필요한 중계) — 인터페이스·퍼사드 재배치.
- **Speculative Generality / Lazy Element**: 실제로 쓰이지 않는 유연성·요소 — 제거.
- **Data Class / Refused Bequest**: 로직 없는 데이터 덩어리, 상속 계층의 오용 — 책임 재배치.

## 절차와 우선순위

리팩터링은 작은 단계(Extract Function, Move Function, Extract Class, Replace Conditional with Polymorphism, Change Value to Reference 등 카탈로그의 개별 리팩터링)로 나누어, 각 단계마다 테스트로 동작을 보존하며 진행한다. 아키텍처 관점에서는 변경 빈도(핫스팟)와 복잡도가 높은 곳부터 우선한다 — 코드 품질이 개선되면 변경 소요 시간과 결함률이 눈에 띄게 줄어든다는 실측 연구가 있다(예: Tornhill·Borg 의 Code Red 연구).
