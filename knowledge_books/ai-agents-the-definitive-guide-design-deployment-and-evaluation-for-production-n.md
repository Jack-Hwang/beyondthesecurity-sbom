# ai agents the definitive guide design deployment and evaluation for production n

출처: AI Agents: The Definitive Guide (Koenigstein) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 에이전트를 데모가 아니라 생산 시스템으로 본다: 배포·관측·평가가 설계의 1급 시민이다.
- 에이전트 평가는 단일 점수가 아니라 작업 성공률·지연·비용·안전을 함께 잰다.
- 실패는 예외가 아니라 데이터다 — 실패 유형을 분류해 회귀로 삼는 것이 운영의 핵심이다.

## 이 프로젝트 적용

- evalrag/evalchat/evallicense와 RAG 6지표 기준선이 이 원칙의 구현이다.
- events.py 단계 이벤트와 supply_chain_gate가 관측성 요구를 충족한다.
- 회귀 4분면(impact.py)과 케이스 회귀율 게이트가 실패를 회귀로 삼는 요구를 구현한다.
