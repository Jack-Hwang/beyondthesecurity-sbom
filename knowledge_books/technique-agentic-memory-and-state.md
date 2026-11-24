# technique agentic memory and state

출처: Illustrated Guide + Harness Engineering 종합 (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 짧은 기억은 컨텍스트, 긴 기억은 저장소 — 경계를 명시해야 누수가 없다.
- 상태는 불변 레코드+명시 스키마로 저장해야 재생 가능하다.
- 기억에 신뢰 등급을 남겨라: 측정값과 사용자 진술은 등급이 다르다.

## 이 프로젝트 적용

- project record+prev.json 스냅샷+triage 스토어가 긴 기억의 스키마화다.
- trust 등급(knowledge/untrusted-quote/book)이 기억 신뢰 등급의 구현이다.
