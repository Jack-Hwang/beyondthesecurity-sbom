# harness engineering

출처: Harness Engineering (Johnson) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 비결정 에이전트를 감싸는 하니스가 품질을 결정한다: 입력 준비·도구 접착·출력 검증.
- 컨텍스트는 예산이다 — 자동 압축과 계층적 요약이 운영 전제다.
- 하니스는 결정론적이어야 에이전트의 비결정성을 측정할 수 있다.

## 이 프로젝트 적용

- ai.evidence의 목록 캡+trimmed 보고가 컨텍스트 예산 관리의 구현이다.
- verify_claims·citation_accuracy 게이트가 출력 검증 계층이다.
- chat_stream의 7종 이벤트가 하니스 관측점이다 (AC-517~520).
