# technique agent loops budgets

출처: Loop Engineering + Harness Engineering 종합 (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 루프에는 3가지 상한이 필요하다: 반복 수·동일오류 중단·비용 예산.
- 수정 프롬프트에는 원 실패의 구체 오류를 첨부한다 — 요약이 아니라 원문이다.
- 루프 종료는 상태로 보고한다: success/partial/failure+사유.

## 이 프로젝트 적용

- nl2sql answer()가 3상한+오류 첨부를 그대로 구현했다 (AC-512).
- ERROR 이벤트(error_type/severity/retryable/recovery_hint)가 종료 상태 보고다.
