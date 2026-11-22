# technique rag context rot and position

출처: Illustrated Guide + LLM Design Patterns 종합 (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 컨텍스트가 길어질수록 중간 내용이 묻힌다(lost in the middle) — 순서가 품질이다.
- 컨텍스트 회전: 관련 없는 첨부가 전체 답을 나쁘게 만든다.
- 무엇을 넣을지가 무엇을 빼달지보다 어렵다 — 관련성 순으로 상한을 둔다.

## 이 프로젝트 적용

- 구현: chat 경로의 신뢰 문서를 질문 관련도 순으로 재배열해 상한 6개를 프롬프트에 넣는다 (AC-536).
- ai.evidence의 목록 캡+trimmed 보고가 상한+정직의 구현이다.
