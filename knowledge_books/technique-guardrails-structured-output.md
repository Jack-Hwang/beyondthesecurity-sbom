# technique guardrails structured output

출처: LLM Design Patterns + Harness Engineering 종합 (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 가드레일 3층: 스키마 검증→정책 검증→효과 게이트(승인).
- 구조화 출력은 json_mode+재파싱 검증으로 하고 실패는 결정론 폴백으로 간다.
- 권한 상승 값(토큰·코드)은 모델이 만들 수 없다 — 사용자 텍스트에서만 온다.

## 이 프로젝트 적용

- validate_calls의 토큰=사용자 텍스트 규칙이 가장 강한 가드레일이다.
- json_mode+verify_claims+결정론 추출 폴백이 구조화 실패 체인이다.
- plan→token→apply 게이트가 효과 게이트다.
