# loop engineering for ai agents design reliable agentic ai systems beyond the pro

출처: Loop Engineering for AI Agents (Papalini) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 신뢰성은 프롬프트 밖의 루프에서 나온다: 계획→실행→검증→수정의 명시적 사이클.
- 재시도는 상한과 동일오류 중단이 있어야 무한루프가 아니다.
- 루프의 각 단계는 관측 가능해야 한다.

## 이 프로젝트 적용

- nl2sql 자기교정 루프(오류 첨부·상한 3회·동일오류 즉시 중단)가 이 책 루프의 직접 구현이다 (AC-512).
- events.py 단계 이벤트가 루프 관측의 구현이다.
