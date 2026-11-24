# technique a2a agent card

출처: Building Agentic AI Systems(A2A 절) + handoff 계약 종합 (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- A2A의 발견 단위는 Agent Card: 이름·버전·스킬·입출력·보안을 JSON으로 공개한다.
- 스킬은 id·설명·입출력 모드를 자기 서술해야 오케스트레이터가 자동 조립한다.
- 카드는 능력 선언일 뿐 실제 상태가 아니다 — 런타임 확인은 별도 프로브(readyz)다.

## 이 프로젝트 적용

- 구현: GET /api/agent-card — skills: scan, patch(승인 게이트), council, chat(stream), book_search, nl2sql.
- capabilities.streaming=true(SSE), securitySchemes none-localhost를 정직히 표기한다 (AC-535).
