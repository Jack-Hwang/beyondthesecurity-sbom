# building agentic ai systems build connected agent systems with mcp a2a agent loo

출처: Building Agentic AI Systems (Biswas & Talukdar) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- MCP는 에이전트-도구, A2A는 에이전트-에이전트 연결 — 역할이 다른 두 프로토콜이다.
- A2A는 Agent Card로 상대 에이전트의 능력을 먼저 발견한다.
- 오케스트레이터는 상태를 소유하고 서브에이전트는 작업 단위로 격리된다.

## 이 프로젝트 적용

- A2A 스타일 Agent Card를 /api/agent-card로 구현해 우리 에이전트 능력을 기계가 읽게 한다 (AC-535).
- handoff.py의 스테이지 계약이 오케스트레이터 상태 소유를 문서 수준으로 구현했다.
