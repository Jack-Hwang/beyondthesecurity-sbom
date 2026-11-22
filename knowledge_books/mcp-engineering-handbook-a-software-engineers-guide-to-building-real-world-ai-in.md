# mcp engineering handbook a software engineers guide to building real world ai in

출처: MCP Engineering Handbook (Pedersen) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 실전 MCP 서버는 작게 시작한다: 도구 몇 개, 명확한 스키마, 표준 에러 코드.
- 전송·세션·보안(원격 서버 신뢰)을 설계 초기에 결정한다.
- 도구 이름과 설명이 곧 모델의 사용성이다 — 카탈로그 문서가 API 문서다.

## 이 프로젝트 적용

- mcp_server.py를 stdlib stdio JSON-RPC로 구현한다: initialize/tools/list/tools/call + 표준 에러 (AC-534).
- 도구는 기존 API 재사용: engine_status, book_search, project_overview, chat_ask — 새 로직 없이 위임.
