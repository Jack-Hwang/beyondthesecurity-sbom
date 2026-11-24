# ai agents with mcp

출처: AI Agents with MCP (Stratis) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 호스트 앱이 MCP 클라이언트 역할을 하고 서버가 도구·리소스·프롬프트를 표준으로 노출한다.
- MCP 전송은 stdio와 HTTP 두 계열이고 로컬 도구는 stdio가 기본이다.
- 도구 스키마는 JSON Schema로 자기 서술적이어야 모델이 안전하게 호출한다.
- sampling·elicitation 같은 서버에서 호스트로의 역방향 요청도 프로토콜에 있다.

## 이 프로젝트 적용

- G2로 미뤄뒀던 MCP 서버를 이 책 기준으로 구현한다: stdio + JSON-RPC 2.0 + tools/list, tools/call (AC-534).
- chat.py TOOL_CATALOG가 도구 스키마의 원천이다 — 이중 정의를 만들지 않는다.
