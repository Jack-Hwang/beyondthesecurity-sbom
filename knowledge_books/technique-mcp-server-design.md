# technique mcp server design

출처: MCP Engineering Handbook + AI Agents with MCP 종합 (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- MCP는 JSON-RPC 2.0 위의 3원 책정(도구/리소스/프롬프트)이고 초기화 핸드셰이크로 능력을 협상한다.
- stdio 전송은 한 줄·한 메시지로 충분하고 서버는 비프로토콜 출력을 절대 섞지 않는다.
- 도구 오류는 result.isError로 모델에게 보이게 전달한다 — 예외로 숨기지 않는다.
- 호스트가 주입하는 경로/환경을 신뢰하지 않고 경계에서 검증한다.

## 이 프로젝트 적용

- 구현: bts_sbom_app/mcp_server.py (stdlib, stdio). 도구: engine_status, book_search, project_overview, chat_ask.
- 오류는 isError+메시지 — 우리 4상태 철학과 동일하다 (AC-534).
