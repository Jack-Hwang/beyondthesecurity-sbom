# A2UI 분석과 우리 도구로의 채택 (BTS UI Cards)

- 날짜: 2026-11-28
- 대상: https://github.com/a2ui-project/a2ui (Sparx 사례와 같은 "설치물 REA"가 아니라 공개 명세·소스 분석; 클론 후 `specification/v1_0/docs/a2ui_protocol.md` 정밀 독해)
- 라이선스: A2UI는 **Apache-2.0**. 우리는 코드를 한 줄도 가져오지 않는 **명세 수준 클린룸 채택**(기존 판례: ADR-0023·0024, GPL/AGPL 판정 문서의 원칙)이며, 영감 출처를 이 문서로 명시한다.

## 1. A2UI가 무엇인가 (관찰)

A2UI(Agent-to-User Interface)는 "에이전트가 레이아웃 데이터를 스트리밍하고, 앱이 네이티브 컴포넌트로 렌더하는"
제너러티브 UI 프레임워크다. 핵심 결정 세 개:

1. **UI는 코드가 아니라 데이터다** — 에이전트는 HTML/JS를 만드는 게 아니라, 카탈로그에 등록된 컴포넌트
   (Text·Row·Column·Card·List·Button·TextField·CheckBox·ChoicePicker·Image·Icon·Divider)의 조합을
   스키마 검증된 JSON으로 스트림한다. 임의 실행 코드는 금지된다.
2. **엔벨로프 프로토콜** — v1.0의 에이전트→렌더러 메시지는 정확히 하나의 키를 갖는다:
   `createSurface` / `updateComponents` / `updateDataModel` / `deleteSurface` / `callRendererFunction` /
   `agentFunctionResponse`. 렌더러는 surface별 `catalogId`를 고정하고(카탈로그 협상), 데이터는 `@path`로
   데이터 모델에 바인딩한다.
3. **실행 경계** — 렌더러 함수는 `rendererOnly`/`agentOnly`/`rendererOrAgent` 경계와
   `requiresUserActivation`을 카탈로그가 선언하고, 렌더러가 런타임에 강제한다(위반 시 `INVALID_FUNCTION_CALL`).
   즉 에이전트가 UI를 통해 임의 동작을 트리거할 수 없다.

## 2. 우리 도구와의 접점 (추론)

우리 챗 파이프라인은 이미 A2UI가 푸는 문제의 절반을 갖고 있다: 도구 결과는 결정론적 데이터(라인 배열)이고,
채널은 SSE 7종이며, 렌더러(챗 독)는 신뢰 경계 밖의 텍스트를 절대 innerHTML로 넣지 않는다. 빠진 절반은
"**에이전트 턴이 구조화된 UI를 제안할 형태의 어휘**"였다 — 지금은 모든 결과가 산문 `lines`로만 담긴다.

A2UI 패턴을 그대로 이식하면(작게, 정직하게):

| A2UI 개념 | 우리 판 (BTS UI Cards) |
|---|---|
| 카탈로그(Basic Catalog) | `ui_cards.CATALOG` — SBOM 도메인 카드 8종(stat_row·table·kv·decision·approval_request·progress·findings_badges·diagram_ref), 각 kind별 스키마 |
| `createSurface/updateComponents` | 도구 결과 후처리: `_run`이 도구 결과를 카드로 변환해 `p["cards"]`로 부착 (에이전트가 아니라 **결정론 변환기가 UI를 만든다** — A2UI보다 한 단계 더 강한 경계) |
| 스키마 검증·validator compliance | `validate_cards()` — 엄격 검증(알 수 없는 kind·초과 행·비문자 필드·과다 카드는 드롭+사유 라인), **불량 카드는 전송되지 않고 산문 폴반이 항상 남는다** |
| 카탈로그 협상(catalogId 고정) | `GET /api/ui/catalog` — 렌더러(독)가 지원 종류를 서버에서 읽음; 렌더러가 모르는 kind는 무시(산문이 답한다) |
| 데이터 바인딩(`@path`) | 채택하지 않음 — 우리 카드는 값 자체를 담는다(모델이 쓴 값이 아니라 도구가 측정한 값이므로 간접 참조가 늘 이득이진 않다) |
| `callRendererFunction`·사용자 활성 | **의도적 기각** — 클릭 액션 채널을 에이전트에 주면 우리의 승인 토큰·확인 코드 게이트(사용자가 직접 타이핑한 값만 유효)가 우회된다. 승인은 산문+기존 독 버튼 그대로 유지 |
| 다중 프레임워크 렌더러 | 채택하지 않음 — 우리 렌더러는 챗 독 하나(vanilla DOM) |

## 3. 구현 표면

- `bts_sbom_app/ui_cards.py` — 카탈로그·검증기·도구→카드 빌더(결정론, 상한: 턴당 4장·표 8행·문자열 90자).
- `chat.py::_run` 후처리 1곳, `ask()` 수집 2줄·응답 2곳, `chat_stream.py` final 1필드 — SSE와 JSON 응답 모두 `cards`로 이동.
- `server.py` `GET /api/ui/catalog` — 카탈로그 협상.
- `web/bts_chat_panel.js`·`web/bts_ui.js` — 네이티브 렌더(textContent 전용, kind 미지원 시 산문 폴백).
- 테스트 `tests/bts_sbom_app/test_ui_cards.py` — 스키마 거부·빌더·XSS 소재(값에 `<script>`가 들어가도 데이터로만 전송됨)·상한.

## 4. 정직 한계

- A2UI 프로토콜을 구현한 것이 아니라, 그 **설계 원칙 4개(데이터 전용·스키마 검증·카탈로그 협상·실행 경계)를
  우리 규모에 맞게 채택**한 것이다. 와이어 호환성은 없다.
- 카드는 산문의 치환이 아니라 보조다 — 산문 라인은 항상 함께 전송되며, 카드 렌더가 실패하면 산문이 답한다.
- 에이전트(LLM)는 카드를 만들지 못한다. 만드는 주체는 도구 후처리(결정론 코드)다 — 프롬프트 주입이 UI를
  조작할 길이 원천 차단된다.
