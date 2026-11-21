# ADR-0013: Scan progress as SSE; the event set is six types

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/events.py`(신규), `bts_sbom_app/server.py`(`/api/jobs/<id>/events`, /healthz, /readyz), `bts_sbom_app/pipeline.py:_Stages/run_project(progress=)`. AC: BSA-AC-336~354, 테스트 `tests/bts_sbom_app/test_events_sse.py`·`test_ops_probes.py`·`test_container_policy.py`.

## 근거 (Context)
스캔 진행은 `GET /api/jobs/<id>` 폴링뿐이었다. 강의 4주차 3차시는 SSE 이벤트 스키마(token/step_start/tool_call/tool_result/handoff/final/error)와 HITL, 구조화 오류 봉투(error_type, severity, retryable, recovery_hint)를 가르친다. 이 제품은 `http.server` 표준 라이브러리 기반이고 스캔은 모델 토큰 스트리밍이 아니다.

## 결정 (Decision)
스키마 `bts-sbom.events.v1`, 6종(job_start/step_start/step_end/patch_gate/final/error)으로 축약한다. 모든 이벤트에 단조 증가 seq·type·schema. `EventBus`는 검증 실패 이벤트를 거절(미발행), Last-Event-ID 이어받기, 구독자 상한 4, 하트비트 주석(`: keepalive`), final/error 뒤 스트림 종료. patch_gate에는 승인 토큰이 절대 들어가지 않는다(상태만). 파이프라인은 선택 콜백 `progress=` 를 받고 콜백 예외는 `stage_errors["progress_callback"]` 한 번 기록 후 계속. `/healthz`(항상 200)·`/readyz`(3점검, 실패 시 점검 이름만 503)를 추가.

## 기각 대안 (Rejected alternatives)
- 폴링 유지: 지연·불필요한 요청 — 작업이 끝나기 전까지 클라이언트가 주기적으로 다시 물어야 한다.
- WebSocket: 표준 라이브러리 `http.server` 로 구현 부담이 크고 양방향이 불필요하다(서버 → 클라이언트 단방향이면 충분).
- 장기 폴링: SSE 보다 타임아웃·재접속 처리가 복잡하고 표준 이어받기(Last-Event-ID)가 없다.
- 강의의 7종 이벤트 그대로: token/handoff/tool_call/tool_result 는 이 제품의 스캔에 해당 상황이 없다(모델 토큰 스트리밍 없음, 도구 호출은 챗 계층의 일).

## 결과 (Consequences)
기존 `/api/scan`·`/api/jobs/<id>`·`/api/health` 응답 모양은 불변(AC-354). 클라우드 모드(작업 10 이후)에서 SSE 는 인증 뒤에 둔다. 헬스 체크 3점검의 이름만 실패 본문에 나온다(경로·예외 비노출, AC-345).
