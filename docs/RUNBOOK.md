# RUNBOOK — BTS-SBOM app service

운영 런북. 이 서비스는 원래 **localhost 전용·인증 없음**인 도구다(서버 기본 바인딩 `127.0.0.1`, 인증 없음 — `server.py` docstring).
컨테이너 안에서는 `0.0.0.0` 으로 바인딩되며, 호스트에서는 `docker run -p 127.0.0.1:8800:8800` 처럼 localhost 로만 publish 해야 한다.
Azure 배포(클라우드 모드) 전까지 이 전제는 유효하다. 측정값은 이 저장소의 실제 존재하는 지표만 쓴다(오토스케일·APIM 등 이 제품에 없는 것은 적지 않는다).

## Delivery State

- 코드 상태: `main` 커밋 `00c0401` 이후 `course/glm` 브랜치에서 작업 중(커밋 전).
- 테스트: `python -X utf8 -m pytest -q -p no:cacheprovider tests/bts_sbom_app` (기준선 232 → 현재 318 passed, 1 skipped).
- 컨테이너 이미지: **NOT BUILT** (`docker build` 미실행 — 작업 환경에 Docker 없음). `Dockerfile.bts-sbom-app` 첫 줄 주석도 같은 사실을 적는다.
- 배포: **NOT DEPLOYED** (Azure 구독 없음).

## Deployment

- 인증(클라우드 모드): `BTS_SBOM_API_TOKEN`(Bearer) 또는 `BTS_SBOM_TRUST_IDENTITY_HEADER=1` + `BTS_SBOM_IDENTITY_HEADER`.
  **신원 헤더 방식은 App Service 인증(Easy Auth) 뒤에서만 안전하다** — 앱이 직접 노출되면 클라이언트가 헤더를 위조할 수 있다.
  두 방식 모두 없으면 프로브를 뺀 모든 /api 가 503 auth_not_configured 로 닫힌다(fail-closed).
  감사 로그는 `<evidence>/audit.jsonl` (해시 체인, `bts_sbom_app.audit.AuditLog.verify()` 로 검증).

- 로컬 실행: `python -m bts_sbom_app --root <repo> serve` (기본 `127.0.0.1:8800`, evidence 폴더 기본 `<root>/evidence/runs`).
- 컨테이너: `docker build -f Dockerfile.bts-sbom-app -t bts-sbom-app .` → `docker run --rm -p 127.0.0.1:8800:8800 bts-sbom-app`.
  - 비루트(숫자 UID 10001), `HEALTHCHECK`는 `/readyz` 를 호출(스탠다드 urllib, curl 설치 없음), 베이스 이미지는 마이너 고정(`python:3.12-slim`, `latest` 금지).
  - 증거 폴더는 컨테이너 안 `/var/lib/bts-sbom/evidence`(10001 소유). 재시작 사이에 증거를 남기려면 볼륨 마운트로 유지한다.
- 준비 상태: 트래픽을 받기 전 `GET /readyz` 가 200 인지 확인한다(증거 폴더 쓰기 가능, 코어 import, `knowledge/` 코퍼스 존재 3점검). 503 이면 본문의 `failed` 목록(점검 이름만)을 본다.
- 스캔 진행 상황: `GET /api/jobs/<id>/events` (SSE, `Last-Event-ID` 이어받기, 하트비트 주석 줄). 폴백은 기존 `GET /api/jobs/<id>` 폴링.

## Cleanup (비용 안전)

데모 종료 시 `azd down --purge` 로 리소스를 지우고, `az resource list` 로 구독에 남은 리소스를 확인한다.
자세한 절차·비용 수식은 `docs/COST.md` 와 `python -I -X utf8 tools/cost_estimate.py` 를 본다.

## Rollback

- 이 서비스는 아직 배포 슬롯이 없으므로(단일 로컬/컨테이너 실행) 롤백은 **프로세스/이미지 되돌리기**다.
- 측정 가능한 트리거(임계값은 이 제품의 실제 지표 기준):
  - `GET /readyz` 가 **연속 3회** 503 (점검 실패: 증거 폴더 비가용, 코어 import 실패, 코퍼스 누락).
  - 작업 결과 상태 `error` 비율: 최근 10작업 중 **3 이상**(`GET /api/history` 의 `stage_errors`·`metrics` 확인).
  - `net.STATS` 의 `failures` 가 세션 시작 대비 **10배** 이상 급증하거나 `short_circuited` > 0 이 지속되면 외부 정보원 접근이 깨진 것(서비스 로직 문제는 아님 — 네트워크·정보원 확인 후 재시작).
- 되돌리기: 이전 이미지 태그로 컨테이너 재시작(`docker run` 이전 태그), 로컬이면 이전 커밋의 워크트리에서 `serve`. 적용된 패치의 롤백은 제품 안에 이미 있다(`patch.py` revert, 회귀 시 자동 revert — AC-18).

## Monitoring

- 프로브: `GET /healthz` (항상 200, 1초 이내)와 `GET /readyz` (3점검, 실패 시 503 + 점검 이름만). 컨테이너 HEALTHCHECK 는 `/readyz` 를 30초 간격으로 호출한다.
- 요청 통계: `net.STATS` (`requests`, `failures`, `short_circuited`, `empty`, `partial`, `last_error`) — 외부 정보원(OSV·deps.dev·PyPI·npm·Maven·endoflife.date) 호출의 정직한 계수. `/api/health` 응답의 `llm` 필드에 EXAONE 호출 수·장부도 나온다.
- 로그: 요청마다 stdout 에 **한 줄 JSON**(`{"ts","level","event","request_id","job_id","route_class","status","ms"}`, 신원이 있으면 `who`). 본문·쿼리 문자열·Authorization·API 키·승인 토큰·URL 자격 증명은 절대 기록되지 않는다. 요청 id는 응답 헤더 `X-Request-Id` 로 돌아오고(안전한 형식일 때만 재사용), 이어지는 요청에 넣으면 추적이 이어진다.
- `/metrics`: Prometheus 텍스트. `bts_sbom_requests_total{route_class,status_class}`(route_class 는 고정 집합 — 원시 경로는 라벨이 아니다), `bts_sbom_jobs_total{state}`, `bts_sbom_jobs_running`, `bts_sbom_job_seconds_sum/_count`, `bts_sbom_net_failures_total`, `bts_sbom_net_short_circuited_total`. 클라우드 모드에서는 인증 필요(/healthz·/readyz 만 무인증).
- SLI/SLO 표 — **모든 수치는 가정(assumption)이다**: 실제 사용자 요구를 측정한 적이 없으므로 배포 후 실측으로 바꾼다.

  | SLI | SLO(가정) | 경보(가정) |
  |---|---|---|
  | `/readyz` 가용성 | 99% over 30일 (가정) | 5분 연속 503 → Sev2 |
  | 작업 성공률 `done/(done+error)` | 95% (가정) | 15분 동안 error 비율 > 5% → Sev2 |
  | 스캔 소요 p95 (`job_seconds`) | 300초 (가정) | p95 > 600초 15분 → Sev3 |
  | 외부 조회 실패율 (`net_failures_total` / requests) | 5% (가정) | circuit breaker short_circuited > 0 지속 → Sev3 |

- Log Analytics 의 JSON 로그 쿼리 **예시(미검증 — 실제 컬럼 이름은 확인 필요)**:
  - 실패한 요청: `AppConsoleLogs | where Event == "http_request" | where Status >= 500 | summarize count() by bin(TimeGenerated, 5m)`
  - 느린 스캔: `AppConsoleLogs | where RouteClass == "scan" | summarize percentile(Ms, 95) by bin(TimeGenerated, 15m)`
  - 드레인: `AppConsoleLogs | where Event contains "drain"`
- SSE 스트림: 구독자 상한 4(5번째는 429), 작업당 이벤트는 `job_start` → `step_*` → (`patch_gate`) → `final`/`error`. 승인 토큰은 이벤트에 절대 없다.
- 알려진 한계(정직 기록): 클라우드 모드의 소스 정책은 DNS 를 한 번 확인한 뒤 git 이 다시 해석한다 — 이 사이 주소가 바뀌는 TOCTOU 창이 남는다(완전히 막으려면 주소 고정이 필요, 이번 범위 밖). 클라우드 모드에서는 인증(작업 10)과 함께 이 한계를 감안해 배치한다.
