# OSV 실시간 연동: 빠른 취약점 리포트 설계와 구현

Google OSV(https://osv.dev)를 BTS-SBOM에 "빠르게, 가능한 한 실시간으로" 연결하는 방법을 분석하고 구현한 기록입니다.
모든 수치는 실제 `api.osv.dev`와 OSV 공개 버킷에 대해 `scripts/osv_bench.py`로 측정한 값이며(한국에서 측정, 왕복 지연 약 180 ms),
측정 전에 세운 가정 중 하나가 틀렸다는 것도 그대로 적었습니다.

## 1. 결론 먼저

| 질문 | 답 |
|---|---|
| 기존 구조의 병목은? | **네트워크 요청 수**입니다. 컴포넌트마다 `POST /v1/query`를 1회, 매번 새 TLS 연결, 호출마다 0.1초 sleep, 워커 8개였습니다. 계산은 병목이 아니었습니다. |
| OSV DB를 "실시간"으로 가져오는 방법은? | OSV는 버킷 `gs://osv-vulnerabilities/<생태계>/modified_id.csv`(최신순 변경 목록)를 공개합니다. 첫 64 KiB만 Range로 읽고, 이미 처리한 시각에서 멈추고, 바뀐 레코드만 내려받습니다. DB 전체를 다시 받을 필요가 없습니다. |
| 얼마나 빨라졌나? | 취약점이 많은 94개 컴포넌트(advisory 1,671건) 기준 **10.6~13.6초 -> 5.5초**(연결 재사용 + 24 워커), 변경 피드로 검증되는 캐시가 따뜻하면 **0.8초, 요청 2건**. 결과는 모든 전략에서 동일했습니다(94개 컴포넌트 전부, advisory 1,671건 일치). |
| "실시간"의 실제 한계는? | OSV가 advisory를 버킷으로 내보내는 데 **몇 분**이 걸립니다(측정 시 약 3분). 그래서 피드 기반 모드는 "마지막 피드 동기화 시점 기준 최신"이며, 그렇게 표기합니다. API를 직접 묻는 경로(`auto`/`batch`/`single`)는 그 지연이 없습니다. |

## 2. 기존 구조 분석

- `osvscanner._query_online` -> `OsvClient.post_query`: 컴포넌트당 `POST /v1/query` 1회. `urllib.request.urlopen`이라 호출마다 TCP + TLS 핸드셰이크(왕복 3회 안팎), 성공해도 `time.sleep(0.1)`.
- `_prefetch`: 워커 최대 16(기본 8). 300개 컴포넌트면 약 300/8 x (왕복 + 서버 처리 + 0.1초) 만큼 걸립니다.
- 오프라인 DB(`osv_local_db`): `all.zip`을 통째로 **메모리(`BytesIO`)** 에 받아 풀고, 이후 갱신 수단이 없습니다(다시 통째로 받는 수밖에 없음). 신선도는 `imported_at` 하나뿐입니다.
- `OsvClient.query_batch`: 구현은 있으나 스캐너가 쓰지 않았고, OSV의 `querybatch`가 **id와 modified만** 돌려준다는 사실을 몰라 전체 레코드가 온다고 가정했으며 `next_page_token`을 따라가지 않았습니다.
- 알려진 정확성 결함 하나: GIT 범위의 `fixed`(커밋 해시)를 "수정 버전"으로 취급했습니다(`docs/CORE_ISSUES.md` #1). 빠른 경로가 같은 결함을 물려받지 않도록 함께 고쳤습니다.

## 3. OSV가 실제로 제공하는 것 (공식 문서와 라이브 확인)

- `POST /v1/query`: 패키지+버전 하나에 대한 **전체 레코드**.
- `POST /v1/querybatch`: 여러 질의를 한 번에. 결과는 질의당 `{id, modified}`만 돌려줍니다. 질의 하나가 1,000건 초과이거나 배치 합계가 3,000건 초과면 `next_page_token`으로 페이지가 나뉩니다.
- `GET /v1/vulns/{id}`: 레코드 하나.
- 공식 문서: 속도 제한 없음, HTTP/1.1 응답 32 MiB 제한.
- 버킷 `https://storage.googleapis.com/osv-vulnerabilities/`: `<ECO>/all.zip`, `<ECO>/<ID>.json`, `<ECO>/modified_id.csv`(행 형식 `<RFC3339 modified>,<ID>`, 최신순), `ecosystems.txt`. 버전이 붙은 생태계(`Debian:12`)의 디렉터리는 기본 이름(`Debian`)입니다.
- 라이브 확인: PyPI 피드 전체는 1.1 MB(1,158,242 B)이고 `ETag`가 있으며 Range/`If-None-Match`가 동작합니다(206/304). 첫 64 KiB만으로 최근 변경분을 얻습니다.

## 4. 추론: 무엇이 "빠름"이고 무엇이 "실시간"인가

1. 왕복 지연이 180 ms면 **요청 수 x 지연 / 동시성**이 곧 시간입니다. 줄이는 방법은 요청을 합치거나(batch), 아예 안 하거나(검증된 캐시), 동시성을 올리고 연결을 재사용하는 것입니다.
2. "실시간"은 두 지연의 합입니다. (a) OSV가 advisory를 버킷으로 내보내는 지연, (b) 우리가 피드를 확인하는 주기. 피드 확인 비용이 몇 KiB 또는 304라서 (b)는 분 단위로 줄일 수 있습니다.
3. 캐시를 믿으려면 **무효화가 정확해야** 합니다. 변경 피드가 바로 그 신호입니다. 어떤 advisory 개정이 어떤 패키지를 건드렸는지(예전에 나열했다가 빠진 패키지 포함)를 기록하면, 그 패키지의 캐시 답만 버릴 수 있습니다.
4. 로컬이 **판단**하지 않습니다. watch는 로컬 사본으로 "무엇을 다시 볼지"만 정하고, 취약 여부는 OSV API가 결정합니다(우리 버전 비교기가 판정의 근거가 되지 않음). 완전한 미러(`--full`)만 로컬에서 "advisory 없음"이라고 답할 수 있고, 부분 미러(lazy)는 구조적으로 그럴 수 없습니다.

## 5. 설계

```
                      +--------------------- OSV (Google) ---------------------+
                      | api.osv.dev            osv-vulnerabilities 버킷        |
                      | query / querybatch     <ECO>/modified_id.csv (피드)    |
                      | vulns/{id}             <ECO>/<ID>.json, all.zip        |
                      +-----------+------------------------+-------------------+
                                  |                        |
                   osv_http  (keep-alive 풀, 재시도+jitter, Retry-After, gzip, Range 이어받기)
                                  |                        |
                 osv_fast (batch + 레코드 캐시)     osv_mirror (피드 폴링, 워터마크, sqlite)
                                  |                        |
                 osvscanner._prefetch  -- 전략 선택 --  validated_cache (피드로 검증된 캐시)
                                  |                        |
                         scan 리포트                osv_watch (변경 -> 후보 -> 재확인 -> 이벤트)
```

모듈은 모두 표준 라이브러리만 씁니다(`http.client`, `sqlite3`, `concurrent.futures`, `zipfile`).

| 모듈 | 역할 |
|---|---|
| `_internal/osv_http.py` | 스레드별 keep-alive 연결, 429/5xx/네트워크 오류 재시도(지수 백오프+jitter, `Retry-After` 존중), gzip, 프록시가 있으면 urllib로 자동 전환, 큰 파일 스트리밍 다운로드(Range 이어받기). **404/304는 답이고 5xx/네트워크 오류는 실패**로 구분하며, 실패는 빈 결과로 둔갑하지 않습니다. |
| `_internal/osv_mirror.py` | 로컬 sqlite 레코드 저장소 + 변경 피드 동기화. 워터마크는 모든 처리가 끝난 뒤에만 전진합니다. 실패한 레코드는 다음 폴링에서 다시 시도합니다. `lazy`(피드 변경분과 API로 받은 레코드만)와 `full`(`all.zip` 부트스트랩 후 증분 유지) 두 모드. |
| `_internal/osv_fast.py` | `querybatch`(페이지 추적, 400이면 이분 탐색) + 레코드 캐시(`modified`로 검증). 캐시에 없는 advisory가 많은 컴포넌트는 `/v1/query` 1회, 적은 컴포넌트는 `/v1/vulns/{id}`. |
| `_internal/osv_watch.py` | 피드 변경 -> 영향받는 컴포넌트만 OSV에 재확인 -> `new` / `updated` / `resolved` 이벤트(advisory의 `modified`와 감지 시각의 차이 `lag_s` 포함). |
| `osvscanner.py` | `_prefetch`가 전략을 고릅니다. OSV 자체가 응답하지 않으면(모든 재시도 실패) 컴포넌트마다 같은 요청을 반복하지 않고 곧바로 "도달 불가"로 보고합니다. |

### 전략 (`bts-sbom scan --osv-mode ...`, 환경변수 `BTS_SBOM_OSV_MODE`)

| 모드 | 동작 | 언제 |
|---|---|---|
| `single` | 컴포넌트당 `/v1/query`, 연결 재사용, 24 워커 | 항상 안전한 기본 경로 |
| `batch` | `querybatch`로 id+modified를 한 번에 받고, 변경된 advisory만 다시 받음 | 캐시가 따뜻할 때 |
| `auto`(기본) | 컴포넌트 8개 이상이고 50% 이상이 이미 캐시에 있으면 `batch`, 아니면 `single` | 대부분 |
| `feed` | 변경 피드가 "아직 유효하다"고 증명하는 캐시 답만 로컬로 반환, 나머지는 OSV에 질의 | 반복 스캔, 대시보드, 서버 |

`feed`의 유효 조건(모두 충족): 이번 스캔에서 해당 생태계 피드 동기화가 성공했고, 답이 피드 추적이 시작된 뒤에 저장되었고, 그 패키지를 건드린 advisory 개정의 `modified`가 저장 시각 - 120초 이전입니다(시계 오차 여유). 하나라도 어긋나면 그 컴포넌트만 OSV에 묻고, 사유는 `scan_status.feed_validated.not_validated_reasons`에 남습니다.
`feed` 답은 `queried_offline`(로컬 데이터, 마지막 동기화 시점 기준)으로 표기하고 실시간 질의로 위장하지 않습니다.

## 6. 측정 (실제 OSV, `python scripts/osv_bench.py`)

입력: PyPI 64개 + npm 30개 = 94개 컴포넌트, 오래된 고정 버전이라 advisory가 1,671건(컴포넌트당 평균 약 18건).

| 시나리오 | 시간 | HTTP 요청 | 비고 |
|---|---:|---:|---|
| 기존: 요청마다 새 TLS, 0.1초 sleep, 워커 8 | 10.6 ~ 13.6초 | 94 | 3회 측정 범위 |
| 연결 재사용 + 워커 24 (`single`) | 5.5초 | 94 | 약 2배 |
| `auto` 콜드 | 5.5초 | 94 | 캐시가 비어 `single` 선택 |
| `auto` 웜 (`batch`) | 4.3 ~ 4.6초 | 1 | `querybatch` 한 번이 약 3.9초(서버 쪽 처리) |
| `feed` 콜드 | 6.0초 | 96 | 피드 추적 시작 |
| **`feed` 웜** | **0.8초** | **2** | 94개 전부 검증된 캐시에서 응답 |
| `batch` 강제, 콜드 | 10.0초 | 103 | 이 경우 `auto`가 피한 선택 |
| 피드: 변경 없음 확인 | 0.08 ~ 0.2초 | 1/생태계 | 304 또는 첫 64 KiB |
| 피드: 하루치 변경 받기 | 0.97초 | 155 | 154개 레코드(PyPI) |

### 측정 전 가정이 틀린 부분

처음 구현은 `querybatch`로 id만 받고 advisory를 하나씩 `GET /v1/vulns/{id}`로 받았습니다. 콜드 캐시에서 **요청이 1,671건이 되어 38초**가 걸렸고 기존 방식(13.6초)보다 느렸습니다. 왕복 지연 때문에 "요청 수"가 곧 시간인데, advisory가 많은 컴포넌트는 `/v1/query` 한 번이 레코드를 통째로 주기 때문입니다. 그래서 (1) 캐시에 없는 advisory가 많은 컴포넌트는 `/v1/query` 1회로 받고, (2) `auto`는 캐시가 따뜻할 때만 `batch`를 고르도록 바꿨습니다. 또 `querybatch` 자체가 이런 입력에서는 느려서(약 3.9초) 요청을 쪼개 병렬로 보내도 줄지 않았습니다. 그래서 따뜻한 캐시의 진짜 이득은 `batch`가 아니라 **`feed`(요청 자체를 하지 않음)** 쪽에서 나왔습니다.

## 7. 사용법

```bash
# 변경 피드 동기화 (첫 접속은 "지금부터" 추적 시작, 이후는 바뀐 레코드만 받음)
bts-sbom osv sync --target ./my-project
bts-sbom osv sync --ecosystem PyPI --ecosystem npm
bts-sbom osv sync --ecosystem PyPI --full      # all.zip으로 완전한 미러를 한 번 만든 뒤 증분 유지
bts-sbom osv status

# 빠른 스캔 (캐시가 따뜻하면 요청 거의 없이 응답)
bts-sbom scan ./my-project --osv-mode feed --gate

# 새 advisory가 나오는 즉시 알림 (cron/CI: --once, 종료 코드 0 조용함 / 1 새 항목 / 2 오류)
bts-sbom osv watch ./my-project --interval 300 --state watch.json --events events.jsonl
bts-sbom osv watch ./my-project --once --json
```

`osv watch` 출력 예: `2026-11-17T11:30:37Z NEW       HIGH     GHSA-xxxx (CVE-...)  requests@2.19.1 [PyPI]  fix: 2.20.0  lag 142s`.
`--state`를 주면 프로세스가 꺼져 있던 동안 생긴 변경도 재시작 후 첫 주기에 보고합니다.

환경변수: `BTS_SBOM_OSV_MODE`(`auto|batch|single|feed`), `BTS_SBOM_OSV_WORKERS`(기본 24, 최대 64), `BTS_SBOM_OSV_API_BASE`, `BTS_SBOM_OSV_DUMP_BASE_URL`, `BTS_SBOM_OSV_DB_PATH`, `BTS_SBOM_OSV_TIMEOUT`.

## 8. 정직성 계약과 한계

- **네트워크 실패는 빈 결과가 아닙니다.** `osv_http`는 5xx/네트워크 오류를 `ok=False`로 돌려주고, 빠른 경로는 advisory 레코드를 하나라도 못 받으면 그 컴포넌트를 "답함"으로 처리하지 않고 컴포넌트별 경로로 되돌립니다. 배치가 OSV 도달 불가를 확인하면 같은 요청을 컴포넌트마다 반복하지 않고 기존의 `unqueried` / `network_failure` 판정으로 이어집니다.
- **워터마크는 앞서 가지 않습니다.** 레코드 다운로드가 하나라도 실패하면 워터마크와 ETag를 그대로 두고 다음 폴링에서 같은 항목을 다시 시도합니다. 피드를 끝까지(또는 워터마크까지) 읽지 못하면 "최신"이 아니라 오류로 보고합니다. 워터마크와 같은 시각의 행은 다시 확인합니다(같은 시각의 advisory가 서로 다른 폴링에 나타날 수 있기 때문).
- **피드 모드의 한계**: "마지막 동기화 시점 기준". OSV의 버킷 내보내기 지연(몇 분)만큼 API보다 늦을 수 있습니다. 보수적으로 어긋나는 쪽(불필요한 재질의)은 허용하고, 최신이 아닌 답을 최신으로 내는 쪽은 허용하지 않도록 설계했지만, 이 가정은 실제 장기 운영으로 검증되지 않았습니다.
- **부분 미러(lazy)는 부정 답을 못 합니다.** `--full`로 부트스트랩한 생태계만 로컬에서 "advisory 없음"이라고 답할 수 있습니다.
- 검증하지 못한 것: Python 3.10에서의 실행(설치된 인터프리터가 3.12뿐), 며칠 단위로 켜 둔 `watch`, 수십만 건 `all.zip` 부트스트랩의 시간/메모리, HTTP/2(표준 라이브러리에 없어 HTTP/1.1만 사용; OSV는 큰 응답에 HTTP/2를 권장).
- 기존 `exact_cache`는 TTL이 없고 `queried_offline`의 신선도는 저장 시각 기준이라는 점은 그대로입니다. `feed` 모드는 이 캐시를 건드리지 않고 "지금도 유효한지"만 판정합니다.

## 9. 적대적 리뷰 결과와 수정

구현 후 5개 관점(프로토콜 적합성, 저장소/동시성, 신선도 정당성, 정직성/호환성, 보안/견고성)으로 리뷰를 돌렸고,
검증자 2명이 반박을 시도해 확인된 결함 17건을 모두 고쳤습니다. 각 수정에는 재현 테스트가 있습니다(`tests/test_osv_live.py`, 68개).

| 심각도 | 결함 | 수정 |
|---|---|---|
| 치명 | 변경 피드를 여러 페이지로 읽는 도중 객체가 갱신되면 최신 advisory를 조용히 버리고 "성공"으로 보고 | 이후 페이지를 첫 페이지의 ETag에 고정(`If-Range`), 바뀌면 처음부터 다시 읽고, 3회 안에 안정되지 않으면 오류. 깨진 행도 오류 |
| 치명 | `max_fetch` 때문에 일부 변경을 보류했는데도 "최신"으로 표시해, 아직 못 받은 advisory가 걸린 패키지의 캐시 답이 유효로 판정됨 | 보류가 있으면 `last_ok`를 지워 검증을 거부, 스캐너도 보류된 생태계는 검증 대상에서 제외 |
| 치명 | `watch` 상태 파일만 남고 미러 DB가 초기화/이동되면 피드를 "지금"으로 다시 잡아 그 사이 변경을 조용히 건너뜀 | 상태 파일에 미러 앵커(워터마크, 추적 시작 시각)를 기록하고, 맞지 않으면 상태 파일을 무시하고 기준선을 다시 잡으며 그 사실을 알림 |
| 치명 | 피드 변경은 처리했는데 권위 재확인(querybatch)만 일시 실패하면 워터마크가 이미 지나가서 그 취약점이 영영 보고되지 않음 | 실패한 재확인을 `pending`으로 저장하고 피드와 무관하게 다음 주기에 재시도(상태 파일에 유지) |
| 높음 | 압축 폭탄(gzip/deflate), 무제한 `read()` | 디코딩 결과와 본문을 128 MiB로 제한, 초과는 재시도 없이 실패 |
| 높음 | purl/SBOM의 생태계 이름(`..`)이 버킷 URL 경로로 들어감 | 생태계 이름 검증(`..`, `/` 거부)과 URL 인코딩, 대소문자 정규화(`pypi` -> `PyPI`) |
| 높음 | all.zip 멤버 크기 무제한, 다운로드 크기 무제한 | 멤버 8 MiB·총 8 GiB·다운로드 4 GiB 제한, 초과 멤버는 건너뛰고 보고 |
| 높음 | 깊게 중첩된 JSON이 `RecursionError`로 sync/watch를 중단 | 파싱 실패로 처리 |
| 높음 | `osvscanner._fixed_version()`이 GIT 커밋 SHA를 수정 버전으로 반환 | GIT 범위 건너뜀 |
| 중간 | 요청의 타임아웃이 소켓 읽기마다만 적용되어, 조금씩 보내는 서버가 워커를 무한히 붙잡음 | 요청 전체에 시간 상한(기본 180초, 다운로드 3시간)과 `read1`로 패킷마다 확인 |
| 중간 | 프록시 경로(urllib)가 다른 호스트로의 리다이렉트를 조용히 따라감 | 리다이렉트를 따르지 않음(3xx는 실패로 보고) |
| 중간 | 완전 미러의 `lookup`이 철회(withdrawn)된 advisory를 결과로 반환 | 철회된 레코드는 결과에서 제외(OSV API와 동일) |
| 중간 | querybatch 결과에 `modified`가 없으면 오래된 캐시를 영원히 신뢰 | 검증할 수 없는 캐시는 미스로 처리해 다시 받음 |
| 중간 | `watch`가 저장소 예외(DB 잠김/삭제)나 Windows의 상태 파일 `os.replace` 거부로 종료 | 주기마다 예외를 오류 이벤트로 보고하고 계속, 스키마는 매 연결에서 보장, `os.replace`는 재시도 |
| 중간 | `osv sync --ecosystem pypi`가 404 | 대소문자 정규화 |
| 낮음 | `osv_local_db` 연결의 busy 대기 5초 | 30초 |
| (요약에 약속한 항목) | `OsvClient.query_batch`가 id/modified 스텁을 전체 레코드로 오해, 페이지네이션 미추적, 실패를 빈 결과로 둔갑 | `querybatch` + 레코드 해석으로 재구현, 실패는 `OsvQueryError` |

리뷰에서 "깨지지 않았다"고 확인된 것: Range/304/416 처리, 공백/콜론이 든 생태계·id의 URL 인코딩, 빈 결과 모양(`{}`), 한 쿼리가 400이어도 이분 탐색으로 나머지 보존, 변경 피드의 동일 시각 행 처리, advisory에서 패키지가 빠진 개정의 캐시 무효화.

## 10. 다음 단계 후보

- `bts_sbom_app`(웹 콘솔)에 `osv status` / watch 이벤트 표시.
- `watch` 이벤트를 파일/stdout 이외로 보내는 통로(웹훅 등). 외부 전송이므로 별도 명시 플래그가 필요합니다.
- Python 3.10/3.11 CI 매트릭스에서 새 테스트(`tests/test_osv_live.py`) 실행 확인.
