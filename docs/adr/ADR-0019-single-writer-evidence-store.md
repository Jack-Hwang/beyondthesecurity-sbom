# ADR-0019: The evidence store has one writer; the lock is the safety net

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/instance.py`(신규), `bts_sbom_app/server.py`(serve 잠금·standby 게이트·/readyz). AC: BSA-AC-473~480, 테스트 `tests/bts_sbom_app/test_instance_lock.py`.

## 근거 (Context)
컨테이너 파일시스템은 재시작·재배포 때 사라지고, 같은 증거 폴더를 두 인스턴스(예: 스테이징 슬롯과 운영 슬롯이 스왑되는 동안)가 동시에 쓰면 `.prev.json` 교체·작업 기록이 충돌한다. 강의 4주차 2차시의 "상태 저장 위치 4질문" — 증거는 "중단을 견뎌야 하고 재구성 비용이 크다" → 영속 저장소 + 쓰기 주체 한 번에 하나.

## 결정 (Decision)
`<evidence>/.instance.lock`(JSON: host, pid, started, heartbeat)을 O_CREAT|O_EXCL 로 만든다(로컬 파일시스템에서 원자적). heartbeat 가 60초(stale_after) 이내면 보유 중 → 기본은 시작 거부(LockHeld), `BTS_SBOM_STANDBY_OK=1` 이면 대기 모드: 읽기 전용 API, 쓰기 요청(/api/scan·/api/triage·/api/chat·/api/llm*)은 503 {"error": "standby"}, /readyz 는 200 + mode: standby, 잠금이 stale 해지면 인수해 active 로 전환. 보유자는 15초마다 heartbeat 를 갱신하는 데몬 스레드를 돌리고 종료 시 잠금 파일을 지운다. /readyz 에 evidence_lock 점검을 추가(잠금을 잃으면 503). 작업 복사본은 계속 로컬 임시 폴더(tempfile.mkdtemp)에 만든다(공유 증거 저장소에 만들지 않음 — AC-479).

## 기각 대안 (Rejected alternatives)
- 락 없이 인스턴스 수를 문서로만 제한: 슬롯 스왑 중 이중 쓰기가 실제로 발생할 수 있다 — 안전망이 필요하다.
- 외부 DB(PostgreSQL) 도입: 의존성 0 원칙 위반 + 과설계(이 규모의 단일 서비스).
- 인스턴스마다 별도 증거 폴더: 상태가 갈라져 "어디에 무엇이 기록됐는지"를 알 수 없다 — 단일 저장소가 정직 계약과 맞는다.

## 결과 (Consequences)
알려진 한계(정직 기록): 공유 파일시스템(SMB/Azure Files)에서 O_CREAT|O_EXCL 과 os.replace 의 원자성은 이 환경에서 확인하지 못했다(NOT RUN) — 로컬 디스크에서만 테스트했다. Azure 에서는 인스턴스 수 1(capacity 1, 자동 확장 없음)을 전제로 하고 잠금은 이를 어겼을 때의 안전망이다. App Service 컨테이너의 영속 저장 위치(WEBSITES_ENABLE_APP_SERVICE_STORAGE, /home)와 Azure Files 마운트 방식은 확인 필요(지시서 "확인 필요" 항목 2).
