# ADR-0017: Cloud-mode access control and the identity of an approver

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/auth.py`(신규), `bts_sbom_app/audit.py`(신규), `bts_sbom_app/server.py`(게이트·감사). AC: BSA-AC-441~451, 테스트 `tests/bts_sbom_app/test_auth_audit.py`.

## 근거 (Context)
공개 주소의 서버가 인증 없이 열려 있으면 누구나 스캔을 돌리고(비용·자원), 승인형 패치·VEX 결정을 낼 수 있다. 또 지금의 승인은 "누가 했는지"를 기록하지 않는다(익명 승인). 강의 3주차 AI DBA 는 승인자 비어 있으면 적용 거부를 요구하고, RFC 보안 통제는 감사 로그(해시 체인)를 요구한다.

## 결정 (Decision)
클라우드 모드에서 두 방식 중 하나: ① `BTS_SBOM_API_TOKEN`(Bearer, hmac.compare_digest, Azure 에서는 Key Vault 참조로 주입, 신원 "api-token"), ② `BTS_SBOM_TRUST_IDENTITY_HEADER=1` 일 때만 신원 헤더(`BTS_SBOM_IDENTITY_HEADER`, 기본 `X-MS-CLIENT-PRINCIPAL-NAME` — Easy Auth 가 검증한 사용자 이름. 이 헤더는 Easy Auth 뒤에서만 안전하다: 직접 노출되면 위조 가능 — README·RUNBOOK 경고). 두 방식 모두 없으면 fail-closed: 프로브(/healthz, /readyz)를 뺀 모든 /api 는 503 auth_not_configured. 인증 실패는 401 한 몸(없음=틀림 구별 불가, 오라클 방지). 쓰기 동작(승인·VEX 결정)은 신원 없으면 거부, 신원 있으면 `approved_by`·triage `by`·감사 줄의 `who` 에 기록. 감사는 `<evidence>/audit.jsonl` 추가 전용 JSON 줄, 각 줄이 자기 무결성 해시 `h`와 앞 줄의 `h`를 `prev`로 가진다 — 임의의 줄을 바꾸면 그 줄에서 검증이 끊긴다(작업 5b 의 재검증은 `verify()`).

## 기각 대안 (Rejected alternatives)
- IP 허용 목록만: 신원이 없다 — "누가 승인했는가"에 답하지 못하고 공유 IP 뒤의 사용자를 구별하지 못한다.
- 신원 헤더 무조건 신뢰: 직접 노출된 서버에서 위조 가능(Easy Auth 뒤에서만 유효) — 트러스트 플래그로 한정.
- 앱이 자체 로그인 화면 제공: stdlib 만으로 세션·비밀번호 저장 구현은 부담이고 Easy Auth 가 이미 그 역할을 한다.
- 감사 로그를 일반 파일 롤링만: 변조 탐지가 없다 — 해시 체인으로 "기록을 몰래 고칠 수 없다"를 만든다.

## 결과 (Consequences)
작업 17의 /metrics 도 이 게이트를 통과한다(클라우드에서 인증 필요). 승인 토큰·API 키·URL 자격 증명은 감사 줄에 절대 없다(AC-448). 로컬 모드(스위치 꺼짐)는 이전과 완전히 같다(AC-451).
