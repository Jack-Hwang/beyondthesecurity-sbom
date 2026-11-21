# ADR-0018: One cloud-mode switch (BTS_SBOM_CLOUD) and the cloud source policy

## Status
Accepted — 사후 기록(작업 12·11). 코드: `bts_sbom_app/cloud.py`(신규), `bts_sbom_app/server.py`(정책 적용), `bts_sbom_app/workspace.py`(소스 정책, 작업 11). AC: BSA-AC-465~470(클라우드 모드), BSA-AC-453~460(소스 제한).

## 근거 (Context)
Azure 배포 시 서버는 공개 주소로 노출된다. 현재 전제 — "localhost 전용, 인증 없음, 로컬 경로 분석 가능, 키 평문 저장, LLM 기본 켜짐" — 은 공개 서버에서 안전하지 않다(`server.py` docstring, `workspace.normalize_source` 는 `file://`·`ssh://`·로컬 경로를 받음, `/api/llm` 이 평문 키 저장). 강의 3주차는 "안전장치는 프롬프트가 아니라 코드로 강제"를 요구한다.

## 결정 (Decision)
하나의 스위치 `BTS_SBOM_CLOUD` 로 모든 안전 기본값을 한 곳에서 뒤집는다. 값 판정은 fail-closed: unset/빈 값/0/false/no/off 만 꺼짐, 그 밖의 모든 값은 켜짐. 켜짐이면: 로컬 경로 차단, URL 스킴 https 만 허용 + 호스트 허용 목록 + 공개 주소 확인(작업 11), `POST /api/llm`·`/api/llm/clear` 는 403(키 파일 쓰기 0), 챗 액션은 `BTS_SBOM_CLOUD_ALLOW_ACTIONS=1` 없이는 거부, 스캔의 `use_llm` 은 `BTS_SBOM_CLOUD_LLM=1` 없이는 무시. `GET /api/engine` 은 `cloud: {enabled, policy}` 를 추가로 보고하고, 서버 시작 시 정책 요약 한 줄을 stdout 에 출력한다(비밀 없음). 스위치가 꺼져 있으면 동작은 이전과 완전히 같다(AC-470).

## 기각 대안 (Rejected alternatives)
- 기능별 개별 환경변수만 두기: 하나라도 빠뜨리면 그 기능이 그대로 노출된다 — "한 곳의 안전 기본값"이 깨진다.
- 클라우드 여부를 호스트명·환경으로 추측: 불안정하고 위장 가능 — 명시적 스위치가 정직하다.
- 챗 액션을 아예 제거: 승인·결정 쓰기가 필요한 배포도 있으므로 옵트인 환경변수로 남긴다.

## 결과 (Consequences)
`cloud.policy()` 를 작업 10(인증)·11(소스 제한)·14(자원 한도)·17(/metrics 인증)·19(LLM 라우터)가 읽는다. 로컬 모드 회귀는 AC-470·458 의 8경로 비교 테스트로 고정한다.
