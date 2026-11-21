# ORIGIN LINEAGE — 데이터 출처 계보

## Sources (출처 표)

`grep -rn "https://" bts_sbom_app` 으로 실제 호출 URL 을 확인했다(코드에 있는 것만 적는다):

| 출처 | 실제 호출 위치 | 무엇을 가져오는가 |
|---|---|---|
| OSV.dev (`https://api.osv.dev/v1`) | `bts_sbom_app/osv.py` (API 상수) | 취약점 배치 질의·권고 문서 |
| deps.dev (`https://api.deps.dev/v3/...`) | `bts_sbom_app/licenses.py:347` | 라이선스 정보 |
| PyPI (`https://pypi.org/pypi/<pkg>/<ver>/json`) | `bts_sbom_app/licenses.py:380` | 라이선스 폴백 |
| npm (`https://registry.npmjs.org/<pkg>/<ver>`) | `bts_sbom_app/licenses.py:389` | 라이선스 폴백 |
| Maven Central (`https://repo1.maven.org/maven2/...pom`) | `bts_sbom_app/licenses.py:366` | POM 라이선스 |
| endoflife.date (`https://endoflife.date/api/<product>.json`) | `bts_sbom_app/arch.py:431` | 런타임 EOL |
| LG EXAONE API (`https://api.exaone.ai/v1`) | `bts_sbom_app/llm.py`, `council.py` | 제안·계획·참고 의견(기본 꺼질 수 있음) |
| CVSS v4 참조 표 (`https://github.com/FIRSTdotorg/cvss-v4-calculator`, BSD-2-Clause) | `bts_sbom_app/cvss4_data.py` 파일 서두 | 점수 룩업 표(2026-11-20 사용자 허락으로 수록) |
| 강의 코퍼스(`knowledge/`) | 저장소 내부 파일 | RAG 근거 — **강의 내용의 의역·요약**, 슬라이드 원문 아님(`docs/LECTURE_MAPPING.md` 저작권 메모) |
| 레드팀 픽스처(`evals/redteam/`) | 저장소 내부 파일 | 합성 공격 문서 — 운영 코퍼스에 심지 않고 테스트가 심어서 측정 |

## Collection (수집 방법)

- 모든 외부 호출은 `net.py` 하나를 통과한다(User-Agent, 재시도·백오프, Retry-After, 호스트별 서킷브레이커, 4상태
  Outcome — AC-301~313). 테스트 훅(TRANSPORT)으로 네트워크 없이 재현한다.
- 오프라인 모드(`offline: true`)에서는 외부 질의를 하지 않고 결과를 "확인 못 함(unverified)"으로 남긴다(AC-7).
- 캐시는 **원본 증거**를 저장하고 읽을 때 재해석한다(ADR-0009, AC-50).

## Freshness (갱신·신선도)

- OSV 권고는 스캔 시점에 질의한다. 라이선스·EOL 은 런타임 캐시(`_EOL_CACHE`)로 세션 내 중복 호출을 줄인다.
- 캐시된 원본은 규칙이 바뀌면 다시 해석되므로 "오래된 캐시"는 규칙 개선을 가리지 않는다.
- CVSS v4 표는 수록 시점(2026-11-20) 기준 FIRST 참조 계산기 고정본이다.

## Failure behavior (실패 시 동작)

- 접속 실패(재시도 소진·서킷 열림) = `access_failure` — "찾지 못함"이 아니라 "확인하지 못함"으로 기록(AC-302).
- 404 = `empty_result`(기록 없음이며 실패 아님, AC-307).
- LLM 실패(429·한도·네트워크·검증 실패) = 결정적 강등 + 사유(AC-33·34, AC-547).
- 오프라인 스캔의 검증은 `unverified`(null) — 절대 clean 이 아니다(AC-7).

## Terms (이용 조건)

- OSV·deps.dev·PyPI·npm·Maven·endoflife.date 의 **이용 약관 본문은 이 환경에서 확인하지 못했다 — "확인 필요"**.
  지어내지 않는다. 배포 전 각 서비스의 약관(특히 상업적 사용·rate limit 정책)을 확인할 것.
- CVSS v4 참조 표는 BSD-2-Clause — `cvss4_data.py` 헤더에 원 고지가 수록되어 있다(직접 확인).
- 강의 코퍼스는 의역·요약이며, 저장소를 공개하기 전 수강 약관/출처 표기 정책을 확인해야 한다(`docs/LECTURE_MAPPING.md`).
- EXAONE API 이용은 LG 의 서비스 약관의 적용을 받는다(본문 확인 필요).
