# 출처 계보 (Origin / Data Lineage) — bts_sbom_app

이 문서는 이 패키지가 실제로 호출하는 외부 출처만 코드에서 확인해 적는다(URL 은 `net.py`/`arch.py`/`licenses.py`/`osv.py`/
`llm.py` 를 grep 해 확인). 약관(이용 조건)은 이번 작업에서 원문을 읽지 않았으므로 전부 "확인 필요"로 남긴다 — 지어내지
않는다.

## 출처 표 (Sources)

| 출처 | 가져오는 것 | 호출 위치 | 이용 조건 |
|---|---|---|---|
| OSV.dev (`https://api.osv.dev/v1`) | 취약점 공고(advisory), 별칭(alias) 묶음 | `bts_sbom_app/osv.py` (`API` 상수), `net.http_json` 경유 | 확인 필요 |
| deps.dev (`https://api.deps.dev/v3`) | 패키지 버전별 라이선스 메타데이터 | `bts_sbom_app/licenses.py:_depsdev` | 확인 필요 |
| PyPI JSON API (`https://pypi.org/pypi/{name}/{version}/json`) | PyPI 패키지의 라이선스 표시(및 trove classifier) | `bts_sbom_app/licenses.py:_registry`(`eco == "pypi"`) | 확인 필요 |
| npm 레지스트리 (`https://registry.npmjs.org/{name}/{version}`) | npm 패키지의 `license`/레거시 `licenses` 배열 | `bts_sbom_app/licenses.py:_registry`(`eco == "npm"`) | 확인 필요 |
| Maven Central (`https://repo1.maven.org/maven2/.../*.pom`) | Maven 아티팩트 POM 의 라이선스 이름(부모 POM 상속 포함) | `bts_sbom_app/licenses.py:_maven_pom` | 확인 필요 |
| endoflife.date (`https://endoflife.date/api/{product}.json`) | 런타임(Python/Node/PHP/Ruby/.NET 등) 지원 종료(EOL) 일자 | `bts_sbom_app/arch.py:eol_lookup` | 확인 필요 |
| LG EXAONE / 호환 API (`https://api.exaone.ai/v1`, 또는 사용자가 지정한 베이스 URL) | 모델 추론 호출(데이터 소스가 아니라 연산 공급자) | `bts_sbom_app/llm.py:ChatClient` | 확인 필요(요청 보존 정책 미확인) |
| `knowledge/lecture/`, `knowledge/domain/` (로컬, 네트워크 아님) | 챗봇 RAG 코퍼스 | `bts_sbom_app/rag.py:load_dir`, `bts_sbom_app/evals.py:build_index` | 강의 내용의 **의역·요약**이며 슬라이드 원문을 옮기지 않음(`docs/LECTURE_MAPPING.md` 저작권 메모). 공개 전 수강 약관을 별도 확인해야 함 |

## 수집 방법 (Collection)

- **라이선스**: `licenses.resolve()` 가 먼저 락파일에 선언된 라이선스(`lf.get((name, version))`)를 쓰고, 다음으로
  디스크 캐시(`licenses_raw.json`)에 유효한 원본 증거가 있으면 그것을 재해석하며(ADR-0009), 그래도 없으면
  `ThreadPoolExecutor` 로 deps.dev → 레지스트리(PyPI/npm/Maven) 순서로 조회한다(`_registry`/`_depsdev` 중 먼저 읽을 수
  있는 응답을 채택 — "first source whose evidence we can actually read").
- **취약점**: OSV 의 `query`/`querybatch` 엔드포인트를 통해 수집하며, 모든 호출은 `net.py` 를 거쳐 재시도/백오프와 요청
  통계(`STATS`)가 적용된다.
- **EOL**: 런타임별로 프로세스 생애주기 동안 1회만 조회해 메모리에 캐시한다(`arch._EOL_CACHE`, 디스크 캐시 아님).
- **지식 코퍼스**: 네트워크가 아니라 저장소에 포함된 로컬 마크다운 파일을 읽는다(`rag.load_dir`).

## 갱신·신선도 (Freshness)

- **라이선스 원본 캐시**: 성공적으로 식별된 원본 증거는 재해석만 하면 되므로 TTL 없이 계속 재사용한다(ADR-0009). "미식별"
  로 끝난 조회만 `ttl_s`(기본 7×86400 초 = 7일) 동안 재시도를 보류한다(`licenses.py` `resolve()` 의 `ttl_s` 파라미터) —
  그마저도 그 사이 더 넓은 레지스트리 폴백이 켜졌다면 다시 시도한다.
- **EOL 데이터**: 디스크에 캐시되지 않으므로 매 프로세스 실행마다 새로 조회된다(프로세스 내에서는 제품당 1회로 묶임).
- **규제표(conformance)**: `conformance.table_age()` 가 검토 기준일로부터의 경과 개월을 계산해, 6개월 이상 지나면
  결과·Markdown·기록·챗봇 답변이 "검토 필요(review due)"를 명시한다(`BSA-AC-210`) — 오래된 표를 현재 표처럼 조용히
  통과시키지 않는다.
- **분석 기록**: 매 분석 시 이전 전체 기록이 `.prev.json` 으로 보존되어(ADR-0009), 변경(diff)은 항상 두 완전한 기록을
  비교해 계산된다.

## 실패 시 동작 (Failure behavior)

- **네트워크 호출**: `net.http_json`/`net.http_text` 는 404 또는 모든 재시도 실패 시 `None` 을 반환한다 — 이는 "확인하지
  못함"이지 "취약점 없음"이 아니다. 엔진 수준에서는 `data_status`/`vulnerability_presence` 필드로 이 구분을 보존한다
  (README 정직 규율: "'No data' is never reported as 'no vulnerability'").
- **오프라인 모드**: `offline=True` 로 실행하면 온라인 조회를 건너뛰고 그 사실을 `engine.analyze` 의 `data_status` 에
  정직하게 남긴다(네트워크 미사용, 수치를 지어내지 않음).
- **EOL 조회 실패/오프라인**: `endoflife.date` 를 못 받으면 내장 정적 표(`arch._EOL_STATIC`, 소스 주석에 `UNVERIFIED`
  로 명시)로 대체하고, 그 표에도 없으면 `status="unknown"` 을 반환한다 — 알 수 없는 것을 "지원됨"으로 둔갑시키지 않는다.
- **라이선스 조회 실패**: 모든 소스가 실패하면 컴포넌트는 라이선스 미식별(`license=None`) 상태로 남고, 이는 라이선스
  해소율 지표에 그대로 반영된다(지어낸 라이선스를 채우지 않음).
- **LLM 호출 실패**: `ai.propose`/`chat` 모두 결정적 경로로 정직하게 강등하고 원인을 기록한다(ADR-0010).

## 이용 조건 (Terms)

OSV.dev, deps.dev, PyPI, npm 레지스트리, Maven Central, endoflife.date, 그리고 LG EXAONE(또는 사용자가 지정한 호환
엔드포인트)의 이용 약관/요청 보존 정책은 이번 작업에서 원문을 확인하지 못했다 — **확인 필요**로 남긴다. 유일하게 확인한
것은 `knowledge/lecture/` 가 강의 슬라이드 원문이 아니라 의역·요약이라는 점이며(`docs/LECTURE_MAPPING.md` 저작권 메모),
그 메모 역시 "레포를 공개하기 전에 수강 약관/출처 표기 정책을 확인하고, 필요하면 해당 폴더를 제외하라"고 스스로 명시하고
있다.
