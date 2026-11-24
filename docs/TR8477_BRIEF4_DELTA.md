# 지시서 4(작업 36~40) vs course/glm 기존 TR 8477 구현 — 차이점 보고

작성: 2026-11-21. 사용자 결정에 따라 **기존 구현을 유지**하고 아래 차이점만 보고한다.
기존 구현은 course/glm 워크트리 커밋 `875691d`의 "TR 8477 검토" 산출물이고, 지시서 4
(`docs/GLM_IMPLEMENTATION_BRIEF_4.md`)는 같은 기능을 더 세부적인 명세로 요구한다. 양쪽 모두 "등급이 아니라
입력", "권고 데이터에 적힌 것만", "증거이지 평가가 아니다"라는 핵심 정직 규칙은 동일하게 지킨다.

## 기능별 비교

### 작업 36 — 공격 입력
| 항목 | 지시서 4 명세 | 기존 구현 (course/glm) | 차이 판정 |
|---|---|---|---|
| 위치 | `cvss.attack_inputs(vector)` (벡터 문자열 입력) | `evidence.attack_inputs(rec)` (레코드 입력, `engine.attack_inputs`는 위임 존재) | 설계 다름 |
| 어휘 | `attack_vector/attack_complexity/attack_requirements/privileges_required/user_interaction/scope` + 상수 `ATTACK_INPUTS_BASIS` | 버전별 지표 이름 그대로(`AV/AC/PR/UI/AT/S`) + note 문구 | 어휘 다름, 내용 동등 |
| 발견 부착 | `engine.normalize`가 `rec["attack_inputs"]`에 별칭 묶음 최고점 벡터로 부착 | 발견 레코드에 `cvss_v3_vector`/`cvss_v4_vector`를 저장하고 보고서 단계에서 분해 | 부착 시점 다름(동등 정보) |
| 등급 금지 | basis 상수로 명시 | note로 명시 | 동일 |

### 작업 37 — CWE 집계
| 항목 | 지시서 4 | 기존 구현 | 판정 |
|---|---|---|---|
| 모듈 | `cwe.py` 신설, 23개 id만 제목(`NAMES`), 없으면 None | `evidence.cwe_top` (제목 없이 id 집계) | 제목 표시 없음(지어내지 않는 규칙은 준수) |
| 발견 부착 | `engine.normalize`가 `database_specific.cwe_ids` 합집합을 `^CWE-\d{1,5}$` 필터로 `cwe` 부착, NVD 자리표시자는 `cwe_unclassified` | `v.get("cwe")`를 이미 있다고 가정하고 집계 — **발견 레코드로의 cwe 부착 단계가 있는지는 파이프라인에서 별도 확인 필요** | 부착 단계 확인 필요 |
| 파이프라인/리포트/롤업 | `rec["weakness"]`, `project_md` 절, `fleet.rollup` 포함 | `cwe_top`은 evidence 번들 경로에서만 호출 | 리포트·롤업 통합은 지시서 4에만 있음 |

### 작업 38 — V&V 증거 보고서
| 항목 | 지시서 4 | 기존 `vnv.py` (115줄) | 판정 |
|---|---|---|---|
| 등급 | `pass`/`pass_with_restrictions`/`fail`/`no_data`, 열린 차단 발견(fail), 구성요소 0 = `no_data` | `fail`(분석 오류)/`pass`/`pass with restrictions`. **구성요소 0을 `pass with restrictions`로 표시** | ⚠️ 정직 규칙 차이: 0구성요소는 `no_data`여야 한다(지시서 4 §0.6-1). pass 계열에 "제한 있는 통과"로 보이는 건 거짓 안심 소지 |
| 트리아지 처분 | `triage.evaluate` 연동, `not_affected`/`accepted`만 처분 인정, rejected/expired는 open 유지 | **트리아지 미연동** — 열린 차단 발견 개념 없음 | ⚠️ 미구현(기능 격차) |
| 기준(criteria) | `--criteria` 3키 검증, block_severities, 편차(deviations) 절 | 없음 | 미구현 |
| 추적성 | layer/approach/방법군 표(5개 미수행 방법 고정 나열)/고정 문구 2개 | 존재 확인 고정 문구·제외 목록 있음. 5방법군 표·approach 표기는 부분적 | 부분 구현 |
| report_id | 본문 SHA-256 12자리, `--stamp` 영향 없음 | 없음 | 미구현 |
| CLI/API | `vnv-report --require ...`, `GET /api/vnv/<p>` | API `/api/vnv/<p>` 있음(서버 라우트 확인됨), CLI `vnv` 존재(COMMANDS에 vnv) — `--require` 옵션 여부는 별도 확인 | 부분 구현 |

### 작업 39 — 증거 묶음
| 항목 | 지시서 4 | 기존 `evidence.bundle` | 판정 |
|---|---|---|---|
| 형태 | 폴더 복사(레코드·SBOM·VEX·triaged VEX·vnv·conformance·triage 결정·README) + `MANIFEST.json` | `bundle.json` 매니페스트가 원본 산출물 **경로**를 참조(복사 없음) | 설계 다름(원본 이동 없이 참조 — 오히려 안전할 수 있으나 "폴더 하나로 전달" 요구는 미충족) |
| 검증 | `bundle-verify`로 변조 확인(modified/missing/extra/unsafe) | 없음(매니페스트만) | 미구현 |
| 거부 규칙 | 출력 폴더 충돌·증거 폴더 내부·심볼릭 링크 거부 | 없음 | 미구현 |

### 작업 40 — 챗 도구·평가·문서
- `vnv_report`/`weakness_classes` 챗 도구 2개: 미구현(기존 chat에는 obligations 계열 도구만 있음).
- `evals_chat.VNV_CASES` 6문항, `knowledge/domain` 보강, `docs/WORKFLOW.md`·`CHANGELOG.md` 갱신: 미구현.

## 권고 (사용자 결정 대기)

1. **즉시 고칠 것(정직 규격)** — 기존 `vnv.py`의 0구성요소 등급을 `no_data`로 변경하고, 열린 차단 발견
   (CRITICAL/HIGH + open disposition)을 `fail`로 승격. 트리아지 연동은 `triage.evaluate` 호출 한 번이므로
   기존 AC 721-759와 충돌하지 않게 절 추가로 해소 가능.
2. **가치가 큰 추가** — `bundle-verify`(해시 재검증)와 `report_id`. 둘 다 순수 추가라 기존 테스트 무손상.
3. **유지해도 좋은 것** — 공격 입력의 버전별 지표 원문 표기(어휘만 다름), cwe 무제목 집계(지어내기 방지),
   매니페스트 참조형 번들(원본 비훼손).
4. 지시서 4 문서 그대로의 재구현은 **하지 않음** — 기존 AC 721-759 테스트와 이중 관리가 되므로, 위 1~2의
   "격차 해소" 방식으로 통합하는 것을 권고한다.
