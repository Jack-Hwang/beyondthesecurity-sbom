# SBOM → 재작성 지원 E2E — 실제 u-boot 스캔 레코드 + concurrencytest (GPL) (2026-11-26)

목적: SBOM을 만든 뒤 개발자가 실제로 코드를 다시 쓸 때 받는 자료를 **실데이터로 측정**한다 (스크립트: `scripts/rewrite_e2e.py`).

## 입력 (모두 로컬, 읽기 전용)

| 입력 | 값 |
|---|---|
| 스캔 레코드 | u-boot 실스캔(68 구성요소 / 43 advisory) — `evidence/runs/u-boot` |
| 레거시 구성요소 | concurrencytest sdist 0.1.12 (GPL 계열), 단일 모듈 |
| 프로젝트 소스 | u-boot 트리(사용 지점 탐색용, 418개 .py/.js 파일 스캔) |
| 생성 | 배포 모델(Azure OpenAI 배포, 사용자 설정) — 명세만 전달 |
| 패턴 | 로컬 책 KB(tier book) |

## 측정 결과

### 1) 재작성 후보 (rewrite.candidates, 실레코드)

| 사유 | 개수 | 비고 |
|---|---|---|
| license (강한 카피레프트) | **4** (concurrencytest, fattools, pylint, yamllint) | 측정 |
| no_fix / fix_incomplete | 0 / 0 | 이 레코드의 17개 플랜은 모두 검증된 upgrade — 수정판이 있다 |
| eol / incompatible | 0 / 0 | **미평가**: eol 입력 없음(섹터 보고서의 eol 계약), 비호환은 운영자 선언만 — 결과에 `not_assessed`로 기록 |

### 2) Run A — license 트리거, REA 요청 (`run_A_license/`)

| 단계 | 결과 |
|---|---|
| 트리거 | `license` (GPL-3.0-only, 클린룸 법적 필수 = true) |
| REA | 검출 상태 **absent** (rea 미설치), 레인에서는 **not_applicable** — 대상이 Python 소스라 REA의 정적 JS/ASAR 경로 밖. 통과로 표시하지 않음, 단계는 `rea_skipped` |
| 패턴 | tier **book** |
| 생성 | **LLM 실생성**, 1회 시도 |
| 카피 게이트 | overlap **0.0** (게이트 0.05) |
| 계약 테스트 | **2 run / 0 failed** |
| 원본 오라클 | sdist에 테스트 없음 → 없음으로 기록(dossier §10 공백) |
| 판정 | **ok** |
| dossier | 10개 절 전부. **§5 사용 지점: u-boot가 실제로 쓰는 심볼은 `ConcurrentTestSuite`, `fork_for_tests` 둘뿐(`tools/u_boot_pylib/test_util.py:19-20`) — `partition_tests`, `partition_tests_by_class`는 이 프로젝트에서 미사용(교체본에서 뺄 후보)** |

### 3) Run B — EOL 경로 **메커니즘 데모** (`run_B_eol_declared_demo/`)

운영자 선언 `eol`을 **데모 입력**으로 주입했다(이 구성요소의 측정된 사실이 아니다 — 선언 노트에 그렇게 적혀 있다). 오프라인 스캐폴드로
같은 레인을 재실행해 확인한 것: 트리거 종류가 `license + eol`로 기록되고, 명세에 "Compatibility target" 절(테스트가 도는
인터프리터 3.12.10, 제거된 stdlib API 금지)이 붙으며, 판정 ok(스캐폴드).

## 정직한 기록

- **REA는 이 E2E에서 실행되지 않았다.** (1) 이 PC에 rea CLI가 없고(`rea_detect.json` = absent), (2) 설치하려면 npm 패키지를 내려받아
  제3자 코드를 실행해야 하는데 승인 없이 하지 않았다, (3) 대상 구성요소(Python)는 REA의 정적 JS 경로 대상도 아니다. 어댑터의
  실행·파싱·실패 경로는 가짜 rea 프로세스로 단위 검증했고(`tests/bts_sbom_app/test_rewrite_rea.py`), **실제 rea 출력에 대한 실측은 없다.**
- Run B의 EOL은 메커니즘 시연이다. EOL/비호환 사유의 실데이터 측정은 eol 입력(또는 선언)이 주어질 때 가능하다.
- 생성 코드는 계약(이름·인자 수) 수준으로만 검증된다 — 동작 동일성은 증명하지 않는다(레거시 테스트가 없어서).
