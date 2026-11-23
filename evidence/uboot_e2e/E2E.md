# u-boot v2026.10 실전 E2E 기록 (2026-11-23)

표적: https://github.com/u-boot/u-boot — shallow clone, tag **v2026.10** (commit 55084065 "Prepare v2026.10"), 388MB, `C:\firebaseprojects\usertest\u-boot`.
경로: 스캔(8822 서비스) → 라이선스/취약점 소견 → 클린룸 재구현 레인 → 발견 기반 고도화(AC-611~616).

## 1. 스캔 (job 4f9ee753a1 → evidence/runs/u-boot/)

| 항목 | 실측 |
|---|---|
| 구성요소 | **68** (docs/sphinx requirements 등 핀된 Python 의존 — deps.dev 44 + registry:pypi 21) |
| 취약점 | **43** (CRITICAL 2 · HIGH 15 · MEDIUM 23 · LOW 3) |
| 최상위 소견 | GHSA-6q48-6c7w-9gw2 certifi CRITICAL (fixed 2026.10.18), CVE-2026-97689 urllib3 HIGH, CVE-2025-66471/66418 urllib3, CVE-2024-56201 jinja2 |
| 프로젝트 라이선스 | **GPL-2.0-or-later** (출처: SPDX 헤더 다수결 — 루트 LICENSE 파일 없이) |
| 라이선스 해결 | 65/68 (95.6%) |
| 정책 소견 | strong-copyleft 4(concurrencytest·fattools·pylint·yamllint) / unknown 3(docutils@0.17.1·pycryptodomex·setuptools@78.1.1) / weak-copyleft 2(certifi 두 버전 — 같은 패키지가 서로 다른 requirements에서 이중 핀) |
| data_status | complete · vulnerability_presence **found** |

## 2. 클린룸 재구현 (job 3c60a39754 → evidence/reimpl/3c60a39754/)

- 표적: `tools/dtoc/src_scan.py` — u-boot 자체의 C 소스 인터페이스 스캐너 (stdlib-only: collections/os/re/sys, 공개 def 6 · class 4)
- **생성: LLM 실생성** (1차 시도는 `empty completion` — gpt-5-mini 추론이 4096 예산 소진 → 생성 예산 16384로 수선 후 실생성)
- **카피 게이트: overlap 0.0 (게이트 0.05) 통과**, license strings 없음
- **계약 테스트: 5 run / 0 failed**
- **원본 오라클(test_dtoc·test_fdt·test_src_scan): 3파일 전부 FAILED — 정직 판정 `compatibility_failed`**
  - 원인 사슬이 정확히 기록됨: `from u_boot_pylib import test_util` → u_boot_pylib → cros_subprocess → `import pty` → **Windows 비지원(POSIX 전용)**. 오라클은 리바인딩(`from dtoc import src_scan`→`import src_scan`)·형제 패키지 경로(PYTHONPATH)까지 도달했으나 헬퍼의 pty가 Windows에서 실패.
  - test_fdt(확장자 없는 파일) → **SKIPPED (no runnable tests)** — 무실행 파일의 무음 통과 방지 하드닝이 실동작.

## 3. 발견 → 고도화 (AC-611~616)

1. **AC-611 클린룸 워크벤치 판 신설** — /api/reimpl+SSE를 UI로(단계 스트립·판정 카드). 이전엔 API/CLI만 존재.
2. **AC-612 스캔 진행 SSE** — 4단계 바가 잡 이벤트를 소비(stage·완료 수·초). u-boot 스캔 ~5분의 무음 시계 해소.
3. **AC-613 정직 배너** — 0구성요소/unknown에 pinned sca_app의 녹색 "No known vulnerabilities"가 경고 배너와 충돌 → post-render "Unknown — not a pass" 경고로 교체.
4. **AC-614 프로젝트 카피레프트 의무** — GPL 프로젝트의 바이너리 배포 소스 제공 의무가 어느 표면에도 없었음 → policy_findings 확장 + /api/policy?distribution= 재계산 + 라이선스 판 배포모델 셀렉터.
5. **AC-615 setup.py 공개** — u-boot tools의 setup.py들이 파싱도 공개도 안 되는 침묵 → 코어 roster에 disclose.
6. **AC-616 오라클 하드닝** — 패키지 임포트 리바인딩(오라클은 새 코드를 채점)·헬퍼 패키지 경로·TestCase main 꼬리 주입·무실행 파일 정직 skip·shim 수정(argv 정규화·runner result 반환)·생성 예산 16384.

## 4. 부수 버그 (이 라운드에서 수정)

- **db 판 바인딩이 첫 렌더에서 null 참조로 init 전체를 죽였다**(프로젝트 미선택 시 needProject 마크업에 #dbQBtn 부재 → loadHistory가 안 돌아 "분석 기록이 없다"). 판 바인딩을 지속 컨테이너 위임으로 전환. 지난 라운드의 "부트 경합" 오진의 진원지.
- 재구현 생성 예산: 추론 배포의 빈 응답(empty completion) → 16384.
