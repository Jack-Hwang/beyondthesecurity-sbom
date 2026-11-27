# EU CRA 컴플라이언스 레인 E2E (2026-11-28, 로컬 8800)

표적: 실제 스캔 레코드 **u-boot** (68 컴포넌트 · 44 취약점, evidence/runs/u-boot).
서비스: `python -m bts_sbom_app serve --port 8800 --evidence evidence --llm-config evidence/.llm_config.json`
(+ `BTS_SBOM_CVD_CONTACT=https://github.com/Jack-Hwang/beyondthesecurity-sbom/security`)

## 실측 결과

| 항목 | 결과 |
|---|---|
| security.txt (RFC 9116) | 200 text/plain — Contact(Repo Security URL)·Expires(2027-02-25, +90일)·Preferred-Languages: ko, en. 미설정 시 404+fix 확인 |
| readiness (before) | **37.5%** (pass 2 · partial 2 · gap 4) — `sbom_machine_readable=partial` (eu-cra-annex-i=**conformant**, bsi-tr-03183-2=gaps: hash/supplier) |
| CycloneDX 검증 | CRA Annex I Part II(1) regime **conformant** (68 컴포넌트) — BSI TR-03183-2 gap은 fix-once 목록으로 안내 |
| 지원 기간 선언 | `2032-06` → **ok** (minimum_end 2031-11-27, declared_end 2032-06-30); `2029-01` → below_minimum 34개월; garbage → 400 |
| Article 14 시계 | CVE-2025-27516 T0 기록 → 24h 조기 경보 due 2026-11-29T10:30Z(open, hours_left 42.4) · 72h 통보 due 2026-12-01T10:30Z · 최종 보고 **awaiting_input**(시정 가용 시점 기록 대기) |
| EOL 유지 플래그 | 켜기 → readiness `eol_ledger_maintained` gap→pass |
| readiness (after) | **75.0%** (pass 5 · partial 2 · gap 1) — 잔여 gap = triage_disclosure(0 decisions), partial 2 = SBOM hash/supplier 필드·분석 1회 |
| 5종 대장 행수 | 대장1 제품등록 14 · 대장2 취약점추적 45(44 취약점+주석, 악용여부=`미판정 (KEV·EUVD 미연동)`) · 대장3 EOL 70(68 컴포넌트, 상류EOL일 공란+4구간 규칙 주석) · 대장4 갱신이력 3 · 대장5 당국제출 2(헤더+“제출 이력 없음”) |

## 정직 규칙 확인

- 악용여부·상류 EOL일은 scan이 계산하지 않으므로 대장에서 공란/`미판정`으로 남는다 (docs/CRA_COMPLIANCE.md §2).
- 토큰 게이트 미설정 환경에서 security.txt는 공개 서빙 — 토큰 배포에서는 게이트 뒤에 놓이는 문서화된 편차.

## 회귀

- tests/bts_sbom_app/test_cra.py 8/8 passed · test_specs.py (AC↔테스트 추적) passed
- 전체 스위트 910 passed / 3 failed → 실패 3건 모두 내 변경 무관 환경 flake(kubectl 6550 미가동 등, --lf 재실행으로 분리 확인)
