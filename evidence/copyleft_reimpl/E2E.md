# 컴플라이언스 클린룸 재구현 E2E — concurrencytest (GPL) (2026-11-24)

시나리오: 패치로 끝나지 않는 라이선스(GPL 계열) → **클린룸 코드 교체**가 정답 경로. 교체 구현에
아키텍처 패턴을 자동 주입하는 2단 추론: **Tier 1 = 로컬 책 KB(Book 15권+정제 노트, 9,179 청크) →
Tier 2 = 배포 모델 지식 폴백**. 사용자 지정 흐름: "책으로 추론하고, 못 하면 AI가 찾는다".

## 표적

concurrencytest (u-boot 스캔 evidence/runs/u-boot에서 발견, tools/u_boot_pylib의 의존):
- 원본: PyPI concurrencytest, 단일 모듈 7.8KB — ConcurrentTestSuite · fork_for_tests · partition_tests(2)
- 라이선스: 강한 카피레프트(u-boot 스캔은 registry 메타로 GPL-3.0-only 기록, sdist 본문 표기는 GPL-2.0-or-later
  — Bazaar bzrlib 파생, Canonical 저작) — **어느 쪽이든 패치 불가, 코드 교체 필요**
- 표적 파일: sdist 0.1.12 (13,615B) 직접 다운로드·추출

## 실행 결과 (evidence/copyleft_reimpl/record.json)

| 단계 | 결과 |
|---|---|
| 패턴 추론 | **tier=book** — 로컬 책 15권(9,179 청크)에서 히트: GoF Design Patterns, Architecting AI Software Systems, 정제 노트(OAuth bearer 예 포함) |
| 생성 | **LLM 실생성** (generated_by=llm, attempts=1 — 첫 시도 성공) |
| 카피 게이트 | **overlap 0.0** (게이트 0.05) — 원본과 겹침 없음, license strings 없음 |
| 계약 테스트 | **2 run / 0 failed** |
| 원본 오라클 | sdist에 upstream 테스트 없음 → 계약-전용 증적(honesty 필드에 명시) |
| 판정 | **ok** |

## 1차 시도에서 발견한 것 (정직 기록)

동일 스크립트가 공유 장부(evidence/.llm_ledger.json)를 기본 예산 80으로 읽어 **scaffold로 정직 폴백**한 1차
실행이 있었다 — 예산 600으로 재실행하여 LLM 실생성 확인. 장부는 프로세스 간 공유 상태라는 점을 재확인.

## 2단 추론의 채널 분리 (법적 안전망)

패턴 섹션은 **명세(spec) 채널만** 흐른다: 명세는 카피 게이트의 연산 대상이 아니고(게이트 = 생성코드 vs 원본,
docstring 제외 4행 shingle), 책 인용은 원칙 요약 400자 컷. 생성 코드가 원본과 겹치면 판정 rejected —
"책에서 읽은 패턴으로 쓴 새 코드"와 "원본 복사"가 측정으로 구분된다.
