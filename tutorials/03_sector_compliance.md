# 튜토리얼 3 — 섹터 규제 컴플라이언스 리포트 (40분)

> CRA · FDA 524B · UNECE R155/R156 · EO 14028(방산) · 금융 OSS 가이드 ·
> 로봇(ISO 10218) — 같은 SBOM 하나로 6개 섹터 요구를 점검합니다.

## 0. 핵심 개념 (5분)

규제마다 요구하는 SBOM "필드"가 다릅니다. bts-sbom의 섹터 리포트는 **하나의
SBOM을 6개 규제의 요구 목록과 대조**해서, 무엇이 충족되고 무엇이 빠졌는지
행별로 알려줍니다.

판정은 3가지뿐입니다 (정직 규율 — 추측이 없습니다):

| 판정 | 의미 |
|---|---|
| `pass` | 문서 필드에서 충족 확인 (측정 수치 동봉) |
| `gap` | 증거는 있으나 불충분 (예: EOL 표기 50%) |
| `not_evidence` | 판단에 필요한 입력 자체가 없음 (예: VEX 파일 미제공) |

## 1. CRA (EU 사이버복원력법) 실습 (10분)

CRA 요구(발효 2024-12 → 전면 2027-12-11): machine-readable SBOM · 구성요소
명세 · 공급자 표기 · 취약점 처리 증거 · 지원 기간(EOL) 표기.

```bash
bts-sbom sector --sector cra --sbom demo.spdx.json --vex demo.vex.json --eol demo.eol.json
```

입력 파일 3개의 역할:

- `--sbom`: 구성요소 명세 (튜토리얼 1에서 생성)
- `--vex`: 취약점 활용가능성 서술 (어느 CVE가 우리 제품에 영향 없는지 등)
- `--eol`: `{"openssl": {"eol": "2027-09-01", "status": "supported"}}` 형태의
  지원 기간 표

읽는 법 — 나온 행마다:

- `CRA-01 pass` — 형식 선언 있음
- `CRA-03 gap (supplier 50%)` — 절반만 공급자 표기 → **누구를 보완할지**
  evidence에 컴포넌트 수가 나옵니다
- `CRA-05 not_evidence` — EOL 표를 안 줬으면 이렇게 나옵니다 (추측 판정 없음)

**교육 포인트**: `not_evidence`는 실패가 아니라 "아직 증거를 안 올렸다"는
뜻입니다. 규제 대응 워크플로에서는 not_evidence → 증거 수집 → 재실행의
반복입니다.

## 2. FDA 524B (의료기기) 실습 (10분)

의료기기는 **2025-06 최종 가이던스에서 새 요구**가 붙었습니다: 컴포넌트마다
**support status + end-of-support date**.

```bash
bts-sbom sector --sector fda --sbom demo.spdx.json --vex demo.vex.json --eol demo.eol.json
```

`FDA-04` 행이 바로 그 새 요구입니다. EOL 입력이 없으면 `not_evidence`,
일부만 있으면 `gap (50%)` — 실제 제출 문서에서는 **100%**가 되어야 합니다.

## 3. 나머지 4섹터 한 번에 (10분)

```bash
for s in r155 dod finance robot; do
  bts-sbom sector --sector $s --sbom demo.spdx.json --vex demo.vex.json --eol demo.eol.json --out report_$s.json
done
```

- `r155` — 자동차(RXSWIN 소프트웨어 식별자·의존 그래프 확인)
- `dod` — 미 방위(생성 도구 선언·VEX 분류 증거)
- `finance` — 금융(라이선스 미확인(NOASSERTION) 0%가 핵심 요구)
- `robot` — 로봇(ISO 10218-1:2025 + CRA 중첩 대응)

`--out report_<sector>.json`으로 저장하면 감사 증적이 됩니다.

## 4. 워크샵 과제 (5분)

1. 자기 프로젝트의 lockfile로 SBOM을 만들어 6개 섹터를 모두 돌려보고,
   **가장 먼저 보완해야 할 gap 1개**를 골라 보고하세요.
2. `not_evidence` 행 중 증거 수집이 가장 저렴한 것은 무엇인가요?
   (힌트: 파일 하나만 추가하면 해소되는 것)

## 참고

- 섹터 요구 목록과 근거 규제: `bts_sbom/sectors.py`의 `SECTOR_PROFILES`
  (행마다 `basis` 필드에 규제명이 기록됩니다)
- 스키마: `bts-sector-report-1` — 행/판정/증적 구조는 README "Sector reports"
  절 참고
