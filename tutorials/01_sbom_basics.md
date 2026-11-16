# 튜토리얼 1 — SBOM 기초와 bts-sbom 실습 (30분)

> 대상: SBOM이 처음인 개발자·보안 담당자. 빌드 도구 없이 표준 라이브러리만으로
> 따라할 수 있습니다.

## 1. SBOM이란 무엇인가 (5분)

SBOM(Software Bill of Materials, 소프트웨어 자재 명세서)은 **하나의 소프트웨어가
어떤 구성요소(의존성)로 만들어졌는지 기계가 읽을 수 있게 목록화한 문서**입니다.

- 자동차 부품 명세서와 같은 원리 — 리콜(취약점)이 터졌을 때 **내 제품에 그 부품이
  들어갔는지 5분 만에 확인**하려면 명세서가 필요합니다.
- 규제가 이미 현실입니다:
  - **EU CRA**: 2027-12-11부터 시장 판매 제품에 machine-readable SBOM 의무
  - **미국 FDA 524B**: 의료기기 인가 신청에 SBOM 제출 의무(2023-03~)
  - **미국 방위**: EO 14028 → CISA 증명 양식 → DoD 조달 SBOM 요구
  - 한국: KISA SW 공급망 보안 가이드라인 · 금융보안원 OSS 관리 안내서

## 2. 두 가지 표준 형식 (5분)

| | SPDX 2.3 | CycloneDX 1.5 |
|---|---|---|
| 관리 단체 | Linux Foundation | OWASP |
| 강점 | 라이선스 표현(`licenseConcluded` 등 법적 필드) | 취약점·VEX·서명 등 보안 친화 |
| 문서 최상위 | `spdxVersion: "SPDX-2.3"` | `bomFormat: "CycloneDX"` |

bts-sbom은 **둘 다 읽고 쓸 수 있습니다**. 규제 제출용이면 제출처가 요구하는 쪽을
고르면 됩니다(둘 다 "commonly used, machine-readable"으로 인정).

**NTIA 최소 요소(2021)** — 어느 형식이든 이 7가지는 있어야 "제대로 된 SBOM"으로
봅니다: 공급자(supplier) · 구성요소 이름 · 버전 · 고유 식별자 · 의존 관계 ·
SBOM 작성자 · 작성 시각. `bts-sbom`은 이 체크를 내장했습니다.

## 3. 실습 — 의존성 목록에서 SBOM 만들기 (10분)

설치:

```bash
git clone https://github.com/Jack-Hwang/beyondthesecurity-sbom.git
cd beyondthesecurity-sbom && pip install -e .
```

`requirements.txt` 예시 (실습용 — `examples/requirements.txt`에도 동일):

```
requests==2.31.0
cryptography==41.0.4
jinja2==3.1.2
```

SBOM 생성:

```bash
bts-sbom sbom examples/requirements.txt --name "demo-app" --out demo.spdx.json
```

결과 확인 포인트 (demo.spdx.json 열어서):

1. `spdxVersion: "SPDX-2.3"` — 형식 선언
2. `packages[]` — 구성요소마다 name/version/`licenseConcluded`/`supplier`
3. `relationships[]` — "demo-app DESCRIBES requests" 같은 의존 관계
4. `creationInfo` — 작성자(도구)와 시각

> **교육 포인트**: 라이선스 증거가 없는 구성요소는 `NOASSERTION`으로 정직하게
> 기록됩니다. SBOM에 "추측"은 없어야 합니다.

## 4. NTIA 최소 요소 자가진단 (5분)

```bash
python -m bts_sbom sector --sector cra --sbom demo.spdx.json
```

CRA-02(NTIA 최소요소) 행의 `evidence.total_score`를 보세요. 요소 하나라도
빠지면 점수가 떨어지고 `gap`이 됩니다 — 예를 들어 checksum이 없으면
"per-component checksum" 요소가 미달됩니다.

## 5. 정리 퀴즈 (5분)

1. SPDX와 CycloneDX 중 취약점 상태(VEX)와 함께 쓰기 좋은 쪽은?
2. `licenseConcluded: "NOASSERTION"`은 실패인가?
3. CRA 시행(2027-12-11) 이후 SBOM이 없는 제품은?

<details><summary>정답</summary>

1. CycloneDX (vulnerabilities 블록 내장 — 다만 SPDX+별도 VEX도 가능)
2. 아니다 — 증거가 없을 때의 **정직한 상태**다. 다만 라이선스 리스크 관점에서
  는 해소가 필요하다(스캔 → 라이선스 확인 → 기록).
3. EU 시장 판매가 제한될 수 있다(과태료 최대 매출 15%·1,500만 유로).
</details>

## 다음 단계

- [튜토리얼 2](02_vulnerability_scan.md) — OSV로 취약점 스캔과 수정 버전 제안
- [튜토리얼 3](03_sector_compliance.md) — CRA/FDA 규제 컴플라이언스 리포트
