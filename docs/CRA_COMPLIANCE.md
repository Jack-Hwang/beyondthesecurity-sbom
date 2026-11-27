# EU CRA 컴플라이언스 레인 (Regulation (EU) 2024/2847)

**적용 근거**: K-OSSC 「EU 사이버 복원력법(CRA) 실무 가이드 1.0」(최윤성, 2026-11-23, CC BY-NC 4.0) + Regulation (EU) 2024/2847.
**AC**: BSA-AC-1241~1246 (지시서 세대 ac-645-650). **모듈**: `bts_sbom_app/cra.py` (계산) · `bts_sbom_app/cra_api.py` (HTTP) · 콘솔 `🇪🇺 CRA` 판 (compliance 그룹).

## 1. 무엇을 자동화했는가 (가이드 → 기능 매핑)

| 가이드 요구 | CRA 조항 | 본 플랫폼 구현 |
|---|---|---|
| 기계 판독 SBOM (최상위 의존성 이상) | Annex I Part II(1) | 기존 CycloneDX 1.5·SPDX 2.3 생성(`sbom.py`) + `conformance.py`의 EU CRA·BSI TR-03183-2 regime 채점을 readiness에 연동 |
| CVD 연락처·security.txt | Part II(5)·(6), RFC 9116 | `/.well-known/security.txt` 자동 서빙 (Contact·Expires(90일 갱신 예시)·Preferred-Languages·Policy·CSAF) |
| 지원 기간 선언 (최소 5년, 연·월 고지) | Article 13(8)·Annex II 7 | `POST /api/cra/<p>/support` 선언 → 5년 미달 시 **개월 수 실측** 표시 |
| EOL 컴포넌트 관리 | Article 13(5)·부록 J 대장 3 | 컴포넌트 전수 대장 CSV + 4구간 우선순위 규칙(음수=즉시/0-180 긴급/180-365 계획/365+ 모니터링) |
| Article 14 보고 체계 | Article 14(2)·(4) — **2026-09-11부터 적용 중** | 인지 시점(T0) 기록 → 24h 조기 경보·72h 통보·최종(취약점: 시정 가용+14일 / 사고: 통보+1개월) 시계 자동 계산 |
| SBOM 관리 5종 대장 | 부록 J | 대장 1~5 CSV 다운로드 (`?which=1..5`) |
| 취약점 공개 공시·처분 근거 | Part II(4) | OpenVEX(`sbom.py`) + triage 결정(not_affected는 VEX 근거 fail-closed) 기록 |

## 2. 정직 규칙 (이 앱의 공통 계약)

1. **악용 판정을 자동으로 하지 않는다** — CISA KEV·ENISA EUVD 피드는 미연동이므로 "적극적 악용"은 **사람이 기록하는 인지 판정**(증거 참조 포함)이며, 취약점 추적 대장의 악용여부 열은 `미판정 (KEV·EUVD 미연동)`으로 채워진다.
2. **상류 EOL일을 측정하지 않는다** — EOL 대장은 열과 우선순위 규칙을 제공하고 날짜는 팀이 기입한다. 날짜를 추측해 채운 대장은 빈 대장보다 나쁘다.
3. **주소를 추측하지 않는다** — `BTS_SBOM_CVD_CONTACT` 미설정이면 security.txt를 만들지 않고 404+해결책을 답한다.
4. 모든 체크는 근거 조항(`ref`)을 표시하고, 미측정 항목은 gap+fix로 답한다.

## 3. API 표면

```
GET  /.well-known/security.txt               RFC 9116 파일 (BTS_SBOM_CVD_CONTACT 설정 시; 미설정=404+fix)
GET  /api/cra/<project>                      readiness 스코어카드(8체크) + security.txt 상태·미리보기 + 지원기간 + 인지 기록
GET  /api/cra/<project>/ledgers?which=1..5   부록 J 5종 대장 CSV 다운로드
GET  /api/cra/<project>/article14            인지 기록 + 계산된 Article 14 시계
POST /api/cra/<project>/article14            {id, kind: aev|incident, aware_at?, mitigation_available?, evidence?}
POST /api/cra/<project>/support              {support_end: "YYYY-MM"} (빈 값=선언 삭제)
POST /api/cra/<project>/eol-maintained       {maintained: bool} — EOL 대장 유지 플래그
```

환경변수: `BTS_SBOM_CVD_CONTACT`(필수, mailto: 또는 URL), `BTS_SBOM_CVD_POLICY_URL`·`BTS_SBOM_CVD_CSAF_URL`(선택).
토큰 게이트: `BTS_SBOM_ACCESS_TOKEN` 설정 시 security.txt도 게이트 뒤에 놓인다 — RFC 9116 발견 가능성과의 충돌이므로 토큰 배포에서는 예외 허용을 검토할 것(문서화된 편차).

## 4. 콘솔

사이드바 **지식과 컴플라이언스 → 🇪🇺 CRA** 판: readiness 8체크 스코어카드(gap은 fix 표시), security.txt 미리보기, 지원기간 선언 폼, EOL 유지 플래그, Article 14 인지 기록 폼+시계 표, 대장 5종 다운로드.

## 5. 실측 (2026-11-28, 로컬)

- 기존 스캔 레코드 기준 readiness 실측·security.txt 서빙·대장 행수·Article 14 시계는 `evidence/cra_e2e/E2E.md` 참조.
- 테스트: `tests/bts_sbom_app/test_cra.py` (8테스트 — 모듈 6 + HTTP 표면 1 + 인지 중복 1).

## 6. 하는 일이 아닌 것

- 적합성 평가·CE 마킹·DoC 작성 (CRA 적합성 평가는 Module A/B+C/H의 별도 절차)
- 법률 판단·보고 제출 (ENISA SRP 제출은 담당자의 EU Login 계정으로 사람이 한다 — 부록 K 절차서)
- KEV·EUVD 자동 매칭 (미연동; 연동 시 악용여부 열이 자동화될 수 있다)
