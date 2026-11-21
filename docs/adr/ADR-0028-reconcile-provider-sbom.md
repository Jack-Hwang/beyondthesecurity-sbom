# ADR-0028: 공급자 SBOM 을 믿지 않고 산출물과 대조한다 (TR 5.2 교차 확인)

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/reconcile.py`(신규), `bts_sbom_app/server.py`(/api/reconcile/(by project)?sbom=path), `bts_sbom_app/cli_ext.py`(reconcile --sbom). AC: BSA-AC-741~748, 테스트 `tests/bts_sbom_app/test_reconcile.py`.

## 근거 (Context)
TR 8477 5.2 계획 예시: BOM 을 받고, 알려진 취약점을 식별하고, 스캔하고, 결과를 BOM 과 교차 확인한다. 검토 §5-P2: "공급자 SBOM 을 믿지 않고 확인하는 기능이 자동차 공급망에서 가장 쓸모가 크다". `binscan` 은 문자열 증거만 주고 식별은 하지 않는다고 스스로 명시한다 — 그 정직함을 그대로 옮긴다.

## 결정 (Decision)
`reconcile(provider_sbom, rec, string_evidence=None)` 는 네 갈래를 낸다: ① 스캔에는 있는데 공급자가 선언하지 않은 부품 — **"선언되지 않은 것으로 보인다(후보)"** 까지만(문자열 증거는 식별이 아님), ② 공급자가 선언했는데 스캔에서 못 찾은 부품(번들·미사용·이름 변경 가능성을 이유에 명시), ③ 버전 불일치(양쪽 버전 나란히), ④ BOM 기준 권고와 스캔 기준 권고의 차이(양방향). 출력은 "reconciliation findings only — no conformance verdict"(부속서 A). CycloneDX 와 SPDX 를 읽는다.

## 기각 대안 (Rejected alternatives)
- 공급자 SBOM 을 곧이곧대로 믿고 스캔 생략: 5.2 가 직접 요구하는 교차 확인을 생략하는 것 — 공급망 신뢰를 검증 없이 이전.
- 문자열 증거로 "선언되지 않음"을 단정: binscan 은 식별 도구가 아니다 — 후보까지만.
- 적합/불적합 판정 첨부: 평가자의 독립 판단(부속서 A)을 도구가 대신한다.

## 결과 (Consequences)
대조는 네트워크 0건, 결정적 출력. 공급자 SBOM 의 vulnerabilities 블록(CycloneDX)만 읽는다(SPDX 권고 표기는 형태가 다양해 확인 필요 — 한계로 문서화). 사용자는 `--sbom <file>` 로 공급자 문서를 직접 준다(가져오기 경로의 신뢰 경계는 사용자 책임).
