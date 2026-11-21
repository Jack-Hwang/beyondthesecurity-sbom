# ADR-0026: 스캔 결과를 TR 8477 8.1 형태의 V&V 증거 보고서로 내보낸다 (적합 판정 없음)

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/vnv.py`(신규), `bts_sbom_app/pipeline.py`(vnv 단계 + engine.offline 기록), `bts_sbom_app/server.py`(/api/vnv/(by project)), `bts_sbom_app/cli_ext.py`(vnv). AC: BSA-AC-721~730, 테스트 `tests/bts_sbom_app/test_vnv.py`.

## 근거 (Context)
ISO/SAE TR 8477 검토(`docs/ISO_SAE_TR_8477_REVIEW.md` §5-P1)의 권고: "스캔 결과"를 평가자가 읽는 "V&V 증거"로 바꾸는 가장 작은 변경. 8.1 보고 형식은 추적성·범위(제외와 이유)·결과 등급·편차·결론을 요구하고, 6.11은 존재 확인과 악용 입증을 구분한다. 이 도구의 정직 계약: 조회 실패·오프라인·미해결이 있으면 절대 "pass"라 하지 않는다.

## 결정 (Decision)
`vnv.report(rec, plan_ref, req_ref)` 는 결정적으로 세 등급 중 하나를 낸다: **fail**(분석 실패) / **pass with restrictions**(오프라인, 조회 실패 패키지, 버전 미확정, 라이선스 미해결, 미지원 파일 중 하나라도 있거나 부품 0개) / **pass**(그 외). 범위에는 고정 문구 "공격 실현 가능성(악용 입증)은 시험하지 않았습니다 — 존재만 확인"을 항상 넣고, 제외 사유는 기록의 자체 장부(status.query_status, engine.unsupported, license_category)에서만 채운다. 추적성에 사용자가 준 plan/req 참조와 온라인 여부, 코어 버전을 넣는다. **적합 판정은 내지 않는다**(부속서 A: 평가자의 독립 판단).

## 기각 대안 (Rejected alternatives)
- TR 조항별 적합 판정 산출: 평가자의 독립 판단을 도구가 대신한다 — 검토서 §6이 금지.
- 오프라인·조회 실패를 숨기고 pass: 근거 없는 통과 — 정직 계약 위반.
- 악용 가능성 등급 산출: TARA 의 몫(검토서 §6 하지 않을 것) — 지표 입력(작업 31)까지만.

## 결과 (Consequences)
기록에 `vnv` 키 추가(추가형). 파이프라인이 `engine.offline` 을 기록해 오프라인 증거가 보고서에 남는다. `plan_ref`·`req_ref` 는 사용자 참조 필드(고객-공급자 합의용) — 검토서 §8 물어볼 것의 전자안.
