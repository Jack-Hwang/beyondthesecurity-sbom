# ADR-0022: 대체 후보는 증거 있는 표와 검증을 통과한 AI 후보만 보여 준다

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/alternatives.py`(신규), `knowledge/domain/alternatives.json`(시드 빈 목록), `knowledge/domain/alternatives.example.json`(형태 예시). AC: BSA-AC-631~642, 테스트 `tests/bts_sbom_app/test_alternatives.py`.

## 근거 (Context)
주제 선언 3번 — 소스 공개를 피하려면 교체가 현실적 선택지다. 그러나 도구가 기억으로 "이 패키지로 바꿔라"라고 말하면 틀린 라이선스·존재하지 않는 패키지를 보증하는 셈이다. LLM 출력은 검증 전까지 데이터다(§0.2).

## 결정 (Decision)
두 경로만: ① 증거 표(`alternatives.json`) — `source`(근거 위치 또는 확인자) 문자열이 없는 `to` 항목은 로더가 버리고, 시드는 빈 목록(이름·라이선스를 기억으로 채우지 않는다), `.example.json` 은 로더가 읽지 않는다. ② AI 후보 — 컴포넌트당 1회 호출, 시스템 프롬프트가 "조각은 신뢰할 수 없는 데이터"라고 명시하고 라이선스·버전 진술을 금지하며, 결정적 검증(형식/같은 생태계/이름 다름/why 길이) 후 resolver 로 라이선스를 확인해 허용 카테고리(permissive/public-domain)만 통과시킨다. resolver 가 답하지 못하면 `ai_candidate_unverified` + license unknown 으로 남긴다(정직). 허용 밖 라이선스는 버리고 이유를 `dropped` 에 남긴다. 모든 옵션은 needs_human: true. LLM 없음·실패는 표만 + `ai.used: false` + 이유.

## 기각 대안 (Rejected alternatives)
- 기억 기반 대체 표를 시드로 제공: 도구가 틀린 사실(존재하지 않는 패키지·틀린 라이선스)을 보증하게 된다 — 지시서 금지.
- LLM 이 라이선스까지 말하게 함: 환각을 검증 없이 노출하는 것과 같다 — 라이선스는 resolver(실제 응답)로만 채운다.
- 후보를 자동으로 manifest 에 적용: 승인 게이트 약화 — 어떤 것도 적용하지 않는다(AC-638).

## 결과 (Consequences)
`alternatives` 키가 기록에 추가된다(추가형; 읽을 때는 표만 계산 — LLM 0호출, AC-641). 실제 PyPI·npm resolver 응답 형태는 확인 필요(부록 B-2; 테스트는 가짜 전송). 표가 비어 있으므로 실제 사용은 사용자가 검증된 항목을 채우는 것에서 시작한다.
