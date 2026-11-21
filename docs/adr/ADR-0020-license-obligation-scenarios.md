# ADR-0020: 라이선스 의무를 컴포넌트×시나리오로 보고한다 (참고 규칙, 법률 자문 아님)

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/obligations.py`(신규), `bts_sbom_app/pipeline.py`(obligations 단계), `bts_sbom_app/server.py`(/api/obligations/(by project)), `bts_sbom_app/cli_ext.py`(obligations), `bts_sbom_app/report.py`(Obligations 절). AC: BSA-AC-601~614, 테스트 `tests/bts_sbom_app/test_obligations.py`.

## 근거 (Context)
주제 선언 3번 — AGPL·GPL 계열의 소스 공개 부담 때문에 현업이 코드 재구현을 하고 있다. 기존 `licenses.policy_findings` 는 **카테고리 단위**("이 배포 형태에서 이 카테고리 N개")라서 "어느 컴포넌트가 어느 사용 형태에서 어떤 범위의 의무를 일으키는가"에 답하지 못한다. 강의의 정직 규칙: 판단할 수 없으면 unknown 이고 unknown 은 절대 ok 로 세지 않는다.

## 결정 (Decision)
시나리오 3종(internal/binary/saas) × 카테고리의 참고 규칙 표(`SCOPE`, `confidence: "reference"`)로 컴포넌트별 verdict(none/offer/review/unknown)와 scope(library_only/combined_work/combined_work_incl_network/unknown)를 계산한다. 미해결 라이선스는 모든 시나리오에서 unknown(never none). 호환성은 **정확히 5개의 참고 규칙**만 두고 그 밖의 조합은 `no_rule` — "compatible" 이라고 단정하는 규칙은 만들지 않는다. offer 컴포넌트에는 순서가 고정된 완화 선택지 5개(`needs_human: true`)를 붙인다. 모든 출력에 DISCLAIMER("엔지니어링 신호이며 법률 자문이 아닙니다")를 붙인다. 기존 `policy_findings` 반환값은 불변(AC-613).

## 기각 대안 (Rejected alternatives)
- 카테고리 단위 정책만 유지: 컴포넌트·시나리오 질문("이 AGPL 컴포넌트를 SaaS 로 쓰면?")에 답할 수 없다 — 주제 선언이 요구하는 바로 그 질문이다.
- 호환성을 "compatible" 로 단정하는 표: 법률 판단을 코드가 대신하게 되고 시점이 바뀌면 거짓 안심이 된다 — 5개 참고 규칙 + no_rule 로 제한.
- unknown 을 "안전"으로 간주: 정직 계약 위반(근거 없는 통과).

## 결과 (Consequences)
파이프라인 기록에 `obligations` 키가 추가된다(추가형 — 옛 기록은 읽을 때 계산, AC-612). 규칙 표·호환성 5규칙·프리셋(작업 28)은 `legal_review_flags` 의 검토 대상이다. 조항 번호·원문 인용은 어디에도 없다.
