# ADR-0025: 분야별 정책은 조직이 고치는 시작 예시 값이다 (규제 요구가 아니다)

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/sector_policy.py`(신규), `bts_sbom_app/cli.py`(--sector-policy, --policy 와 상호 배타). AC: BSA-AC-686~692, 테스트 `tests/bts_sbom_app/test_sector_policy.py`.

## 근거 (Context)
주제 선언 5번(금융·국방·선박·자동차·의료). 분야별 보고서는 문서 요건을 판정할 뿐, 라이선스·EOL 정책 기본값은 하나(DEFAULT_POLICY)였다. 정직 규칙: 도구가 규제 요구를 하드코딩하면 법률 판단을 코드가 대신하고 시점이 바뀌면 거짓이 된다.

## 결정 (Decision)
정확히 5개 프리셋(finance/defense/maritime/automotive/medical — 지시서 표의 값 그대로)만 두고, 각 항목의 basis 문구를 "starter-template (example values chosen by the tool author, not a regulation)" 로 고정한다. `resolve` 는 DEFAULT_POLICY 와 병합한 유효 정책을 돌려주고, `<evidence>/policy_presets.json` 으로 덮어쓰기·추가를 허용하되 검증 실패 항목은 이유와 함께 거부한다. `--policy` 와 `--sector-policy` 는 상호 배타, 프리셋 미선택은 기존 기본값 그대로(AC-690). scan·obligations·legacy 출력은 쓰인 유효 정책과 basis 를 한 줄로 보여 준다. `eol_tolerance` 는 legacy.assess 가, distribution·deny·review 는 obligations.assess 와 policy_findings 가 읽는다. cra·robot 은 프리셋 없음(default).

## 기각 대안 (Rejected alternatives)
- 분야 이름으로 규제 요구를 하드코딩: 법률 판단을 코드가 대신하고 규제 개정 시 거짓이 된다 — basis 문구로 "예시 값"임을 코드에 새긴다.
- 프리셋 없이 `--policy` JSON 만: 분야별 시작점이 없어 매번 처음부터 써야 한다(주제 선언의 "적용 분야"와 안 맞음).
- 프리셋을 규제 조항과 함께 기록: 조항 인용 금지(§0.2) — 근거 열은 두지 않는다.

## 결과 (Consequences)
`legal_review_flags` 대상: 프리셋 5행의 값 자체는 사람이 법무 관점에서 검토해야 하는 예시다. `eol_tolerance` 의 fail/review 가 legacy findings 등급에 반영되고(작업 24), 기존 `--policy` 동작은 불변(AC-690).
