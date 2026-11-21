# ADR-0027: 공격 실현 가능성은 입력만, CWE 는 집계, 증거는 내용 주소로 묶는다

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/evidence.py`(신규), `bts_sbom_app/engine.py`(레코드에 cwe·CVSS 벡터 저장 — 추가형), `bts_sbom_app/pipeline.py`(attack_inputs·cwe 단계), `bts_sbom_app/server.py`(/api/evidence/(by project)), `bts_sbom_app/cli_ext.py`(evidence). AC: BSA-AC-731~740, 테스트 `tests/bts_sbom_app/test_evidence.py`.

## 근거 (Context)
TR 8477 검토 §5-P1: 6.11 은 존재 확인과 악용 입증을 구분하고, 표 3~5 는 "가장 흔한 CWE 대비 리뷰"를 근거 방법으로 든다. 부속서 A 의 증거 사이드카는 평가자가 "무엇을 받았는가"를 고정하라고 요구한다. 도구의 정직 규칙: 등급을 내지 않는다(§6 하지 않을 것).

## 결정 (Decision)
`attack_inputs` 는 발견별로 CVSS v3(AV/AC/PR/UI)와 v4(AV/AC/AT/PR/UI) 지표를 풀어 싣는다 — **입력일 뿐 등급이 아니며**, 벡터가 없으면 `{}` 로 남긴다(지어내지 않음). `cwe_top` 은 OSV `database_specific.cwe_ids`(레코드에 `cwe` 로 저장, 없으면 0건)를 레코드·포트폴리오에서 집계한다. `bundle` 은 SBOM·VEX·레코드 산출물의 SHA-256·바이트·도구/코어 버전·시각을 담은 매니페스트를 `<project>/bundle/bundle.json` 으로 쓴다 — **내용 주소만, 서명 없음**(키 보유자가 별도 작업).

## 기각 대안 (Rejected alternatives)
- 공격 실현 가능성 등급 산출: TARA 대체 — 검토서 §6 이 명시적으로 금지.
- CWE 없는 권고에 CWE 를 추론: 근거 없는 데이터 생성 — 없으면 0건.
- 번들에 서명 첨부: 키 관리가 이번 범위 밖 — 내용 주소만 제공하고 한계를 문서화.

## 결과 (Consequences)
기록에 `attack_inputs`·`cwe` 키 추가(추가형). engine 레코드에 `cwe`·`cvss_v3_vector`·`cvss_v4_vector` 가 선택 필드로 추가(기존 소비자 영향 없음 — 키 부재 관대). 번들은 결정적(타임스탬프 제외)이고 네트워크 호출 0건.
