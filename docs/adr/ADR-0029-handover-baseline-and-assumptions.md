# ADR-0029: 인계 시점에 기준선을 동결하고, 가정은 검증 근거 없으면 fail-closed 로 남긴다

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/handover.py`(신규), `bts_sbom_app/server.py`(/api/handover/freeze·/post), `bts_sbom_app/cli_ext.py`(handover --freeze/--post). AC: BSA-AC-749~758, 테스트 `tests/bts_sbom_app/test_handover.py`.

## 근거 (Context)
TR 8477 검토 §5-P2: 4.7 은 인수인계 시점의 **동결된 기준선**과 인계 뒤 한쪽이 발견한 것의 갱신을 요구하고, 4.8 은 가정을 명시하고 검증 대상으로 삼으라 한다. 지금은 `.prev.json` 으로 직전 1건만 남아 기준선 동결이 없고, false-positive 결정의 가정(예: vulnerable_code_not_present)에 검증 근거 참조가 강제되지 않는다.

## 결정 (Decision)
`freeze` 는 인수 시점의 SBOM/VEX/레코드 해시, 부품·버전 목록, 발견 id 집합을 `handover-baseline.json` 으로 **한 번만** 쓴다(기존 기준선 절대 덮어쓰지 않음). 이후 분석에서 기준선에 없는 권고가 기준선 부품에 붙어 있으면 `post_handover` 가 "인수 후 발견(상대 당사자에게 영향)"으로 표시하고, 부품 구성 해시가 바뀌면 그 사실도 보고한다. 부품 정보가 없는 발견은 **fail-closed** 로 기준선 부품으로 간주해 표시한다. `assumptions.evaluate` 는 false-positive 결정의 가정을 등록부로 만들고, 노트가 근거 참조(저장소 경로·증거 id·긴 해시)를 담지 않으면 **unverified** 로 남긴다 — 미검증 가정은 발견을 조용히 지우지 않는다(VEX 는 justification+reason 게이트를 유지).

## 기각 대안 (Rejected alternatives)
- `.prev.json` 재사용: 직전 1건만 있어 동결·보존이 안 된다 — 인계 기준선은 별도 파일로 한 번만 쓴다.
- 기준선을 덮어쓰는 갱신 명령: 동결의 의미가 사라진다 — 존재하면 already_frozen 을 보고한다.
- 가정을 VEX 에서 강제 제거: 기존 justification+reason 게이트(AC 계열)를 깨는 중대 변경 — 등록부가 평가자용 증거를 추가하는 방향.

## 결과 (Consequences)
기록에는 새 파일이 추가될 뿐 `rec` 키는 추가되지 않는다. 부품 판정은 fail-closed(정보 없으면 표시). 근거 참조 판정은 결정적(정규식)이며 사람이 최종 확인한다. `component_hash` 로 구성 변화를 보고한다.
