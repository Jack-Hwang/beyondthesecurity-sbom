# Dataset Datasheet — bts-sbom 평가·지식 코퍼스

schema: bts-sbom.dataset-datasheet.v1 | 이 문서는 코퍼스가 바뀌면 스테일로 판정된다 — `python -m bts_sbom_app datasheet --check`가 기계 판정.

## 동기·구성

평가셋은 곧 평가가 찾아낼 수 있는 실패의 상한이다: 전형(일상 질의)·경계(주제 밖 ood)·적대(공격·교란)의 구성비가 그대로 커버리지를 정의한다. 아래는 각 코퍼스의 실측 구성(전형/경계/적대)과 내용 핀(fingerprint)이다.

- `evals\chat_features.json` — n=27, 전형 27 / 경계 0 / 적대 0, fingerprint `353f5f46c780`
- `evals\injection_holdout.jsonl` — n=46, 전형 24 / 경계 0 / 적대 22, fingerprint `f363879cdd04`
- `evals\injection_samples.jsonl` — n=50, 전형 25 / 경계 0 / 적대 25, fingerprint `6a6c912e20c1`
- `evals\rag_dev.json` — n=20, 전형 15 / 경계 5 / 적대 0, fingerprint `4b7823e570fc`
- `evals\rag_golden.json` — n=25, 전형 20 / 경계 5 / 적대 0, fingerprint `d60c939bb542`
- `evals\rag_test.json` — n=16, 전형 12 / 경계 4 / 적대 0, fingerprint `bcfd2d9f65f2`

## 수집·출처

RAG 골든셋은 제품 문서·강의 노트에서 질의를 작성해 만들었고, holdout(rag_test)은 튜닝 전에 작성되어 따로 핀을 갖는다. injection 코퍼스는 공격 라벨/정상 라벨이 붙은 이중 언어 표본이다. 지식 코퍼스 출처:

- `knowledge/domain` — 16개 문서
- `knowledge/lecture` — 6개 문서

## 위생·한계

- 누출 검사: blocking 0건, warning 0건 (clean — `python -m bts_sbom_app evalsets`가 재판정한다).
- 한계: 골든셋이 작다(합계 0건) — 점수는 Wilson 구간으로 읽어야 한다. chat_features는 전형뿐이다(구성표가 그 간극을 드러낸다).
- 이 문서의 모든 역따옴표 경로는 존재해야 하고 코퍼스 건수는 실측과 일치해야 한다 — 어긋나면 스테일이고 exit 1이다.
