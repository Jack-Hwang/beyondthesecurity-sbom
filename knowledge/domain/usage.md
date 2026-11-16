# 사용법 (CLI usage)

## 한 프로젝트 분석

`python -m sbomplus scan <소스>` — 소스는 GitHub URL, `owner/repo` 약식, 또는 로컬 폴더다. 작업은 항상 복사본에서 이루어지며 원본은 바뀌지 않는다.
옵션: `--ref` 브랜치나 태그, `--depth` clone 깊이(기본 200), `--offline`, `--no-license-online`, `--no-llm`, `--industries finance,maritime`, `--policy policy.json`.
결과는 `--out` 폴더에 프로젝트별 JSON 레코드, CycloneDX, SPDX, OpenVEX, Markdown 보고서로 저장된다.

## 패치

`python -m sbomplus patch <소스>` 는 계획만 보여준다(승인 없음, 파일 변경 0). `--approve` 를 주면 매니페스트를 수정하고 재스캔으로 검증한 뒤 fix 브랜치에 커밋한다.
`--token <digest>` 로 검토한 계획과 일치할 때만 적용한다. 전달 대상은 `--deliver branch|folder|inplace|github` 이며 inplace 는 `--allow-origin-write`, github 는 `--remote URL --allow-push` 가 필요하다.

## 아키텍처

`python -m sbomplus arch <소스>` — 핫스팟, 변경 결합, import 순환, 도메인 클러스터, 런타임 EOL 과 현대화 제안을 출력한다.

## 배치와 평가

`python -m sbomplus batch evals/e2e_sources.json --tag mypass` 는 여러 소스를 한 번에 분석하고 합계 지표를 `latest.json` 에 쓴다.
`python -m sbomplus loop ...` 는 패스를 실행하고 기준선과 비교해 accept 또는 rollback 을 기록한다. `python -m sbomplus evalrag` 는 검색 품질(Recall@5, MRR, nDCG@5)을 잰다.

## 챗봇과 서버

`python -m sbomplus chat "<질문>" --evidence <out 폴더>` 는 분석 결과와 지식베이스로 답한다. `python -m sbomplus serve --port 8800` 는 JSON API 와 간단한 웹 화면을 연다.

## EXAONE 설정

환경 변수 `EXAONE_API_KEY`, `EXAONE_BASE_URL`(기본 https://api.exaone.ai/v1), `EXAONE_MODEL`(기본 k-exaone_v2.5) 또는 `SBOMPLUS_LLM_CONFIG` 로 JSON 설정 파일 경로를 지정한다. 키가 없으면 결정적 제안으로 동작한다.
