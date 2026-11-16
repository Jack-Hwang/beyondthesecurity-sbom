# 레거시 아키텍처 분석 (Legacy architecture analysis)

## 측정 항목

- **stack**: 언어별 파일 수와 LOC.
- **핫스팟(hotspot)**: git 변경 빈도와 복잡도의 곱. 자주 바뀌면서 복잡한 파일이 가장 위험하며 가장 먼저 테스트와 리팩터링을 해야 한다. 점수는 두 순위 백분위의 곱이다.
- **변경 결합(coupling)**: 함께 자주 바뀌는 파일 쌍(공유 커밋 3회 이상, jaccard 0.3 이상). 두 파일 사이에 import 가 없으면 숨은 의존(hidden dependency)이다.
- **import 그래프**: 파이썬, JS/TS, 자바/코틀린, 고, C/C++, 러스트의 내부 import 를 해석한다. 해석 못 하는 언어는 `languages_without_import_analysis` 로 밝힌다.
- **순환 의존(cycle)**: 강연결 요소(Tarjan SCC). 순환에 속한 모듈은 독립 배포와 점진 교체(strangler)가 어렵다. 순환을 먼저 끊는다. 패키지 `__init__.py` 재노출로 생긴 순환은 무해한 경우가 많다.
- **계층(layers)**: 응축 그래프의 최장 경로. fan-in, fan-out, 불안정성(instability)으로 허브 모듈을 찾는다.
- **도메인 클러스터**: 디렉터리 기준 응집도(내부 간선 / 전체 간선). 응집도 0.6 이상이고 모듈이 3개 이상이며 유입 의존이 적으면 분리 후보(extraction candidate)다.

## 런타임 EOL

.python-version, runtime.txt, .nvmrc, go.mod, package.json engines, pyproject 의 requires-python, Dockerfile FROM 에서 런타임 버전을 읽고 지원 종료 여부를 판정한다.
endoflife.date 온라인 데이터를 우선하고, 온라인이 불가하면 내장 표를 쓰되 "UNVERIFIED" 로 표시한다.

## 정직 원칙

얕은 clone(shallow)이면 핫스팟과 결합이 최근 커밋 범위만 반영한다고 notes 에 적는다. .git 이 없으면 핫스팟 분석을 건너뛰고 그 사유를 기록한다.
import 간선이 하나도 해석되지 않으면 "위험 없음"이 아니라 "분석 불가"로 보고한다.

## 현대화 제안

런타임 업그레이드(EOL), 순환 끊기, 핫스팟 리팩터링, 숨은 의존 명시화, 도메인 분리 후보를 측정 근거와 함께 제안한다. 각 제안은 근거 수치를 인용한다.
