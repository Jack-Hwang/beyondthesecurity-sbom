# Systems Design and Engineering, 2판 (Bonnema, Broenink, et al.) — 정제 노트

출처: 로컬 도서 "Systems Design and Engineering — Facilitating Multidisciplinary Development Projects 2nd" (PDF,
slug `systems-design-and-engineering-facilitating-multidisciplinary-development-projec`). 추출 원문을 읽고 우리 말로
정리한 종합 — 원문 인용이 아니다. 원문 검색은 `/api/books/search` 또는 채팅 `book_search`.

## 이 책의 논지

다학제(기계·전기·소프트웨어) 프로젝트를 위한 시스템 엔지니어링 교과서. 모델 기반 사고(영향 다이어그램, 결함
트리, N2 다이어그램)로 요구→기능→구성요소→인터페이스를 체계적으로 전개한다. 핵심 도구 **N2 다이어그램(N-squared)**:
n×n 행렬에 구성요소를 배치하고 대각선 밖 칸에 인터페이스를 표기해 **모든 인터페이스를 빠짐없이 점검** 하게
한다 — 분해-합성 사고(decomposition-composition thinking)의 인터페이스 관리 도구.

## 핵심 개념 지도

- **영향 다이어그램**: 목표 변수(예: 태양광 레이서의 순항 속도)에 기여하는 인자를 화살표로 — 상반되는 효과도
  모델링 가능. 결함 트리와 형태가 닮았고 위험·오류 조사에 쓴다.
- **N2 다이어그램**: 기능·구성요소 간 모든 인터페이스의 누락 방지 목록화 — 인터페이스 관리의 표준 도구(Kapurch &
  Rainwater 참조).
- **다학제 조율**: 전문 분야 용어·단위·책임 경계를 명시적 계약으로 — 소통 실패가 시스템 실패의 주원인.
- **요구 계층**: 사용자 요구 → 시스템 요구 → 기능 → 구성요소의 추적 사다리.

## 이 프로젝트 적용

- **N2 사고 = import 엣지 행렬**: dep-graph 판·arch.py 그래프(import_edges, 순환, tangle)가 소프트웨어판 N2 —
  모듈 간 인터페이스 전수 목록화와 누락·순환 검사. 새 모듈 추가 시 "누구와 말하는가"를 먼저 목록화.
- **영향 다이어그램 → 게이트 논쟁**: "p95가 나쁘면 무엇이 기여하는가" 같은 질문에 기여 인자(청크 수·필터·토크나이저)
  다이어그램으로 접근 — 성능 회귀 시 원인 인자를 하나씩 잰다(capacity.md의 측정 분해).
- **다학제 조율 언어**: 이 저장소의 다학제 = 테스트·문서·런타임·증거 — 각 전문 축의 계약(AC↔테스트 추적성,
  doclint 참조 존재)이 명시적. 새 문서 유형도 참조 계약을 갖는다.
- **요구 추적 사다리**: specs AC → 테스트 docstring → ENFORCEMENT_MAP 행의 3단 추적이 이 책의 요구 계층 관행.
