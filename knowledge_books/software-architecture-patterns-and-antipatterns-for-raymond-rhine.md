# Software Architecture Patterns, Antipatterns, and Pitfalls (얼리 릴리스 사본) — 정제 노트

출처: 로컬 도서 "Software Architecture Patterns and Antipatterns" 얼리 릴리스 사본 (EPUB, slug
`software-architecture-patterns-and-antipatterns-for-raymond-rhine` — EPUB 메타데이터 제목이 축약돼 있어 슬러그가
파일명과 다르다; 책 표지 제목은 아래 전체판 노트 [[software-architecture-patterns-antipatterns-and-pitfalls]]와
같다). 추출 원문(8.7만 자, 전체판 96만 자)을 읽고 정리한 종합 — 원문 인용이 아니다.

## 이 책의 논지

전체판의 얼리 릴리스 사본으로, 질문형 장("메시지를 어떻게 우선순위화하는가", "메시지 손실을 어떻게 막는가")
으로 스타일·패턴·함정을 다룬다. 이 사본에서 확인되는 핵심 논지 하나: **메시지 구돡(confirm)은 데이터베이스 커밋
"뒤에" 보낸다** — 커밋 전에 구돡하면 브로커가 메시지를 제거한 뒤 DB 실패가 나면 메시지가 사라진다. 메시지
주도 시스템에서 브로커는 트랜잭션 흐름의 마지막 참여자다.

## 핵심 개념 지도

- **구돡 순서 규칙**: receive → 처리 → DB 커밋 → 브로커 구돡. 순서 하나가 "적어도 한 번"과 "최대 한 번"의
  경계를 정한다.
- **질문형 목차**: 전체판과 같은 기능(capability)별 질문 구조 — 스타일을 장르가 아니라 해결할 질문으로 고른다.

## 이 프로젝트 적용

- **구돡 순서 원칙의 일반화**: 이 앱의 "작업 상태를 done으로 바꾸는 시점" 규칙 — 스캔 작업에서 `st.jobs[jid]=final`
  이 클린업(임시 폴더 제거·버스 종료) "뒤에" 일어나는 이유(server.py /api/scan)가 같은 원칙이다: 완료 선언을
  먼저 하면 뒤의 실패가 유실된다. 새 배경 작업(books ingest 포함)도 같은 순서를 지킨다.
- **전체판과 함께 읽기**: 원문 검색은 두 슬러그 모두를 히트한다 — 개념 질문은 전체판
  [[software-architecture-patterns-antipatterns-and-pitfalls]] 노트를 우선 참조.
