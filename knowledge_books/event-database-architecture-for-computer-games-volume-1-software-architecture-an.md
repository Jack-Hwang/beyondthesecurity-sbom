# Event-Database Architecture for Computer Games, Volume 1 (Rodney Quaye) — 정제 노트

출처: 로컬 도서 "Event-Database Architecture for Computer Games, Volume 1 — Software Architecture and the Software
Production Process" (PDF, slug
`event-database-architecture-for-computer-games-volume-1-software-architecture-an`). 추출 원문을 읽고 우리 말로
정리한 종합 — 원문 인용이 아니다. 원문 검색은 `/api/books/search` 또는 `book_search`.

## 이 책의 논지

게임 서버를 **Events Host·Objects Host·Physics Host·Database Host** 의 호스트 분리로 모델링하는 이벤트 데이터베이스
아키텍처. 1권은 아키텍처와 소프트웨어 생산 프로세스 전반을 다루며, 버전 관리·병합(게임 두 버전의 차이 비교·병합,
텍스트 형식 데이터라면 아트·사운드 자원까지)·소프트웨어 라이브러리 재사용 정책까지 생산 절차로 묶는다.
특히 "이벤트 호스트·오브젝트 호스트·피직스 호스트는 제3자 라이브러리 없이 언어만으로 구현 가능"하다는 자립
주장이 인상적 — 핵심 호스트는 외부 의존성 없이, 저장소(Database Host)만 외부 도구를 쓴다.

## 핵심 개념 지도

- **호스트 분리**: 이벤트(입력/통지)·오브젝트(상태)·피직스(시뮬레이션)·데이터베이스(영속)의 역할별 호스트 —
  각 호스트는 계약(이벤트 스트림)으로만 대화.
- **이벤트 데이터베이스**: 상태를 이벤트 로그의 함수로 — 결정론적 재생(리플레이)·차이 비교가 가능해진다.
- **버전 관리·병합**: 텍스트 기반 자원 형식이면 범용 VCS(당시 CVS)로 자원까지 버전 관리할 수 있다는 통찰 —
  형식 선택이 도구 생태계를 결정.
- **라이브러리 자립 정책**: 핵심 경로는 의존성 0, 주변(저장·도구)만 재사용.

## 이 프로젝트 적용

- **의존성 0 자립 주장의 현대판**: ADR-0007(표준 라이브러리 전용)과 이 책의 자립 정책이 같은 논리 — 핵심 경로
  (파서·엔진·RAG)는 stdlib만, 저장(SQLite OSV 미러)·추출(pdftotext)처럼 도구 성격인 것만 외부.
- **이벤트 로그 → evidence/loop**: 루프 패스·LLM 호출 장부(.llm_ledger.json)를 로그로 남겨 재생·차이 비교하는
  관행 — "상태는 로그의 함수" 원칙의 응용. 루프 히스토리(looplog)로 과거 패스를 재현·비교한다.
- **호스트 분리의 축소판**: 서버의 구성 — 분석 파이프라인(오브젝트), 이벤트 버스(이벤트), SQLite 미러(데이터베이스)
  — 역할별 분리가 명확하다. 새 기능은 어느 호스트에 속하는지 먼저 판단.
- **텍스트 형식 우선**: 산출물(book.md·registry.json·벤치 JSON)을 전부 텍스트로 쓰는 관행 — 책의 "텍스트 형식이면
  범용 도구로 병합·비교 가능" 통찰의 적용.
