# ADR-0021: Book knowledge base — two-tier extraction, serve-time-only raw index, eval isolation

## Status

Accepted (2026-11-22, Book KB: 실제 30권 422MB 폴더 기준 실측 — docs/capacity.md §3 참조)

## 근거 (Context)

레거시 재구현 프로젝트의 지식 원으로 사용자가 소유한 로컬 아키텍처 도서 30권(20 PDF + 10 EPUB, 422MB)을
RAG/채팅/UI에 통합해야 한다. 제약은 세 가지다. (1) ADR-0007의 표준 라이브러리 전용 원칙 — PDF/EPUB 파서가
의존성으로 들어오면 자기-SBOM 정직성 계약이 깨진다. (2) `State.bot()`이 채팅 요청마다 메인 인덱스를
재구성하는 구조(rag.Index.add는 추가마다 idf/norm 캐시를 무효화) — 원문 수만 청크를 메인 인덱스에 넣으면
질문당 수 초의 재구성 비용이 든다. (3) RAG 6지표 기준선(golden/dev/test)은 `evals.build_index`가 읽는
`knowledge/` 코퍼스로 측정된다 — 원문이 이 코퍼스에 섞이면 기준선의 의미가 바뀐다. 추출 신뢰성도 실측
변수다: 시스템에 `pdftotext`(poppler)가 존재하는 것이 확인됐고, EPUB은 표준 라이브러리로 완전 파싱이
가능하다.

## 결정 (Decision)

1. **계층 1 — 결정론적 원문 추출**: EPUB은 표준 라이브러리만(zipfile+html.parser+xml.etree)으로 spine 순서
   섹션 추출; PDF는 외부 `pdftotext` 서브프로세스(부재·실패·무텍스트레이어는 사유를 남긴 skipped — 원문
   원문은 절대 날조하지 않는다). 중복은 SHA-256으로 한 번만 인덱스. 모든 원문은 gitignored
   `evidence/books/`에만 존재한다(저작물 원문은 커밋하지 않는다). (BSA-AC-523..526)
2. **계층 2 — 정제 노트**: `knowledge_books/*.md`는 추출 원문을 읽고 우리 말로 종합한 노트로, 각 노트가
   "이 프로젝트 적용" 절을 가진다(테스트가 400자 초과 라인 금지와 적용 절 존재를 강제 — BSA-AC-530).
   kind="knowledge"로 채팅 인덱스에 적재되어 답변의 1차 근거가 되지만, **평가 코퍼스(knowledge/)에는
   절대 흡수되지 않는다**. 처음엔 노트를 knowledge/books에 두어 주 코퍼스에 흡수했고, 실측에서 golden mrr
   0.975→0.938, dev recall 0.933→0.867(-0.066, 게이트 허용폭 0.02 초과), dev ndcg 0.828→0.778의 회귀가
   나왔다(2026-11-22, evidence/loop/books_eval_baseline.json 대비 books_eval_after_notes.json). 책의
   원칙(측정이 판정한다)에 따라 노트는 serve-time 전용 계층(knowledge_books/, books.load_notes)으로
   재배치했고 재측정에서 기준선은 불변이다.
3. **2-인덱스 분리**: 원문 청크(kind="books")는 `State.books_index()`가 registry 시그니처(mtime+size)로
   캐시하는 serve-time 전용 인덱스로만 검색된다. `evals.build_index`는 절대 책 청크를 읽지 않는다 —
   golden/dev/test 기준선은 책 수집 여부와 무관하게 불변(측정: evidence/loop/books_eval_baseline.json 대비
   동일). (BSA-AC-529)
4. **채팅·API·UI**: `book_search` 도구(NO_PROJECT_TOOLS, trust="book", 모든 행 `[book] 제목 (형식) - 절:` 속성)
   + `/api/books`, `/api/books/<slug>`, `/api/books/search`, `POST /api/books/ingest`(동시 1건, 로컬 폴더만,
   arch_api와 같은 Host/origin 검사) + Book KB 탭(bts_books.js). (BSA-AC-527, 528, 531, 532)

## 기각 대안 (Rejected alternatives)

- **pypdf/PyMuPDF 등 파서 의존성 추가** — ADR-0007 위반. stdlib PDF 텍스트 추출기 자작은 폰트/CMap
  커버리지가 파편화되어 날조 위험; pdftotext가 있는 환경에서 품질·비용 모두 열위.
- **원문 청크를 메인 채팅 인덱스에 병합** — 요청마다 인덱스 재구성 비용이 청크 수에 비례해 수 초로
  치닫고, 평가 코퍼스 오염으로 6지표 기준선이 무의미해진다.
- **sqlite FTS5 원문 저장소(nl2sql 선례)** — 유효한 대안이었으나 rag.Index 재사용이 토크나이저·동의어·
  RRF·메타 형태를 그대로 공유해 코드가 작고 provenance 형태가 일치한다. 메모리/지연 실측이 임계를 넘으면
  FTS5로의 전환을 다음 ADR에서 다룬다.
- **LLM 요약으로 원문 대체** — 요약은 원문 검색을 대체할 수 없고(인용 불가), 결정론성이 깨지며 비용이
  수집 규모에 비례한다. 원문은 결정론적으로, 종합은 사람이 검증한 정제 노트로.

## 결과 (Consequences)

긍정: 채팅 질문당 비용 불변(2차 인덱스는 캐시 1회 구성), 평가 기준선 불변(원문+정제 노트 모두 격리 —
노트의 knowledge/ 흡수 시 나온 dev recall -0.066 회귀 실측이 그 근거), 의존성 0 유지, 저작물 원문이
저장소에 들어가지 않음, 모든 책 인용에 출처 속성. 부담: pdftotext 부재 환경에서는 PDF가 정직하게 skipped
(EPUB은 전량 파싱), 2차 인덱스는 서버당 1회 구성 비용(실측은 capacity.md), 정제 노트는 사람(에이전트)이
쓰므로 책 추가 시 노트 보완이 수반된다. 원문 인용은 로컬 소유 사본에서의 학습용 단편 인용으로 제한하고
저작권은 저자에게 있음을 도구 응답이 매번 명시한다(BSA-AC-532).
