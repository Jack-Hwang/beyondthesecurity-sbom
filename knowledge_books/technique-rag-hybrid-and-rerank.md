# technique rag hybrid and rerank

출처: Illustrated Guide + LLM Design Patterns 종합 (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- BM25+벡터 하이브리드는 RRF로 합치는 것이 표준이다.
- 리랭커는 비용 대비 이득을 측정 전에는 도입하지 않는다.
- 동의어 확장과 종류/출처 필터는 저비용 고이득 리트리벌이다.

## 이 프로젝트 적용

- rag.py RRF+동의어+필터가 이미 하이브리드다; 리랭커는 3변형 실측 후 기각(ADR-0016).
- books 2계층 인덱스 분리로 기준선 오염도 방지했다 (ADR-0021).
