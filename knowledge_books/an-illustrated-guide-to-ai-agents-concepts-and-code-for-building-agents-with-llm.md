# an illustrated guide to ai agents concepts and code for building agents with llm

출처: An Illustrated Guide to AI Agents (Grootendorst & Alammar) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 에이전트는 모델+도구+메모리+루프다 — 그림으로 먼저 이해하고 코드로 좁힌다.
- 도구 호출은 구조화 출력으로 — 자유 텍스트 파싱은 신뢰할 수 없다.
- 메모리는 짧은(컨텍스트) 것과 긴(저장소) 것으로 나누고 무엇을 기억할지 정책이 필요하다.

## 이 프로젝트 적용

- chat.py TOOL_CATALOG + validate_calls가 구조화 도구 호출의 구현이다.
- handoff.py의 명시 계약이 에이전트 간 메모리 이관 정책이다.
- 트리아지 스토어가 긴 기억의 결정론적 형태다.
