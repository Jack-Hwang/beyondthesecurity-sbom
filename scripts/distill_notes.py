"""Distilled notes writer (knowledge_books/*.md): our own synthesis of the ingested book library.

Contract (BSA-AC-530, ADR-0021): every note is our own wording (no pasted book text), carries a
"## 이 프로젝트 적용" section, keeps every line <= 400 chars, and every indexed-ok book slug has a
same-named note. Notes are the serve-time chat layer (books.load_notes) and never enter knowledge/
(the eval corpus). Re-run after re-ingesting a changed library: python scripts/distill_notes.py
"""
from __future__ import annotations

import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "knowledge_books")
N: dict = {}


def note(name: str, src: str, points: list, apply: list) -> None:
    body = "# %s\n\n출처: %s (우리 말 종합 — 원문 인용 없음)\n\n## 핵심 원칙\n\n" % (name[:-3].replace('-', ' '), src)
    body += "".join("- %s\n" % p for p in points)
    body += "\n## 이 프로젝트 적용\n\n" + "".join("- %s\n" % a for a in apply)
    N[name] = body


# ---------- per-book notes (filename == registry slug, mandatory) ----------
note('ai-agents-the-definitive-guide-design-deployment-and-evaluation-for-production-n.md',
     'AI Agents: The Definitive Guide (Koenigstein)',
     ['에이전트를 데모가 아니라 생산 시스템으로 본다: 배포·관측·평가가 설계의 1급 시민이다.',
      '에이전트 평가는 단일 점수가 아니라 작업 성공률·지연·비용·안전을 함께 잰다.',
      '실패는 예외가 아니라 데이터다 — 실패 유형을 분류해 회귀로 삼는 것이 운영의 핵심이다.'],
     ['evalrag/evalchat/evallicense와 RAG 6지표 기준선이 이 원칙의 구현이다.',
      'events.py 단계 이벤트와 supply_chain_gate가 관측성 요구를 충족한다.',
      '회귀 4분면(impact.py)과 케이스 회귀율 게이트가 실패를 회귀로 삼는 요구를 구현한다.'])
note('ai-agents-with-mcp.md',
     'AI Agents with MCP (Stratis)',
     ['호스트 앱이 MCP 클라이언트 역할을 하고 서버가 도구·리소스·프롬프트를 표준으로 노출한다.',
      'MCP 전송은 stdio와 HTTP 두 계열이고 로컬 도구는 stdio가 기본이다.',
      '도구 스키마는 JSON Schema로 자기 서술적이어야 모델이 안전하게 호출한다.',
      'sampling·elicitation 같은 서버에서 호스트로의 역방향 요청도 프로토콜에 있다.'],
     ['G2로 미뤄뒀던 MCP 서버를 이 책 기준으로 구현한다: stdio + JSON-RPC 2.0 + tools/list, tools/call (AC-534).',
      'chat.py TOOL_CATALOG가 도구 스키마의 원천이다 — 이중 정의를 만들지 않는다.'])
note('ai-native-software-engineering-building-with-ai-agents-and-spec-driven-developme.md',
     'AI-Native Software Engineering (Graziano)',
     ['AI 네이티브 개발의 축은 명세가 곧 산출물이라는 것 — 코드는 명세의 파생물이다.',
      '에이전트에게 자유를 주기 전에 검증 가능한 계약(테스트·AC)을 먼저 고정한다.',
      '사람의 검토 지점을 명시적으로 설계해야 에이전트 자동화가 안전해진다.'],
     ['이 프로젝트는 이미 SDD다: BSA-AC-* 명세 + speclint 양방향 trace + doclint가 계약을 강제한다.',
      'patch 게이트(계획→토큰→승인)가 사람 검토 지점 명시의 구현이다.'])
note('an-illustrated-guide-to-ai-agents-concepts-and-code-for-building-agents-with-llm.md',
     'An Illustrated Guide to AI Agents (Grootendorst & Alammar)',
     ['에이전트는 모델+도구+메모리+루프다 — 그림으로 먼저 이해하고 코드로 좁힌다.',
      '도구 호출은 구조화 출력으로 — 자유 텍스트 파싱은 신뢰할 수 없다.',
      '메모리는 짧은(컨텍스트) 것과 긴(저장소) 것으로 나누고 무엇을 기억할지 정책이 필요하다.'],
     ['chat.py TOOL_CATALOG + validate_calls가 구조화 도구 호출의 구현이다.',
      'handoff.py의 명시 계약이 에이전트 간 메모리 이관 정책이다.',
      '트리아지 스토어가 긴 기억의 결정론적 형태다.'])
note('architecting-ai-software-systems-richard-d-availa-imran-ahmad-1.md',
     'Architecting AI Software Systems (Availa & Ahmad)',
     ['AI 시스템 아키텍처는 비결정 구성요소를 결정론 경계로 감싸는 일이다.',
      '폴백·타임아웃·캐시는 예외 처리가 아니라 아키텍처 요소다.',
      '데이터 흐름(수집→인덱스→검색→생성)을 파이프라인으로 그려야 비용이 보인다.'],
     ['net.fetch_json + 회로차단기 + 4상태 보고가 비결정 외부호출의 결정론 경계다 (AC-301~315).',
      'books 2계층(원문 결정론 추출 / 정제 노트)이 데이터 파이프라인 분리의 실례다 (ADR-0021).'])
note('building-agentic-ai-systems-build-connected-agent-systems-with-mcp-a2a-agent-loo.md',
     'Building Agentic AI Systems (Biswas & Talukdar)',
     ['MCP는 에이전트-도구, A2A는 에이전트-에이전트 연결 — 역할이 다른 두 프로토콜이다.',
      'A2A는 Agent Card로 상대 에이전트의 능력을 먼저 발견한다.',
      '오케스트레이터는 상태를 소유하고 서브에이전트는 작업 단위로 격리된다.'],
     ['A2A 스타일 Agent Card를 /api/agent-card로 구현해 우리 에이전트 능력을 기계가 읽게 한다 (AC-535).',
      'handoff.py의 스테이지 계약이 오케스트레이터 상태 소유를 문서 수준으로 구현했다.'])
note('code-complete.md',
     'Code Complete (McConnell)',
     ['생성 품질의 본질은 가독성·응집·낮은 결합 — AI 시대에도 불변이다.',
      '방어적 프로그래밍: 입력 검증은 경계에서, 어설션은 내부 불변식에 둔다.',
      '측정 없는 최적화는 금지 — 먼저 재고 다음 단순화한다.'],
     ['stdlib 전용·결정론 테스트·정직한 미측정 표기가 방어적 원칙과 같다.',
      'capacity.md의 실측/수식/미측정 규칙이 측정 우선 원칙이다.'])
note('design-patterns-elements-of-reusable-object-oriented-software-gang-of-four-erich.md',
     'Design Patterns (GoF)',
     ['패턴은 재사용이 아니라 변화를 담을 자리를 미리 만드는 것이다.',
      '인터페이스에 의존하고 구현에 의존하지 않는다 — 콤포지션으로 유연성을 산다.'],
     ['llm.TRANSPORT 교체 가능 구조가 스트래티지 패턴의 실례다.',
      'events.EventBus의 구독자 분리는 옵저버 패턴 그 자체다.'])
note('designing-for-ai-for-duc-ka.md',
     'Designing for AI (Sadr)',
     ['AI 제품 설계는 상호작용 계약이 어렵다 — 기대·실패·복구를 설계하라.',
      '불확실성을 숨기지 말고 UI에서 그대로 보여라.'],
     ['계산 못 함을 0으로 쓰지 않는 규칙과 충돌 주석 병기가 이 원칙의 구현이다.',
      'HITL 승인 배너가 실패·복구 상호작용의 실례다 (AC-517~520).'])
note('fine-tuning-ai.md',
     'Fine-Tuning AI (Moroney)',
     ['파인튜닝은 프롬프트·RAG·도구로 못 푼 문제의 마지막 수단이다.',
      '데이터 품질이 학습률보다 중요하고 평가셋 분리가 필수다.'],
     ['프로젝트 판정: API-only 환경이라 적용 불가 — RAG+도구로 같은 문제를 푼다 (브리프5 매핑).',
      '평가셋 분리는 golden/dev/test와 books의 eval 격리(ADR-0021)로 지켜진다.'])
note('harness-engineering.md',
     'Harness Engineering (Johnson)',
     ['비결정 에이전트를 감싸는 하니스가 품질을 결정한다: 입력 준비·도구 접착·출력 검증.',
      '컨텍스트는 예산이다 — 자동 압축과 계층적 요약이 운영 전제다.',
      '하니스는 결정론적이어야 에이전트의 비결정성을 측정할 수 있다.'],
     ['ai.evidence의 목록 캡+trimmed 보고가 컨텍스트 예산 관리의 구현이다.',
      'verify_claims·citation_accuracy 게이트가 출력 검증 계층이다.',
      'chat_stream의 7종 이벤트가 하니스 관측점이다 (AC-517~520).'])
note('llm-design-patterns.md',
     'LLM Design Patterns (Huang)',
     ['가드레일·구조화 출력·셀프 컨시스턴시·라우팅·폴백 등 패턴을 이름 붙여 재사용한다.',
      '가드레일은 입력·출력 양쪽에 두고 위반은 차단+사유다.',
      '복잡한 추론엔 다수 샘플 투표가 단일 샘플을 이긴다.'],
     ['validate_calls + approval 게이트가 출력 가드레일의 구현이다.',
      'council 3멤버 합의가 셀프 컨시스턴시의 도메인 특화 형태다.',
      'nl2sql 4상태 실행기가 차단+사유 가드레일의 데이터 계층 구현이다 (AC-510~513).'])
note('loop-engineering-for-ai-agents-design-reliable-agentic-ai-systems-beyond-the-pro.md',
     'Loop Engineering for AI Agents (Papalini)',
     ['신뢰성은 프롬프트 밖의 루프에서 나온다: 계획→실행→검증→수정의 명시적 사이클.',
      '재시도는 상한과 동일오류 중단이 있어야 무한루프가 아니다.',
      '루프의 각 단계는 관측 가능해야 한다.'],
     ['nl2sql 자기교정 루프(오류 첨부·상한 3회·동일오류 즉시 중단)가 이 책 루프의 직접 구현이다 (AC-512).',
      'events.py 단계 이벤트가 루프 관측의 구현이다.'])
note('mcp-engineering-handbook-a-software-engineers-guide-to-building-real-world-ai-in.md',
     'MCP Engineering Handbook (Pedersen)',
     ['실전 MCP 서버는 작게 시작한다: 도구 몇 개, 명확한 스키마, 표준 에러 코드.',
      '전송·세션·보안(원격 서버 신뢰)을 설계 초기에 결정한다.',
      '도구 이름과 설명이 곧 모델의 사용성이다 — 카탈로그 문서가 API 문서다.'],
     ['mcp_server.py를 stdlib stdio JSON-RPC로 구현한다: initialize/tools/list/tools/call + 표준 에러 (AC-534).',
      '도구는 기존 API 재사용: engine_status, book_search, project_overview, chat_ask — 새 로직 없이 위임.'])
note('spec-driven-development-from-specs-to-code-with-ai-agents-simon-martinelli.md',
     'Spec-Driven Development (Martinelli)',
     ['SDD 사이클: specify→plan→tasks→implement이고 에이전트가 각 단계 산출물을 소비한다.',
      '프로젝트 헌법이 불변 원칙을 선언해 모든 생성물이 그 검사를 받는다.',
      '명세와 구현의 불일치는 테스트보다 이른 시점에 기계로 잡는다.'],
     ['이 저장소의 헌법은 ADR + speclint(AC 문법) + doclint(문서 게이트) + 양방향 trace다.',
      '갭 없음을 정직히 기록한다 — SDD는 구현돼 있고 책의 새 도구는 도입하지 않는다.'])

# ---------- technique notes ----------
note('technique-mcp-server-design.md', 'MCP Engineering Handbook + AI Agents with MCP 종합',
     ['MCP는 JSON-RPC 2.0 위의 3원 책정(도구/리소스/프롬프트)이고 초기화 핸드셰이크로 능력을 협상한다.',
      'stdio 전송은 한 줄·한 메시지로 충분하고 서버는 비프로토콜 출력을 절대 섞지 않는다.',
      '도구 오류는 result.isError로 모델에게 보이게 전달한다 — 예외로 숨기지 않는다.',
      '호스트가 주입하는 경로/환경을 신뢰하지 않고 경계에서 검증한다.'],
     ['구현: bts_sbom_app/mcp_server.py (stdlib, stdio). 도구: engine_status, book_search, project_overview, chat_ask.',
      '오류는 isError+메시지 — 우리 4상태 철학과 동일하다 (AC-534).'])
note('technique-a2a-agent-card.md', 'Building Agentic AI Systems(A2A 절) + handoff 계약 종합',
     ['A2A의 발견 단위는 Agent Card: 이름·버전·스킬·입출력·보안을 JSON으로 공개한다.',
      '스킬은 id·설명·입출력 모드를 자기 서술해야 오케스트레이터가 자동 조립한다.',
      '카드는 능력 선언일 뿐 실제 상태가 아니다 — 런타임 확인은 별도 프로브(readyz)다.'],
     ['구현: GET /api/agent-card — skills: scan, patch(승인 게이트), council, chat(stream), book_search, nl2sql.',
      'capabilities.streaming=true(SSE), securitySchemes none-localhost를 정직히 표기한다 (AC-535).'])
note('technique-multi-agent-orchestration.md', 'Building Agentic AI Systems + Illustrated Guide 종합',
     ['오케스트레이터가 상태·예산·중단을 소유하고 서브에이전트는 작업에만 책임진다.',
      '서브에이전트 결과는 명시 전달(비상속)이 원칙 — 암묵 컨텍스트 상속은 오류의 원천이다.',
      '합의가 필요한 판정은 독립 멤버 다수+결정론 집계가 단일 LLM 판정을 이긴다.'],
     ['council(3멤버+결정론 verdict)와 council_handoff(not_passed 명시)가 이 구조의 구현이다.',
      '부분 결과+갭 주석(오류 봉투)은 오케스트레이터-서브 계약의 실례다 (AC-517).'])
note('technique-sdd-spec-to-code.md', 'SDD (Martinelli) + AI-Native SWE (Graziano) 종합',
     ['specify→plan→tasks→implement의 각 단계 산출물은 버전화되고 기계 판독 가능해야 한다.',
      '에이전트는 명세를 읽는 것이 아니라 검사(테스트·린트)로 소비해야 한다.',
      '구현 전 명세의 모호함을 잡는 린트가 가장 싼 품질 장치다.'],
     ['speclint: AC 문법 검사+양방향 trace가 기계가 명세를 소비하는 구현이다.',
      '브리프(작업 지시서)가 plan/tasks 산출물 역할이고 ADR이 헌법이다.'])
note('technique-sdd-acceptance-gates.md', 'SDD + Loop Engineering 종합',
     ['수용 기준은 측정 가능한 동사로 써야 한다: 횟수·문서 수·상태 전이.',
      '게이트는 자동으로 돌고 실패는 명명된 이유를 남긴다.',
      '기준선은 고정하고 변경은 게이트 허용폭 안에서만 인정한다.'],
     ['AC n-of-n 관례 + test_specs trace + RAG 6지표 허용폭 0.02 게이트가 이 원칙의 구현이다.',
      '케이스 회귀율 차단(AC-318~335)은 기준선 대비 게이트의 실례다.'])
note('technique-rag-context-rot-and-position.md', 'Illustrated Guide + LLM Design Patterns 종합',
     ['컨텍스트가 길어질수록 중간 내용이 묻힌다(lost in the middle) — 순서가 품질이다.',
      '컨텍스트 회전: 관련 없는 첨부가 전체 답을 나쁘게 만든다.',
      '무엇을 넣을지가 무엇을 빼달지보다 어렵다 — 관련성 순으로 상한을 둔다.'],
     ['구현: chat 경로의 신뢰 문서를 질문 관련도 순으로 재배열해 상한 6개를 프롬프트에 넣는다 (AC-536).',
      'ai.evidence의 목록 캡+trimmed 보고가 상한+정직의 구현이다.'])
note('technique-rag-hybrid-and-rerank.md', 'Illustrated Guide + LLM Design Patterns 종합',
     ['BM25+벡터 하이브리드는 RRF로 합치는 것이 표준이다.',
      '리랭커는 비용 대비 이득을 측정 전에는 도입하지 않는다.',
      '동의어 확장과 종류/출처 필터는 저비용 고이득 리트리벌이다.'],
     ['rag.py RRF+동의어+필터가 이미 하이브리드다; 리랭커는 3변형 실측 후 기각(ADR-0016).',
      'books 2계층 인덱스 분리로 기준선 오염도 방지했다 (ADR-0021).'])
note('technique-guardrails-structured-output.md', 'LLM Design Patterns + Harness Engineering 종합',
     ['가드레일 3층: 스키마 검증→정책 검증→효과 게이트(승인).',
      '구조화 출력은 json_mode+재파싱 검증으로 하고 실패는 결정론 폴백으로 간다.',
      '권한 상승 값(토큰·코드)은 모델이 만들 수 없다 — 사용자 텍스트에서만 온다.'],
     ['validate_calls의 토큰=사용자 텍스트 규칙이 가장 강한 가드레일이다.',
      'json_mode+verify_claims+결정론 추출 폴백이 구조화 실패 체인이다.',
      'plan→token→apply 게이트가 효과 게이트다.'])
note('technique-harness-compaction.md', 'Harness Engineering + LLM Design Patterns 종합',
     ['컨텍스트 예산 초과 시 계층적으로 압축한다: 원문→요약→포인터.',
      '압축에서 무엇이 잘렸는지 반드시 보고한다 — 조용한 손실 금지.',
      '세션 상태는 재시작 가능한 파일로 저장한다.'],
     ['ai.evidence trimmed 보고·triage 스토어·evidence/runs 레코드가 이 원칙의 구현이다.',
      'handoff 스키마가 세션 간 상태 이관의 결정론 형식이다.'])
note('technique-eval-driven-quality.md', 'AI Agents Definitive Guide + Code Complete 종합',
     ['품질은 속성 목록이 아니라 측정 세트다: 성공률·지연·비용·안전을 함께 본다.',
      '평가는 오프라인 골든셋(결정론)과 온라인 실측으로 나눈다.',
      'LLM-as-judge는 편향이 있어 코드 계산이 우선이다.'],
     ['TOP10 게이트는 전부 코드 계산 — 판정 모델이 없다 (품질 철학 일치).',
      'evalrag/evalchat/evallicense 골든셋 + live 실측 스코어카드가 이중 평가다 (AC-481~485).'])
note('technique-fine-tuning-when-not.md', 'Fine-Tuning AI 종합',
     ['파인튜닝 전에 물어라: 프롬프트·검색·도구·캐시로 못 푸는가? 대부분 풀 수 있다.',
      '도메인 용어와 형식은 RAG+프롬프트로 충분하고 행동 스타일만 파인튜닝 영역이다.',
      '비용은 학습뿐 아니라 운영·재학습 주기까지 포함한다.'],
     ['판정 유지: API-only 환경에서 파인튜닝은 적용 불가 — RAG+도구+게이트로 동등 목표를 달성한다.',
      '재학습 주기 대응물은 knowledge/ 코퍼스 갱신+6지표 재측정이다.'])
note('technique-agentic-memory-and-state.md', 'Illustrated Guide + Harness Engineering 종합',
     ['짧은 기억은 컨텍스트, 긴 기억은 저장소 — 경계를 명시해야 누수가 없다.',
      '상태는 불변 레코드+명시 스키마로 저장해야 재생 가능하다.',
      '기억에 신뢰 등급을 남겨라: 측정값과 사용자 진술은 등급이 다르다.'],
     ['project record+prev.json 스냅샷+triage 스토어가 긴 기억의 스키마화다.',
      'trust 등급(knowledge/untrusted-quote/book)이 기억 신뢰 등급의 구현이다.'])
note('technique-agent-loops-budgets.md', 'Loop Engineering + Harness Engineering 종합',
     ['루프에는 3가지 상한이 필요하다: 반복 수·동일오류 중단·비용 예산.',
      '수정 프롬프트에는 원 실패의 구체 오류를 첨부한다 — 요약이 아니라 원문이다.',
      '루프 종료는 상태로 보고한다: success/partial/failure+사유.'],
     ['nl2sql answer()가 3상한+오류 첨부를 그대로 구현했다 (AC-512).',
      'ERROR 이벤트(error_type/severity/retryable/recovery_hint)가 종료 상태 보고다.'])
note('technique-context-engineering-catalog.md', '책 전체 종합 (기존 수집 context-engineering 권 포함)',
     ['컨텍스트 엔지니어링 = 예산 안에서 관련·신뢰·순서를 동시에 최적화하는 것이다.',
      '검색 결과에 메타(출처·신뢰·절)를 붙여 모델이 근거를 자기 서술하게 한다.',
      '컨텍스트 구성은 측정 대상이다 — 구성 변경은 기준선 재측정을 수반한다.'],
     ['청크 메타(kind/book/source/heading)와 [book]/[untrusted-quote] 접두 행이 메타 부착의 구현이다.',
      '노트 위치 이동 사건(ADR-0021)이 구성 변경은 재측정 규칙의 실제 사례다.'])
note('technique-reliability-probes-and-deploy.md', 'Architecting AI Systems + AI Agents Definitive Guide 종합',
     ['배포 가능성은 빌드 재현성+취약점 게이트+가동부 프로브+롤백 트리거의 세트다.',
      '헬스(프로세스)와 레디니스(의존성)는 다른 질문이다 — 섞지 않는다.',
      '릴리스는 게이트 통과와 실측 기록이 함께 있을 때만 선언한다.'],
     ['healthz/readyz 분리·공급망 게이트·RUNBOOK 4블록·capacity.md가 이 원칙의 구현이다 (AC-514~516, 521).',
      'Dockerfile NOT BUILT YET 제거 관례처럼 배포 문장은 실행자만 쓴다.'])


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    reg_path = os.path.join(ROOT, 'evidence', 'books', 'registry.json')
    slugs: list = []
    if os.path.exists(reg_path):
        reg = json.load(io.open(reg_path, encoding='utf-8'))
        slugs = [b['slug'] for b in reg.get('books', []) if b.get('status') == 'ok']
    missing = [s + '.md' for s in slugs if s + '.md' not in N]
    if missing:
        print('ERROR: registry has indexed books without a note in this script:', missing)
        return 1
    for name, body in N.items():
        over = [ln for ln in body.splitlines() if len(ln) > 400]
        if over:
            print('ERROR: line over 400 chars in', name)
            return 1
        io.open(os.path.join(OUT, name), 'w', encoding='utf-8', newline='\n').write(body)
    print('wrote %d notes to %s' % (len(N), OUT))
    return 0


if __name__ == '__main__':
    sys.exit(main())
