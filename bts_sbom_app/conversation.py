"""Conversation memory, question decomposition and injection-pattern guard (2025-26 research round).

Three chatbot/agent upgrades grounded in the current literature and this repo's rules (deterministic first,
LLM only when a rule cannot decide; every claim measurable offline):

* **ConversationMemory** — multi-turn continuity (2026 multi-turn playbook, Rasa, Parlant): the last few
  turns' question/tools/found survive across requests, so an elliptical follow-up ("그중 HIGH만 보여줘",
  "라이선스는?") routes against the previous turn's context instead of returning found=False. The merge is
  a deterministic string join - no LLM decides what the user meant; the router still decides the tools.
* **decompose_question** — compound questions (arXiv 2507.00355, Haystack/NVIDIA query decomposition):
  explicit-coordination splits (그리고/및/하고/comma/and) always, particle splits (와/과/이랑/랑) only when
  the right side carries a tool keyword, so "CVE-2020-1111과 관련된 프로젝트" is NOT split (single question)
  but "취약점과 라이선스 보여줘" is.
* **scan_injection** — the context layer of layered prompt-injection defence (Fiddler guardrail layers,
  arXiv 2511.15759): tool/retrieval text is scanned for instruction-injection patterns before it can reach
  the model or the user; hits are counted and annotated, never obeyed (the structural defence stays
  validate_calls + passages-only prompts + verbatim untrusted marking).
"""
from __future__ import annotations

import re
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

MAX_TURNS = 3

# follow-up shape: starts with a demonstrative, references the prior turn, is a bare filter ("HIGH만 보여줘"),
# or a bare topic+particle question ("라이선스는?") - the elliptical form the router alone cannot place.
_FOLLOWUP = re.compile(
    r"^\s*(그|이|저)\s|그중|이중|그것|아까|방금|위 (질문|답변|사례)|좀 더|더 자세히|바로 그|같은 조건"
    r"|^\s*[\w.]+\s*(등급|이상|이하)?\s*(만)\s*(보여|알려|찾)"
    r"|(만|만\s*(보여줘|알려줘|검색|필터))\s*$"
    r"|^\s*(high|critical|medium|low)\b"
    r"|^[^?？]{1,24}(은|는|이|가)\s*[?？]\s*$", re.I)
# explicit coordination always splits; particles split only when the right side names a tool intent
_EXPLICIT = re.compile(r"\s*(?:그리고|및|,| 및 | and | OR | 또는 )\s*")
_PARTICLE = re.compile(r"(?:와|과|이랑|랑)\s*")
_TOOL_INTENT = re.compile(r"취약|cve|라이선스|license|패치|patch|아키텍처|architecture|규제|컴플라이언스|"
                          r"compliance|라이선스 리스크|sbom|구성요소|component|프로젝트|project", re.I)
_INJECTION = re.compile(
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?"
    r"|disregard\s+(all\s+)?(previous|prior|above)"
    r"|system\s*prompt"
    r"|you\s+are\s+now"
    r"|act\s+as\s+(an?\s+)?(different|new|unrestricted)"
    r"|reveal\s+(your\s+)?(system\s+)?(prompt|instructions)"
    r"|" + chr(60) + "/?" + chr(115) + chr(121) + chr(115) + chr(116) + chr(101) + chr(109) + chr(62), re.I)


class ConversationMemory:
    """The last MAX_TURNS turns of one chat session (question, tools used, found, project). Plain object,
    owned by the server's State so it survives across /api/chat requests even though bots are per-request."""

    def __init__(self) -> None:
        self.turns: deque = deque(maxlen=MAX_TURNS)

    def record(self, question: str, tools: List[str], found: Any, project: Optional[str] = None) -> None:
        self.turns.append({"question": question, "tools": list(tools or []), "found": bool(found), "project": project})

    def last(self) -> Optional[Dict[str, Any]]:
        return self.turns[-1] if self.turns else None


def is_followup(question: str) -> bool:
    return bool(_FOLLOWUP.search(question or ""))


def resolve_followup(question: str, memory: Optional[ConversationMemory]) -> Tuple[str, bool]:
    """Merge an elliptical follow-up with the previous turn's question so the router sees both contexts.

    Deterministic string join: the previous question is appended as context - position does not matter to
    the regex router, and nothing about the user's intent is guessed beyond "this turn continues that one"."""
    if memory is None or not is_followup(question):
        return question, False
    prev = memory.last()
    if not prev or not prev.get("question"):
        return question, False
    return "%s (앞서 묻던: %s)" % (question, prev["question"]), True


def decompose_question(question: str) -> List[str]:
    """Split a compound question into tool-intent parts; a single-intent question returns [question] unchanged."""
    q = (question or "").strip()
    if not q:
        return [q]
    parts = [p.strip(" .?!?!,") for p in _EXPLICIT.split(q) if p and p.strip(" .?!?!,")]
    if len(parts) < 2:                                     # particle split only when a right side OPENS with a tool intent
        parts = [p.strip(" .?!?!,") for p in _PARTICLE.split(q) if p and p.strip(" .?!?!,")]
        if len(parts) >= 2 and not all(_TOOL_INTENT.match(p) for p in parts[1:]):
            parts = [q]                                    # "CVE-X와 관련된 프로젝트" stays one question
    if len(parts) < 2 or any(len(p) < 3 for p in parts):   # Korean tool words are short (취약점=3); a 3-char floor
        return [q]                                         # still kills trivial splits like 이거/저것
    return parts[:4]


def merge_tool_results(parts: List[str], run_tools) -> List[Dict[str, Any]]:
    """Run the router per part and merge results, keeping first occurrence per source (deterministic order)."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for part in parts:
        for t in run_tools(part):
            src = t.get("source")
            if src in seen:
                continue
            seen.add(src)
            out.append(t)
    return out


def scan_injection(texts: Dict[str, str]) -> Dict[str, Any]:
    """Count instruction-injection patterns across tool/retrieval texts. Detection only: the content is
    already quarantined by design (validated tool calls, trusted-passage-only prompts, verbatim untrusted
    quotes) - this reports what the guard saw so attempts are visible, never silently absorbed."""
    hits: List[Dict[str, Any]] = []
    for sid, txt in (texts or {}).items():
        for m in _INJECTION.finditer(txt or ""):
            hits.append({"source": sid, "pattern": m.group(0)[:60]})
    return {"attempts": len(hits), "sources": sorted({h["source"] for h in hits}), "hits": hits[:5]}
