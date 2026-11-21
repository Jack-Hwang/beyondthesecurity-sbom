"""Deterministic input guardrails for the public chatbot (task 20) - no LLM in the loop, no Content Safety needed.

Lecture 5-1 / OWASP LLM Top 10: the chatbot receives internet questions AND untrusted advisory text (third-party
databases). ``check_input`` blocks instruction-override, system-prompt/policy exfiltration, requests for approval
tokens / confirmation codes / API keys, and tool-call JSON smuggled into the question - English and Korean, decided
by pattern only (a prompt is not an enforcement mechanism). A blocked question is refused with a GENERIC message
that never echoes the request back. ``suspicious_advisory`` marks lines of untrusted advisory text that carry the
same patterns: they stay in the deterministic view but are excluded from the model context.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

_RULES: List[Dict[str, Any]] = [
    {"rule": "instruction_override",
     "patterns": [r"ignore (?:all )?(?:previous|prior|above) instructions?", r"disregard (?:all )?(?:previous|prior) instructions?",
                  r"이전 (?:지시|설정) ?(?:를 )?무시", r"지시를 무시하고", r"시스템 프롬프트를 무시"]},
    {"rule": "role_override",
     "patterns": [r"you are now (?:a|an|the) ", r"act as (?:a|an) ", r"pretend to be ", r"새로운 (?:역할|페르소나)로(?:서)? 행동",
                  r"당신은 이제 (?:부터)?"]},
    {"rule": "system_prompt_exfiltration",
     "patterns": [r"(?:show|reveal|print|repeat) (?:your )?(?:system prompt|instructions|internal policy)", r"시스템 프롬프트를 보여 ?줘",
                  r"내부 (?:정책|지시문)을 (?:보여|알려) ?줘"]},
    {"rule": "secret_request",
     "patterns": [r"(?:approval token|approval_token|confirmation code|api[_ -]?key|bearer token).{0,40}(?:please|tell me|give|show|what is|what's)",
                  r"(?:tell|give|show) me (?:the |your )(?:approval token|confirmation code|api[_ -]?key)",
                  r"(?:승인 ?토큰|확인 ?코드|api ?키|인증 ?키).{0,30}(?:알려|보여|줘|뭐야|무엇)"]},
    {"rule": "tool_call_smuggling",
     "patterns": [r'\{"\s*tool"\s*:', r'\{"tool":']},                                # a tool-call JSON planted in the question
]

_BLOCK_REPLY = "I can't act on that request. Ask about the analysed projects or the knowledge base instead."


def check_input(text: str) -> Dict[str, str]:
    """{"blocked": bool, "rule": str} - deterministic; the reply for a block must be the generic one."""
    s = str(text or "").lower()
    for entry in _RULES:
        for pat in entry["patterns"]:
            if re.search(pat, s, re.I):
                return {"blocked": True, "rule": entry["rule"]}
    return {"blocked": False, "rule": ""}


def generic_reply() -> str:
    return _BLOCK_REPLY


def suspicious_advisory(text: str) -> Dict[str, Any]:
    """Split advisory text into lines; each line matching a pattern gets "suspicious": true (kept in the
    deterministic view, excluded from the model context by the caller)."""
    out: List[Dict[str, Any]] = []
    for line in str(text or "").splitlines():
        hit = check_input(line)
        out.append({"line": line, "suspicious": bool(hit["blocked"]), "rule": hit["rule"]})
    return {"lines": out, "suspicious_count": sum(1 for ln in out if ln["suspicious"])}
