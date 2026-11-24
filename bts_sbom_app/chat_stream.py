"""Chat-level step streaming (MetaNet 4주차 3차시, D3+D4).

``events.py`` streams *job* level events (scan/patch runs); a chat turn has its own finer grain: the 7 course
events step_start -> tool_call -> tool_result -> awaiting_approval -> handoff -> final, with error whenever a
tool or the turn itself fails. The failure is an honest envelope (handoff.error_envelope), a tool result that
asks for an approval emits ``awaiting_approval`` carrying the same patch-gate states events.py already defines
(HITL: the user, not the model, closes the loop), and the handoff event carries the explicit stage contract.

Subclass, never monkeypatch: ``StreamingChatbot`` is a plain ``chat.Chatbot`` - the regex router, the LLM
planner, the validators and the gates are all inherited untouched. Only observation is added.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Sequence

from . import chat as chatmod
from . import events as eventsmod
from .handoff import error_envelope, handoff

EVENT_KINDS = ("step_start", "tool_call", "tool_result", "awaiting_approval", "handoff", "final", "error")
_TOKEN = re.compile(r"Approval token ([0-9a-f]{16})")


def format_stream_sse(ev: Dict[str, Any]) -> str:
    """Same wire discipline as events.format_sse (multi-line JSON data bodies, blank-line terminated)."""
    data = json.dumps(ev, ensure_ascii=False, sort_keys=True, default=str)
    body = "\n".join("data: %s" % line for line in data.split("\n"))
    return "id: %s\nevent: %s\n%s\n\n" % (ev.get("seq"), ev.get("kind"), body)


class StreamingChatbot(chatmod.Chatbot):
    """A Chatbot that records and emits the 7 chat-level events while asking exactly the same questions."""

    def __init__(self, *args: Any, sink: Optional[Callable[[Dict[str, Any]], None]] = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._sink = sink
        self.stream: List[Dict[str, Any]] = []

    def _emit(self, kind: str, **payload: Any) -> Dict[str, Any]:
        if kind not in EVENT_KINDS:
            raise ValueError("unknown chat event kind %r (known: %s)" % (kind, ", ".join(EVENT_KINDS)))
        ev = {"seq": len(self.stream) + 1, "kind": kind, **payload}
        self.stream.append(ev)
        if self._sink is not None:
            self._sink(ev)
        return ev

    def _run(self, rec: Optional[Dict[str, Any]], calls: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for c in calls:
            self._emit("tool_call", tool=c["tool"], args=c.get("args", {}))
            try:
                produced = super()._run(rec, [c])
            except Exception as exc:                      # one tool down never kills the turn: honest envelope, keep going
                self._emit("error", envelope=error_envelope(
                    type(exc).__name__, "recoverable", retry_budget=1,
                    completed_steps=["tool_call:%s" % c["tool"]],
                    coverage_gap="tool %s failed; the answer rests on the remaining tools" % c["tool"]))
                continue
            for p in produced:
                new = p.pop("record", None)               # parent semantics: an analysis mid-turn retargets the rest
                if new is not None:
                    self.projects[new["name"]] = new
                    rec = new
                out.append(p)
                self._emit("tool_result", tool=p.get("tool"), lines=len(p.get("lines") or []))
                if p.get("tool") == "plan_patch":         # HITL: the plan asks the user, never the model
                    m = _TOKEN.search("\n".join(p.get("lines") or []))
                    self._emit("awaiting_approval", gate="patch", state="awaiting_approval",
                               token=m.group(1) if m else None,
                               states=list(eventsmod.PATCH_GATE_STATES),
                               note="아무것도 변경되지 않았다 - 승인 토큰을 확인하고 사용자가 직접 승인해야 적용된다")
        return out

    def ask(self, question: str, **kw: Any) -> Dict[str, Any]:
        self.stream = []                                   # one turn, one ordered event list
        self._emit("step_start", phase="chat", question=question)
        try:
            res = super().ask(question, **kw)
        except Exception as exc:                          # fatal: the turn produced nothing usable
            self._emit("error", envelope=error_envelope(
                type(exc).__name__, "fatal", retry_budget=1, completed_steps=["step_start"],
                coverage_gap="the chat turn itself failed; no partial answer"))
            raise
        not_passed: List[str] = []
        if res.get("found") is False:
            not_passed.append("grounded_answer:no_passage_found")
        if res.get("conflicts"):
            not_passed.append("single_answer:sources_disagree")
        if res.get("contains_untrusted"):
            not_passed.append("trusted_only:answer_contains_untrusted_quotes")
        self._emit("handoff", handoff=handoff(
            "chat_answer",
            {"routing": res.get("routing"), "tools": res.get("tools") or [],
             "answer_source": res.get("answer_source"), "citation_accuracy": res.get("citation_accuracy"),
             "retrieval_coverage": (res.get("retrieval") or {}).get("coverage")},
            constraints=["the model only ever sees trusted passages", "untrusted quotes are appended verbatim",
                         "every claim is verified against its cited document"],
            not_passed=not_passed))
        self._emit("final", found=res.get("found"), answer_source=res.get("answer_source"),
                   tools=res.get("tools") or [], citation_accuracy=res.get("citation_accuracy"),
                   llm_note=res.get("llm_note") or "",
                   answer=res.get("answer") or "",                        # the turn's answer body - a stream client
                   contains_untrusted=bool(res.get("contains_untrusted")),   # renders the whole turn from events alone
                   conflicts=res.get("conflicts") or [],
                   retrieval_top=(res.get("retrieval") or {}).get("top") or [],
                   routing=res.get("routing"), routing_note=res.get("routing_note") or "",
                   followup=bool(res.get("followup")), decomposed=res.get("decomposed") or [],
                   diagrams=res.get("diagrams") or [],                      # drawn mid-conversation (ADR-0024)
                   injection_attempts=(res.get("injection") or {}).get("attempts", 0))
        return res
