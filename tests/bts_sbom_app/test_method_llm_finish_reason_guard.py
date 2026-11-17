"""finish_reason=='length' must be a hard error, never a parseable answer (course idea: map every provider
termination signal explicitly instead of trusting that truncated-but-well-formed text is a real answer)."""
from __future__ import annotations

import json

from bts_sbom_app import ai, evals
from bts_sbom_app.llm import ChatClient, LLMError


def _truncated_but_parseable(body):
    """Looks like a complete, valid JSON answer, but the provider cut it short mid-list - the one-item
    list below is syntactically closed, so json.loads() alone cannot detect the truncation."""
    content = json.dumps({"summary": "s", "proposals": [{"title": "only one made it before the cutoff"}]})
    text = json.dumps({"choices": [{"message": {"content": content}, "finish_reason": "length"}],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 2048}})
    return 200, text


def test_finish_reason_length_raises_llmerror(world):
    """AC: BSA-AC-206"""
    world.llm_handler = _truncated_but_parseable
    try:
        ChatClient("k").complete("s", "u", max_tokens=2048, json_mode=True)
    except LLMError as exc:
        assert "length" in str(exc).lower() or "truncat" in str(exc).lower()
    else:
        raise AssertionError("ChatClient.complete() must raise LLMError on finish_reason=='length'")


def test_propose_falls_back_to_deterministic_on_truncation(world):
    """AC: BSA-AC-206"""
    world.llm_handler = _truncated_but_parseable
    res = ai.propose(evals.synthetic_project(), client=ChatClient("k"), use_llm=True)
    assert res["source"] == "deterministic"
    assert "truncat" in res["llm_note"].lower()
    assert res["items"]
