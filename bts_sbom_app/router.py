"""LLM backend routing with honest reasons (task 19) - a pure function, stdlib only.

Lecture 1-1 S6: a router that decides between providers by data sovereignty, daily budget and throttling.
Priority order (first match wins):
  1. cloud LLM use not allowed                -> deterministic
  2. data_class == "private" (the scan request can flag it)  -> deterministic: nothing leaves the deployment
  3. daily_budget_ratio >= 0.9                -> deterministic: protect the daily limit before the provider does
  4. throttled (HTTP 429): a configured fallback takes over, otherwise deterministic
  5. otherwise the primary provider.
The reason for every non-LLM answer is appended to ``reasons`` when the caller supplies a list - an honest
downgrade always carries its why (the same contract as ai.propose).
"""
from __future__ import annotations

from typing import Dict, List, Optional


def choose_backend(*, data_class: str, daily_budget_ratio: float, throttled: bool, cloud_llm_allowed: bool,
                   providers: Optional[Dict[str, str]] = None, reasons: Optional[List[str]] = None) -> str:
    """Return "deterministic" | "exaone" | "azure-openai". Reasons are appended when ``reasons`` is a list."""
    why = reasons if reasons is not None else []
    if not cloud_llm_allowed:
        why.append("cloud LLM use is not allowed")
        return "deterministic"
    if data_class == "private":
        why.append("data class is private: the evidence must not leave the deployment")
        return "deterministic"
    if daily_budget_ratio >= 0.9:
        why.append("daily budget ratio %.2f is at or above 0.9" % daily_budget_ratio)
        return "deterministic"
    if throttled:
        fallback = (providers or {}).get("fallback")
        if fallback:
            why.append("primary provider throttled; falling back to %s" % fallback)
            return fallback
        why.append("primary provider throttled and no fallback is configured")
        return "deterministic"
    return (providers or {}).get("primary") or "exaone"
