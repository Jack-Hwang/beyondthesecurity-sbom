"""LG EXAONE (K-EXAONE, OpenAI-compatible chat completions) client - stdlib only.

Configuration (first found wins):  environment ``EXAONE_API_KEY`` / ``EXAONE_BASE_URL`` / ``EXAONE_MODEL``,
a JSON file named by ``BTS_SBOM_LLM_CONFIG`` (keys exaone_api_key / exaone_base_url / exaone_model, or api_key /
base_url / model), or the generic ``LLM_API_KEY`` / ``LLM_BASE_URL`` / ``LLM_MODEL`` for any OpenAI-compatible server
(e.g. a local Ollama at http://localhost:11434/v1 running an EXAONE build - no daily limit there).
The key is never written to evidence, logs, caches or errors.

Cost/limit protection: a per-day call ledger (``daily_budget``, default 80 < the 100/day free tier) stops calls BEFORE
the provider does; an HTTP 429 that talks about a day/limit is not retried (retrying cannot help).
K-EXAONE is a reasoning model: reasoning tokens count against ``max_tokens`` and cannot be disabled, so the budget
floor is 1024 and ``reasoning_effort`` is sent as "low".
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from .util import read_json, write_json

DEFAULT_BASE = "https://api.exaone.ai/v1"
DEFAULT_MODEL = "k-exaone_v2.5"
FLOOR_TOKENS = 1024
# tests: callable(url, headers, body_dict) -> (status:int, text:str); None = real network
TRANSPORT: Optional[Callable[[str, Dict[str, str], Dict[str, Any]], Tuple[int, str]]] = None


class LLMError(RuntimeError):
    pass


class LLMUnavailable(LLMError):
    """no key / budget exhausted / provider says the day limit is reached - callers downgrade honestly."""


class ChatClient:
    def __init__(self, api_key: str = "", base_url: str = DEFAULT_BASE, model: str = DEFAULT_MODEL, *,
                 timeout: float = 300.0, daily_budget: Optional[int] = None, ledger: Optional[str] = None,
                 provider: str = "exaone"):
        self._lock = threading.Lock()
        self.api_key = api_key
        self.base_url = (base_url or DEFAULT_BASE).rstrip("/")
        self.model = model or DEFAULT_MODEL
        self.timeout = timeout
        self.provider = provider
        self.daily_budget = int(os.environ.get("BTS_SBOM_LLM_DAILY_BUDGET", "80")) if daily_budget is None else daily_budget
        self.ledger = ledger
        self.calls = 0
        self.errors: List[str] = []
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0}

    # -- configuration
    @classmethod
    def from_env(cls, ledger: Optional[str] = None) -> "ChatClient":
        cfg: Dict[str, Any] = {}
        path = os.environ.get("BTS_SBOM_LLM_CONFIG", "")
        if path:
            cfg = read_json(path, {}) or {}
        key = os.environ.get("EXAONE_API_KEY") or cfg.get("exaone_api_key") or cfg.get("api_key") or os.environ.get("LLM_API_KEY", "")
        base = os.environ.get("EXAONE_BASE_URL") or cfg.get("exaone_base_url") or cfg.get("base_url") or os.environ.get("LLM_BASE_URL") or DEFAULT_BASE
        model = os.environ.get("EXAONE_MODEL") or cfg.get("exaone_model") or cfg.get("model") or os.environ.get("LLM_MODEL") or DEFAULT_MODEL
        local = base.startswith(("http://localhost", "http://127.0.0.1"))
        c = cls(key, base, model, ledger=ledger, provider="exaone" if "exaone" in model.lower() else "openai-compatible")
        if local and not key:
            c.api_key = "local"                      # local servers ignore the key
        if local:
            c.daily_budget = 10 ** 9                 # no provider-side daily limit on a local server
        return c

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    # -- ledger
    def _today(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime())

    def calls_today(self) -> int:
        if not self.ledger:
            return self.calls
        return int((read_json(self.ledger, {}) or {}).get(self._today(), 0))

    def _bump(self) -> None:
        self.calls += 1
        if self.ledger:
            d = read_json(self.ledger, {}) or {}
            d = {k: v for k, v in d.items() if k >= self._today()}
            d[self._today()] = int(d.get(self._today(), 0)) + 1
            write_json(self.ledger, d)

    # -- call
    def complete(self, system: str, user: str, max_tokens: int = 2048, *, json_mode: bool = False) -> str:
        """One request in flight at a time: parallel batch workers sharing this client would otherwise trip the provider's
        'service is busy' 429 (measured: 2 of 10 projects lost their proposals that way)."""
        with self._lock:
            return self._complete(system, user, max_tokens, json_mode=json_mode)

    def _complete(self, system: str, user: str, max_tokens: int, *, json_mode: bool) -> str:
        if not self.available:
            raise LLMUnavailable("no API key configured (set EXAONE_API_KEY)")
        if self.calls_today() >= self.daily_budget:
            raise LLMUnavailable("local daily budget reached (%d calls) - protecting the provider's day limit" % self.daily_budget)
        msgs = [{"role": "system", "content": system + ("\n\nRespond with ONLY valid JSON, no prose, no code fences." if json_mode else "")},
                {"role": "user", "content": user}]
        body: Dict[str, Any] = {"model": self.model, "messages": msgs, "max_tokens": max(max_tokens, FLOOR_TOKENS)}
        if self.provider == "exaone":
            body["reasoning_effort"] = "low"
        headers = {"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json",
                   "User-Agent": "bts-sbom-app/0.1"}
        url = self.base_url + "/chat/completions"
        wait = 3.0
        for attempt in range(2):
            self._bump()                  # every network attempt counts against the provider's day limit, failures included
            status, text = self._post(url, headers, body)
            if status == 429:
                low = text.lower()
                if any(w in low for w in ("day", "daily", "quota", "limit exceeded")) or attempt == 1:
                    self.errors.append("HTTP 429: " + text[:160])
                    raise LLMUnavailable("provider rate/day limit (HTTP 429): " + text[:200].replace(self.api_key, "***"))
                time.sleep(wait)
                continue
            if status >= 500 and attempt == 0:
                time.sleep(wait)
                continue
            break
        if status >= 400:
            self.errors.append("HTTP %s" % status)
            raise LLMError("HTTP %s: %s" % (status, text[:200].replace(self.api_key, "***")))
        try:
            data = json.loads(text)
            content = str(((data.get("choices") or [{}])[0].get("message") or {}).get("content") or "")
            u = data.get("usage") or {}
            self.usage["prompt_tokens"] += int(u.get("prompt_tokens") or 0)
            self.usage["completion_tokens"] += int(u.get("completion_tokens") or 0)
        except (ValueError, AttributeError, TypeError) as exc:
            raise LLMError("unparseable provider response: %s" % type(exc).__name__)
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.S).strip()
        if not content:
            raise LLMError("empty completion (reasoning consumed the token budget?)")
        return content

    def _post(self, url: str, headers: Dict[str, str], body: Dict[str, Any]) -> Tuple[int, str]:
        if TRANSPORT is not None:
            return TRANSPORT(url, headers, body)
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else str(exc)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.errors.append(type(exc).__name__)
            raise LLMUnavailable("network error: %s" % type(exc).__name__)

    def describe(self) -> Dict[str, Any]:
        return {"provider": self.provider, "model": self.model, "base_url": self.base_url, "key_configured": self.available,
                "calls_this_run": self.calls, "calls_today": self.calls_today(), "daily_budget": self.daily_budget,
                "tokens": dict(self.usage)}
