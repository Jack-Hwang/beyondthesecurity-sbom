"""LG EXAONE (K-EXAONE, OpenAI-compatible chat completions) client - stdlib only.

Configuration (first found wins):  environment ``EXAONE_API_KEY`` / ``EXAONE_BASE_URL`` / ``EXAONE_MODEL``,
a JSON file named by ``BTS_SBOM_LLM_CONFIG`` (keys exaone_api_key / exaone_base_url / exaone_model, or api_key /
base_url / model), or the generic ``LLM_API_KEY`` / ``LLM_BASE_URL`` / ``LLM_MODEL`` for any OpenAI-compatible server
(e.g. a local Ollama at http://localhost:11434/v1 running an EXAONE build - no daily limit there).
Azure OpenAI is also supported (checked first): ``AZURE_OPENAI_API_KEY`` / ``AZURE_OPENAI_BASE_URL`` /
``AZURE_OPENAI_DEPLOYMENT`` / ``AZURE_OPENAI_API_VERSION`` or config keys azure_api_key / azure_base_url /
azure_deployment / azure_api_version - auth is the ``api-key`` header and the URL is the deployment-scoped
``/openai/deployments/<deployment>/chat/completions?api-version=<v>`` form.
The key is never written to evidence, logs, caches or errors.

Cost/limit protection: a per-day call ledger (``daily_budget``, default 80 < the 100/day free tier) stops calls BEFORE
the provider does; an HTTP 429 that talks about a day/limit is not retried (retrying cannot help).
K-EXAONE is a reasoning model: reasoning tokens count against ``max_tokens`` and cannot be disabled, so the budget
floor is 1024 and ``reasoning_effort`` is sent as "low".
"""
from __future__ import annotations
from . import __version__

import datetime
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from .net import _retry_after_seconds
from .util import read_json, write_json

DEFAULT_BASE = "https://api.exaone.ai/v1"
DEFAULT_MODEL = "k-exaone_v2.5"
DEFAULT_AZURE_API_VERSION = "2024-10-21"
FLOOR_TOKENS = 1024
# tests: callable(url, headers, body_dict) -> (status:int, text:str) OR (status:int, text:str, response_headers:dict);
# the 3-tuple form lets a fake transport simulate a Retry-After header (C15), mirroring net.py's TRANSPORT contract.
# None = real network.
TRANSPORT: Optional[Callable[..., Any]] = None
#: Injectable backoff sleep (tests replace this with a recording no-op so retry/Retry-After tests run instantly,
#: mirroring net.py's SLEEP hook).
SLEEP: Callable[[float], None] = time.sleep

# C48: static USD-per-1000-token price table for the estimated daily cost ledger. These are illustrative
# published list prices (not a live price feed), keyed by the lowercased model name. A model this table does
# not know about - including the EXAONE models this app talks to by default, whose commercial per-token price
# is not public - reports its cost as None rather than guessing: never a silent wrong number.
PRICE_PER_1K_USD: Dict[str, Tuple[float, float]] = {
    # model name (lowercase) -> (prompt $/1K tokens, completion $/1K tokens)
    "gpt-4o": (0.0025, 0.0100),
    "gpt-4o-mini": (0.00015, 0.00060),
    "gpt-4-turbo": (0.0100, 0.0300),
    "gpt-4": (0.0300, 0.0600),
    "gpt-3.5-turbo": (0.0005, 0.0015),
    "gpt-5": (0.00125, 0.0100),
    "o1": (0.0150, 0.0600),
    "o1-mini": (0.0011, 0.0044),
    "o3-mini": (0.0011, 0.0044),
}


def _price_lookup(model: str) -> Optional[Tuple[float, float]]:
    """PRICE_PER_1K_USD lookup: an exact match on the lowercased model name first, else the longest registered
    key the model name starts with (covers a dated/suffixed deployment name like 'gpt-4o-2024-08-06' or an
    Azure deployment alias such as 'gpt-4o-mini-eu'). No match -> None."""
    key = (model or "").strip().lower()
    if key in PRICE_PER_1K_USD:
        return PRICE_PER_1K_USD[key]
    best = ""
    for k in PRICE_PER_1K_USD:
        if key.startswith(k) and len(k) > len(best):
            best = k
    return PRICE_PER_1K_USD[best] if best else None


def estimated_cost_usd(prompt_tokens: int, completion_tokens: int, model: str) -> Optional[float]:
    """C48: the estimated USD cost of ``prompt_tokens``/``completion_tokens`` on ``model``, or None when the
    model is not in PRICE_PER_1K_USD (an honest "unknown", never a guess)."""
    price = _price_lookup(model)
    if price is None:
        return None
    return round(max(0, prompt_tokens) / 1000.0 * price[0] + max(0, completion_tokens) / 1000.0 * price[1], 6)


class LLMError(RuntimeError):
    pass


class LLMUnavailable(LLMError):
    """no key / budget exhausted / provider says the day limit is reached - callers downgrade honestly."""


class LLMTruncated(LLMError):
    """C41: finish_reason == 'length' - the provider cut the completion short at the token budget. This is not
    a parse failure and not an availability problem, but the (possibly cut-off) text must not be trusted, so
    it is raised instead of returned; every existing caller already catches the LLMError base class and records
    str(exc) as its downgrade note, so this message ("truncated by token budget...") flows through unchanged."""


class ChatClient:
    def __init__(self, api_key: str = "", base_url: str = DEFAULT_BASE, model: str = DEFAULT_MODEL, *,
                 timeout: float = 300.0, daily_budget: Optional[int] = None, ledger: Optional[str] = None,
                 provider: str = "exaone", api_version: str = ""):
        self._lock = threading.Lock()
        self.api_key = api_key
        self.base_url = (base_url or DEFAULT_BASE).rstrip("/")
        self.model = model or DEFAULT_MODEL
        self.timeout = timeout
        self.provider = provider
        self.api_version = api_version or DEFAULT_AZURE_API_VERSION
        self.daily_budget = int(os.environ.get("BTS_SBOM_LLM_DAILY_BUDGET", "80")) if daily_budget is None else daily_budget
        self.min_interval = float(os.environ.get("BTS_SBOM_LLM_MIN_INTERVAL", "0") or 0)   # C68: proactive pacing (0 = off)
        self._last_call_at: Optional[float] = None
        self.ledger = ledger
        self.calls = 0
        self.errors: List[str] = []
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0}
        self.attempt_log: List[Dict[str, Any]] = []      # D4 §20: every attempt is recorded - what happened, and why it was retried or not
        self._ATTEMPT_CAP = 200                          # bounded: this is a health signal, not an audit journal (escalations.py owns that role)

    # -- configuration
    @classmethod
    def from_config(cls, key: str, base_url: str = "", model: str = "", *, ledger: Optional[str] = None,
                    provider: Optional[str] = None, api_version: Optional[str] = None) -> "ChatClient":
        """A client from explicit parts (the web console sends exactly these). A localhost base needs no key and has no daily budget."""
        eff_model = model or DEFAULT_MODEL
        eff_provider = provider or (
            "azure" if ".openai.azure.com" in (base_url or "") else
            "exaone" if "exaone" in eff_model.lower() else "openai-compatible")
        if eff_provider == "azure" and not api_version:
            api_version = "2025-04-01-preview" if re.match(r"^(gpt-[5-9]|o\d)", eff_model) else "2024-10-21"
        c = cls(key or "", base_url or DEFAULT_BASE, eff_model, ledger=ledger, provider=eff_provider,
                api_version=api_version or "")
        if c.base_url.startswith(("http://localhost", "http://127.0.0.1")):
            if not c.api_key:
                c.api_key = "local"                  # local servers ignore the key
            c.daily_budget = 10 ** 9                 # no provider-side daily limit on a local server
        return c

    @classmethod
    def from_env(cls, ledger: Optional[str] = None) -> "ChatClient":
        cfg: Dict[str, Any] = {}
        path = os.environ.get("BTS_SBOM_LLM_CONFIG", "")
        if path:
            cfg = read_json(path, {}) or {}
        azure_key = os.environ.get("AZURE_OPENAI_API_KEY") or cfg.get("azure_api_key")
        if azure_key:
            a_base = os.environ.get("AZURE_OPENAI_BASE_URL") or cfg.get("azure_base_url") or ""
            a_model = os.environ.get("AZURE_OPENAI_DEPLOYMENT") or cfg.get("azure_deployment") or cfg.get("azure_model") or ""
            a_ver = os.environ.get("AZURE_OPENAI_API_VERSION") or cfg.get("azure_api_version") or ""
            return cls.from_config(azure_key, a_base, a_model, ledger=ledger, provider="azure", api_version=a_ver)
        key = os.environ.get("EXAONE_API_KEY") or cfg.get("exaone_api_key") or cfg.get("api_key") or os.environ.get("LLM_API_KEY", "")
        base = os.environ.get("EXAONE_BASE_URL") or cfg.get("exaone_base_url") or cfg.get("base_url") or os.environ.get("LLM_BASE_URL") or ""
        model = os.environ.get("EXAONE_MODEL") or cfg.get("exaone_model") or cfg.get("model") or os.environ.get("LLM_MODEL") or ""
        return cls.from_config(key, base, model, ledger=ledger)

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    # -- ledger
    def _today(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime())

    @staticmethod
    def _day_entry(raw: Any) -> Dict[str, Any]:
        """One ledger day's record. A pre-C48 ledger stores a bare int (call count only); that is migrated in
        place to the dict shape right here on read, so an OLD ledger file still parses correctly (calls known,
        tokens/cost unknown) - the on-disk format of an old ledger is never broken."""
        if isinstance(raw, dict):
            return dict(raw)
        return {"calls": int(raw or 0)}

    def calls_today(self) -> int:
        if not self.ledger:
            return self.calls
        raw = (read_json(self.ledger, {}) or {}).get(self._today(), 0)
        return int(self._day_entry(raw).get("calls", 0))

    def ledger_today(self) -> Dict[str, Any]:
        """Today's ledger entry (calls/prompt_tokens/completion_tokens/cost_usd); the in-memory counters when
        there is no ledger file configured at all (e.g. a short-lived CLI invocation)."""
        if not self.ledger:
            return {"calls": self.calls, "prompt_tokens": self.usage["prompt_tokens"],
                    "completion_tokens": self.usage["completion_tokens"],
                    "cost_usd": estimated_cost_usd(self.usage["prompt_tokens"], self.usage["completion_tokens"], self.model)}
        raw = (read_json(self.ledger, {}) or {}).get(self._today(), 0)
        entry = self._day_entry(raw)
        entry.setdefault("calls", 0)
        entry.setdefault("prompt_tokens", 0)
        entry.setdefault("completion_tokens", 0)
        entry.setdefault("cost_usd", estimated_cost_usd(entry["prompt_tokens"], entry["completion_tokens"], self.model))
        return entry

    # -- budget tiers (C33): ok / warn / critical / exhausted from calls_today vs. daily_budget
    BUDGET_WARN_RATIO = 0.5
    BUDGET_CRITICAL_RATIO = 0.8

    def budget_tier(self) -> str:
        """50%/80%/100% of daily_budget -> warn/critical/exhausted (2 of 2 thresholds), else ok."""
        if self.daily_budget <= 0:
            return "exhausted"
        ratio = self.calls_today() / float(self.daily_budget)
        if ratio >= 1.0:
            return "exhausted"
        if ratio >= self.BUDGET_CRITICAL_RATIO:
            return "critical"
        if ratio >= self.BUDGET_WARN_RATIO:
            return "warn"
        return "ok"

    def budget_state(self) -> Dict[str, Any]:
        """The tier plus the numbers a caller needs to render it: GET /api/llm (describe()) and the chat
        llm_note path (server.py annotates the existing llm_note field with this - chat.py itself is untouched)."""
        tier = self.budget_tier()
        today = self.calls_today()
        return {"tier": tier, "degraded": tier != "ok", "calls_today": today, "daily_budget": self.daily_budget,
                "remaining_calls": max(0, self.daily_budget - today)}

    def _bump(self) -> None:
        self.calls += 1
        if not self.ledger:
            return
        d = read_json(self.ledger, {}) or {}
        d = {k: v for k, v in d.items() if k >= self._today()}
        day = self._today()
        entry = self._day_entry(d.get(day, 0))
        entry["calls"] = int(entry.get("calls", 0)) + 1
        entry.setdefault("prompt_tokens", 0)
        entry.setdefault("completion_tokens", 0)
        entry.setdefault("cost_usd", None if _price_lookup(self.model) is None else entry.get("cost_usd", 0.0))
        d[day] = entry
        write_json(self.ledger, d)

    def _log_attempt(self, attempt: int, outcome: str, status: Optional[int], reason: str) -> None:
        """D4 §20: every transport attempt is recorded - which attempt, what happened, the HTTP status and WHY it was
        retried or refused (429_retry_after / 429_day_limit / 5xx_transient / http_4xx / network_lost). The ledger is
        in-memory and bounded: it is a health signal for :meth:`retry_stats`, not an audit journal."""
        self.attempt_log.append({"at": datetime.datetime.now().isoformat(timespec="seconds"),
                                 "attempt": attempt, "outcome": outcome, "status": status, "reason": reason})
        if len(self.attempt_log) > self._ATTEMPT_CAP:
            del self.attempt_log[: len(self.attempt_log) - self._ATTEMPT_CAP]

    def retry_stats(self) -> Dict[str, Any]:
        """The course's retry-budget health signal (week 5 lesson 3: a spiking retry rate is a PROMPT/transport
        smell, so it is measured, not guessed): attempts, completions, retried attempts with reasons, hard failures,
        and the retry rate over completed calls. Empty log -> an honest zero shape, never a made-up ratio."""
        log = self.attempt_log
        retried = [e for e in log if e["outcome"] == "retried"]
        failed = [e for e in log if e["outcome"] == "failed"]
        by_reason: Dict[str, int] = {}
        for e in retried + failed:
            by_reason[e["reason"]] = by_reason.get(e["reason"], 0) + 1
        attempts = len(log)
        completions = sum(1 for e in log if e["outcome"] == "ok")
        return {"attempts": attempts, "completions": completions, "retried": len(retried), "failures": len(failed),
                "retry_rate": round(len(retried) / attempts, 3) if attempts else None,
                "by_reason": dict(sorted(by_reason.items(), key=lambda kv: -kv[1])),
                "recent_errors": list(self.errors[-3:])}

    def _record_usage(self, prompt_tokens: int, completion_tokens: int) -> None:
        """C48: add this completion's tokens to both the in-run counter (self.usage) and today's ledger entry,
        accumulating the estimated USD cost for a priced model (stays None for an unpriced one)."""
        self.usage["prompt_tokens"] += prompt_tokens
        self.usage["completion_tokens"] += completion_tokens
        if not self.ledger:
            return
        d = read_json(self.ledger, {}) or {}
        d = {k: v for k, v in d.items() if k >= self._today()}
        day = self._today()
        entry = self._day_entry(d.get(day, 0))
        entry["prompt_tokens"] = int(entry.get("prompt_tokens", 0)) + prompt_tokens
        entry["completion_tokens"] = int(entry.get("completion_tokens", 0)) + completion_tokens
        price = _price_lookup(self.model)
        if price is None:
            entry.setdefault("cost_usd", None)   # never overwrite a real cost_usd accumulated earlier the
            # same day under a priced model (mirrors _bump()'s own setdefault guard on this same field)
        else:
            prior = entry.get("cost_usd")
            entry["cost_usd"] = round((prior if isinstance(prior, (int, float)) else 0.0) +
                                       prompt_tokens / 1000.0 * price[0] + completion_tokens / 1000.0 * price[1], 6)
        entry.setdefault("calls", 0)
        d[day] = entry
        write_json(self.ledger, d)

    # -- call
    def complete(self, system: str, user: str, max_tokens: int = 2048, *, json_mode: bool = False,
                 temperature: Optional[float] = None) -> str:
        """One request in flight at a time: parallel batch workers sharing this client would otherwise trip the provider's
        'service is busy' 429 (measured: 2 of 10 projects lost their proposals that way). With ``min_interval`` set
        (BTS_SBOM_LLM_MIN_INTERVAL, C68) the client ALSO paces proactively - the wait happens before the request is
        built, instead of after a 429 has already been spent."""
        with self._lock:
            if self.min_interval > 0 and self._last_call_at is not None:
                wait = self.min_interval - (time.monotonic() - self._last_call_at)
                if wait > 0:
                    SLEEP(wait)                            # C68: pace BEFORE spending a call, not after a refusal
            out = self._complete(system, user, max_tokens, json_mode=json_mode, temperature=temperature)
            self._last_call_at = time.monotonic()
            return out

    def _accepts_temperature(self) -> bool:
        """Reasoning models ignore/reject sampling temperature - their ``reasoning_effort`` is the control. Sending
        temperature there would 400 the request (or be silently ignored), so the client refuses to send it."""
        if self.provider == "exaone":
            return False
        if self.provider == "azure":
            return not re.match(r"^(gpt-[5-9]|o\d)", self.model)
        return True

    def _complete(self, system: str, user: str, max_tokens: int, *, json_mode: bool,
                  temperature: Optional[float] = None) -> str:
        if not self.available:
            raise LLMUnavailable("no API key configured (set EXAONE_API_KEY)")
        if self.calls_today() >= self.daily_budget:
            raise LLMUnavailable("local daily budget reached (%d calls) - protecting the provider's day limit" % self.daily_budget)
        msgs = [{"role": "system", "content": system + ("\n\nRespond with ONLY valid JSON, no prose, no code fences." if json_mode else "")},
                {"role": "user", "content": user}]
        floor = 2048 if self.provider == "azure" else FLOOR_TOKENS
        body: Dict[str, Any] = {"messages": msgs, "max_tokens": max(max_tokens, floor)}
        if json_mode and temperature is None:
            temperature = 0.2                              # C49: structured/extraction output wants a low sampling temperature -
        if temperature is not None and self._accepts_temperature():   # a default at the client, so every JSON call site inherits it
            body["temperature"] = temperature
        if self.provider == "azure":
            # Azure OpenAI: the deployment rides in the URL, auth is the api-key header. gpt-5+/o* reasoning
            # deployments require max_completion_tokens and burn completion tokens on reasoning, so the floor is
            # higher and reasoning_effort is pinned low; non-reasoning deployments reject that parameter.
            body["max_completion_tokens"] = body.pop("max_tokens")
            if re.match(r"^(gpt-[5-9]|o\d)", self.model):
                body["reasoning_effort"] = "low"
            url = "%s/openai/deployments/%s/chat/completions?api-version=%s" % (
                self.base_url, self.model, self.api_version)
            headers = {"api-key": self.api_key, "Content-Type": "application/json",
                       "User-Agent": "bts-sbom-app/" + __version__}
        else:
            if self.provider == "exaone":
                body["reasoning_effort"] = "low"
            body["model"] = self.model
            url = self.base_url + "/chat/completions"
            headers = {"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json",
                       "User-Agent": "bts-sbom-app/" + __version__}
        wait = 3.0
        status, text, resp_headers = 0, "", {}
        for attempt in range(2):
            self._bump()                  # every network attempt counts against the provider's day limit, failures included
            try:
                status, text, resp_headers = self._post(url, headers, body)
            except Exception as exc:      # D1 §21: a network loss is an attempt too - recorded, then raised honestly
                self._log_attempt(attempt, "failed", None, "network_lost")
                raise
            if status == 429:
                low = text.lower()
                if any(w in low for w in ("day", "daily", "quota", "limit exceeded")) or attempt == 1:
                    self._log_attempt(attempt, "failed", status, "429_day_limit")
                    self.errors.append("HTTP 429: " + text[:160])
                    raise LLMUnavailable("provider rate/day limit (HTTP 429): " + text[:200].replace(self.api_key, "***"))
                # C15: honour the provider's own Retry-After when it sends one (net._retry_after_seconds caps it
                # at 30s), falling back to the fixed wait only when the header is absent or unparseable.
                self._log_attempt(attempt, "retried", status, "429_retry_after")
                retry_after = _retry_after_seconds(resp_headers)
                SLEEP(retry_after if retry_after is not None else wait)
                continue
            if status >= 500 and attempt == 0:
                self._log_attempt(attempt, "retried", status, "5xx_transient")
                SLEEP(wait)
                continue
            break
        if status >= 400:
            self._log_attempt(attempt, "failed", status, "http_%d" % status)
            self.errors.append("HTTP %s" % status)
            raise LLMError("HTTP %s: %s" % (status, text[:200].replace(self.api_key, "***")))
        self._log_attempt(attempt, "ok", status, "completed")
        try:
            data = json.loads(text)
            choice0 = (data.get("choices") or [{}])[0]
            content = str((choice0.get("message") or {}).get("content") or "")
            finish_reason = choice0.get("finish_reason")
            u = data.get("usage") or {}
            p_tok, c_tok = int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0)
        except (ValueError, AttributeError, TypeError) as exc:
            raise LLMError("unparseable provider response: %s" % type(exc).__name__)
        self._record_usage(p_tok, c_tok)                      # C48: counted whether or not the completion below turns out usable
        if finish_reason == "length":
            # C41: cut short at the token budget - the existing LLMError path carries the honest explanation on
            # to every caller (ai.propose/chat.ask/council/reimpl_c) without any of those files needing a change.
            raise LLMTruncated("truncated by token budget (finish_reason=length, requested max_tokens=%d, "
                                "prompt_tokens=%d, completion_tokens=%d) - raise max_tokens or shorten the prompt"
                                % (max(max_tokens, floor), p_tok, c_tok))
        content = re.sub(r"<think>.*?</think>", "", content, flags=re.S).strip()
        if not content:
            raise LLMError("empty completion (reasoning consumed the token budget?)")
        return content

    def _post(self, url: str, headers: Dict[str, str], body: Dict[str, Any]) -> Tuple[int, str, Dict[str, str]]:
        if TRANSPORT is not None:
            result = TRANSPORT(url, headers, body)              # 2-tuple (status, text) or 3-tuple (+ response headers, C15)
            if len(result) == 3:
                status, text, resp_headers = result
                return status, text, dict(resp_headers or {})
            status, text = result
            return status, text, {}
        req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace"), dict(resp.headers.items())
        except urllib.error.HTTPError as exc:
            resp_headers = dict(exc.headers.items()) if exc.headers is not None else {}
            text = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else str(exc)
            return exc.code, text, resp_headers
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            self.errors.append(type(exc).__name__)
            raise LLMUnavailable("network error: %s" % type(exc).__name__)

    def describe(self) -> Dict[str, Any]:
        tier = self.budget_tier()
        ledger_today = self.ledger_today()
        return {"provider": self.provider, "model": self.model, "base_url": self.base_url, "key_configured": self.available,
                "calls_this_run": self.calls, "calls_today": self.calls_today(), "daily_budget": self.daily_budget,
                "tokens": dict(self.usage),
                "budget_tier": tier, "degraded": tier != "ok",                            # C33
                "remaining_calls_today": max(0, self.daily_budget - self.calls_today()),
                "ledger_today": {"calls": ledger_today.get("calls", 0),                    # C48
                                 "prompt_tokens": ledger_today.get("prompt_tokens", 0),
                                 "completion_tokens": ledger_today.get("completion_tokens", 0),
                                 "cost_usd": ledger_today.get("cost_usd")},
                "retry": self.retry_stats()}                                               # D4 §20: retry-budget health, measured
