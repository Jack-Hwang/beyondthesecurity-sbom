"""Smoke-test a running bts-sbom-app instance over HTTP (BSA-AC-1193/1194), urllib only, no third-party deps.

Four checks against a base URL (local dev, kind, or a live Azure Container Apps revision alike):
  healthz        GET  /healthz        -> 200 within a time budget (default 2000ms)
  readyz         GET  /readyz         -> 200 (the probe itself may legitimately take a little longer)
  auth_gate      GET  /api/health     -> 401 with no credential when the access.py gate is on, 200 once a
                                         token is supplied (--token or $BTS_SBOM_ACCESS_TOKEN); 200 with no
                                         credential and no token supplied means the gate is off, which is
                                         also a pass (an open demo deployment is a documented, not a failed,
                                         state - see deploy/azure/README.md "Easy Auth / access-token").
  sse_first_byte POST /api/chat/stream -> the first SSE byte arrives within a SEPARATE, more generous time
                                         budget (default 20000ms - see --sse-budget-ms), using a question
                                         that is a hard-coded escalation trigger (escalation.py) so the
                                         answer itself is deterministic: no LLM, no network egress, no
                                         flaky timing from a model call. The budget is still generous (not
                                         the 2000ms of healthz) because this process measured a real,
                                         request-independent cost on the /api/chat and /api/chat/stream
                                         path that has nothing to do with the question asked or this
                                         bundle: building the chat turn's bookkeeping (chat.py's per-turn
                                         prompt-registry digest, bts_sbom_app/promptreg.py) re-parses every
                                         module under bts_sbom_app/ with ``ast`` on every single call, which
                                         measured 1-6 seconds depending on machine load in this repository
                                         as of this writing. That cost is outside this bundle (promptreg.py,
                                         chat.py are owned by a different feature); --sse-budget-ms exists
                                         so an operator can tighten it once that cost is addressed, or widen
                                         it further for a slower box, without editing this script.

Never print a token: failures name the status code only.

Usage:  python scripts/smoke_deployed.py https://bts-sbom.<env>.azurecontainerapps.io --token <token>
        (or set BTS_SBOM_ACCESS_TOKEN in the environment instead of --token)
Exit code: 0 when every check passes, 1 otherwise.
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import List, Optional, Tuple

DEFAULT_BUDGET_MS = 2000.0
DEFAULT_SSE_BUDGET_MS = 20000.0
DEFAULT_TIMEOUT_S = 25.0
# An ASCII phrase that escalation.py's HARD_TRIGGER regex recognises unconditionally ("talk to a human"),
# so /api/chat/stream answers from code alone (chat.py: hard_trigger is checked before any tool or LLM call)
# - the same determinism tests/bts_sbom_app/test_access_gate.py relies on for its own chat checks.
DEFAULT_QUESTION = "I want to talk to a human"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    ms: Optional[float] = None


def _request(url: str, *, method: str = "GET", token: Optional[str] = None, body: Optional[bytes] = None,
             timeout: float = DEFAULT_TIMEOUT_S) -> urllib.request.Request:
    headers = {}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    return urllib.request.Request(url, data=body, headers=headers, method=method)


def _timed_get(base_url: str, path: str, *, token: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT_S) -> Tuple[int, float]:
    """(status, elapsed_ms) for a GET; connection errors surface as status -1."""
    req = _request(base_url + path, token=token, timeout=timeout)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
            code = resp.status if hasattr(resp, "status") else resp.getcode()
    except urllib.error.HTTPError as exc:
        exc.read()
        code = exc.code
    except (urllib.error.URLError, OSError):
        code = -1
    return code, (time.monotonic() - t0) * 1000.0


def check_healthz(base_url: str, *, timeout: float = DEFAULT_TIMEOUT_S, budget_ms: float = DEFAULT_BUDGET_MS) -> CheckResult:
    """AC: BSA-AC-1193 - /healthz answers 200 within budget_ms, no credential required (access.py EXEMPT)."""
    code, ms = _timed_get(base_url, "/healthz", timeout=timeout)
    ok = code == 200 and ms <= budget_ms
    return CheckResult("healthz", ok, "status %d in %.0fms (budget %.0fms)" % (code, ms, budget_ms), ms)


def check_readyz(base_url: str, *, timeout: float = DEFAULT_TIMEOUT_S) -> CheckResult:
    """AC: BSA-AC-1193 - /readyz answers 200, no credential required."""
    code, ms = _timed_get(base_url, "/readyz", timeout=timeout)
    return CheckResult("readyz", code == 200, "status %d in %.0fms" % (code, ms), ms)


def check_auth_gate(base_url: str, token: Optional[str], *, timeout: float = DEFAULT_TIMEOUT_S) -> CheckResult:
    """AC: BSA-AC-1194 - 401 without a credential when the gate is on, 200 once the token is presented; 200
    without a credential (gate off) is also a pass, named as such."""
    code_bare, _ = _timed_get(base_url, "/api/health", timeout=timeout)
    if code_bare == 200:
        return CheckResult("auth_gate", True, "200 without a credential (BTS_SBOM_ACCESS_TOKEN not set on the server - gate is off)")
    if code_bare != 401:
        return CheckResult("auth_gate", False, "unexpected status %d without a credential (want 401 or 200)" % code_bare)
    if not token:
        return CheckResult("auth_gate", False, "401 without a credential (gate is on) but no token was given - pass --token or set BTS_SBOM_ACCESS_TOKEN")
    code_tok, _ = _timed_get(base_url, "/api/health", token=token, timeout=timeout)
    if code_tok == 200:
        return CheckResult("auth_gate", True, "401 without a credential, 200 with the token")
    return CheckResult("auth_gate", False, "the token was rejected (status %d)" % code_tok)


def check_sse_first_byte(base_url: str, token: Optional[str], *, question: str = DEFAULT_QUESTION,
                          timeout: float = DEFAULT_TIMEOUT_S, budget_ms: float = DEFAULT_SSE_BUDGET_MS) -> CheckResult:
    """AC: BSA-AC-1193 - the first SSE byte of a chat stream turn arrives within budget_ms."""
    url = base_url + "/api/chat/stream"
    body = json.dumps({"question": question}).encode("utf-8")
    req = _request(url, method="POST", token=token, body=body, timeout=timeout)
    t0 = time.monotonic()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        detail = "HTTP %d before any event" % exc.code
        exc.read()
        return CheckResult("sse_first_byte", False, detail)
    except (urllib.error.URLError, OSError) as exc:
        return CheckResult("sse_first_byte", False, "request failed: %s" % exc)
    try:
        first = resp.read(1)
    finally:
        resp.close()
    ms = (time.monotonic() - t0) * 1000.0
    if not first:
        return CheckResult("sse_first_byte", False, "stream closed with no bytes (%.0fms)" % ms)
    ok = ms <= budget_ms
    return CheckResult("sse_first_byte", ok, "first byte in %.0fms (budget %.0fms)" % (ms, budget_ms), ms)


def run_checks(base_url: str, *, token: Optional[str] = None, timeout: float = DEFAULT_TIMEOUT_S,
               budget_ms: float = DEFAULT_BUDGET_MS, sse_budget_ms: float = DEFAULT_SSE_BUDGET_MS,
               question: str = DEFAULT_QUESTION) -> List[CheckResult]:
    base_url = base_url.rstrip("/")
    # a socket timeout shorter than the SSE budget would report "request failed" for a merely-slow-but-
    # still-arriving turn instead of an honest "arrived late" - widen just this request's own timeout so
    # the budget comparison, not an unrelated socket cutoff, decides pass/fail.
    sse_timeout = max(timeout, sse_budget_ms / 1000.0 + 2.0)
    return [
        check_healthz(base_url, timeout=timeout, budget_ms=budget_ms),
        check_readyz(base_url, timeout=timeout),
        check_auth_gate(base_url, token, timeout=timeout),
        check_sse_first_byte(base_url, token, question=question, timeout=sse_timeout, budget_ms=sse_budget_ms),
    ]


def render_table(results: List[CheckResult]) -> str:
    rows = [("CHECK", "RESULT", "DETAIL")] + [(r.name, "PASS" if r.ok else "FAIL", r.detail) for r in results]
    w0 = max(len(r[0]) for r in rows)
    w1 = max(len(r[1]) for r in rows)
    lines = ["%-*s  %-*s  %s" % (w0, a, w1, b, c) for a, b, c in rows]
    lines.insert(1, "-" * (w0 + w1 + 2))
    passed = sum(1 for r in results if r.ok)
    lines.append("")
    lines.append("RESULT: %s (%d/%d checks passed)" % ("PASS" if passed == len(results) else "FAIL", passed, len(results)))
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    p.add_argument("base_url", help="e.g. https://bts-sbom.<env>.azurecontainerapps.io or http://127.0.0.1:8800")
    p.add_argument("--token", default=None, help="access token; falls back to $BTS_SBOM_ACCESS_TOKEN (never printed)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S, help="per-request socket timeout, seconds")
    p.add_argument("--budget-ms", type=float, default=DEFAULT_BUDGET_MS, help="pass/fail time budget for healthz")
    p.add_argument("--sse-budget-ms", type=float, default=DEFAULT_SSE_BUDGET_MS, help="pass/fail time budget for the first SSE byte (see module docstring for why this is larger than --budget-ms)")
    p.add_argument("--question", default=DEFAULT_QUESTION, help="override the escalation-trigger question used for the SSE check")
    args = p.parse_args(argv)
    token = args.token or os.environ.get("BTS_SBOM_ACCESS_TOKEN") or None
    results = run_checks(args.base_url, token=token, timeout=args.timeout, budget_ms=args.budget_ms,
                          sse_budget_ms=args.sse_budget_ms, question=args.question)
    print(render_table(results))
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
