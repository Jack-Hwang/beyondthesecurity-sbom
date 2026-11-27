"""Optional shared-secret gate for a service that is reachable beyond localhost.

The service has no accounts: its honesty contract (docs/RUNBOOK.md) says "localhost, no authentication". A deployment
(Azure Container Apps public ingress) changes that, so one switch closes the gap without an identity provider: when
``BTS_SBOM_ACCESS_TOKEN`` is set every request except the two probes must present the token, as the HTTP Basic
password (a browser prompts once and then sends it with every same-origin request, SSE included), as a Bearer
token, or in ``X-BTS-Token``. The comparison is constant-time, the token is never logged or echoed, and a token
shorter than ``MIN_LENGTH`` is refused at start-up (a guessable shared secret is not a gate).
"""
from __future__ import annotations

import base64
import hmac
import os
import secrets
from typing import Any, Dict, Mapping, Optional

ENV = "BTS_SBOM_ACCESS_TOKEN"
MIN_LENGTH = 16
EXEMPT = ("/healthz", "/readyz")                  # liveness / readiness probes carry no data and must work without a credential
REALM = "bts-sbom"


def configured_token(env: Optional[Mapping[str, str]] = None) -> Optional[str]:
    """The configured token, None when the gate is off. A too-short token raises ValueError (fail at start-up, never run half-open)."""
    raw = (env if env is not None else os.environ).get(ENV, "")
    tok = raw.strip()
    if not tok:
        return None
    if len(tok) < MIN_LENGTH:
        raise ValueError("%s must be at least %d characters (generate one with: python -m bts_sbom_app access-token)" % (ENV, MIN_LENGTH))
    return tok


def generate() -> str:
    """A fresh 256-bit URL-safe token."""
    return secrets.token_urlsafe(32)


def exempt(path: str) -> bool:
    return path in EXEMPT


def presented(headers: Any) -> Optional[str]:
    """The credential a request carries: Basic password, Bearer token or X-BTS-Token (first one present wins), else None."""
    auth = (headers.get("Authorization") or "").strip()
    scheme, _, value = auth.partition(" ")
    value = value.strip()
    if scheme.lower() == "basic" and value:
        try:
            decoded = base64.b64decode(value, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
        return decoded.partition(":")[2]                      # user:password - the user name is free, the password is the token
    if scheme.lower() == "bearer" and value:
        return value
    alt = (headers.get("X-BTS-Token") or "").strip()
    return alt or None


def authorized(headers: Any, token: Optional[str]) -> bool:
    """True when the gate is off or the request carries the token (constant-time compare)."""
    if not token:
        return True
    got = presented(headers)
    return got is not None and hmac.compare_digest(got.encode("utf-8"), token.encode("utf-8"))


def challenge() -> Dict[str, str]:
    """The 401 header that makes a browser ask for the credential."""
    return {"WWW-Authenticate": 'Basic realm="%s", charset="UTF-8"' % REALM}
