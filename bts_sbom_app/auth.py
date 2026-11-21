"""Authentication for cloud mode (task 10): bearer token or a trusted identity header, fail-closed.

Local mode (BTS_SBOM_CLOUD off) authenticates nothing - exactly the earlier behaviour. Cloud mode demands ONE of:
  * ``BTS_SBOM_API_TOKEN``  -> Authorization: Bearer <token>, compared with hmac.compare_digest. Identity: "api-token".
    On Azure the value is injected as a Key Vault reference, never written to code or logs.
  * ``BTS_SBOM_TRUST_IDENTITY_HEADER=1`` -> the identity header named by ``BTS_SBOM_IDENTITY_HEADER`` is trusted.
    This is ONLY safe behind App Service authentication (Easy Auth), which validates the user before the request
    reaches the app and strips incoming client-supplied identity headers. Directly exposed, this header is
    forgeable - see README/RUNBOOK for that warning. Unrecognised/odd values fail closed.

When cloud mode is on but neither method is configured, every /api route except the health probes answers
503 {"error": "auth_not_configured"} - a public server that silently accepts anonymous writes is the failure
this exists to prevent. Auth failures are 401 with ONE body for "missing" and "wrong" (no oracle).
"""
from __future__ import annotations

import hmac
import os
import re
from typing import Any, Dict, Optional

_ID_RE = re.compile(r"^[^\\/\r\n]{1,128}$")


def _env(env: Dict[str, str], key: str) -> str:
    return str(env.get(key, "") or "")


def configured(env: Optional[Dict[str, str]] = None) -> bool:
    e = env if env is not None else dict(os.environ)
    return bool(_env(e, "BTS_SBOM_API_TOKEN")) or trust_identity_header(e)


def trust_identity_header(env: Optional[Dict[str, str]] = None) -> bool:
    e = env if env is not None else dict(os.environ)
    return _env(e, "BTS_SBOM_TRUST_IDENTITY_HEADER") in ("1", "true", "yes", "on")


def identity_header_name(env: Optional[Dict[str, str]] = None) -> str:
    """The header Easy Auth fills with the caller's identity. App Service authentication injects
    ``X-MS-CLIENT-PRINCIPAL-NAME`` for the name claim (verify against the current App Service docs before
    deploying - the exact header set has changed across App Service versions)."""
    e = env if env is not None else dict(os.environ)
    return _env(e, "BTS_SBOM_IDENTITY_HEADER") or "X-MS-CLIENT-PRINCIPAL-NAME"


def check(headers: Any, env: Optional[Dict[str, str]] = None) -> Optional[str]:
    """The caller's identity for a request's headers, or None when unauthenticated. Constant-time token compare."""
    e = env if env is not None else dict(os.environ)
    token = _env(e, "BTS_SBOM_API_TOKEN")
    if token:
        auth = ""
        getter = getattr(headers, "get", None)
        if getter:
            auth = str(getter("Authorization") or getter("authorization") or "")
        expected = "Bearer " + token
        if auth and hmac.compare_digest(auth, expected):
            return "api-token"
        return None                                   # missing and wrong get the same 401 upstream
    if trust_identity_header(e):
        getter = getattr(headers, "get", None)
        if getter:
            name = str(getter(identity_header_name(e)) or "")
            if name and _ID_RE.match(name):
                return name
    return None


def write_methods() -> tuple:
    """Actions that change something - they additionally require a known identity in cloud mode."""
    return ("scan", "patch_approve", "vex_decision", "llm_connect")
