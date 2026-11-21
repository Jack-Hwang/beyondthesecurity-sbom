"""Cloud mode: one switch (BTS_SBOM_CLOUD) that turns every localhost-only assumption into a safe default.

On Azure the server has a public address, so "localhost only, no auth, local paths, plaintext key storage, LLM
by default" must all change. They change together here, fail-closed: an unrecognised value of the env var counts
as ON (the safe side), never as off. With the switch off, behaviour is byte-identical to before.
"""
from __future__ import annotations

import os
from typing import Any, Dict

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"", "0", "false", "no", "off"}


def is_cloud(env: Dict[str, str] = None) -> bool:
    """True when cloud mode is on. Unset/empty/0/false/no/off are off; ANY other value is on (fail-closed)."""
    raw = (env if env is not None else os.environ).get("BTS_SBOM_CLOUD")
    if raw is None:
        return False
    low = str(raw).strip().lower()
    if low in _FALSE:
        return False
    return True                                    # "1"/"true"/... and every unrecognised value: on


def policy(env: Dict[str, str] = None) -> Dict[str, Any]:
    """The effective policy flags (no secrets). Cloud-off returns the permissive defaults."""
    e = env if env is not None else os.environ
    if not is_cloud(e):
        return {"local_paths_allowed": True, "chat_actions_allowed": True, "llm_write_allowed": True, "llm_default": True}
    return {"local_paths_allowed": False,
            "chat_actions_allowed": e.get("BTS_SBOM_CLOUD_ALLOW_ACTIONS") in _TRUE,
            "llm_write_allowed": False,
            "llm_default": e.get("BTS_SBOM_CLOUD_LLM") in _TRUE}
