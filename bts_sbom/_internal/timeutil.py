# vendored from common/timeutil.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""Canonical UTC time helpers (round 12 P2: datetime.utcnow() deprecation).

``datetime.utcnow()`` is deprecated (Python 3.12+) and raises
DeprecationWarning under ``-W error``; the documented replacement
``datetime.now(timezone.utc)`` returns an AWARE datetime whose isoformat
carries a ``+00:00`` suffix - a silent wire-format change for every API
response that concatenated ``"Z"``.

``utcnow()`` here returns the SAME naive-UTC datetime the deprecated call
produced, so existing ``.isoformat() + "Z"`` call sites keep byte-identical
output. New code should prefer :func:`utc_now_iso`.
"""
from __future__ import annotations

from datetime import datetime, timezone


def utcnow() -> datetime:
    """Naive UTC datetime - drop-in for the deprecated datetime.utcnow()."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_now_iso() -> str:
    """UTC timestamp in the wire format used across the platform: ...Z."""
    return utcnow().isoformat() + "Z"


__all__ = ["utcnow", "utc_now_iso"]
