"""PII and secret-shaped redaction for text that leaves the chat turn and reaches a human outside it: an escalation's
triggering question and a reviewer's resolution note, and (exported for the owners of those call sites to wire in)
a chat answer or a VEX decision reason.

Course source (MetaNet advanced course week 2 lesson 2 S2-2 "PII 마스킹: 유형 토큰 치환"; adv-lab w2-2 README AC-1
"PII 잔존 0건"; week 5 lesson 1 "가드레일 3층: 결정적 후처리" - a deterministic post-filter, not a model's judgement).

Deterministic, stdlib-only regex matching, most-specific pattern first: an email, a phone number, a Korean resident
registration-number-shaped number, a PEM private-key block, an AWS access-key id, a GitHub personal-access token, a
bearer/Authorization token and a ``key=value``-shaped secret assignment are each replaced with ``[redacted:<kind>]``.

Nothing else is touched. A CVE/GHSA/PYSEC/RUSTSEC/GO advisory id, a semantic version, an SPDX license id and an
ordinary number all have their own fixed, narrower shape that these patterns do not match - this is a property of
the patterns above (none of them matches a bare "CVE-2024-12345" or "1.2.3" or "MIT"), checked by a regression test
in tests/bts_sbom_app/test_memory_pii.py rather than merely asserted here. A limit, stated honestly: this is shape
matching over a fixed pattern list, not a PII classifier - a PII value that does not look like any of the shapes
below (a bare name, a street address) is not caught.

Pure: ``redact(text) -> (masked_text, [kinds])``. No network, no state, no exception for ordinary input.
"""
from __future__ import annotations

import re
from typing import List, Tuple

# ---- PII / secret shapes, most specific first so a private-key block is consumed before its inner lines could ------
# ---- otherwise match a looser pattern ------------------------------------------------------------------------------
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RRN = re.compile(r"(?<!\d)\d{6}[- ]?[1-4]\d{6}(?!\d)")                        # Korean RRN shape: YYMMDD-[1-4]XXXXXX
_PHONE = re.compile(r"(?<!\d)(?:\+?82[- ]?1[0-9]|0(?:2|1[0-9]|[3-6][1-5]))[- ]\d{3,4}[- ]\d{4}(?!\d)")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_GH_TOKEN = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")
_BEARER = re.compile(r"\b[Bb]earer\s+[A-Za-z0-9._\-]{10,}")
_ASSIGN_SECRET = re.compile(r"\b(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"]?[A-Za-z0-9._\-/+]{6,}['\"]?", re.I)

#: (kind, pattern) in match-priority order - a PEM block before email/phone so none of its base64 body is re-matched
_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("private-key", _PEM),
    ("email", _EMAIL),
    ("rrn", _RRN),
    ("phone", _PHONE),
    ("aws-key", _AWS_KEY),
    ("github-token", _GH_TOKEN),
    ("bearer-token", _BEARER),
    ("secret-assignment", _ASSIGN_SECRET),
]


def redact(text: str) -> Tuple[str, List[str]]:
    """Mask PII/secret-shaped substrings in ``text``. Returns ``(masked_text, sorted kinds actually masked)``;
    ``[]`` when nothing matched (the common case). ``""``/``None`` in -> ``""`` out, never an exception."""
    s = str(text or "")
    if not s:
        return s, []
    hits: List[str] = []

    def _mk(kind: str):
        def _sub(m: "re.Match[str]") -> str:
            hits.append(kind)
            return "[redacted:%s]" % kind
        return _sub

    for kind, pat in _PATTERNS:
        s = pat.sub(_mk(kind), s)
    return s, sorted(set(hits))


__all__ = ["redact"]
