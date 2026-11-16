"""Version ordering for the ecosystems BTS-SBOM patches (PEP 440, semver, Maven-ish, Go, gem, composer).

This is a deliberately small, documented approximation of each ecosystem's rules:
  * a version is tokenised into numbers and qualifiers; numbers compare numerically, missing numbers are 0
    (so 1.0 == 1.0.0);
  * qualifiers rank dev < alpha < beta < milestone < rc < (release) < post/sp < unknown;
  * a leading ``v`` and semver build metadata (``+...``) are ignored; a PEP 440 epoch (``1!``) wins first.
It is NOT a full resolver (no range solving): callers only need "is A before B" and "pick the smallest >= X".
"""
from __future__ import annotations

import functools
import re
from itertools import zip_longest
from typing import Iterable, List, Optional

_TOKEN = re.compile(r"\d+|[A-Za-z]+")
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_RANK = {"dev": -5, "snapshot": -5, "nightly": -5, "a": -4, "alpha": -4, "b": -3, "beta": -3, "m": -2,
         "milestone": -2, "rc": -1, "cr": -1, "c": -1, "pre": -1, "preview": -1, "final": 0, "ga": 0,
         "release": 0, "sp": 1, "post": 1, "rev": 1, "r": 1}


def is_version(v: object) -> bool:
    """True when ``v`` looks like a real release version (not a git SHA, not empty/'0'-only noise)."""
    s = str(v or "").strip()
    return bool(s) and not _SHA.match(s) and bool(re.search(r"\d", s)) and len(s) <= 64


def _norm(v: str) -> str:
    s = str(v).strip()
    if s[:1] in "vV" and len(s) > 1 and s[1].isdigit():
        s = s[1:]
    s = s.split("+", 1)[0] if "+" in s and not s.startswith("+") else s
    return s.replace("+incompatible", "")


def _tokens(v: str):
    epoch = 0
    s = _norm(v)
    if "!" in s:
        e, s = s.split("!", 1)
        epoch = int(e) if e.isdigit() else 0
    toks = []
    for t in _TOKEN.findall(s):
        if t.isdigit():
            toks.append((1, int(t), ""))
        else:
            low = t.lower()
            toks.append((0, _RANK.get(low, 2), low))
    return epoch, toks


def compare(a: str, b: str) -> int:
    ea, ta = _tokens(a)
    eb, tb = _tokens(b)
    if ea != eb:
        return -1 if ea < eb else 1
    for x, y in zip_longest(ta, tb, fillvalue=None):
        if x is None:
            x = (1, 0, "") if (y is not None and y[0] == 1) else (0, 0, "")
        if y is None:
            y = (1, 0, "") if x[0] == 1 else (0, 0, "")
        if x[0] != y[0]:                       # number vs qualifier: a number beats a pre-release qualifier
            q = x if x[0] == 0 else y
            num_wins = q[1] < 0 or q[1] == 0
            return (1 if x[0] == 1 else -1) if num_wins else (-1 if x[0] == 1 else 1)
        if x[0] == 1:
            if x[1] != y[1]:
                return -1 if x[1] < y[1] else 1
        else:
            if x[1] != y[1]:
                return -1 if x[1] < y[1] else 1
            if x[2] != y[2]:
                return -1 if x[2] < y[2] else 1
    return 0


_key = functools.cmp_to_key(compare)


def sort_versions(vs: Iterable[str]) -> List[str]:
    return sorted(vs, key=_key)


def max_version(vs: Iterable[str]) -> Optional[str]:
    best = None
    for v in vs:
        if is_version(v) and (best is None or compare(v, best) > 0):
            best = v
    return best


def min_greater_or_equal(vs: Iterable[str], floor: str) -> Optional[str]:
    best = None
    for v in vs:
        if is_version(v) and compare(v, floor) >= 0 and (best is None or compare(v, best) < 0):
            best = v
    return best


def major(v: str) -> Optional[int]:
    _, toks = _tokens(v)
    nums = [t[1] for t in toks if t[0] == 1]
    return nums[0] if nums else None


def lt(a: str, b: str) -> bool:
    return compare(a, b) < 0


def le(a: str, b: str) -> bool:
    return compare(a, b) <= 0
