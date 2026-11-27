"""Deterministic stratified audit sampling (stdlib only).

Two things an honest "we checked a sample" claim needs, that an aggregate rate hides: (1) how many items a
reviewer actually has to look at to say anything about a population of a given size and an assumed error rate
(``sample_size``, normal approximation + finite-population correction - Cochran's formula), and (2) WHICH items
get drawn, reproducibly, per stratum, so a group with a worse true error rate is not swamped by better groups in
one pooled sample (``stratified_sample``). An empty stratum always samples 0 - there is nothing dishonest about
reporting zero reviewed items from a group that has none.

Used by two audits that read decisions another module already recorded (nothing here fetches or invents data):
  * ``licenses.audit_sample``     - a licence-resolution review queue stratified by ``license_source``.
  * ``triage.stratified_audit``   - a closed triage/VEX decision review queue stratified by severity lane.

The draw is seeded and content-addressed (sha256 of "seed:stratum:index"), not Python's ``random`` module, so the
same seed draws the same items forever regardless of interpreter/PYTHONHASHSEED, and changing one stratum's
membership never reshuffles another stratum's draw.
"""
from __future__ import annotations

import hashlib
import math
from typing import Callable, Dict, Hashable, List, Optional, Sequence, TypeVar

T = TypeVar("T")


def _z_for(confidence: float) -> float:
    """Two-sided normal z-score for ``confidence`` (e.g. 0.95 -> ~1.96), via bisection on ``math.erf`` - stdlib has
    no inverse error function, but ``erf`` is monotonic so bisection converges to float precision in <100 steps."""
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be strictly between 0 and 1, got %r" % (confidence,))
    lo, hi = 0.0, 10.0
    for _ in range(100):
        mid = (lo + hi) / 2.0
        if math.erf(mid / math.sqrt(2.0)) < confidence:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def sample_size(n: int, margin: float = 0.1, confidence: float = 0.9, p: float = 0.5) -> int:
    """How many of a population of ``n`` must be sampled to estimate a proportion within +/- ``margin`` at
    ``confidence`` (Cochran's formula with the finite-population correction): ``n0 = z^2*p*(1-p)/margin^2``,
    ``size = ceil(n0 / (1 + (n0-1)/n))``. ``p=0.5`` (default) is the conservative, maximum-variance assumption
    used when the true error rate is unknown. ``n <= 0`` -> 0 (an empty population needs no sample); the result
    is always capped at ``n`` (never sample more than exists) and never less than 1 for a non-empty population.
    """
    if n <= 0:
        return 0
    if not 0.0 < p < 1.0:
        raise ValueError("p must be strictly between 0 and 1, got %r" % (p,))
    if margin <= 0.0:
        raise ValueError("margin must be > 0, got %r" % (margin,))
    z = _z_for(confidence)
    n0 = (z * z * p * (1.0 - p)) / (margin * margin)
    corrected = n0 / (1.0 + (n0 - 1.0) / n)
    return min(n, max(1, math.ceil(corrected - 1e-9)))


def group_by(items: Sequence[T], key_fn: Callable[[T], Hashable]) -> Dict[Hashable, List[T]]:
    """Items bucketed by ``key_fn``, preserving each bucket's original relative order."""
    out: Dict[Hashable, List[T]] = {}
    for it in items:
        out.setdefault(key_fn(it), []).append(it)
    return out


def _stratum_count(n: int, *, frac: Optional[float], size_fn: Optional[Callable[[int], int]], minimum: int) -> int:
    if n <= 0:
        return 0
    if size_fn is not None:
        return max(0, min(n, int(size_fn(n))))
    return min(n, max(minimum, math.ceil(n * frac - 1e-9)))


def _draw(members: Sequence[T], k: int, seed: int, stratum: Hashable) -> List[T]:
    if k <= 0:
        return []
    order = sorted(range(len(members)), key=lambda i: hashlib.sha256(("%r:%r:%d" % (seed, stratum, i)).encode("utf-8")).hexdigest())
    return [members[i] for i in sorted(order[:k])]


def stratified_sample(items: Sequence[T], key_fn: Callable[[T], Hashable], *, frac: Optional[float] = None,
                       size_fn: Optional[Callable[[int], int]] = None, seed: int = 0, minimum: int = 1) -> Dict[Hashable, List[T]]:
    """Deterministic, seeded, per-stratum sample of ``items`` grouped by ``key_fn``.

    Exactly one of ``frac`` (sample >= ``frac`` of a stratum, at least ``minimum``, default 1) or ``size_fn``
    (``size_fn(stratum_size) -> exact count``, e.g. ``audit.sample_size``) selects how many items come out of
    each stratum; either way the count is capped at the stratum's own size. The same ``seed`` draws exactly the
    same members from a stratum whose membership has not changed (content-addressed, not ``random``-module
    state), independent of any other stratum. A stratum with 0 items samples 0 - it is never padded or skipped
    silently; it simply does not appear worth auditing.
    """
    if (frac is None) == (size_fn is None):
        raise ValueError("stratified_sample needs exactly one of frac= or size_fn=")
    groups = group_by(items, key_fn)
    out: Dict[Hashable, List[T]] = {}
    for stratum, members in groups.items():
        k = _stratum_count(len(members), frac=frac, size_fn=size_fn, minimum=minimum)
        out[stratum] = _draw(members, k, seed, stratum)
    return out


__all__ = ["sample_size", "group_by", "stratified_sample"]
