"""CVSS v4.0 scoring from a vector string, stdlib only.

A faithful port of the scoring procedure of FIRST's reference calculator (https://github.com/FIRSTdotorg/cvss-v4-calculator, BSD-2-Clause;
tables in ``cvss4_data.py``): the vector is mapped to one of 270 macro vectors, whose looked-up score is lowered by the mean, over the
equivalence classes that have a lower neighbour, of the vector's proportional severity distance from the highest-severity vectors of
its macro vector. Operations keep the reference's order so the floating-point results agree; rounding is half-up like ``Math.round``.

Why: FOSSLight Hub scores with CVSS v4.0 first (then v3.1); many recent advisories carry ONLY a v4 vector, and without this module such
a finding had no score at all (``cvss.severity_of`` fell back to the advisory's label or UNKNOWN).

``score`` returns None for anything that is not a complete, valid CVSS:4.0 vector (never a guess). Metrics omitted from the optional
groups take the specification's defaults: E:X is E:A, CR/IR/AR:X are H, and an absent modified metric uses the base metric.
"""
from __future__ import annotations

import math
from typing import Dict, List, Optional

from .cvss4_data import LOOKUP, MAX_COMPOSED, MAX_SEVERITY, METRICS

BASE = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
_THREAT, _ENV = ("E",), ("CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA")

# position of each metric value in the distance computation (reference: AV_levels ... E_levels)
_LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3}, "PR": {"N": 0.0, "L": 0.1, "H": 0.2}, "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1}, "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2}, "VI": {"H": 0.0, "L": 0.1, "N": 0.2}, "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3}, "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3}, "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2}, "IR": {"H": 0.0, "M": 0.1, "L": 0.2}, "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}


def parse_vector(vec: object) -> Optional[Dict[str, str]]:
    """{metric: value} of a complete CVSS:4.0 vector, or None (wrong prefix, unknown / repeated metric, invalid value, missing base metric)."""
    s = str(vec or "").strip()
    if not s.startswith("CVSS:4.0/"):
        return None
    out: Dict[str, str] = {}
    for part in s.split("/")[1:]:
        k, sep, v = part.partition(":")
        if not sep or k in out or k not in METRICS or v not in METRICS[k]:
            return None
        out[k] = v
    return out if all(k in out for k in BASE) else None


def _m(sel: Dict[str, str], metric: str) -> Optional[str]:
    """The effective value of a metric (reference ``m``): defaults for E / CR / IR / AR, and a modified metric overrides its base metric."""
    selected = sel.get(metric)
    if metric == "E" and selected in (None, "X"):
        return "A"
    if metric in ("CR", "IR", "AR") and selected in (None, "X"):
        return "H"
    mod = sel.get("M" + metric)
    if mod is not None and mod != "X":
        return mod
    return selected


def macro_vector(sel: Dict[str, str]) -> str:
    av, pr, ui = _m(sel, "AV"), _m(sel, "PR"), _m(sel, "UI")
    if av == "N" and pr == "N" and ui == "N":
        eq1 = "0"
    elif (av == "N" or pr == "N" or ui == "N") and av != "P":
        eq1 = "1"
    else:
        eq1 = "2"
    eq2 = "0" if (_m(sel, "AC") == "L" and _m(sel, "AT") == "N") else "1"
    vc, vi, va = _m(sel, "VC"), _m(sel, "VI"), _m(sel, "VA")
    if vc == "H" and vi == "H":
        eq3 = "0"
    elif vc == "H" or vi == "H" or va == "H":
        eq3 = "1"
    else:
        eq3 = "2"
    if _m(sel, "MSI") == "S" or _m(sel, "MSA") == "S":
        eq4 = "0"
    elif _m(sel, "SC") == "H" or _m(sel, "SI") == "H" or _m(sel, "SA") == "H":
        eq4 = "1"
    else:
        eq4 = "2"
    eq5 = {"A": "0", "P": "1", "U": "2"}[str(_m(sel, "E"))]
    eq6 = "0" if ((_m(sel, "CR") == "H" and vc == "H") or (_m(sel, "IR") == "H" and vi == "H") or (_m(sel, "AR") == "H" and va == "H")) else "1"
    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6


def _extract(metric: str, max_vector: str) -> str:
    """Value of ``metric`` inside a composed max vector such as ``AV:N/PR:N/UI:N/AC:L/...`` (reference ``extractValueMetric``)."""
    for part in max_vector.split("/"):
        if part.startswith(metric + ":"):
            return part[len(metric) + 1:]
    raise KeyError(metric)


def _sub(a: Optional[float], b: Optional[float]) -> Optional[float]:
    return None if (a is None or b is None) else a - b          # None plays the reference's NaN: "there is no lower macro vector"


def score(vec: object) -> Optional[float]:
    """The CVSS v4.0 score (CVSS-B for a base vector, -BT / -BE / -BTE when threat or environmental metrics are present), or None."""
    sel = parse_vector(vec)
    if sel is None:
        return None
    if all(_m(sel, k) == "N" for k in ("VC", "VI", "VA", "SC", "SI", "SA")):          # no impact on the vulnerable or the subsequent system
        return 0.0
    mv = macro_vector(sel)
    value = LOOKUP[mv]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in mv)

    def look(a: int, b: int, c: int, d: int, e: int, f: int) -> Optional[float]:
        return LOOKUP.get("%d%d%d%d%d%d" % (a, b, c, d, e, f))

    s1, s2 = look(eq1 + 1, eq2, eq3, eq4, eq5, eq6), look(eq1, eq2 + 1, eq3, eq4, eq5, eq6)
    if eq3 == 1 and eq6 == 1:
        s36 = look(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 0 and eq6 == 1:
        s36 = look(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
    elif eq3 == 1 and eq6 == 0:
        s36 = look(eq1, eq2, eq3, eq4, eq5, eq6 + 1)
    elif eq3 == 0 and eq6 == 0:                                          # two lower neighbours: the one with the higher score
        left, right = look(eq1, eq2, eq3, eq4, eq5, eq6 + 1), look(eq1, eq2, eq3 + 1, eq4, eq5, eq6)
        s36 = left if (left is not None and right is not None and left > right) else right
    else:
        s36 = look(eq1, eq2, eq3 + 1, eq4, eq5, eq6 + 1)
    s4, s5 = look(eq1, eq2, eq3, eq4 + 1, eq5, eq6), look(eq1, eq2, eq3, eq4, eq5 + 1, eq6)

    # the highest-severity vectors of this macro vector, composed over the equivalence classes
    maxes = [MAX_COMPOSED["eq1"][eq1], MAX_COMPOSED["eq2"][eq2], MAX_COMPOSED["eq3"][eq3][eq6], MAX_COMPOSED["eq4"][eq4], MAX_COMPOSED["eq5"][eq5]]
    max_vectors: List[str] = [a + b + c + d + e for a in maxes[0] for b in maxes[1] for c in maxes[2] for d in maxes[3] for e in maxes[4]]
    dist: Dict[str, float] = {}
    for max_vector in max_vectors:                                       # the first one that is at least as severe as the vector in every metric
        dist = {k: _LEVELS[k][str(_m(sel, k))] - _LEVELS[k][_extract(k, max_vector)] for k in _LEVELS}
        if not any(d < 0 for d in dist.values()):
            break                                                        # (if none is, the last one is used, as in the reference)

    cur1 = dist["AV"] + dist["PR"] + dist["UI"]
    cur2 = dist["AC"] + dist["AT"]
    cur36 = dist["VC"] + dist["VI"] + dist["VA"] + dist["CR"] + dist["IR"] + dist["AR"]
    cur4 = dist["SC"] + dist["SI"] + dist["SA"]
    step = 0.1
    avail = [_sub(value, s1), _sub(value, s2), _sub(value, s36), _sub(value, s4), _sub(value, s5)]
    top = [MAX_SEVERITY["eq1"][eq1] * step, MAX_SEVERITY["eq2"][eq2] * step, MAX_SEVERITY["eq3eq6"][eq3][eq6] * step, MAX_SEVERITY["eq4"][eq4] * step]
    cur = [cur1, cur2, cur36, cur4]
    n_lower = 0
    normalized = [0.0] * 5
    for i in range(4):
        if avail[i] is not None:
            n_lower += 1
            normalized[i] = avail[i] * (cur[i] / top[i])
    if avail[4] is not None:                                              # EQ5 never moves the score by distance (its percentage is always 0)
        n_lower += 1
        normalized[4] = avail[4] * 0
    mean = 0 if n_lower == 0 else (normalized[0] + normalized[1] + normalized[2] + normalized[3] + normalized[4]) / n_lower
    value -= mean
    value = min(max(value, 0.0), 10.0)
    return math.floor(value * 10 + 0.5) / 10


def nomenclature(vec: object) -> str:
    """CVSS-B / CVSS-BT / CVSS-BE / CVSS-BTE: which metric groups the vector actually uses (a value other than X)."""
    sel = parse_vector(vec) or {}
    t = any(sel.get(k, "X") != "X" for k in _THREAT)
    e = any(sel.get(k, "X") != "X" for k in _ENV)
    return "CVSS-B" + ("T" if t else "") + ("E" if e else "")
