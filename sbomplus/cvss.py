"""CVSS v3.x base score from a vector string (FIRST CVSS v3.1 specification, section 7.1), stdlib only.

CVSS v4.0 vectors are NOT scored here (the v4 macro-vector lookup is out of scope); callers fall back to the
advisory's own severity label and the record says so (``score_source``).
"""
from __future__ import annotations

import math
from typing import Dict, Optional, Tuple

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vec: str) -> Dict[str, str]:
    parts = str(vec or "").split("/")
    out: Dict[str, str] = {}
    for p in parts[1:]:
        if ":" in p:
            k, v = p.split(":", 1)
            out[k] = v
    return out


def base_score_v3(vec: str) -> Optional[float]:
    if not str(vec or "").startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    m = parse_vector(vec)
    try:
        scope_changed = m["S"] == "C"
        av, ac, ui = _AV[m["AV"]], _AC[m["AC"]], _UI[m["UI"]]
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    expl = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + expl), 10)) if scope_changed else _roundup(min(impact + expl, 10))


def label(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


_LABELS = {"LOW": "LOW", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}


def severity_of(osv_vuln: dict) -> Tuple[str, Optional[float], str]:
    """(label, score, source) for one OSV record. Order: v3 vector -> advisory label -> UNKNOWN (never guessed)."""
    best: Optional[float] = None
    for s in osv_vuln.get("severity") or []:
        sc = base_score_v3(s.get("score", "")) if isinstance(s, dict) else None
        if sc is not None and (best is None or sc > best):
            best = sc
    if best is not None:
        return label(best), best, "cvss_v3_vector"
    lab = str((osv_vuln.get("database_specific") or {}).get("severity") or "").upper()
    if lab in _LABELS:
        return _LABELS[lab], None, "advisory_label"
    return "UNKNOWN", None, "none"
