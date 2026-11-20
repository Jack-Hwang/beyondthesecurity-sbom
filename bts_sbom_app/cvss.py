"""CVSS v3.x base score from a vector string (FIRST CVSS v3.1 specification, section 7.1), stdlib only.

CVSS v4.0 vectors are scored by ``cvss4.py`` (FIRST's reference tables); ``severity_of`` prefers the v3 score unless told to prefer v4
(``prefer="v4"`` or ``BTS_SBOM_CVSS_PREFER=v4``, which is what FOSSLight Hub does), and falls back to the advisory's own severity label
when no vector can be scored. The record says which one it used (``score_source``) and keeps both scores when an advisory has both.
"""
from __future__ import annotations

import math
import os
from typing import Dict, Optional, Tuple

from . import cvss4

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


def scores_of(osv_vuln: dict) -> Dict[str, Optional[float]]:
    """{"v3": best v3.x base score, "v4": best v4.0 score} over the record's severity vectors (None where there is none)."""
    out: Dict[str, Optional[float]] = {"v3": None, "v4": None}
    for s in osv_vuln.get("severity") or []:
        vec = s.get("score", "") if isinstance(s, dict) else ""
        for key, fn in (("v3", base_score_v3), ("v4", cvss4.score)):
            sc = fn(vec)
            if sc is not None and (out[key] is None or sc > out[key]):
                out[key] = sc
    return out


def severity_of(osv_vuln: dict, prefer: Optional[str] = None) -> Tuple[str, Optional[float], str]:
    """(label, score, source) for one OSV record. Order: preferred vector version (v3 unless ``prefer``/BTS_SBOM_CVSS_PREFER says v4)
    -> the other version -> advisory label -> UNKNOWN (never guessed)."""
    sc = scores_of(osv_vuln)
    pref = str(prefer or os.environ.get("BTS_SBOM_CVSS_PREFER") or "v3").lower()
    for key in (("v4", "v3") if pref == "v4" else ("v3", "v4")):
        if sc[key] is not None:
            return label(sc[key]), sc[key], "cvss_%s_vector" % key
    lab = str((osv_vuln.get("database_specific") or {}).get("severity") or "").upper()
    if lab in _LABELS:
        return _LABELS[lab], None, "advisory_label"
    return "UNKNOWN", None, "none"
