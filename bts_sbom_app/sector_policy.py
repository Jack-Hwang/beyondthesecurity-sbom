"""Sector policy starter presets (task 28, brief 2) - stdlib only.

EXACTLY the 5 seeded presets from the brief, with the basis text saying they are EXAMPLE values chosen by the
tool author - NOT regulation requirements. `resolve` merges a preset over licenses.DEFAULT_POLICY; a user file
`<evidence>/policy_presets.json` can override or add presets (invalid entries are rejected with a reason).
`--policy FILE` and `--sector-policy NAME` are mutually exclusive; no preset means the default policy, exactly
as before.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from . import licenses

BASIS = "starter-template (example values chosen by the tool author, not a regulation)"

PRESETS: Dict[str, Dict[str, Any]] = {
    "finance": {"distribution": "saas", "deny": ["network-copyleft", "restricted"],
                "review": ["strong-copyleft", "weak-copyleft", "unknown"], "eol_tolerance": "review"},
    "defense": {"distribution": "binary", "deny": ["network-copyleft", "restricted", "strong-copyleft"],
                "review": ["weak-copyleft", "unknown"], "eol_tolerance": "fail"},
    "maritime": {"distribution": "binary", "deny": ["network-copyleft", "restricted"],
                 "review": ["strong-copyleft", "weak-copyleft", "unknown"], "eol_tolerance": "review"},
    "automotive": {"distribution": "binary", "deny": ["network-copyleft", "restricted"],
                   "review": ["strong-copyleft", "weak-copyleft", "unknown"], "eol_tolerance": "fail"},
    "medical": {"distribution": "binary", "deny": ["network-copyleft", "restricted"],
                "review": ["strong-copyleft", "weak-copyleft", "unknown"], "eol_tolerance": "fail"},
}

REQUIRED_KEYS = ("distribution", "deny", "review", "eol_tolerance")
USER_FILE = "policy_presets.json"


def _validate(preset: Dict[str, Any], name: str) -> Optional[str]:
    """A reason string when the preset is unusable, else None."""
    for k in REQUIRED_KEYS:
        if k not in preset:
            return "%s: missing %s" % (name, k)
    if preset["distribution"] not in ("binary", "saas", "internal"):
        return "%s: distribution must be binary/saas/internal" % name
    if preset["eol_tolerance"] not in ("fail", "review", "ignore"):
        return "%s: eol_tolerance must be fail/review/ignore" % name
    for k in ("deny", "review"):
        if not isinstance(preset[k], list) or any(not isinstance(x, str) for x in preset[k]):
            return "%s: %s must be a list of strings" % (name, k)
    return None


def user_presets(evidence: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Validated overrides from <evidence>/policy_presets.json (empty when absent/unreadable)."""
    return user_presets_with_reasons(evidence)[0]


def user_presets_with_reasons(evidence: Optional[str] = None):
    """(valid presets, [rejection reasons]) from <evidence>/policy_presets.json; invalid entries are refused with a reason."""
    if not evidence:
        return {}, []
    path = os.path.join(evidence, USER_FILE)
    if not os.path.isfile(path):
        return {}, []
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return {}, []
    out: Dict[str, Dict[str, Any]] = {}
    reasons: list = []
    for name, preset in (data.get("presets") or {}).items() if isinstance(data, dict) else []:
        why = _validate(preset, str(name))
        if why is None:
            out[str(name)] = preset
        else:
            reasons.append(why)
    return out, reasons


def resolve(name: str, *, evidence: Optional[str] = None) -> Dict[str, Any]:
    """Effective policy = DEFAULT_POLICY merged with the preset (user file overrides win), plus the basis text.
    An invalid user preset raises its validation reason; an unknown name lists the 5 known presets."""
    valid, reasons = user_presets_with_reasons(evidence)
    if name in valid:
        eff = dict(licenses.DEFAULT_POLICY)
        eff.update(valid[name])
    elif name in PRESETS:
        eff = dict(licenses.DEFAULT_POLICY)
        eff.update(PRESETS[name])
    else:
        bad = next((r for r in reasons if r.startswith("%s:" % name)), None)
        if bad:
            raise ValueError(bad)
        known = sorted(set(PRESETS) | set(valid))
        raise ValueError("unknown sector policy preset %r (known presets: %s)" % (name, ", ".join(known)))
    eff["basis"] = BASIS
    eff["sector"] = name
    return eff


def basis_line(effective: Dict[str, Any]) -> str:
    """One line summarising the effective policy used (for scan/obligations/legacy output)."""
    sector = effective.get("sector") or "default"
    return "effective policy: sector=%s distribution=%s deny=%s review=%s eol_tolerance=%s | %s" % (
        sector, effective.get("distribution"), effective.get("deny"), effective.get("review"),
        effective.get("eol_tolerance") or "n/a", effective.get("basis") or BASIS)
