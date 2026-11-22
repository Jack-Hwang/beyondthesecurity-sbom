"""DMN-style decision table engine - the natively reimplemented core of what Enterprise Architect 17.2 ships as
its DMN decision model / "DMN-Sim" lane (REA evidence: DMN-Sim workspaces, DMNTagActionTool.xml, BPMN+DMN example
models inside easetup_x64.msi, ProductVersion 17.2.1721.15). A decision table is the same artefact DMN standardises:
inputs on the left, outputs on the right, one row per rule, a hit policy saying how the fired rules collapse into
one answer. The evaluation is a real inference run: measured facts in, one chosen action out, with a trace saying
which rule fired and why - never a model-written opinion.

Determinism: the same table and the same facts always produce the same verdict and the same trace. No LLM, no
sampling, no network. ``facts_from_record``-style enrichment belongs to the callers (diagrams.py / chat.py), so
this module stays pure: tables in, verdicts out.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# severity ranks so ">= high" compares labels the way CVSS bands do (UNKNOWN never satisfies an upper bound)
_SEV_RANK = {"unknown": 0, "none": 0, "low": 1, "moderate": 2, "medium": 2, "high": 3, "critical": 4}

_HIT_POLICIES = ("U", "F", "P", "A", "R")


class Rule:
    __slots__ = ("rid", "conditions", "outputs", "priority", "annotation")

    def __init__(self, rid: str, conditions: Dict[str, str], outputs: Dict[str, Any],
                 priority: int = 0, annotation: str = "") -> None:
        self.rid = rid
        self.conditions = conditions
        self.outputs = outputs
        self.priority = priority
        self.annotation = annotation


class DecisionTable:
    __slots__ = ("name", "hit_policy", "inputs", "outputs", "rules", "default_outputs")

    def __init__(self, name: str, inputs: Dict[str, str], outputs: Dict[str, str], rules: List[Rule],
                 hit_policy: str = "F", default_outputs: Optional[Dict[str, Any]] = None) -> None:
        if hit_policy not in _HIT_POLICIES:
            raise ValueError("hit policy must be one of %s" % ", ".join(_HIT_POLICIES))
        self.name = name
        self.hit_policy = hit_policy
        self.inputs = inputs
        self.outputs = outputs
        self.rules = rules
        self.default_outputs = default_outputs or {}


def _rank(value: Any) -> Optional[int]:
    if isinstance(value, (int, float)):
        return None
    s = str(value).strip().lower()
    if s in _SEV_RANK:
        return _SEV_RANK[s]
    return None


def _literal(tok: str) -> Any:
    tok = tok.strip().strip("'\"")
    try:
        return int(tok)
    except ValueError:
        pass
    try:
        return float(tok)
    except ValueError:
        pass
    if tok.lower() == "true":
        return True
    if tok.lower() == "false":
        return False
    return tok


def _cmp(a: Any, op: str, b: Any) -> bool:
    ra, rb = _rank(a), _rank(b)
    if ra is not None and rb is not None:          # severity labels compare by band rank
        a, b = ra, rb
    elif isinstance(a, (int, float)) and isinstance(b, (int, float)):
        pass
    else:
        a, b = str(a).lower(), str(b).lower()
    if op == ">":
        return a > b
    if op == ">=":
        return a >= b
    if op == "<":
        return a < b
    if op == "<=":
        return a <= b
    if op == "==":
        return a == b
    if op == "!=":
        return a != b
    raise ValueError("unknown comparison %r" % op)


_COND_RX = re.compile(r"^\s*(>=|<=|==|!=|>|<)\s*(.+)$")


def _condition_ok(fact: Any, expr: str) -> bool:
    """One condition cell. Grammar: ``*``/``-``/empty (always - the DMN don't-care cell) |
    ``(>=|<=|==|!=|>|<) literal`` | ``in(a, b, ...)`` | ``contains x`` | bare literal (equality, so a cell
    holding ``true``/``false`` tests the boolean value, it does not mean "always"). An absent fact satisfies
    nothing - a missing input never silently matches."""
    e = (expr or "").strip()
    if e in ("", "*", "-"):
        return True
    m = _COND_RX.match(e)
    if m:
        return fact is not None and _cmp(fact, m.group(1), _literal(m.group(2)))
    low = e.lower()
    if low.startswith("in(") and e.endswith(")"):
        if fact is None:
            return False
        items = [_literal(x) for x in e[3:-1].split(",")]
        fs = str(fact).strip().lower()
        return any(str(x).lower() == fs for x in items)
    if low.startswith("contains"):
        if fact is None:
            return False
        needle = _literal(e[len("contains"):])
        if isinstance(fact, (list, tuple)):
            return any(str(x).lower() == str(needle).lower() for x in fact)
        return str(needle).lower() in str(fact).lower()
    return fact is not None and _cmp(fact, "==", _literal(e))


def evaluate(table: DecisionTable, facts: Dict[str, Any]) -> Dict[str, Any]:
    """Run the table against measured facts. Verdict: decided (one answer), conflict (U table with 2+ fired
    rules - the table itself is wrong, reported not resolved), none (no rule fired -> default outputs or none).
    The trace names every rule's matching result, including the facts each rule was missing."""
    matched: List[Rule] = []
    trace: List[Dict[str, Any]] = []
    for r in table.rules:
        ok = True
        missing: List[str] = []
        for key, expr in r.conditions.items():
            fact = facts.get(key)
            if fact is None:
                missing.append(key)
            if not _condition_ok(fact, expr):
                ok = False
                break
        if ok and not missing:
            matched.append(r)
        trace.append({"rule": r.rid, "matched": bool(ok and not missing),
                      "missing_inputs": missing, "priority": r.priority})
    outputs: Optional[Dict[str, Any]] = None
    chosen: List[str] = []
    verdict = "none"
    if len(matched) == 1:
        outputs, chosen, verdict = dict(matched[0].outputs), [matched[0].rid], "decided"
    elif len(matched) > 1:
        if table.hit_policy in ("F", "R"):                      # first match in declared order wins
            first = min(matched, key=lambda r: table.rules.index(r))
            outputs, chosen, verdict = dict(first.outputs), [first.rid], "decided"
        elif table.hit_policy == "P":                           # highest priority wins; tie -> first declared
            best = min(matched, key=lambda r: (-r.priority, table.rules.index(r)))
            outputs, chosen, verdict = dict(best.outputs), [best.rid], "decided"
        elif table.hit_policy == "A":                           # any: all fired rules must agree on the outputs
            agree = all(r.outputs == matched[0].outputs for r in matched[1:])
            if agree:
                outputs, chosen, verdict = dict(matched[0].outputs), [r.rid for r in matched], "decided"
            else:
                chosen, verdict = [r.rid for r in matched], "conflict"
        else:                                                   # U: uniqueness violated - the table is wrong
            chosen, verdict = [r.rid for r in matched], "conflict"
    elif table.default_outputs:
        outputs, verdict = dict(table.default_outputs), "default"
    return {"table": table.name, "hit_policy": table.hit_policy, "verdict": verdict,
            "matched": chosen, "outputs": outputs, "trace": trace}


def table_lines(table: DecisionTable, limit: int = 12) -> List[str]:
    """The table as chat-readable lines: input columns | output columns, one line per rule."""
    in_keys = list(table.inputs)
    out_keys = list(table.outputs)
    head = "[%s] decision table %s (hit policy %s): %s -> %s" % (
        "DMN-lite", table.name, table.hit_policy, ", ".join(in_keys), ", ".join(out_keys))
    rows = [head]
    for r in table.rules[:limit]:
        cond = "; ".join("%s %s" % (k, r.conditions.get(k, "*")) for k in in_keys)
        outs = "; ".join("%s=%s" % (k, r.outputs.get(k)) for k in out_keys)
        rows.append("  %s: if %s then %s" % (r.rid, cond or "*", outs))
    if len(table.rules) > limit:
        rows.append("  ... %d more rules not shown" % (len(table.rules) - limit))
    return rows


# ------------------------------------------------------------------------- the product's own remediation policy
def remediation_policy() -> DecisionTable:
    """Our engineering policy for what to do about one finding, as a first-match decision table. The table is
    OURS (this tool's documented defaults, same thresholds the triage lane enforces); the facts are the project's
    measured ones. Editing the table changes only what this tool recommends - never what it measured."""
    return DecisionTable(
        name="remediation-policy",
        hit_policy="F",
        inputs={"severity": "LOW|MEDIUM|HIGH|CRITICAL", "malicious": "true|false",
                "license_category": "permissive|weak-copyleft|copyleft|unknown|none",
                "distribution": "binary|saas|internal", "fixed_available": "true|false"},
        outputs={"action": "what to do", "priority": "P0..P5"},
        rules=[
            Rule("R1", {"malicious": "true"}, {"action": "quarantine: remove or pin away the package immediately, then report", "priority": "P0"}, 5),
            Rule("R2", {"severity": ">=critical", "fixed_available": "true"}, {"action": "patch now: upgrade to the fixed version this release window", "priority": "P1"}, 4),
            Rule("R3", {"severity": ">=high", "license_category": "copyleft", "distribution": "binary"}, {"action": "patch now AND open a license review (copyleft shipped in binary)", "priority": "P1"}, 4),
            Rule("R4", {"severity": ">=high"}, {"action": "plan the patch: put the fix on the next train", "priority": "P2"}, 3),
            Rule("R5", {"severity": ">=medium", "license_category": "unknown"}, {"action": "investigate the license before shipping; fix may ride along", "priority": "P3"}, 2),
            Rule("R6", {"severity": ">=medium"}, {"action": "schedule the fix; track it in the worklist", "priority": "P3"}, 2),
            Rule("R7", {"license_category": "copyleft", "distribution": "binary"}, {"action": "license review before distribution", "priority": "P4"}, 1),
            Rule("R8", {}, {"action": "monitor: no action this window", "priority": "P5"}, 0),
        ],
        default_outputs={"action": "monitor: no rule matched (facts were incomplete)", "priority": "P5"},
    )
