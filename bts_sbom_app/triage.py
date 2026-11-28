"""Accountable triage: human decisions about findings, turned into OpenVEX statements - fail-closed.

Why (FOSSLight Community Day 2026, Hub's vulnerability handling): Hub lets owners correct what the matcher got wrong (version
alias, Include / Exclude CPE) and requires a REASON before security mail can be disabled. The same lesson applies to an SBOM
workflow: "ignore" decisions must carry a reason, an owner and an end date, and an exported VEX must never claim more than the
evidence supports. Before this module the web console stored decisions in ``.triage.json`` but they never reached the OpenVEX
document (documented gap).

Decision store (compatible with the existing console file): ``{key: {status, note, ts, [justification, expires, scope, by]}}``.
``key`` is an advisory id or alias (``CVE-2020-1111``), optionally scoped to one package with ``ID@package`` (a purl prefix such
as ``CVE-2020-1111@pkg:pypi/requests`` works too); the ``scope`` field does the same. A scoped decision beats a global one.

Fail-closed rules (every refusal is reported, never silent):
  * ``false-positive`` becomes VEX ``not_affected`` only with a justification from the OpenVEX list AND a reason of at least
    10 characters; otherwise the finding stays ``affected`` and the statement says why (``state: rejected``);
  * ``accepted`` / ``wontfix`` stay ``affected`` in VEX (OpenVEX has no accepted-risk status); the acceptance, its owner and its end
    date go into the action statement; without a reason it is rejected;
  * ``fixed`` is believed only when the scan no longer reports the finding - a finding the scan still reports keeps ``affected``;
  * a decision past its ``expires`` date no longer applies (``state: expired``) and the finding is open again;
  * the model never creates a decision: ``review_candidates`` only LISTS findings worth a human look (never a suggested ``not_affected``).
"""
from __future__ import annotations

import datetime
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import audit, engine, pii_guard

STATUSES = ("open", "accepted", "wontfix", "false-positive", "fixed")
JUSTIFICATIONS = ("component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist")
MIN_REASON = 10
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _today(today: Optional[datetime.date]) -> datetime.date:
    return today or datetime.date.today()


def parse_date(v: Any) -> Optional[datetime.date]:
    if not isinstance(v, str) or not _DATE.match(v.strip()):
        return None
    try:
        return datetime.date.fromisoformat(v.strip()[:10])
    except ValueError:
        return None


def check_extras(justification: Any = None, expires: Any = None, scope: Any = None, by: Any = None) -> Optional[str]:
    """None when the optional decision fields are acceptable, else the reason (the service answers 400 with it)."""
    if justification not in (None, "") and justification not in JUSTIFICATIONS:
        return "justification must be one of %s" % ", ".join(JUSTIFICATIONS)
    if expires not in (None, "") and parse_date(expires) is None:
        return "expires must be a date YYYY-MM-DD"
    if scope not in (None, "") and (not isinstance(scope, str) or len(scope) > 200 or re.search(r"\s", scope)):
        return "scope must be a package name or purl prefix without spaces, at most 200 characters"
    if by not in (None, "") and (not isinstance(by, str) or len(by) > 80):
        return "by must be a string of at most 80 characters"
    return None


def _ids(v: Dict[str, Any]) -> set:
    return {str(x).upper() for x in [v.get("id")] + list(v.get("aliases") or []) + list(v.get("osv_ids") or []) if x}


def _scope_ok(scope: str, v: Dict[str, Any]) -> bool:
    s = scope.strip().lower()
    if not s:
        return True
    if s.startswith("pkg:"):
        return str(v.get("purl") or "").lower().startswith(s)
    return engine._canon(str(v.get("ecosystem") or ""), s) == engine._canon(str(v.get("ecosystem") or ""), str(v.get("package") or ""))


def _split_key(key: str, entry: Dict[str, Any]) -> Tuple[str, str]:
    k, scope = (key.split("@", 1) + [""])[:2] if "@" in key else (key, "")
    return k.strip().upper(), (str(entry.get("scope") or "") or scope).strip()


def _find(store: Dict[str, Any], v: Dict[str, Any]) -> Optional[Tuple[str, Dict[str, Any]]]:
    ids = _ids(v)
    best: Optional[Tuple[int, str, Dict[str, Any]]] = None
    for key, entry in (store or {}).items():
        if not isinstance(entry, dict):
            continue
        k, scope = _split_key(str(key), entry)
        if k in ids and _scope_ok(scope, v):
            rank = len(scope)                                    # a scoped decision beats a global one; longer scope beats shorter
            if best is None or rank > best[0]:
                best = (rank, str(key), entry)
    return (best[1], best[2]) if best else None


def decide(v: Dict[str, Any], store: Dict[str, Any], *, today: Optional[datetime.date] = None) -> Optional[Dict[str, Any]]:
    """The decision that applies to one finding, or None when nobody decided anything about it."""
    hit = _find(store, v)
    if hit is None:
        return None
    key, e = hit
    status, note = str(e.get("status") or "open"), str(e.get("note") or "").strip()
    note, _ = pii_guard.redact(note)  # PII/secret-shaped substrings never reach the VEX statements or the stored decision
    exp, by = parse_date(e.get("expires")), str(e.get("by") or "").strip()
    d: Dict[str, Any] = {"key": key, "status": status, "state": "open", "vex": "affected", "justification": e.get("justification") or "",
                         "note": note, "expires": exp.isoformat() if exp else "", "by": by, "ts": e.get("ts") or "", "issue": ""}
    if exp and exp < _today(today):
        d.update(state="expired", issue="decision expired on %s: the finding is open again" % exp.isoformat())
        return d
    if status == "false-positive":
        if e.get("justification") in JUSTIFICATIONS and len(note) >= MIN_REASON:
            d.update(state="not_affected", vex="not_affected")
        else:
            d.update(state="rejected", issue="false-positive needs a VEX justification (%s) and a reason of at least %d characters; the finding stays affected"
                     % ("|".join(JUSTIFICATIONS), MIN_REASON))
    elif status in ("accepted", "wontfix"):
        if len(note) >= MIN_REASON:
            d.update(state="accepted")
        else:
            d.update(state="rejected", issue="a risk acceptance needs a reason of at least %d characters; the finding stays affected" % MIN_REASON)
    elif status == "fixed":
        d.update(state="rejected", issue="marked fixed, but the scan still reports this finding; re-scan after the change to confirm")
    return d


def apply_to_statement(st: Dict[str, Any], d: Dict[str, Any]) -> Dict[str, Any]:
    """Refine one OpenVEX statement (built as ``affected``) with the decision that applies to its finding."""
    if d["state"] == "not_affected":
        st["status"] = "not_affected"
        st["justification"] = d["justification"]
        st["impact_statement"] = d["note"] + ((" (decided by %s)" % d["by"]) if d["by"] else "")
        st.pop("action_statement", None)
    elif d["state"] == "accepted":
        st["action_statement"] = "Risk accepted%s%s: %s. %s" % ((" by " + d["by"]) if d["by"] else "", (" until " + d["expires"]) if d["expires"] else "", d["note"],
                                                                st.get("action_statement") or "")
        st["action_statement"] = st["action_statement"].strip()
    elif d["issue"]:
        st["status_notes"] = d["issue"]
    return st


def evaluate(vulns: Iterable[Dict[str, Any]], store: Dict[str, Any], *, today: Optional[datetime.date] = None) -> Dict[str, Any]:
    """Apply the store to the findings: annotated findings, counts per state, and the decisions that match nothing (stale)."""
    findings: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {"undecided": 0, "open": 0, "not_affected": 0, "accepted": 0, "rejected": 0, "expired": 0}
    used = set()
    for v in vulns:
        d = decide(v, store, today=today)
        f = dict(v)
        if d is None:
            counts["undecided"] += 1
        else:
            f["triage"] = d
            counts[d["state"]] += 1
            used.add(d["key"])
        findings.append(f)
    stale = sorted(k for k in (store or {}) if k not in used)
    return {"findings": findings, "counts": counts, "stale": stale,
            "rejected": [{"id": f["id"], "package": f["package"], "issue": f["triage"]["issue"]} for f in findings if f.get("triage", {}).get("state") == "rejected"],
            "expired": [{"id": f["id"], "package": f["package"], "expires": f["triage"]["expires"]} for f in findings if f.get("triage", {}).get("state") == "expired"]}


_DEV_WHY = "dev-only dependency: it is not part of the shipped product unless this SBOM describes the build environment"
_RANGE_WHY = "the advisory matched this package but no ECOSYSTEM/SEMVER range of it confirms that this exact version is inside the affected range"


def review_candidates(rec: Dict[str, Any], store: Optional[Dict[str, Any]] = None, *, today: Optional[datetime.date] = None) -> List[Dict[str, Any]]:
    """Findings whose match is weaker than the rest - a worklist for a human, never an automatic verdict.

    Reasons (deterministic): ``range_unconfirmed`` (matched without a confirming version range) and ``dev_only`` (the component is a
    dev dependency). Findings with a standing decision (not_affected / accepted) are left out."""
    scopes = {(str(c.get("ecosystem") or "").lower(), engine._canon(str(c.get("ecosystem") or ""), str(c.get("name") or "")), str(c.get("version") or "")): c.get("scope")
              for c in rec.get("components") or []}
    out: List[Dict[str, Any]] = []
    for v in rec.get("vulns") or []:
        d = decide(v, store or {}, today=today)
        if d and d["state"] in ("not_affected", "accepted"):
            continue
        reasons: List[str] = []
        if v.get("affects_confirmed") is False and not v.get("malicious"):
            reasons.append("range_unconfirmed")
        sc = scopes.get((str(v.get("ecosystem") or "").lower(), engine._canon(str(v.get("ecosystem") or ""), str(v.get("package") or "")), str(v.get("version") or "")))
        if isinstance(sc, dict) and sc.get("dev") is True:
            reasons.append("dev_only")
        if reasons:
            out.append({"id": v["id"], "package": v["package"], "version": v["version"], "severity": v.get("severity"), "reasons": reasons,
                        "why": [{"range_unconfirmed": _RANGE_WHY, "dev_only": _DEV_WHY}[r] for r in reasons],
                        "next_step": "check the evidence, then record a decision with a reason (and a VEX justification for a false positive)"})
    return out



# --------------------------------------------------------------------------- audit sampling (BSA-AC-118x)
def closed_decisions(evaluated: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Findings out of ``evaluate()``'s ``findings`` whose triage decision is CLOSED (``not_affected`` or
    ``accepted``) - the decisions an audit should re-review. A finding that is ``open`` / ``rejected`` /
    ``expired`` (or undecided - no ``triage`` key at all) is not closed and is left out."""
    return [f for f in evaluated.get("findings") or [] if (f.get("triage") or {}).get("state") in ("not_affected", "accepted")]


def stratified_audit(vulns: Iterable[Dict[str, Any]], store: Dict[str, Any], *, seed: int = 0, margin: float = 0.1,
                      confidence: float = 0.9, today: Optional[datetime.date] = None) -> Dict[str, Any]:
    """A stratified re-review sample of CLOSED triage/VEX decisions (``not_affected`` / ``accepted``), grouped by
    severity lane (the finding's own ``severity`` label: CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN/...). Each lane is sized
    by ``audit.sample_size`` (normal-approximation + finite-population correction) rather than a flat fraction - a
    lane of 3 closed decisions and a lane of 300 do not need the same share reviewed to say something with the
    same confidence. Deterministic (the same ``seed`` draws the same decisions from a lane whose membership has
    not changed); an empty lane samples 0.

    Returns ``{seed, margin, confidence, lanes, closed_total, by_lane: {lane: closed_count},
    sampled: {lane: sampled_count}, queue: [finding, ...]}`` - ``queue`` holds the sampled findings themselves
    (shallow copies, plus ``audit_reason``), ready to hand to a reviewer.
    """
    def _lane_key(f: Dict[str, Any]) -> str:
        return str(f.get("severity") or "UNKNOWN")

    ev = evaluate(vulns, store, today=today)
    closed = closed_decisions(ev)
    by_lane = {lane: len(items) for lane, items in audit.group_by(closed, _lane_key).items()}
    sample = audit.stratified_sample(closed, _lane_key, size_fn=lambda n: audit.sample_size(n, margin=margin, confidence=confidence), seed=seed)
    queue = [dict(f, audit_reason="stratified re-review sample of severity lane %r (closed decisions, seed %s)" % (lane, seed))
             for lane, items in sorted(sample.items()) for f in items]
    return {"seed": seed, "margin": margin, "confidence": confidence, "lanes": sorted(by_lane), "closed_total": len(closed),
            "by_lane": by_lane, "sampled": {k: len(v) for k, v in sample.items()}, "queue": queue}


__all__ = ["STATUSES", "JUSTIFICATIONS", "decide", "evaluate", "apply_to_statement", "review_candidates", "check_extras", "parse_date", "MIN_REASON",
           "closed_decisions", "stratified_audit"]


# ------------------------------------------------------------------ C64: triage corrections as eval candidates
def eval_candidates(triage_path: str, *, min_reason_chars: int = 20) -> dict:
    """The human triage corrections as EVAL CANDIDATES (backlog C64; report-only, same contract as the escalation
    feed): one row per recorded decision whose reason carries the minimum substance (the advisory id, the status,
    the human's reason and who decided); a thin or anonymous entry counts as skipped, never as a row. Importing
    them into evals/ is a deliberate human step - never an automatic rewrite of a golden set."""
    import json as _json
    import os as _os
    rows, skipped = [], 0
    try:
        store = _json.load(open(triage_path, encoding="utf-8"))
    except (OSError, ValueError):
        store = {}
    for key, entry in (store or {}).items():
        if not isinstance(entry, dict):
            continue
        adv, scope = _split_key(str(key), entry)
        reason = str(entry.get("reason") or entry.get("justification") or "").strip()
        by = entry.get("by")
        if len(reason) >= min_reason_chars and by:
            rows.append({"id": adv, "status": str(entry.get("status") or ""), "scope": scope,
                         "reason": reason, "by": str(by)[:40], "kind": "triage_correction"})
        else:
            skipped += 1
    return {"candidates": rows, "skipped": skipped,
            "report_only": "importing into evals/ is a deliberate human step - never an automatic rewrite of a golden set"}
