"""Decision coverage graph: which findings the recorded workflow already handles, and what is still open.

Concept credit: ARTEX (github.com/Autumn-27/ARTEX, AGPL-3.0) runs an autonomous test over two graphs - a shared, programmatically
computed asset graph and a per-task exploration graph whose findings are anchored to assets - and highlights tested vs untested
assets. The idea transfers to SBOM governance; no ARTEX code or text is used here, only the concept, reimplemented in this
repository's style (stdlib only, deterministic, fail-closed through triage.py).

Two layers, both computed from what is already recorded (nothing is invented):
  * nodes: components (name@version), advisories (id, severity, package) and the verified upgrade plans of the record;
  * lineage: every triage decision in the store is anchored to the advisory it decides on, with the state the fail-closed rules
    give it (``triage.decide``) - the derived-from evidence a VEX reviewer asks for ("which recorded action led to this verdict").
  * chains: per advisory the exploration lineage ``finding -> plan? -> decision? -> outcome`` - ARTEX keeps this per-task chain
    for attack steps; ours answers "how did the record get from the scan to this verdict" (each step only when evidence exists).

Verdict per advisory (the coverage): ``decided`` a standing human decision covers it; ``planned`` a verified upgrade plan clears it;
``rejected`` / ``expired`` a decision exists but the rules keep the finding open; ``unhandled`` nothing is recorded.

Honest bounds: ``unhandled`` does not mean unexamined - a reviewer may have looked without recording anything; a verdict never
implies reachability (the same rule as contextpack's import sites); and only decisions that stand under the triage rules count.
"""
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Tuple

from . import triage

SCHEMA = "bts-sbom.coverage.v1"
HONESTY = ["coverage counts only what is recorded: unhandled does not mean unexamined, and a verdict never implies reachability",
           "a verdict counts only when the fail-closed triage rules let the decision stand"]
VERDICTS = ("decided", "planned", "rejected", "expired", "unhandled")
_WORKLIST_MAX = 20


def _ids(v: Dict[str, Any]) -> set:
    return {str(x).upper() for x in [v.get("id")] + list(v.get("aliases") or []) + list(v.get("osv_ids") or []) if x}


def build(rec: Dict[str, Any], store: Optional[Dict[str, Any]], *, today: Optional[datetime.date] = None) -> Dict[str, Any]:
    """The coverage graph of one analysed record against one decision store (the same inputs ``vex``/``export_vex`` use)."""
    store = store or {}
    vulns = [v for v in rec.get("vulns") or [] if isinstance(v, dict)]
    plans = [p for p in rec.get("plans") or [] if p.get("status") == "upgrade" and p.get("safe_version")]
    cleared: Dict[str, List[str]] = {}
    for p in plans:
        for aid in p.get("clears") or []:
            cleared.setdefault(str(aid).upper(), []).append("%s -> %s" % (p["component"], p["safe_version"]))
    rows: List[Dict[str, Any]] = []
    lineage: List[Dict[str, Any]] = []
    chains: List[Dict[str, Any]] = []
    analysed_at = str(rec.get("analysed_at") or "")
    for v in vulns:
        d = triage.decide(v, store, today=today)
        if d:
            lineage.append({"advisory": str(v.get("id") or ""), "package": str(v.get("package") or ""), "key": d["key"],
                            "status": d["status"], "state": d["state"], "by": d["by"], "ts": d["ts"], "issue": d["issue"]})
        fixes = cleared.get(str(v.get("id") or "").upper()) or []
        if d and d["state"] in ("not_affected", "accepted"):
            verdict, issue = "decided", ""
        elif fixes:
            verdict, issue = "planned", ""
        elif d and d["state"] == "rejected":
            verdict, issue = "rejected", d["issue"]
        elif d and d["state"] == "expired":
            verdict, issue = "expired", d["issue"]
        else:
            verdict, issue = "unhandled", ""
        rows.append({"id": str(v.get("id") or ""), "package": str(v.get("package") or ""), "version": str(v.get("version") or ""),
                     "severity": str(v.get("severity") or "UNKNOWN"), "verdict": verdict, "decision": d["key"] if d else "",
                     "issue": issue, "fix": fixes[0] if fixes else ""})
        # the exploration lineage of one advisory (ARTEX's per-task chain, ours in SBOM terms): how the record got from
        # "the scan found this" to "here is why it is handled or still open" - each step only when the evidence exists.
        chain: List[Dict[str, Any]] = [{"step": "finding", "at": analysed_at,
                                        "detail": "reported by the scan (severity %s)" % (v.get("severity") or "UNKNOWN")}]
        if fixes:
            chain.append({"step": "plan", "at": "", "detail": "verified upgrade %s" % fixes[0]})
        if d:
            chain.append({"step": "decision", "at": d["ts"], "detail": "%s recorded as %s%s" % (
                d["key"], d["status"], (" by " + d["by"]) if d["by"] else "")})
        chain.append({"step": "outcome", "at": "", "detail": verdict + ((" - " + issue) if issue else "")})
        chains.append({"id": str(v.get("id") or ""), "package": str(v.get("package") or ""), "verdict": verdict, "chain": chain})
    comps: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for r in rows:
        c = comps.setdefault((r["package"], r["version"]), {"component": r["package"], "version": r["version"], "advisories": 0,
                                                            "verdicts": {k: 0 for k in VERDICTS}})
        c["advisories"] += 1
        c["verdicts"][r["verdict"]] += 1
    counts = {k: sum(1 for r in rows if r["verdict"] == k) for k in VERDICTS}
    worklist = [r for r in rows if r["verdict"] != "decided"]
    worklist.sort(key=lambda r: (r["verdict"] != "unhandled", r["id"]))      # nothing recorded first, then rejected/expired
    return {"schema": SCHEMA, "status": "OK" if rows else "NO_DATA", "name": str(rec.get("name") or ""), "advisories": len(rows),
            "components": len(comps), "verdicts": counts,
            "handled_pct": round(100 * (counts["decided"] + counts["planned"]) / len(rows), 1) if rows else None,
            "worklist": worklist[:_WORKLIST_MAX], "worklist_truncated": max(0, len(worklist) - _WORKLIST_MAX),
            "lineage": lineage, "chains": chains,
            "components_view": sorted(comps.values(), key=lambda c: (-c["verdicts"]["unhandled"], c["component"]))[:10],
            "honesty": HONESTY}


def compact(c: Dict[str, Any]) -> Dict[str, Any]:
    """The record-safe subset (the same shape the analysis record keeps for conformance/changes)."""
    return {k: c.get(k) for k in ("schema", "status", "name", "advisories", "components", "verdicts", "handled_pct",
                                  "worklist", "worklist_truncated", "honesty")}


def lines(c: Dict[str, Any]) -> List[str]:
    """The chat answer: the verdict counts, the worklist head, and what a verdict does not mean."""
    if c.get("status") != "OK":
        return ["No coverage to report: the record holds no advisories, so there is nothing a decision or a plan could cover."]
    v = c["verdicts"]
    out = ["Decision coverage of %s: %d advisories across %d components - %d decided, %d planned, %d rejected, %d expired, "
           "%d unhandled (%s%% handled)." % (c["name"], c["advisories"], c["components"], v["decided"], v["planned"], v["rejected"],
                                             v["expired"], v["unhandled"], c["handled_pct"])]
    for r in c["worklist"][:6]:
        out.append("%s [%s, %s]: %s%s%s." % (r["id"], r["severity"], r["package"], r["verdict"],
                                             (" - " + r["issue"]) if r["issue"] else "",
                                             ("; verified fix " + r["fix"]) if r.get("fix") else ""))
    if c["worklist_truncated"]:
        out.append("%d more finding(s) are on the worklist beyond these %d." % (c["worklist_truncated"], len(c["worklist"])))
    out.append("Coverage counts only what is recorded: unhandled does not mean unexamined, and a verdict never implies reachability.")
    return out


def to_md(c: Dict[str, Any]) -> str:
    """Markdown for the CLI: the verdict table, the worklist, and the decision lineage."""
    if c.get("status") != "OK":
        return "# Decision coverage\n\nNo advisories in this record - nothing to cover.\n"
    v = c["verdicts"]
    out = ["# Decision coverage of %s" % c["name"], "",
           "| advisories | decided | planned | rejected | expired | unhandled | handled |", "|---|---|---|---|---|---|---|",
           "| %d | %d | %d | %d | %d | %d | %s%% |" % (c["advisories"], v["decided"], v["planned"], v["rejected"], v["expired"],
                                                       v["unhandled"], c["handled_pct"]), "",
           "## Worklist (nothing recorded first, then decisions the rules keep open)", "",
           "| advisory | package | severity | verdict | why | recorded fix |", "|---|---|---|---|---|---|"]
    for r in c["worklist"]:
        out.append("| %s | %s %s | %s | %s | %s | %s |" % (r["id"], r["package"], r["version"], r["severity"], r["verdict"],
                                                           r["issue"] or "-", r["fix"] or "-"))
    if c["worklist_truncated"]:
        out.append("")
        out.append("%d more finding(s) beyond the %d listed." % (c["worklist_truncated"], _WORKLIST_MAX))
    if c["lineage"]:
        out += ["", "## Decision lineage (the recorded action each verdict is anchored to)", "",
                "| advisory | decision key | status | state | by | recorded at |", "|---|---|---|---|---|---|"]
        for l in c["lineage"]:
            out.append("| %s | %s | %s | %s | %s | %s |" % (l["advisory"], l["key"], l["status"], l["state"], l["by"] or "-", l["ts"] or "-"))
    out += ["", "> " + "; ".join(HONESTY) + "."]
    return "\n".join(out) + "\n"
