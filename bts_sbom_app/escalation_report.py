"""Escalation roll-up report (backlog C52 + C43): the chat handoff log already records every escalation as an
append-only event stream (``escalation.py``), but nothing ever reads it back as a MEASURED health signal — how
often each trigger fires, how fast the queue drains, how long the oldest open handoff has been waiting.

Honesty rules (the app's contract):
  * the report is computed from the event fold only; an unparsable timestamp is a ``skipped`` count, never an
    invented duration;
  * empty log -> empty report with status ``no_data``, not zeros that look like a healthy queue;
  * a report-only surface: it gates nothing by itself — the loop gate decides what to do with the numbers.
"""
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional

from . import escalation

SCHEMA = "bts-sbom.escalation-report.v1"


def _parse_ts(s: Any) -> Optional[datetime.datetime]:
    try:
        t = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return None


def _minutes(a: datetime.datetime, b: datetime.datetime) -> float:
    return round((b - a).total_seconds() / 60.0, 1)


def _median(xs: List[float]) -> Optional[float]:
    if not xs:
        return None
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else round((s[n // 2 - 1] + s[n // 2]) / 2, 1)


def report(evidence: str, *, now: Optional[Any] = None) -> Dict[str, Any]:
    """Aggregate the escalation store: totals, per trigger and per kind rates, the open queue (depth and oldest
    wait) and the resolution-time distribution (mean and median minutes)."""
    nowt = _parse_ts(now) or datetime.datetime.now(datetime.timezone.utc)
    state = escalation.load(evidence)
    out: Dict[str, Any] = {"schema": SCHEMA, "totals": {"open": 0, "resolved": 0, "skipped": 0},
                           "by_trigger": {}, "by_kind": {}, "by_destination": {}, "by_project": {},
                           "open_queue": {"depth": 0, "oldest_wait_minutes": None},
                           "resolution": {"count": 0, "mean_minutes": None, "median_minutes": None},
                           "note": "report-only roll-up over the append-only escalation events; a gate decision is the caller's"}
    if not state:
        return dict(out, status="no_data", reason="no escalation events recorded")
    out["status"] = "OK"
    resolutions: List[float] = []
    for row in state.values():
        p = row.get("payload") or {}
        out["totals"]["open" if row.get("status") == "open" else "resolved"] += 1
        trig = str(p.get("trigger") or "unknown")
        out["by_trigger"][trig] = out["by_trigger"].get(trig, 0) + 1
        kind = str(p.get("kind") or "unknown")
        out["by_kind"][kind] = out["by_kind"].get(kind, 0) + 1
        dest = str(p.get("destination") or "unknown")
        out["by_destination"][dest] = out["by_destination"].get(dest, 0) + 1
        proj = str(p.get("project") or "-")
        out["by_project"][proj] = out["by_project"].get(proj, 0) + 1
        opened = _parse_ts(row.get("opened_at"))
        resolved = _parse_ts(row.get("resolved_at"))
        if row.get("status") == "open":
            out["open_queue"]["depth"] += 1
            if opened:
                wait = _minutes(opened, nowt)
                if out["open_queue"]["oldest_wait_minutes"] is None or wait > out["open_queue"]["oldest_wait_minutes"]:
                    out["open_queue"]["oldest_wait_minutes"] = wait
            else:
                out["totals"]["skipped"] += 1
        elif resolved and opened:
            resolutions.append(_minutes(opened, resolved))
        elif resolved is None:
            out["totals"]["skipped"] += 1
    if resolutions:
        out["resolution"]["count"] = len(resolutions)
        out["resolution"]["mean_minutes"] = round(sum(resolutions) / len(resolutions), 1)
        out["resolution"]["median_minutes"] = _median(resolutions)
    return out


def eval_candidates(evidence: str, *, min_note_chars: int = 10) -> Dict[str, Any]:
    """C71: resolved escalations read back as an eval-candidate feed. A resolution note short enough to say
    nothing (or no note at all) is NOT a usable eval row - it is left out and counted. Report-only: importing
    the rows into ``evals/`` is a deliberate human step (a feed that silently becomes a test would smuggle the
    reviewer's own wording into the golden set without anyone reading it first)."""
    state = escalation.load(evidence)
    rows: List[Dict[str, Any]] = []
    skipped = 0
    for eid, row in sorted(state.items()):
        if row.get("status") != "resolved":
            continue
        res = row.get("resolution") or {}
        note = str(res.get("note") or "").strip()
        if len(note) < min_note_chars:
            skipped += 1
            continue
        p = row.get("payload") or {}
        rows.append({"id": eid, "kind": p.get("kind"), "trigger": p.get("trigger"), "project": p.get("project"),
                     "question": p.get("triggering_question"), "question_trust": p.get("triggering_question_trust"),
                     "resolution_note": note, "resolved_by": res.get("by") or "unattributed", "resolved_at": row.get("resolved_at")})
    return {"schema": "bts-sbom.escalation-eval-candidates.v1", "candidates": rows, "count": len(rows), "skipped": skipped,
            "note": "report-only feed: a human reads these and decides which become eval cases (C71); the question text is "
                    "already PII/secret-redacted at escalation build time"}
