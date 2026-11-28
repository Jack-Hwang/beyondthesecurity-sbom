"""End-user feedback on chat answers + the turn metadata ledger + the stratified review queue (backlog C76, C66;
course week 5 lesson 2 D5.5 사람 검토·층화 표집): a thumbs up/down on a chat answer is the human signal the system
currently never captures, so it is captured here - as an append-only event stream like escalations, keyed by the
turn's trace_id. Privacy by construction: the TURN ledger stores metadata only (trace_id, answer_source, degraded
flag, found flag) - never the question or the answer text, which stay in the conversation they belong to.

The review queue (C66) closes the loop the course names: escalations already route the FAILED answers to a human;
the answers that merely LOOK fine are never sampled. ``review_queue`` draws a stratified sample over the turn
ledger (strata = verdict bucket: rated up / rated down / unrated) using audit.stratified_sample - the unrated
majority is exactly the population that has never been human-checked. Sampling only PROPOSES a worklist: reviewing
is a human step, and a correction feeds back through the same feedback stream (report-only, never auto-rewriting
any eval set).
"""
from __future__ import annotations

import datetime
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from . import audit
from .oss_api import _err, _host_allowed, _ok, _same_origin

SCHEMA = "bts-sbom.chat-feedback.v1"
TURN_FILE = "chat_turns.jsonl"
FEEDBACK_FILE = "chat_feedback.jsonl"
VERDICTS = ("up", "down")
CAP = 5000                                       # bounded event streams, same discipline as escalations.jsonl
MAX_NOTE = 300
TRACE_ID = re.compile(r"^[0-9a-f\-]{8,64}$")


def _now() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def _append(path: str, entry: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    lines: List[str] = []
    if os.path.exists(path):                     # cap: drop the oldest, keep the newest CAP-1
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()[-(CAP - 1):]
    lines.append(json.dumps(entry, ensure_ascii=False) + "\n")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(lines)


def _read(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                try:
                    rec = json.loads(ln)
                except ValueError:
                    continue
                if isinstance(rec, dict):
                    out.append(rec)
    except OSError:
        pass
    return out


# ------------------------------------------------------------------ the turn metadata ledger (no text, ever)
def record_turn(evidence: str, trace_id: str, *, answer_source: str = "", degraded: bool = False,
                found: Any = None, status: str = "") -> Dict[str, Any]:
    """One metadata row per chat turn: the sampling population for the review queue. The question and the answer
    body are deliberately NOT stored here - the ledger answers 'which turns exist and how did they resolve', not
    'what did anyone say'."""
    entry = {"schema": SCHEMA, "trace_id": str(trace_id or "")[:64], "at": _now(),
             "answer_source": str(answer_source or "")[:40], "degraded": bool(degraded),
             "found": None if found is None else bool(found), "status": str(status or "")[:20]}
    _append(os.path.join(evidence, TURN_FILE), entry)
    return entry


def record_feedback(evidence: str, trace_id: str, verdict: str, *, note: Optional[str] = None,
                    by: Optional[str] = None) -> Tuple[Optional[Dict[str, Any]], str]:
    """(entry, error) - an up/down vote on the turn ``trace_id``. The trace id must look like one, the verdict is a
    closed set, the note is capped; a re-vote of the SAME verdict on the same turn is a duplicate (counted once,
    honestly) while the opposite verdict appends - flipping is data too."""
    tid = str(trace_id or "").strip()
    if not TRACE_ID.fullmatch(tid):
        return None, "trace_id must look like a request correlation id"
    if verdict not in VERDICTS:
        return None, "verdict는 up|down 중 하나다"
    note = (str(note) if note is not None else "").strip()
    if len(note) > MAX_NOTE:
        return None, "note is over the %d-char cap" % MAX_NOTE
    prior = [f for f in _read(os.path.join(evidence, FEEDBACK_FILE)) if f.get("trace_id") == tid]
    entry = {"schema": SCHEMA, "trace_id": tid, "at": _now(), "verdict": verdict,
             "note": note or None, "by": (str(by)[:40] if by else None)}
    if any(f.get("verdict") == verdict for f in prior):
        return dict(entry, duplicate=True), ""
    _append(os.path.join(evidence, FEEDBACK_FILE), entry)
    return entry, ""


# ------------------------------------------------------------------ roll-up + the stratified review queue
def verdict_of(trace_id: str, feedback: List[Dict[str, Any]]) -> str:
    vs = [f["verdict"] for f in feedback if f.get("trace_id") == trace_id]
    if "down" in vs:
        return "down"
    if "up" in vs:
        return "up"
    return "unrated"


def summary(evidence: str) -> Dict[str, Any]:
    """The measured feedback state: turns, votes by verdict, response rate, and the down-votes that carry a note
    (those are the cheapest real defect reports the system has)."""
    turns = _read(os.path.join(evidence, TURN_FILE))
    fb = _read(os.path.join(evidence, FEEDBACK_FILE))
    up = sum(1 for f in fb if f.get("verdict") == "up")
    down = sum(1 for f in fb if f.get("verdict") == "down")
    noted_down = [f for f in fb if f.get("verdict") == "down" and f.get("note")]
    return {"schema": SCHEMA, "turns": len(turns), "up": up, "down": down,
            "unrated": max(0, len(turns) - len({f.get("trace_id") for f in fb})),
            "response_rate": round((up + down) / len(turns), 3) if turns else None,
            "down_with_note": len(noted_down), "notes": [f["note"] for f in noted_down[-5:]]}


def review_queue(evidence: str, *, frac: float = 0.2, minimum: int = 4, seed: int = 20261128) -> Dict[str, Any]:
    """A stratified human-review worklist over the turn ledger, strata = verdict bucket (up / down / unrated) —
    the unrated majority is the population no human has ever checked, so it gets its own stratum instead of
    hiding inside the total. Report-only: it proposes rows; it never rewrites an eval set."""
    turns = _read(os.path.join(evidence, TURN_FILE))
    fb = _read(os.path.join(evidence, FEEDBACK_FILE))
    pop: Dict[str, int] = {}
    for t in turns:
        s = verdict_of(t.get("trace_id", ""), fb)
        pop[s] = pop.get(s, 0) + 1
    sampled = audit.stratified_sample(turns, lambda t: verdict_of(t.get("trace_id", ""), fb),
                                      frac=frac, minimum=minimum, seed=seed)
    rows: List[Dict[str, Any]] = []
    for stratum, members in sorted(sampled.items()):
        for t in members:
            rows.append({"trace_id": t.get("trace_id"), "stratum": stratum, "at": t.get("at"),
                         "answer_source": t.get("answer_source"), "degraded": t.get("degraded"),
                         "found": t.get("found"), "status": t.get("status")})
    return {"schema": SCHEMA, "population": len(turns), "strata": dict(sorted(pop.items())),
            "sampled": {k: len(v) for k, v in sorted(sampled.items())}, "queue": rows}


# ------------------------------------------------------------------ HTTP surface (same contract as incidents.route)
def route(method: str, path: str, query: Dict[str, List[str]], body: Dict[str, Any], headers: Any, st: Any,
          bind: Optional[Tuple[Any, ...]] = None):
    """GET/POST /api/chat/feedback - the same host-pin / same-origin discipline as the other lanes."""
    if path != "/api/chat/feedback" and not path.startswith("/api/chat/feedback"):
        return None
    if headers is not None and not _host_allowed(headers.get("Host", "") or "", bind):
        return _err(403, "unexpected Host header (the service answers only at its own address)")
    if method == "POST" and not _same_origin(headers, bind):
        return _err(403, "cross-origin request refused")
    evidence = st.evidence
    if method == "GET":
        return _ok(dict(summary(evidence), queue=review_queue(evidence)))
    if method == "POST":
        tid = body.get("trace_id") or ""
        verdict = body.get("verdict") or ""
        entry, err = record_feedback(evidence, tid, verdict, note=body.get("note"), by=body.get("by"))
        if err:
            return _err(400, err)
        return _ok(entry)
    return _err(405, "method not allowed")
