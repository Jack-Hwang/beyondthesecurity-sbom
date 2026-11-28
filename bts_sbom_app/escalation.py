"""Escalation and handoff for the chatbot: three testable triggers, a structured payload, an append-only log and a closed loop.

Course source (MetaNet advanced course, week 5 lesson 1, D5.2 escalation / D1.4 handoff; week 6 lesson 1): a chatbot that cannot answer
must not guess and must not make the person start over. It hands over when
  * ``human_request``  - the user asked for a person: handed off AT ONCE, no tool runs first (investigating before obeying is the trap);
  * ``policy_gap``     - the question asks for something this tool deliberately does not decide (a legal judgment, a certification or
                         sign-off): the answer is not improvised, the case goes to the owner of that decision;
  * ``no_progress``    - the third consecutive question in a conversation could not be answered (``MAX_FAIL``): stop repeating the
                         same attempt.
Triggers are CONDITIONS decided by code, never a model's feeling: sentiment and self-reported confidence are not inputs and the
payload has no field for them (the course lists both as untrustworthy proxies). A question that names an item present in several
projects is not an escalation but a clarifying question (``ambiguous_projects``): the tool does not pick one by heuristic.

The payload is a schema, not a story (the receiver is assumed not to see the conversation): summary, the triggering question verbatim
(marked untrusted - it is user text), what was attempted, the suggested next step, evidence references. Escalations are logged as data
(``escalations.jsonl``, append-only events) so thresholds and wording can be tuned, and a resolution is fed back: later answers about the
same project show the reviewer's note (``reviewer_notes``) - the escalation is a recovery path, not a dead end.

Nothing here sends anything anywhere: a log line is the handoff; delivering it (mail, ticket) is the operator's explicit step.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import gaps, pii_guard
from .util import now_iso

SCHEMA = "bts-sbom.escalation.v1"
TRIGGERS = ("human_request", "policy_gap", "no_progress")
MAX_FAIL = 3                                   # the 3rd consecutive unanswered question is handed over (course: 2-3)
MAX_LOG_EVENTS = 20000
MAX_QUESTION = 500
MAX_NOTE = 500
REQUIRED = ("schema", "id", "trigger", "destination", "summary", "triggering_question", "attempted_actions", "suggested_next_step", "status")
#: fields that must never exist: the course names them as unreliable proxies for the need to escalate
FORBIDDEN_FIELDS = ("sentiment", "emotion", "mood", "confidence", "score")
DESTINATION = {"human_request": "security-owner", "policy_gap:legal": "legal-review", "policy_gap:certify": "oss-governance",
               "no_progress": "security-owner"}
_ID = re.compile(r"^E-[0-9a-f]{8}$")

_HUMAN = re.compile(
    r"(사람|담당자|상담원|보안 ?팀|책임자|검토자|오픈소스 ?팀|운영자)\s*(이?랑|과|와|하고)?\s*.{0,10}(연결|통화|이야기|얘기|말하|문의|넘겨|바꿔|만나)"
    r"|(연결|넘겨|바꿔)\s*(해?\s*줘|주세요).{0,8}(사람|담당자|상담원)"
    r"|talk to (a )?(human|person|someone)|speak (to|with) (a )?(human|person)|human (agent|review)|escalate (this|to)", re.I)
_LEGAL_TERM = re.compile(r"법적|법률|법무|소송|저작권 ?침해|특허 ?침해|라이선스 ?위반|책임 ?소재|손해 ?배상|\blegal(ly)?\b|lawsuit|liabilit|infring|indemn", re.I)
_JUDGE = re.compile(r"되나|돼\??|괜찮|문제 ?(없|있|될|가)|가능(한가|해|할까)|위반(인가|이야|이냐|맞)|침해(인가|이야|이냐|맞)|맞나|해도 ?(돼|되)|"
                    r"should we|can we|is it (ok|safe|legal)|allowed", re.I)
_CERTIFY = re.compile(r"(문제|이상|위험)\s*(없다고|없음을)\s*(보증|확인해|인증|말해)|(보증|인증|서명)\s*해\s*줘|안전하다고\s*(보증|확인해|말해)|"
                      r"\bcertify\b|\bguarantee\b|sign.?off|\battest\b", re.I)
_ADVISORY = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d{4}-\d+|RUSTSEC-\d{4}-\d+|GO-\d{4}-\d+)\b", re.I)


# ------------------------------------------------------------------ triggers (conditions, decided by code)
def hard_trigger(question: str) -> Optional[Tuple[str, str]]:
    """(trigger, kind) for a question that is handed off BEFORE any tool runs, else None. A human request wins over a policy gap."""
    q = question or ""
    if _HUMAN.search(q):
        return "human_request", "human_request"
    if _LEGAL_TERM.search(q) and _JUDGE.search(q):
        return "policy_gap", "policy_gap:legal"
    if _CERTIFY.search(q):
        return "policy_gap", "policy_gap:certify"
    return None


def trailing_misses(memory: Any) -> int:
    """How many of the most recent turns in a row were NOT answered (``found`` false) - 0 without a memory."""
    n = 0
    for t in reversed(list(getattr(memory, "turns", []) or [])):
        if t.get("found"):
            break
        n += 1
    return n


def ambiguous_projects(question: str, projects: Dict[str, Dict[str, Any]]) -> List[str]:
    """The projects a question could mean when it names an advisory id or a component that SEVERAL loaded projects have and names no
    project itself - sorted names, or [] (nothing to clarify). One matching project is not ambiguous; nothing is picked by heuristic."""
    low = (question or "").lower()
    if any(n.lower() in low for n in projects):
        return []
    ids = {m.upper() for m in _ADVISORY.findall(question or "")}
    names = {c["name"].lower() for p in projects.values() for c in p.get("components") or []
             if len(c.get("name") or "") >= 3 and re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(c["name"].lower()), low)}
    hits = set()
    for pn, rec in projects.items():
        has_id = ids and any(i in {str(v.get("id", "")).upper()} | {str(a).upper() for a in v.get("aliases") or []} for v in rec.get("vulns") or [] for i in ids)
        has_name = names and any(str(c.get("name", "")).lower() in names for c in rec.get("components") or [])
        if has_id or has_name:
            hits.add(pn)
    return sorted(hits) if len(hits) > 1 else []


# ------------------------------------------------------------------ the payload
_SUMMARY = {
    "human_request": "The user asked to speak to a person; no tool was run (a human request is handed off at once, without investigation).",
    "policy_gap:legal": "The question asks for a legal judgment, which this tool does not make; it screens recorded licenses and obligations only.",
    "policy_gap:certify": "The question asks the tool to certify or vouch for a result; that decision belongs to a named owner, not to the tool.",
    "no_progress": "%d consecutive questions could not be answered from the analysed projects or the knowledge base.",
}
_NEXT = {
    "human_request": "Contact the user and continue from this summary; the conversation does not have to be re-read.",
    "policy_gap:legal": "Have the legal reviewer answer the question; the recorded licenses and obligations of the project are the facts to give them.",
    "policy_gap:certify": "Have the owner of the decision review the evidence (findings, plan, VEX decisions) and decide; record the decision as a VEX decision with a reason.",
    "no_progress": "Review the unanswered questions, then either extend the knowledge or analyse the missing project; answer the user directly.",
}


def build(kind: str, question: str, project: Optional[str], attempted: Iterable[Dict[str, Any]] = (), *, misses: int = 0,
          rec: Optional[Dict[str, Any]] = None, trace_id: Optional[str] = None) -> Dict[str, Any]:
    """The structured handoff payload (``bts-sbom.escalation.v1``). ``kind`` is a key of DESTINATION (e.g. ``policy_gap:legal``).

    ``rec`` is the optional analysed project record of ``project`` (week 5 lesson 1 D1.4: a handoff summary names the
    customer id, root cause, amount, recommended action). When supplied for a ``no_progress``/``policy_gap`` kind,
    its coverage gaps (``gaps.of(rec)``, already computed, never re-derived here) are copied verbatim into
    ``evidence_refs['root_cause']`` so the receiver sees WHY the tool could not decide; the key is omitted when there
    is nothing uncovered (no invented root cause). The question text is PII/secret-redacted (``pii_guard.redact``)
    before it is STORED - the field is marked ``untrusted-quote`` precisely because it is user text that may carry
    PII the user typed, not just an injection risk.

    The escalation ``id`` is hashed from the ORIGINAL (pre-redaction) question text, not the redacted one: redaction
    replaces every PII/secret-shaped substring with the same fixed ``[redacted:<kind>]`` placeholder, so two
    genuinely different questions that merely carry the same PII shape (two different people's phone numbers, say)
    would otherwise redact to byte-identical text and collide on the same id - and ``record()`` silently drops the
    second one as a "duplicate" while the first is still open. Hashing the original text keeps the id able to tell
    such questions apart while the STORED/RETURNED ``triggering_question`` field stays fully redacted; the 8-hex id
    is a one-way digest truncated for brevity, not a reversible encoding of the question - the original text does
    not need to be (and is not) recoverable from it."""
    trigger = kind.split(":", 1)[0]
    if trigger not in TRIGGERS or kind not in DESTINATION:
        raise ValueError("unknown escalation kind %r" % kind)
    q_raw = str(question or "")[:MAX_QUESTION]
    q, _redacted = pii_guard.redact(q_raw)
    summary = _SUMMARY[kind] % misses if "%d" in _SUMMARY[kind] else _SUMMARY[kind]
    h = hashlib.sha256(("%s|%s|%s" % (kind, project or "", q_raw)).encode("utf-8")).hexdigest()[:8]
    evidence_refs: Dict[str, Any] = {"project": project, "advisory_ids": sorted({m.upper() for m in _ADVISORY.findall(q)})}
    if rec is not None and trigger in ("no_progress", "policy_gap"):
        root_cause = gaps.of(rec)
        if root_cause:
            evidence_refs["root_cause"] = root_cause
    payload: Dict[str, Any] = {"schema": SCHEMA, "id": "E-" + h, "trigger": trigger, "kind": kind, "destination": DESTINATION[kind], "project": project,
                               "summary": summary, "triggering_question": q, "triggering_question_trust": "untrusted-quote",
                               "attempted_actions": [{"tool": str(a.get("tool")), "lines": int(a.get("lines") or 0)} for a in attempted],
                               "suggested_next_step": _NEXT[kind], "evidence_refs": evidence_refs,
                               "status": "open", "resolution": None}
    if trace_id:                                                  # C25: the HTTP correlation id of the turn that raised it
        payload["trace_id"] = str(trace_id)[:64]
    return payload


def validate(p: Dict[str, Any]) -> List[str]:
    """Problems of a payload ([] = acceptable): every required field present, a known trigger, no forbidden proxy field."""
    out = ["missing %s" % k for k in REQUIRED if k not in p]
    if p.get("trigger") not in TRIGGERS:
        out.append("trigger must be one of %s" % ", ".join(TRIGGERS))
    if not _ID.match(str(p.get("id", ""))):
        out.append("id must look like E-<8 hex>")
    out += ["forbidden field %s" % k for k in p if any(f in k.lower() for f in FORBIDDEN_FIELDS)]
    return out


def answer_text(p: Dict[str, Any]) -> str:
    return ("- [escalation] Handed over to %s (trigger %s, id %s). %s\n- Suggested next step: %s\n"
            "- The receiver gets a structured summary, your question as written and what was tried, so you do not have to repeat yourself."
            % (p["destination"], p["trigger"], p["id"], p["summary"], p["suggested_next_step"]))


def clarification_text(candidates: List[str]) -> str:
    return ("- [clarification] More than one analysed project matches (%s); the tool does not pick one by guess. "
            "Name the project in the question (for example \"%s 에서 ...\") or pass the project id." % (", ".join(candidates), candidates[0]))


def approval_request(decision: str, if_approved: str, if_not_approved: str, deadline: str) -> List[str]:
    """The four elements of an approval request (week 5 lesson 1, D1 interrupt points): the decision needed, what happens if it is
    approved, what happens if it is not, and the deadline - so that waiting is never silent."""
    return ["Decision needed: %s." % decision, "If approved: %s." % if_approved, "If not approved: %s." % if_not_approved, "Deadline: %s." % deadline]


# ------------------------------------------------------------------ the log (append-only events, folded on read)
def log_path(evidence: str) -> str:
    return os.path.join(evidence, "escalations.jsonl")


def _events(evidence: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        with open(log_path(evidence), "r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue                                   # a damaged line is skipped, never fatal
                if isinstance(ev, dict) and ev.get("event") in ("opened", "resolved"):
                    out.append(ev)
    except OSError:
        pass
    return out


def load(evidence: str) -> Dict[str, Dict[str, Any]]:
    """id -> {payload, status, resolution, opened_at, resolved_at}, folding the events in file order."""
    state: Dict[str, Dict[str, Any]] = {}
    for ev in _events(evidence):
        i = ev.get("id")
        if ev["event"] == "opened" and i not in state:
            state[i] = {"payload": ev.get("payload") or {}, "status": "open", "resolution": None, "opened_at": ev.get("ts"), "resolved_at": None}
        elif ev["event"] == "resolved" and i in state and state[i]["status"] == "open":
            state[i].update(status="resolved", resolution={"note": ev.get("note"), "by": ev.get("by")}, resolved_at=ev.get("ts"))
    return state


def _append(evidence: str, ev: Dict[str, Any]) -> None:
    os.makedirs(evidence, exist_ok=True)
    with open(log_path(evidence), "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(ev, ensure_ascii=False, sort_keys=True) + "\n")


def record(evidence: str, payload: Dict[str, Any], *, now: Optional[str] = None) -> Dict[str, Any]:
    """Log one escalation (an event line). The same trigger, project and question while it is still open is NOT logged twice.
    Returns the payload with ``logged`` (a new line was written) and ``duplicate`` set. The triggering question is
    PII/secret-redacted again here (``pii_guard.redact``, idempotent on text ``build()`` already redacted) so a payload
    assembled without going through ``build()`` can never put PII into the logged event or the returned payload."""
    bad = validate(payload)
    if bad:
        raise ValueError("invalid escalation payload: " + "; ".join(bad))
    safe_payload = dict(payload)
    tq = safe_payload.get("triggering_question")
    if tq:
        safe_payload["triggering_question"], _redacted = pii_guard.redact(str(tq))
    cur = load(evidence)
    if safe_payload["id"] in cur and cur[safe_payload["id"]]["status"] == "open":
        return dict(safe_payload, logged=False, duplicate=True)
    if len(_events(evidence)) >= MAX_LOG_EVENTS:
        return dict(safe_payload, logged=False, duplicate=False, log_full=True)
    _append(evidence, {"event": "opened", "id": safe_payload["id"], "ts": now or now_iso(), "payload": safe_payload})
    return dict(safe_payload, logged=True, duplicate=False)


def resolve(evidence: str, esc_id: str, note: str, by: str, *, now: Optional[str] = None) -> Dict[str, Any]:
    """Close an escalation with the reviewer's note. KeyError for an unknown id, ValueError for an already resolved one or a bad note / name.
    The note is length-validated on the reviewer's own text, then PII/secret-redacted (``pii_guard.redact``) before it is
    logged - a reviewer's free-text note is exactly the operator-authored text the PII guard exists for."""
    if not _ID.match(str(esc_id or "")):
        raise ValueError("id must look like E-<8 hex>")
    n, b = str(note or "").strip(), str(by or "").strip()
    if len(n) < 5 or len(n) > MAX_NOTE:
        raise ValueError("note must have 5..%d characters" % MAX_NOTE)
    if not b or len(b) > 80:
        raise ValueError("by must name the reviewer (1..80 characters)")
    cur = load(evidence)
    if esc_id not in cur:
        raise KeyError(esc_id)
    if cur[esc_id]["status"] == "resolved":
        raise ValueError("%s is already resolved" % esc_id)
    n_safe, _redacted = pii_guard.redact(n)
    _append(evidence, {"event": "resolved", "id": esc_id, "ts": now or now_iso(), "note": n_safe, "by": b})
    return load(evidence)[esc_id]


def reviewer_notes(evidence: Optional[str], project: str, limit: int = 2) -> List[Dict[str, Any]]:
    """The resolutions recorded for ``project`` (newest first): fed back into later answers so the escalation closes the loop."""
    if not evidence:
        return []
    rows = [(s["resolved_at"] or "", i, s) for i, s in load(evidence).items()
            if s["status"] == "resolved" and (s["payload"] or {}).get("project") == project]
    rows.sort(key=lambda r: (r[0], r[1]), reverse=True)
    return [{"id": i, "trigger": s["payload"].get("trigger"), "by": s["resolution"]["by"], "note": s["resolution"]["note"]} for _, i, s in rows[:limit]]


__all__ = ["SCHEMA", "TRIGGERS", "MAX_FAIL", "hard_trigger", "trailing_misses", "ambiguous_projects", "build", "validate", "answer_text",
           "clarification_text", "approval_request", "record", "resolve", "load", "reviewer_notes", "log_path"]
