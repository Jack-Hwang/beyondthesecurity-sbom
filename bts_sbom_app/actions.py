"""The effectful side of the chatbot: analyse a source, apply an approved patch, record a VEX decision, export the VEX.

Why: the chat used to be read-only, so "analyse this repo, fix what you can, and mark the rest in the VEX" meant leaving the
conversation for three commands. This module lets the chat drive the same engine - but every effect keeps its gate:

  * ``analyze``     runs the normal pipeline on an isolated WORK COPY (the origin is never written, nothing is executed).
  * ``patch_apply`` needs the approval token = the digest of exactly the plan the user was shown (``patch.approval_digest``). It applies
                    that plan for ONE round only (no follow-up plans nobody approved), re-scans, and reverts on a regression. The result
                    is a branch in the work copy: nothing is pushed, the origin is untouched, and delivery to an origin stays a CLI flag.
  * ``decision_*``  a VEX decision is previewed first and written only with the digest of that exact decision. The triage rules
                    (``triage.py``: justification + reason or it stays ``affected``; expiry; no ``fixed`` the scan contradicts) apply as for the
                    console. The model never invents a decision: the chat layer only passes values the user typed.
  * ``export_vex``  writes ``<project>.triaged.vex.json`` next to the project record.

Nothing here talks to a model; the chat layer decides WHEN to call it and checks that tokens, sources and reasons are the user's own words.
"""
from __future__ import annotations

import copy
import datetime
import hashlib
import json
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from . import console, patch as patchmod, pipeline, sbom, triage, workspace
from .util import read_json, safe_name, write_json

DECISION_STATUSES = ("false-positive", "accepted", "wontfix")
PENDING_TTL_S = 24 * 3600
PENDING_MAX = 50


def plan_selection(rec: Dict[str, Any], components: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """The upgrade plans a token covers: all of them, or only the named components (case-insensitive)."""
    want = {c.lower() for c in components or []}
    return [p for p in rec.get("plans") or [] if p.get("status") == "upgrade" and p.get("safe_version")
            and (not want or str(p["component"]).lower() in want)]


def plan_token(rec: Dict[str, Any], components: Optional[List[str]] = None) -> str:
    return patchmod.approval_digest(plan_selection(rec, components))


def decision_digest(d: Dict[str, Any]) -> str:
    canon = {k: str(d.get(k) or "") for k in ("id", "status", "reason", "justification", "scope", "expires", "by")}
    return hashlib.sha256(json.dumps(canon, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()[:12]


def decision_key(d: Dict[str, Any]) -> str:
    return str(d["id"]).upper() + (("@" + d["scope"]) if d.get("scope") else "")


class ChatActions:
    """Capabilities a chat session may use. Construct it only for a session the user opened with actions enabled."""

    def __init__(self, root: str, evidence: str, *, client: Any = None, work_root: Optional[str] = None, cache_dir: Optional[str] = None,
                 offline: bool = False, scanner: Any = None, use_llm: bool = True, today: Optional[datetime.date] = None):
        self.root, self.evidence, self.client = root, evidence, client
        self.work_root, self.offline, self.scanner, self.use_llm = work_root, offline, scanner, use_llm
        self.cache_dir = cache_dir or os.path.join(root, "evidence", "cache")
        self.today = today
        self.triage_path = os.path.join(evidence, ".triage.json")
        self.pending_path = os.path.join(evidence, ".pending_decisions.json")

    # ---------------------------------------------------------------- records
    def _folder_and_record(self, name: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        from .cli import project_records
        hit = project_records(self.evidence).get(name)
        return (hit[0], hit[1]) if hit else (None, None)

    def store(self) -> Dict[str, Any]:
        d = read_json(self.triage_path, {})
        return d if isinstance(d, dict) else {}

    # ---------------------------------------------------------------- analyse
    def analyze(self, source: str) -> Dict[str, Any]:
        """Run the pipeline on ``source`` (git URL / owner/repo / local folder). Returns {ok, record} or {ok: False, error}."""
        wdir = self.work_root or tempfile.mkdtemp(prefix="bts_sbom_chat_")
        try:
            rec = pipeline.run_project(source, work_root=wdir, out_dir=self.evidence, use_llm=self.use_llm, client=self.client, cache_dir=self.cache_dir,
                                       offline=self.offline, scanner=self.scanner, run_arch=False)
        except Exception as exc:                                    # noqa: BLE001 - reported to the user, never swallowed
            return {"ok": False, "error": "%s: %s" % (type(exc).__name__, str(exc)[:200])}
        finally:
            if not self.work_root:
                shutil.rmtree(wdir, onerror=workspace._force_remove)
        if rec.get("error"):
            return {"ok": False, "error": rec["error"]}
        saved = read_json((rec.get("artifacts") or {}).get("record") or "", None)          # the persisted, slim form (no embedded documents)
        return {"ok": True, "record": saved if isinstance(saved, dict) else {k: v for k, v in rec.items() if k != "_docs"}}

    # ---------------------------------------------------------------- patch
    def patch_apply(self, rec: Dict[str, Any], token: str, components: Optional[List[str]] = None) -> Dict[str, Any]:
        """Apply EXACTLY the plan the token was computed for. One round; re-scan; revert on regression; result recorded in the project record."""
        plans = plan_selection(rec, components)
        digest = patchmod.approval_digest(plans)
        if not plans:
            return {"status": "nothing_to_patch", "digest": digest}
        if token != digest:
            return {"status": "digest_mismatch", "digest": digest}
        work = self.work_root or tempfile.mkdtemp(prefix="bts_sbom_fix_")
        ws = workspace.prepare(rec["source"], work, ref=rec.get("ref") or None, name=safe_name(rec["name"]) + "_fix")
        if not ws.get("ok"):
            if not self.work_root:
                shutil.rmtree(work, onerror=workspace._force_remove)
            return {"status": "error", "error": ws.get("error") or "work copy could not be prepared", "digest": digest}
        scoped = dict(rec, plans=copy.deepcopy(plans))                # the loop sees only the approved plans ...
        out = pipeline._patch_loop(scoped, ws["path"], approved=True, token=token, rounds=1, offline=self.offline,     # ... and runs ONE round
                                   scanner=self.scanner, verify_rounds=3)
        out["at"] = datetime.datetime.now().isoformat(timespec="seconds")   # when this approved run happened (the display labels stale statuses)
        out["work_copy"] = ws["path"] if out.get("status") == "applied" else None
        if out.get("status") != "applied":
            shutil.rmtree(work if not self.work_root else ws["path"], onerror=workspace._force_remove)
        folder, saved = self._folder_and_record(rec["name"])
        if folder and saved is not None:                                # the console and the reports read the patch result from the record
            saved["patch"] = out
            saved["metrics"] = pipeline.metrics(saved)
            write_json(os.path.join(folder, os.path.basename(folder) + ".json"), saved)
        return out

    # ---------------------------------------------------------------- VEX decisions
    def decision_effect(self, rec: Dict[str, Any], d: Dict[str, Any]) -> Dict[str, Any]:
        return decision_effect(rec, d, self.today)

    # ---------------------------------------------------------------- pending decisions (a preview waits for the user's confirm code)
    def _pending(self) -> Dict[str, Any]:
        d = read_json(self.pending_path, {})
        now = datetime.datetime.now().astimezone()
        keep = {}
        for k, v in (d if isinstance(d, dict) else {}).items():
            try:
                if (now - datetime.datetime.fromisoformat(v["ts"])).total_seconds() < PENDING_TTL_S:
                    keep[k] = v
            except (KeyError, ValueError, TypeError):
                continue
        return keep

    def stage_decision(self, project: str, d: Dict[str, Any]) -> str:
        """Remember a previewed decision under the digest of its content; the user confirms by typing that digest."""
        cur = self._pending()
        code = decision_digest(d)
        cur[code] = {"decision": d, "project": project, "ts": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}
        for k in list(cur)[:-PENDING_MAX]:
            cur.pop(k)
        os.makedirs(self.evidence, exist_ok=True)
        write_json(self.pending_path, cur)
        return code

    def pending_decision(self, code: str) -> Optional[Dict[str, Any]]:
        hit = self._pending().get(code)
        if hit and decision_digest(hit["decision"]) == code:           # the stored content must still hash to the code the user typed
            return hit
        return None

    def unstage(self, code: str) -> None:
        cur = self._pending()
        if cur.pop(code, None) is not None:
            write_json(self.pending_path, cur)

    def decision_commit(self, d: Dict[str, Any]) -> Dict[str, Any]:
        cur = self.store()
        key = decision_key(d)
        if key not in cur and len(cur) >= console.TRIAGE_MAX_ENTRIES:
            return {"ok": False, "error": "triage store is full (%d entries)" % console.TRIAGE_MAX_ENTRIES}
        entry: Dict[str, Any] = {"status": d["status"], "note": d["reason"], "ts": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                                 "via": "chat"}
        for k in ("justification", "expires", "scope", "by"):
            if d.get(k):
                entry[k] = d[k]
        cur[key] = entry
        os.makedirs(self.evidence, exist_ok=True)
        write_json(self.triage_path, cur)
        return {"ok": True, "key": key, "path": self.triage_path}

    def export_vex(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        doc = sbom.openvex(rec["name"], rec.get("vulns") or [], triage=self.store(), today=self.today)
        folder, _ = self._folder_and_record(rec["name"])
        path = None
        if folder:
            path = os.path.join(folder, os.path.basename(folder) + ".triaged.vex.json")
            write_json(path, doc)
        ev = triage.evaluate(rec.get("vulns") or [], self.store(), today=self.today)
        return {"statements": len(doc["statements"]), "by_status": _count(s["status"] for s in doc["statements"]), "path": path,
                "counts": ev["counts"], "rejected": ev["rejected"], "expired": ev["expired"], "stale": ev["stale"]}


def decision_effect(rec: Dict[str, Any], d: Dict[str, Any], today: Optional[datetime.date] = None) -> Dict[str, Any]:
    """What a decision would do to the findings of ``rec`` under the triage rules. Pure: nothing is written."""
    entry: Dict[str, Any] = {"status": d["status"], "note": d["reason"], "ts": "preview"}
    for k in ("justification", "expires", "scope", "by"):
        if d.get(k):
            entry[k] = d[k]
    store = {decision_key(d): entry}
    hits = [(v, triage.decide(v, store, today=today)) for v in rec.get("vulns") or []]
    hits = [(v, x) for v, x in hits if x]
    return {"matches": [{"package": v["package"], "version": v["version"]} for v, _ in hits], "states": sorted({x["state"] for _, x in hits}),
            "issues": sorted({x["issue"] for _, x in hits if x["issue"]})}


def _count(items: Any) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return out


__all__ = ["ChatActions", "plan_selection", "plan_token", "decision_digest", "decision_key", "decision_effect", "DECISION_STATUSES"]
