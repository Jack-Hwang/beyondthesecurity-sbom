"""Frozen handover baseline, post-handover findings and the assumption register (task 33, TR 8477 review P2-C/D).

* ``freeze(rec, out_dir)`` — writes a content-hashed handover baseline (SBOM/VEX/record SHA-256s, the declared
  components with versions, and the finding ids known at handover). The file is written ONCE: an existing
  baseline is never overwritten (TR 4.7: the baseline is frozen at handover).
* ``post_handover(rec, frozen)`` — flags advisories that are NEW relative to the frozen baseline but sit on a
  component the baseline already declared: "a finding the other party may be affected by" (TR 4.7 handover).
* ``assumptions.evaluate(triage_entries)`` — the assumption register (TR 4.8): a ``false-positive`` decision that
  maps to VEX ``not_affected`` carries an assumption; it is only VERIFIED when the note references evidence
  (a file/test/report path or an explicit evidence id). Unverified assumptions stay flagged for the assessor —
  fail-closed: they never silence the finding silently.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional

SCHEMA = "bts-sbom.handover.v1"
DISCLAIMER = "엔지니어링 신호이며 법률·적합성 판정이 아닙니다 — 독립 평가는 평가자의 몫입니다"
BASELINE_NAME = "handover-baseline.json"
EVIDENCE_RE = re.compile(r"(tests/|docs/|evidence/|\.py\b|\.md\b|\.json\b|\.diff\b|EVD-|[0-9a-f]{12,64})")


def _component_hash(rec: Dict[str, Any]) -> str:
    rows = sorted((str(c.get("name")).lower(), str(c.get("version") or "")) for c in rec.get("components") or [])
    payload = json.dumps(rows, sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


def freeze(rec: Dict[str, Any], out_dir: str, *, label: str = "handover") -> Dict[str, Any]:
    """Freeze the handover baseline once. Returns the manifest; refuses to overwrite an existing baseline."""
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, BASELINE_NAME)
    if os.path.exists(path):
        existing = json.load(open(path, encoding="utf-8"))
        existing["already_frozen"] = True
        return existing
    art = rec.get("artifacts") or {}
    files: List[Dict[str, str]] = []
    for kind in ("cdx", "spdx", "vex"):
        p = art.get(kind)
        if p and os.path.isfile(str(p)):
            files.append({"kind": kind, "path": str(p), "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest()})
    manifest = {"schema": SCHEMA, "disclaimer": DISCLAIMER, "label": label,
                "target": rec.get("name"), "commit": (rec.get("lineage") or {}).get("commit", ""),
                "component_hash": _component_hash(rec),
                "components": [{"name": c.get("name"), "version": c.get("version")} for c in rec.get("components") or []],
                "finding_ids": sorted({str(v.get("id")) for v in rec.get("vulns") or []}),
                "files": files,
                "ts": None}                                        # content hash of the SBOM fixes the point in time
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    return manifest


def load(out_dir: str) -> Optional[Dict[str, Any]]:
    path = os.path.join(out_dir, BASELINE_NAME)
    if not os.path.isfile(path):
        return None
    try:
        return json.load(open(path, encoding="utf-8"))
    except ValueError:
        return None


def post_handover(rec: Dict[str, Any], frozen: Dict[str, Any]) -> Dict[str, Any]:
    """Advisories on baseline components that the frozen baseline did not know about (TR 4.7)."""
    baseline_ids = set(frozen.get("finding_ids") or [])
    baseline_comps = {_canon(c.get("name")): c for c in frozen.get("components") or []}
    flagged: List[Dict[str, Any]] = []
    known: List[Dict[str, Any]] = []
    for v in rec.get("vulns") or []:
        pkg = v.get("package")
        # fail-closed: a finding with no package info cannot be proven OFF a baseline component, so it counts
        # as on-baseline until someone identifies the package
        on_base = pkg is None or _canon(pkg) in baseline_comps
        row = {"id": v.get("id"), "package": pkg, "version": v.get("version"),
               "on_baseline_component": on_base,
               "new_since_handover": str(v.get("id")) not in baseline_ids}
        if row["new_since_handover"] and row["on_baseline_component"]:
            row["note"] = "인수 후 발견 — 기준선 부품에 새로 붙은 권고 (상대 당사자에게 영향을 줄 수 있다; TR 4.7)"
            flagged.append(row)
        else:
            known.append(row)
    return {"schema": SCHEMA, "disclaimer": DISCLAIMER, "baseline_commit": frozen.get("commit", ""),
            "component_hash_matches": _component_hash(rec) == frozen.get("component_hash"),
            "post_handover": flagged, "known_at_handover": known,
            "counts": {"post_handover": len(flagged), "known": len(known)}}


def _canon(name: str) -> str:
    return str(name or "").strip().lower()


def evaluate(triage_entries: Dict[str, Any]) -> Dict[str, Any]:
    """The assumption register (TR 4.8): every not_affected-mapping decision carries an assumption.

    Verified = the decision's note references evidence (a repo path, an evidence id or a long hash).
    Fail-closed: unverified assumptions stay listed — they never silence the finding silently, and the
    VEX export already keeps the finding affected until the justification+reason gates pass.
    """
    register: List[Dict[str, Any]] = []
    verified = 0
    for key, e in triage_entries.items():
        if str(e.get("status")) != "false-positive":
            continue
        note = str(e.get("note") or "")
        has_evidence = bool(EVIDENCE_RE.search(note))
        register.append({"key": key, "assumption": note[:160],
                         "justification": e.get("justification") or "",
                         "verified": has_evidence,
                         "state": "verified" if has_evidence else "unverified",
                         "by": e.get("by") or "", "expires": e.get("expires") or ""})
        verified += 1 if has_evidence else 0
    return {"schema": SCHEMA, "disclaimer": DISCLAIMER, "register": register,
            "counts": {"assumptions": len(register), "verified": verified, "unverified": len(register) - verified},
            "note": "미검증 가정은 발견을 조용히 지우지 않는다 — 평가자에게 그대로 보인다 (fail-closed)"}
