"""Attack-feasibility inputs, CWE aggregation and the evidence bundle (task 31, brief: TR 8477 review P1-G/E/H).

* ``attack_inputs(rec)`` — decomposes the CVSS v3 (AV/AC/PR/UI) and v4 (AV/AC/AT/PR/UI) metrics of each finding
  into per-finding inputs for an exploitability assessment. **INPUTS ONLY — no rating is computed** (TR 6.11: the
  rating belongs to the TARA; the review doc §6 forbids the tool producing one).
* ``cwe_top(rec[, recs])`` — aggregates the CWE ids captured from OSV ``database_specific.cwe_ids``; the seed of the
  "review against the most common CWEs" checklist (TR tables 3-5) and of the same-weakness-class view.
* ``bundle(rec, out_dir)`` — SHA-256 manifest of the artifacts an assessor receives (SBOM, VEX, record, report,
  diff) plus tool/core versions and the timestamp. Content addressing only — no signatures (keys are out of scope).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, Iterable, List, Optional

from . import cvss

SCHEMA = "bts-sbom.evidence.v1"
DISCLAIMER = "엔지니어링 입력이며 공격 실현 가능성 등급이 아닙니다 — 등급 산정은 TARA 의 몫입니다"
V3_METRICS = ("AV", "AC", "PR", "UI")
V4_METRICS = ("AV", "AC", "AT", "PR", "UI")


def _vector_metrics(vec: str, metrics: Iterable[str]) -> Dict[str, str]:
    parsed = cvss.parse_vector(vec)
    return {m: str(parsed.get(m) or "") for m in metrics}


def attack_inputs(rec: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Per-finding metric decomposition. Findings without a vector carry vectors: {} (never fabricated)."""
    out: List[Dict[str, Any]] = []
    for v in rec.get("vulns") or []:
        entry: Dict[str, Any] = {"id": v.get("id"), "package": v.get("package"), "version": v.get("version"),
                                 "note": "inputs only - no exploitability rating (TR 6.11)"}
        v3 = str(v.get("cvss_v3_vector") or "")
        v4 = str(v.get("cvss_v4_vector") or "")
        if v3:
            entry["v3"] = _vector_metrics(v3, V3_METRICS)
        if v4:
            entry["v4"] = _vector_metrics(v4, V4_METRICS)
        if not v3 and not v4:
            entry["vectors"] = {}
        out.append(entry)
    return out


def cwe_top(rec: Dict[str, Any], *more_recs: Dict[str, Any], n: int = 10) -> Dict[str, Any]:
    """Aggregate CWE ids across findings of one or more records. Absent CWE fields count as 0 (never guessed)."""
    counts: Dict[str, int] = {}
    for r in (rec,) + more_recs:
        for v in r.get("vulns") or []:
            for c in v.get("cwe") or []:
                counts[str(c)] = counts.get(str(c), 0) + 1
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:max(0, n)]
    return {"schema": SCHEMA, "disclaimer": DISCLAIMER, "total_findings_with_cwe": sum(counts.values()),
            "distinct_cwe": len(counts), "top": [{"cwe": k, "count": v} for k, v in top]}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def bundle(rec: Dict[str, Any], out_dir: str, *, extra_files: Optional[List[str]] = None) -> Dict[str, Any]:
    """Write <out_dir>/bundle.json listing every artifact an assessor receives, with SHA-256 and tool versions."""
    artifacts: List[Dict[str, str]] = []
    art = rec.get("artifacts") or {}
    entries: List[tuple] = []
    for kind in ("cdx", "spdx", "vex"):
        if art.get(kind):
            entries.append((kind, str(art[kind])))
    any_path = next((str(v) for v in art.values() if v), None)
    if any_path:                                                       # the slim record json lives beside the artifacts
        entries.append(("record", os.path.join(os.path.dirname(any_path), str(rec.get("name") or "") + ".json")))
    entries += [("extra", p) for p in (extra_files or [])]
    for kind, p in entries:
        if p and os.path.isfile(p):
            artifacts.append({"kind": kind, "path": os.path.relpath(p, os.path.dirname(out_dir) or ".").replace("\\", "/"),
                              "bytes": os.path.getsize(p), "sha256": _sha256(p)})
    manifest = {"schema": SCHEMA, "disclaimer": DISCLAIMER,
                "target": rec.get("name"), "commit": (rec.get("lineage") or {}).get("commit", ""),
                "tool": "bts_sbom_app", "core": rec.get("engine", {}).get("core", ""),
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "artifacts": artifacts,
                "note": "content addressing only - signatures need a key holder and are out of scope"}
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "bundle.json")
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    manifest["bundle_path"] = out_path
    return manifest
