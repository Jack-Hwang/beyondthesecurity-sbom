"""Supply-chain bench regression gate (backlog C59): scripts/supply_chain_gate.py records a bench history
(``evidence/supply_chain/bench/bench_<stamp>.json``, plus ``bench_latest.json``) - but nothing ever READ the
history back, so a serving image could get slower run over run and only a human diffing files would notice.
:func:`gate` compares the two newest bench records per endpoint and fails when a p95 regressed beyond the
allowed factor. Fewer than two records is UNDECIDABLE (named as such, never a pass), and a bench whose HTTP
status was not 200 fails outright - a fast 500 is not a fast answer."""
from __future__ import annotations

import glob
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "bts-sbom.bench-gate.v1"
BENCH_DIR = os.path.join("evidence", "supply_chain", "bench")
_RECORD = re.compile(r"^bench_(\d{8}T\d{6}Z)\.json$")


def _load(path: str) -> Optional[Dict[str, Any]]:
    try:
        rec = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return rec.get("bench") if isinstance(rec, dict) else None


def gate(evidence: str, max_p95_factor: float = 1.5) -> Dict[str, Any]:
    """(report) - p95 regression gate over the bench history inside ``evidence``. The factor is generous (a bench
    on a shared machine is noisy) but not unlimited; a regression beyond it is a named finding per endpoint."""
    d = evidence if evidence.rstrip("/\\").endswith("bench") else os.path.join(evidence, "supply_chain", "bench")
    records: List[Tuple[str, Dict[str, Any]]] = []
    for p in sorted(glob.glob(os.path.join(d, "bench_*.json"))):
        m = _RECORD.match(os.path.basename(p))
        if m:
            b = _load(p)
            if b:
                records.append((m.group(1), b))
    if len(records) < 2:
        return {"schema": SCHEMA, "pass": False, "undecidable": "fewer than two bench records (%d) - a regression gate needs history" % len(records),
                "findings": []}
    latest_stamp, latest = records[-1]
    prior_stamp, prior = records[-2]
    findings: List[str] = []
    checked = 0
    lend, pend = latest.get("endpoints") or {}, prior.get("endpoints") or {}
    for ep in sorted(set(lend) | set(pend)):
        cur, old = lend.get(ep) or {}, pend.get(ep) or {}
        if cur.get("http_status") != 200:
            findings.append("%s: latest bench HTTP %s (a fast failure is still a failure)" % (ep, cur.get("http_status")))
            continue
        if old.get("http_status") != 200:
            continue                                          # the prior run was broken: no honest comparison exists
        c95, o95 = cur.get("p95_ms"), old.get("p95_ms")
        if isinstance(c95, (int, float)) and isinstance(o95, (int, float)) and o95 > 0:
            checked += 1
            if c95 > o95 * max_p95_factor:
                findings.append("%s: p95 %.1fms regressed beyond %.1fx of the prior %.1fms" % (ep, c95, max_p95_factor, o95))
    if not checked and not findings:
        return {"schema": SCHEMA, "pass": False, "undecidable": "no comparable endpoint timings between %s and %s" % (prior_stamp, latest_stamp),
                "findings": []}
    return {"schema": SCHEMA, "pass": not findings, "comparing": {"prior": prior_stamp, "latest": latest_stamp},
            "endpoints_checked": checked, "findings": findings}
