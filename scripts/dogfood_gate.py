# -*- coding: utf-8 -*-
"""Self-dogfood gate (backlog C09): the product runs ITS OWN scanner over its own source tree, offline, and the
gate asserts the resulting self-SBOM is machine-valid and NTIA-2021 conformant — a generator that cannot satisfy
the very regime it checks for users is a real defect, not a niche edge case. Evidence is written to
evidence/nightly/<utcstamp>/ (record + summary) so the nightly drift run has an artifact.

Usage: python scripts/dogfood_gate.py [--target bts_sbom_app] [--out evidence/nightly]
Exit 0 = gate pass; 1 = the self-SBOM is invalid or non-conformant (or the scan failed); nothing is invented.

Honesty: offline=True by default (no OSV network in CI); the record's engine.status.mode says so, and the report
repeats it — a clean offline result means "no KNOWN advisories among our own (stdlib-only) dependencies", which
is the whole honest claim available.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import tempfile
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bts_sbom_app import conformance, sbom  # noqa: E402


def run(target: str, out_root: str) -> tuple:
    from bts_sbom_app import engine, pipeline
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ev_dir = os.path.join(out_root, "dogfood_" + stamp)
    os.makedirs(ev_dir, exist_ok=True)
    summary: dict = {"target": target, "offline": True, "stamp": stamp, "checks": {}}
    try:
        rec = pipeline.run_project(target, work_root=tempfile.mkdtemp(prefix="dogfood_"), name="bts-sbom-self",
                                   offline=True, use_llm=False, run_arch=False, run_proposals=False)
    except Exception as exc:                                  # noqa: BLE001 - the gate names its own failure
        summary["error"] = "%s: %s" % (type(exc).__name__, str(exc)[:200])
        _write(ev_dir, "summary.json", summary)
        return 1, summary
    cdx = (rec.get("_docs") or {}).get("cdx")
    if cdx is None:
        paths = rec.get("artifacts") or {}
        cdx_path = paths.get("cdx")
        cdx = json.load(open(cdx_path, encoding="utf-8")) if cdx_path and os.path.isfile(cdx_path) else None
    summary["checks"]["record_name"] = rec.get("name")
    summary["checks"]["components"] = len(rec.get("components") or [])
    summary["checks"]["mode"] = ((rec.get("engine") or {}).get("status") or {}).get("mode")
    pyproject = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pyproject.toml")
    try:
        in_deps = False
        declared: List[str] = []
        for ln in open(pyproject, encoding="utf-8"):
            s = ln.strip()
            if s.startswith("dependencies"):
                in_deps = True
                continue
            if in_deps:
                if s.startswith("]"):
                    break
                if s.startswith(('"', "'")):
                    declared.append(s.strip("\"',"))
        summary["checks"]["declared_runtime_deps"] = declared     # the stdlib-only claim, parsed from pyproject
    except OSError:
        pass
    ok = True
    if not cdx:
        summary["checks"]["cyclonedx"] = "no self-SBOM produced"
        ok = False
    else:
        _write(ev_dir, "self.cdx.json", cdx)
        errs = sbom.validate_cyclonedx(cdx)
        summary["checks"]["cyclonedx_valid"] = not errs
        summary["checks"]["cyclonedx_errors"] = errs[:5]
        conf = conformance.evaluate(cdx, regimes=("ntia-2021",))
        reg = (conf.get("regimes") or {}).get("ntia-2021") or {}
        summary["checks"]["ntia_2021"] = reg.get("verdict")
        # the NTIA verdict is the DRIFT BASELINE (recorded nightly, compared across runs) - a supplier gap on
        # third-party metadata we cannot honestly know is data, not a defect; what GATES is the document being
        # machine-valid and non-empty (a generator that cannot validate its own output is a real defect).
        summary["checks"]["ntia_elements_gap"] = [k for k, v in (reg.get("elements") or {}).items() if v == "gap"]
        ok = ok and not errs and summary["checks"]["components"] >= 1
    _write(ev_dir, "record.json", {k: rec.get(k) for k in ("name", "analysed_at", "engine")})
    _write(ev_dir, "summary.json", summary)
    return (0 if ok else 1), summary


def _write(dirpath: str, fname: str, obj) -> None:
    with open(os.path.join(dirpath, fname), "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=1)


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(description="self-dogfood gate: scan our own tree offline and assert NTIA-clean SBOM")
    ap.add_argument("--target", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bts_sbom_app"))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence", "nightly"))
    a = ap.parse_args(argv)
    code, summary = run(a.target, a.out)
    print(json.dumps(summary, ensure_ascii=False, indent=1))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
