"""Batch runner: many sources -> per-project evidence + one aggregate summary (the loop-engineering measurement)."""
from __future__ import annotations

import concurrent.futures as cf
import os
import time
from typing import Any, Dict, List, Optional

from . import engine, net, pipeline, report
from .llm import ChatClient
from .util import now_iso, stamp, write_json


def aggregate(recs: List[Dict[str, Any]]) -> Dict[str, Any]:
    ok = [r for r in recs if not r.get("error")]
    ms = [r["metrics"] for r in ok]
    comps = sum(m["components"] for m in ms)
    resolved = sum(m["license_resolved"] or 0 for m in ms)
    sev: Dict[str, int] = {}
    src: Dict[str, int] = {}
    for m in ms:
        for k, v in m["severity"].items():
            sev[k] = sev.get(k, 0) + v
        for k, v in (m["license_sources"] or {}).items():
            src[k] = src.get(k, 0) + v
    ups = sum(m["plans_upgrade"] for m in ms)
    clean = sum(m["plans_verified_clean"] for m in ms)
    ref_rates = [m["sbom_ref_rate"] for m in ms if m["sbom_ref_rate"] is not None]
    patched = [r for r in ok if (r.get("patch") or {}).get("status") not in (None, "not_requested", "not_approved")]
    withfix = [r for r in patched if r["metrics"]["plans_upgrade"]]
    applied = [r for r in withfix if r["metrics"]["patch_applied_components"] > 0]
    vul_before = sum(r["metrics"]["vulns"] for r in withfix)
    fixed = sum(r["metrics"]["patch_rescan_fixed"] for r in withfix)
    est = sum(r["metrics"]["patch_estimated_fixed"] for r in withfix)
    graph = [r for r in ok if r["metrics"]["arch_edges"] > 0]
    props = [(r.get("proposals") or {}).get("source") for r in ok]
    return {
        "projects": len(recs), "errors": len(recs) - len(ok), "project_success_rate": round(len(ok) / len(recs), 3) if recs else None,
        "components": comps, "vulns": sum(m["vulns"] for m in ms), "severity": sev,
        "license_resolved_rate": round(resolved / comps, 3) if comps else None, "license_sources": src,
        "sbom_ref_rate": round(sum(ref_rates) / len(ref_rates), 3) if ref_rates else None,
        "cyclonedx_valid_rate": round(sum(1 for m in ms if m["cyclonedx_valid"]) / len(ms), 3) if ms else None,
        "spdx_valid_rate": round(sum(1 for m in ms if m["spdx_valid"]) / len(ms), 3) if ms else None,
        "plans_upgrade": ups, "plans_verified_clean": clean, "plan_verified_rate": round(clean / ups, 3) if ups else None,
        "patch": {"projects_patched": len(patched), "projects_with_plans": len(withfix), "projects_applied": len(applied),
                  "vulns_before": vul_before, "rescan_fixed": fixed, "estimated_fixed": est,
                  "rescan_fix_rate": round(fixed / vul_before, 3) if vul_before else None,
                  "stop_reasons": _count([(r.get("patch") or {}).get("status") for r in patched])},
        "fix_applied_rate": round(len(applied) / len(withfix), 3) if withfix else None,
        "arch_coverage": round(len(graph) / len(ok), 3) if ok else None,
        "analysis_s_avg": round(sum(m["elapsed_s"] or 0 for m in ms) / len(ms), 1) if ms else None,
        "stage_errors": sum(m["stage_errors"] for m in ms),
        "proposals": _proposal_stats(ok, props),
    }


def _proposal_stats(ok: List[Dict[str, Any]], props: List[Any]) -> Dict[str, Any]:
    exa = [r["proposals"] for r in ok if (r.get("proposals") or {}).get("source") == "exaone"]
    kept = sum(len(p["items"]) for p in exa)
    dropped = sum(sum((p.get("dropped") or {}).values()) for p in exa)
    return {"exaone": sum(1 for p in props if p == "exaone"), "deterministic": sum(1 for p in props if p == "deterministic"),
            "kept": kept, "dropped": dropped, "repaired": sum(p.get("repaired", 0) for p in exa),
            "keep_rate": round(kept / (kept + dropped), 3) if kept + dropped else None}


def _count(xs: List[Any]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for x in xs:
        out[str(x)] = out.get(str(x), 0) + 1
    return out


def run_batch(sources: List[Dict[str, Any]], out_root: str, *, tag: str = "run", work_root: Optional[str] = None, jobs: int = 1,
              client: Optional[ChatClient] = None, settings: Optional[Dict[str, Any]] = None, write: bool = True) -> Dict[str, Any]:
    """sources: [{name, src, ref?, depth?}]. settings are forwarded to pipeline.run_project (patch, approved, use_llm, ...)."""
    settings = dict(settings or {})
    t0 = time.time()
    net.reset_stats()
    work_root = work_root or os.path.join(out_root, "work")
    cache_dir = settings.pop("cache_dir", None) or os.path.join(out_root, "cache")
    run_dir = os.path.join(out_root, "runs", "%s_%s" % (stamp(), tag))

    def one(s: Dict[str, Any]) -> Dict[str, Any]:
        kw = dict(settings)
        for k in ("ref", "depth"):
            if s.get(k) is not None:
                kw[k] = s[k]
        return pipeline.run_project(s["src"], work_root=work_root, out_dir=run_dir if write else None, name=s.get("name"), client=client,
                                    cache_dir=cache_dir, **kw)

    if jobs > 1:
        with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
            recs = list(ex.map(one, sources))
    else:
        recs = [one(s) for s in sources]
    agg = aggregate(recs)
    summary = {"schema": "sbomplus.batch.v1", "tag": tag, "generated_at": now_iso(),
               "settings": {k: v for k, v in settings.items() if k not in ("deliver_kw", "policy")},
               "core": engine.core_info(), "llm": client.describe() if client else None, "net": dict(net.STATS),
               "elapsed_s": round(time.time() - t0, 1), "summary": agg,
               "projects": [{"name": r["name"], "error": r.get("error"), "metrics": r.get("metrics"), "stage_errors": r.get("stage_errors")} for r in recs]}
    if write:
        os.makedirs(run_dir, exist_ok=True)
        write_json(os.path.join(run_dir, "summary.json"), summary)
        write_json(os.path.join(out_root, "latest.json"), summary)
        with open(os.path.join(run_dir, "summary.md"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report.batch_md(summary, recs))
        with open(os.path.join(run_dir, "summary.html"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(report.batch_html(summary, recs))
        for r in recs:
            if not r.get("error"):
                with open(os.path.join(run_dir, r["name"], r["name"] + ".md"), "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(report.project_md(r))
        summary["run_dir"] = run_dir
    return {"summary": summary, "records": recs}
