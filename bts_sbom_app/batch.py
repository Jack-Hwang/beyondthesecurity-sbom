"""Batch runner: many sources -> per-project evidence + one aggregate summary (the loop-engineering measurement)."""
from __future__ import annotations

import concurrent.futures as cf
import os
import time
from typing import Any, Dict, List, Optional

from . import engine, net, pipeline, report
from .llm import ChatClient
from .util import now_iso, read_json, sha256_text, stamp, write_json


def source_id(s: Any) -> str:
    """Stable id for one batch source entry: sha256 of its src (+ ref, if given), first 8 hex chars.

    The same source (by src/ref) always yields the same id, including across separate ``run_batch``/``retry_failed``
    calls and process runs, so a prior run's failed entries can be found again in a fresh ``sources`` list.
    """
    if isinstance(s, str):
        src, ref = s, ""
    elif isinstance(s, dict):
        src, ref = str(s.get("src") or ""), str(s.get("ref") or "")
    else:
        src, ref = str(s), ""
    key = src + "@" + ref if ref else src
    return sha256_text(key)[:8]


def aggregate(recs: List[Dict[str, Any]]) -> Dict[str, Any]:
    ok = [r for r in recs if not r.get("error")]
    errs = [r for r in recs if r.get("error")]
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
    props = [(r.get("metrics") or {}).get("proposal_source") for r in ok]
    if not errs:
        status = "success"
    elif not ok:
        status = "failure"
    else:
        status = "partial_success"
    return {
        "projects": len(recs), "errors": len(recs) - len(ok), "project_success_rate": round(len(ok) / len(recs), 3) if recs else None,
        "status": status, "failed_sources": [{"id": r.get("id"), "name": r.get("name"), "error": r.get("error")} for r in errs],
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
    """Kept/dropped/repaired counts for exaone-sourced proposals, read from each record's `metrics` (not the
    raw `proposals` payload): `metrics` is exactly what survives into the trimmed `projects[]` entries written
    to `summary.json`, so a record reinflated from a prior run (`_reinflate`, used by `retry_failed`) carries
    these counts too, without ever needing the full `items`/`dropped` payload back. A prior `summary.json`
    written before these fields existed degrades to 0 for those records instead of raising `KeyError`."""
    exa = [(r.get("metrics") or {}) for r in ok if (r.get("metrics") or {}).get("proposal_source") == "exaone"]
    kept = sum(m.get("proposal_kept") or 0 for m in exa)
    dropped = sum(m.get("proposal_dropped") or 0 for m in exa)
    return {"exaone": sum(1 for p in props if p == "exaone"), "deterministic": sum(1 for p in props if p == "deterministic"),
            "kept": kept, "dropped": dropped, "repaired": sum(m.get("proposal_repaired") or 0 for m in exa),
            "keep_rate": round(kept / (kept + dropped), 3) if kept + dropped else None}


def _count(xs: List[Any]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for x in xs:
        out[str(x)] = out.get(str(x), 0) + 1
    return out


def _run_one(s: Any, *, work_root: str, run_dir: Optional[str], settings: Dict[str, Any], client: Optional[ChatClient],
             cache_dir: str) -> Dict[str, Any]:
    """Analyse one batch source entry, tagging the result with its stable `source_id`. Shared by `run_batch` and
    `retry_failed` so a retry re-analyses a source exactly the same way a first pass would."""
    sid = source_id(s)
    if isinstance(s, str):
        s = {"src": s}
    if not isinstance(s, dict) or not s.get("src"):
        return {"name": str(s)[:60], "error": "batch entry needs a source: a string or an object with a 'src' key", "metrics": {}, "id": sid}
    kw = dict(settings)
    for k in ("ref", "depth"):
        if s.get(k) is not None:
            kw[k] = s[k]
    t0 = time.time()
    u0 = dict(client.usage) if client is not None else {}
    rec = pipeline.run_project(s["src"], work_root=work_root, out_dir=run_dir, name=s.get("name"), client=client, cache_dir=cache_dir, **kw)
    rec["id"] = sid
    rec["s"] = round(time.time() - t0, 1)             # C42: per-case wall time - the loop can see WHERE a pass spent its minutes
    if client is not None:                            # C42: this case's own token spend (the cost half of the metric)
        rec["llm_tokens"] = {"prompt_tokens": client.usage["prompt_tokens"] - u0.get("prompt_tokens", 0),
                             "completion_tokens": client.usage["completion_tokens"] - u0.get("completion_tokens", 0)}
    _carry_proposal_counts(rec)
    return rec


def _carry_proposal_counts(rec: Dict[str, Any]) -> None:
    """Add proposal kept/dropped/repaired counts onto `rec['metrics']`, derived from the full `rec['proposals']`
    payload, so they survive into the trimmed `projects[]` entries persisted to `summary.json` - and so a record
    reinflated from a prior run (`_reinflate`) carries everything `_proposal_stats` needs without the full
    (untrimmed) `items`/`dropped` lists ever being written back out."""
    m = rec.get("metrics")
    if not isinstance(m, dict):
        return
    p = rec.get("proposals") or {}
    m["proposal_kept"] = len(p.get("items") or [])
    m["proposal_dropped"] = sum((p.get("dropped") or {}).values())
    m["proposal_repaired"] = p.get("repaired", 0) or 0


def _reinflate(p: Dict[str, Any]) -> Dict[str, Any]:
    """Rebuild an `aggregate()`-compatible record from a trimmed prior `projects[]` entry: `summary.json` keeps only
    name/id/error/metrics/stage_errors per project, which is all `aggregate()` actually reads (patch status and
    proposal source are duplicated onto `metrics` for exactly this reason - see `pipeline.metrics`)."""
    m = p.get("metrics") or {}
    return {"name": p.get("name"), "id": p.get("id"), "error": p.get("error"), "metrics": m, "stage_errors": p.get("stage_errors"),
            "patch": {"status": m.get("patch_status")}, "proposals": {"source": m.get("proposal_source")}}


def run_batch(sources: List[Dict[str, Any]], out_root: str, *, tag: str = "run", work_root: Optional[str] = None, jobs: int = 1,
              client: Optional[ChatClient] = None, settings: Optional[Dict[str, Any]] = None, write: bool = True) -> Dict[str, Any]:
    """sources: [{name, src, ref?, depth?}]. settings are forwarded to pipeline.run_project (patch, approved, use_llm, ...)."""
    settings = dict(settings or {})
    t0 = time.time()
    net.reset_stats()
    work_root = work_root or os.path.join(out_root, "work")
    cache_dir = settings.pop("cache_dir", None) or os.path.join(out_root, "cache")
    run_dir = os.path.join(out_root, "runs", "%s_%s" % (stamp(), tag))

    def one(s: Any) -> Dict[str, Any]:
        return _run_one(s, work_root=work_root, run_dir=(run_dir if write else None), settings=settings, client=client, cache_dir=cache_dir)

    if jobs > 1:
        with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
            recs = list(ex.map(one, sources))
    else:
        recs = [one(s) for s in sources]
    agg = aggregate(recs)
    summary = {"schema": "bts-sbom.batch.v1", "tag": tag, "generated_at": now_iso(),
               "settings": {k: v for k, v in settings.items() if k not in ("deliver_kw", "policy")},
               "core": engine.core_info(), "llm": client.describe() if client else None, "net": dict(net.STATS),
               "elapsed_s": round(time.time() - t0, 1), "summary": agg,
               "projects": [{"name": r["name"], "id": r.get("id"), "error": r.get("error"), "metrics": r.get("metrics"), "stage_errors": r.get("stage_errors")} for r in recs]}
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


def retry_failed(sources: List[Dict[str, Any]], prior_run_dir: str, out_root: Optional[str] = None, *, tag: str = "retry",
                  work_root: Optional[str] = None, jobs: int = 1, client: Optional[ChatClient] = None,
                  settings: Optional[Dict[str, Any]] = None, write: bool = True) -> Dict[str, Any]:
    """Re-analyse only the sources that failed in a prior run, merge the fresh results into the prior set by
    `source_id` (0 duplicate ids), and recompute the same aggregate shape `run_batch` produces.

    ``prior_run_dir`` is a run directory written by `run_batch` (or a previous `retry_failed`); it must contain a
    `summary.json`. ``sources`` is looked up by `source_id` to find the entries to re-run - pass the same (or a
    superset of the) sources given to the original run. A failed id with no matching entry in `sources` cannot be
    retried: it is reported under ``missing_ids`` in the result and kept recorded as failed rather than silently
    dropped (absent evidence is never a pass).
    """
    settings = dict(settings or {})
    prior = read_json(os.path.join(prior_run_dir, "summary.json"))
    if not isinstance(prior, dict):
        return {"summary": {"schema": "bts-sbom.batch.v1", "tag": tag, "generated_at": now_iso(),
                            "error": "no prior summary.json found in %r" % prior_run_dir,
                            "summary": aggregate([]), "projects": []}, "records": []}
    prior_projects = prior.get("projects") or []
    failed_ids = [p.get("id") for p in prior_projects if p.get("error") and p.get("id")]

    by_id: Dict[str, Any] = {}
    for s in sources:
        by_id.setdefault(source_id(s), s)
    retry_ids = [i for i in failed_ids if i in by_id]
    missing_ids = [i for i in failed_ids if i not in by_id]

    out_root = out_root or os.path.dirname(os.path.dirname(os.path.normpath(prior_run_dir)))
    t0 = time.time()
    net.reset_stats()
    work_root = work_root or os.path.join(out_root, "work")
    cache_dir = settings.pop("cache_dir", None) or os.path.join(out_root, "cache")
    run_dir = os.path.join(out_root, "runs", "%s_%s" % (stamp(), tag)) if write else None

    def one(s: Any) -> Dict[str, Any]:
        return _run_one(s, work_root=work_root, run_dir=run_dir, settings=settings, client=client, cache_dir=cache_dir)

    retry_sources = [by_id[i] for i in retry_ids]
    if jobs > 1 and retry_sources:
        with cf.ThreadPoolExecutor(max_workers=jobs) as ex:
            fresh = list(ex.map(one, retry_sources))
    else:
        fresh = [one(s) for s in retry_sources]
    fresh_by_id = {r.get("id"): r for r in fresh}

    merged: List[Dict[str, Any]] = []
    seen: Any = set()
    for p in prior_projects:
        pid = p.get("id")
        rec = fresh_by_id.get(pid) if pid is not None else None
        merged.append(rec if rec is not None else _reinflate(p))
        if pid is not None:
            seen.add(pid)
    for pid, rec in fresh_by_id.items():          # a retried id absent from the prior project list (should not normally happen)
        if pid not in seen:
            merged.append(rec)
            seen.add(pid)

    agg = aggregate(merged)
    summary = {"schema": "bts-sbom.batch.v1", "tag": tag, "generated_at": now_iso(),
               "settings": {k: v for k, v in settings.items() if k not in ("deliver_kw", "policy")},
               "core": engine.core_info(), "llm": client.describe() if client else None, "net": dict(net.STATS),
               "elapsed_s": round(time.time() - t0, 1), "summary": agg,
               "retried_ids": retry_ids, "missing_ids": missing_ids, "prior_run_dir": prior_run_dir,
               "projects": [{"name": r.get("name"), "id": r.get("id"), "error": r.get("error"), "metrics": r.get("metrics"),
                            "stage_errors": r.get("stage_errors")} for r in merged]}
    if write:
        os.makedirs(run_dir, exist_ok=True)
        write_json(os.path.join(run_dir, "summary.json"), summary)
        write_json(os.path.join(out_root, "latest.json"), summary)
        summary["run_dir"] = run_dir
    return {"summary": summary, "records": merged}
