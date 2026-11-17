"""One project, end to end: source -> work copy -> SBOM/vulns -> licenses -> remediation plan -> (approved) patch + re-scan
-> delivery -> architecture -> industry reports -> AI proposals -> evidence files.

Every stage is timed and isolated: a failing stage is recorded in ``stage_errors`` and the rest of the run continues, so a
partial result is always visible instead of an exception that hides everything. Nothing here pushes, writes to the origin
or runs code from the analysed project (delivery targets that do are separate, explicit flags in ``deliver``).
"""
from __future__ import annotations

import os
import shutil
import time
from typing import Any, Callable, Dict, List, Optional

from . import ai, arch as archmod, changes as changesmod, conformance, deliver as delivermod, engine, licenses, patch as patchmod, remediate, sbom, sectors, workspace
from .llm import ChatClient
from .util import safe_name, tree_hash, write_json

PROJECT_SCHEMA = "bts-sbom.project.v1"
# Records written before the identifiers were renamed carry this older id. Same layout, so they must keep loading;
# nothing writes it any more.
PROJECT_SCHEMAS_ACCEPTED = (PROJECT_SCHEMA, "sbomplus.project.v1")


class _Stages:
    def __init__(self, rec: Dict[str, Any]):
        self.rec = rec
        rec["timings"] = {}
        rec["stage_errors"] = {}

    def run(self, name: str, fn: Callable[[], Any], default: Any = None) -> Any:
        t = time.time()
        try:
            return fn()
        except Exception as exc:                                   # noqa: BLE001 - recorded, never swallowed silently
            self.rec["stage_errors"][name] = "%s: %s" % (type(exc).__name__, str(exc)[:240])
            return default
        finally:
            self.rec["timings"][name] = round(time.time() - t, 2)


def _ids(vulns: List[Dict[str, Any]]) -> set:
    return {(v["id"], v["package"].lower(), v["version"]) for v in vulns}


def severity_counts(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
    return engine.severity_counts(vulns)


def run_project(src: str, *, work_root: str, out_dir: Optional[str] = None, name: Optional[str] = None, ref: Optional[str] = None,
                depth: int = 200, offline: bool = False, online_license: bool = True, license_extra_registries: bool = True, patch: bool = False, approved: bool = False,
                approval_token: Optional[str] = None, rounds: int = 2, verify_rounds: int = 3,
                deliver_target: str = "branch", deliver_kw: Optional[Dict[str, Any]] = None, use_llm: bool = True,
                client: Optional[ChatClient] = None, industries: Optional[List[str]] = None, policy: Optional[Dict[str, Any]] = None,
                cache_dir: Optional[str] = None, lang: str = "ko", arch_online: bool = False, scanner: Any = None,
                run_arch: bool = True, run_proposals: bool = True, engine_opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    t0 = time.time()
    rec: Dict[str, Any] = {"schema": PROJECT_SCHEMA, "name": name or safe_name(os.path.basename(src.rstrip("/\\")) or "project"),
                           "source": src, "ref": ref or "", "components": [], "vulns": [], "plans": [], "license": {}, "arch": {},
                           "sectors": {}, "patch": {}, "proposals": {}, "sbom_check": {}, "engine": {"core": ""}, "error": None}
    S = _Stages(rec)
    try:
        kind = workspace.normalize_source(src)
    except ValueError:
        kind = {}                                    # prepare() reports the refusal reason
    origin = kind.get("path") if kind.get("kind") == "local" else None
    origin_hash = tree_hash(origin) if origin and os.path.isdir(origin) else None

    ws = S.run("prepare", lambda: workspace.prepare(src, work_root, ref=ref, depth=depth, name=rec["name"]))
    if not ws or not ws.get("ok"):
        rec["error"] = (ws or {}).get("error") or "workspace preparation failed"
        rec["elapsed_s"] = round(time.time() - t0, 1)
        return rec
    path = ws["path"]
    rec.update(path=path, kind=ws["kind"], lineage=ws["lineage"], name=ws["name"] if not name else rec["name"])

    eopts = dict(engine_opts or {})
    ana = S.run("analyze", lambda: engine.analyze(path, offline=offline, scanner=scanner, **eopts))
    if ana is None:
        rec["error"] = "analysis failed: " + rec["stage_errors"].get("analyze", "?")
        rec["elapsed_s"] = round(time.time() - t0, 1)
        return rec
    rec["components"], rec["vulns"] = ana["components"], ana["vulns"]
    rec["engine"] = {"core": S.run("core_version", engine.core_version, ""), "sources": ana["sources"], "unsupported": ana["unsupported"],
                     "status": ana["status"], "adjustments": ana["adjustments"], "data_status": ana["data_status"], "vulnerability_presence": ana["vulnerability_presence"],
                     "notes": ana["notes"]}

    lic_stats = S.run("licenses", lambda: licenses.resolve(rec["components"], path, online=online_license and not offline, cache_dir=cache_dir,
                                                         extra_registries=license_extra_registries), {})
    tree = S.run("license_tree", lambda: licenses.scan_tree(path), {})
    rec["license"] = {"stats": lic_stats, "project_license": (tree or {}).get("project_license", ""),
                      "project_license_source": (tree or {}).get("project_license_source", ""), "tree": tree,
                      "policy": licenses.policy_findings(rec["components"], policy, (tree or {}).get("project_license", ""))}

    rec["plans"] = S.run("plan", lambda: remediate.plan(rec["components"], rec["vulns"]), [])
    if rec["plans"] and not offline:
        S.run("verify", lambda: remediate.verify(rec["plans"], max_rounds=verify_rounds))
    rec["plan_summary"] = remediate.summary(rec["plans"])

    def build_sboms() -> None:
        # generation context (CISA 2025 draft): analysing manifests / lockfiles of source is pre-build; a supplied SBOM says nothing about it
        kinds = {str(s.get("type") or "") for s in rec["engine"].get("sources") or []}
        doc = sbom.cyclonedx(rec["name"], rec["components"], rec["vulns"], lineage=rec["lineage"], project_license=rec["license"]["project_license"],
                             lifecycle="pre-build" if kinds and kinds != {"sbom"} else "")
        errs = sbom.validate_cyclonedx(doc)
        spd = S.run("spdx", lambda: sbom.spdx(rec["name"], rec["components"]))
        spd_err = S.run("spdx_validate", lambda: sbom.validate_spdx(spd), ["spdx not built"]) if spd else ["spdx not built"]
        vex = sbom.openvex(rec["name"], rec["vulns"])
        rec["_docs"] = {"cdx": doc, "spdx": spd, "vex": vex}
        rec["sbom_check"] = {"cyclonedx_errors": errs[:10], "cyclonedx_valid": not errs, "ref_integrity": sbom.ref_integrity(doc),
                             "spdx_errors": list(spd_err)[:5], "spdx_valid": bool(spd) and not spd_err,
                             "components": len(doc["components"]), "vulnerabilities": len(doc["vulnerabilities"])}
        rec["sectors"] = S.run("sectors", lambda: sectors.industry_reports(doc, vex, None, industries or sectors.INDUSTRIES), {})
        conf = S.run("conformance", lambda: conformance.evaluate(doc), None)
        rec["conformance"] = conformance.compact(conf) if conf else {}

    S.run("sbom", build_sboms)

    if run_arch:
        rec["arch"] = S.run("arch", lambda: archmod.analyze(path, online=arch_online), {})

    # ---------------------------------------------------------------- patch loop (approval gated, verified by re-scan)
    if patch:
        rec["patch"] = S.run("patch", lambda: _patch_loop(rec, path, approved=approved, token=approval_token, rounds=rounds, offline=offline,
                                                          scanner=scanner, verify_rounds=verify_rounds, engine_opts=eopts), {})
        if rec["patch"].get("status") == "applied" and deliver_target:
            kw = dict(deliver_kw or {})
            if deliver_target == "inplace":
                kw.setdefault("origin", origin)
            rec["patch"]["delivery"] = S.run("deliver", lambda: delivermod.deliver(path, rec["patch"]["last"], target=deliver_target, **kw), {})
    else:
        rec["patch"] = {"status": "not_requested", "approved": False}

    if run_proposals:
        rec["proposals"] = S.run("proposals", lambda: ai.propose(rec, client=client, cache_dir=cache_dir, use_llm=use_llm, lang=lang), {})

    if origin_hash is not None and deliver_target != "inplace":
        rec["origin_unchanged"] = tree_hash(origin) == origin_hash
    rec["elapsed_s"] = round(time.time() - t0, 1)
    rec["metrics"] = metrics(rec)
    if out_dir:
        # what changed since the last analysis of this project (Hub-style change alerts); the previous record is kept as <name>.prev.json
        prev = S.run("changes", lambda: changesmod.load_previous(out_dir, rec["name"]), None)
        if prev:
            d = S.run("changes_diff", lambda: changesmod.diff(prev, rec), None)
            rec["changes"] = changesmod.compact(d) if d else {}
        persist(rec, out_dir)
    return rec


def _patch_loop(rec: Dict[str, Any], path: str, *, approved: bool, token: Optional[str], rounds: int, offline: bool, scanner: Any,
                verify_rounds: int, engine_opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {"approved": bool(approved), "rounds": [], "status": None, "before": {"vulns": len(rec["vulns"])}}
    if not approved:
        pr = patchmod.apply(path, rec["plans"], approved=False)
        out.update(status="not_approved", note=pr["note"], digest=pr["digest"], plans=[p for p in rec["plans"] if p["status"] == "upgrade"][:30])
        return out
    base = workspace.head(path).get("commit", "")
    cur_plans, cur_vulns = rec["plans"], rec["vulns"]
    seen_plan_sets: List[tuple] = []
    applied_total = 0
    last: Dict[str, Any] = {}
    for rnd in range(1, rounds + 1):
        key = tuple(sorted((p["component"], p["safe_version"]) for p in cur_plans if p["status"] == "upgrade"))
        if key in seen_plan_sets:                                  # spinning guard: identical plan twice = no progress possible
            out["status"] = "spinning_stopped"
            break
        seen_plan_sets.append(key)
        pr = patchmod.apply(path, cur_plans, approved=True, token=token if rnd == 1 else None)
        entry = {"round": rnd, "status": pr["status"], "applied": sum(1 for r in pr["results"] if r["status"] == "applied"),
                 "blocked": sum(1 for r in pr["results"] if r["status"] == "blocked"), "manual": sum(1 for r in pr["results"] if r["status"] == "manual"),
                 "results": pr["results"][:60], "regenerate": pr.get("regenerate", [])}
        last = pr
        out["rounds"].append(entry)
        if pr["status"] == "digest_mismatch":
            out["status"] = "digest_mismatch"
            break
        if pr["status"] != "applied":
            if entry["blocked"] and not applied_total:
                out["status"] = "blocked"
                out["note"] = ("approved patch could not be applied: %d candidate(s) blocked by manifest constraints "
                               "(see rounds[].results[].detail)" % entry["blocked"])
            else:
                out["status"] = "applied" if applied_total else "nothing_applied"
            break
        applied_total += entry["applied"]
        after = engine.analyze(path, offline=offline, scanner=scanner, **(engine_opts or {}))
        b, a = _ids(cur_vulns), _ids(after["vulns"])
        # Regression is judged on the findings attributable to the files we EDITED. A lockfile we deliberately did not touch still
        # pins the old versions, so comparing grand totals blamed the patch for findings it cannot influence (measured: a
        # package.json-only npm patch of 134 packages was reverted because ONE new advisory appeared at an upgraded version).
        edited = set(pr.get("changed_files") or [])

        def scoped(vs: List[Dict[str, Any]]) -> set:
            return {(v["id"], v["package"].lower(), v["version"]) for v in vs if any(f in edited for f in v["files"])}

        b_s, a_s = scoped(cur_vulns), scoped(after["vulns"])
        entry.update(vulns_before=len(cur_vulns), vulns_after=len(after["vulns"]), fixed=sorted(i[0] for i in b - a)[:40],
                     introduced=sorted(i[0] for i in a - b)[:40], edited_files=sorted(edited)[:10],
                     scoped_before=len(b_s), scoped_after=len(a_s))
        if len(a_s) > len(b_s):                                   # regression in what we edited: revert the work copy
            patchmod.revert(path, base)
            out["status"] = "regression_reverted"
            out["final_vulns"] = len(rec["vulns"])
            break
        rescan_fixed = len(b - a)
        out.setdefault("rescan_fixed_total", 0)
        out["rescan_fixed_total"] += rescan_fixed
        cur_vulns = after["vulns"]
        if not after["vulns"]:
            out["status"] = "applied"
            break
        cur_plans = remediate.plan(after["components"], after["vulns"])
        if cur_plans and not offline:
            remediate.verify(cur_plans, max_rounds=verify_rounds)
        if rescan_fixed == 0:
            out["status"] = "applied"                              # manifests changed but scanned inputs (lockfiles) did not
            out["note"] = "manifest edits applied; the scanner reads lockfiles that still pin the old versions - regenerate them (see regenerate) to complete the fix"
            break
    else:
        out["status"] = "applied" if applied_total else "nothing_applied"
    if out["status"] is None:
        out["status"] = "applied" if applied_total else "nothing_applied"
    out.update(applied_components=applied_total, base_commit=base, last=last, branch=last.get("branch"), commit=last.get("commit"),
               regenerate=sorted({x for r in out["rounds"] for x in r.get("regenerate", [])}))
    est = {v["id"] for p in rec["plans"] if p["status"] == "upgrade" and p["verification"].get("clean") is True
           and any(r["component"] == p["component"] and r["status"] == "applied" for ro in out["rounds"] for r in ro["results"])
           for v in rec["vulns"] if v["package"] == p["component"] and v["version"] == p["current_version"] and v.get("fixed_version")}
    out["estimated_fixed_by_plan"] = len(est)
    out["after"] = {"vulns_rescan": len(cur_vulns) if out["status"] != "regression_reverted" else len(rec["vulns"]),
                    "vulns_estimated": max(0, len(rec["vulns"]) - len(est))}
    if base and out["status"] == "applied":
        out["diff"] = patchmod.diff(path, base)
    return out


def metrics(rec: Dict[str, Any]) -> Dict[str, Any]:
    comps, vulns, plans = rec["components"], rec["vulns"], rec["plans"]
    ls = (rec.get("license") or {}).get("stats") or {}
    ups = [p for p in plans if p["status"] == "upgrade"]
    pa = rec.get("patch") or {}
    g = (rec.get("arch") or {}).get("graph") or {}
    m = {"components": len(comps), "vulns": len(vulns), "severity": severity_counts(vulns),
         "license_resolved": ls.get("resolved"), "license_total": ls.get("total"), "license_resolved_rate": ls.get("resolved_rate"),
         "license_sources": ls.get("by_source") or {},
         "plans": len(plans), "plans_upgrade": len(ups), "plans_verified_clean": sum(1 for p in ups if p["verification"].get("clean") is True),
         "plans_unverified": sum(1 for p in ups if p["verification"].get("clean") is None),
         "sbom_ref_rate": (rec.get("sbom_check") or {}).get("ref_integrity", {}).get("rate"),
         "cyclonedx_valid": (rec.get("sbom_check") or {}).get("cyclonedx_valid"), "spdx_valid": (rec.get("sbom_check") or {}).get("spdx_valid"),
         "patch_status": pa.get("status"), "patch_applied_components": pa.get("applied_components", 0),
         "patch_rescan_fixed": pa.get("rescan_fixed_total", 0), "patch_estimated_fixed": pa.get("estimated_fixed_by_plan", 0),
         "arch_edges": g.get("import_edges", 0), "arch_cycles": g.get("cycle_count", 0), "proposal_source": (rec.get("proposals") or {}).get("source"),
         "stage_errors": len(rec.get("stage_errors") or {}), "elapsed_s": rec.get("elapsed_s")}
    return m


def persist(rec: Dict[str, Any], out_dir: str) -> Dict[str, str]:
    nm = safe_name(rec["name"])
    d = os.path.join(out_dir, nm)
    os.makedirs(d, exist_ok=True)
    cur = os.path.join(d, nm + ".json")
    if os.path.isfile(cur):
        try:                                                       # keep the last analysis: `diff <project>` compares it with the new one
            shutil.copyfile(cur, os.path.join(d, nm + ".prev.json"))
        except OSError:
            pass
    docs = rec.pop("_docs", None) or {}
    paths = {}
    for key, fn in (("cdx", nm + ".cdx.json"), ("spdx", nm + ".spdx.json"), ("vex", nm + ".vex.json")):
        if docs.get(key):
            write_json(os.path.join(d, fn), docs[key])
            paths[key] = os.path.join(d, fn)
    slim = dict(rec)
    slim["artifacts"] = paths
    write_json(os.path.join(d, nm + ".json"), slim)
    paths["record"] = os.path.join(d, nm + ".json")
    rec["_docs"] = docs
    rec["artifacts"] = paths
    return paths
