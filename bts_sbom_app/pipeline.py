"""One project, end to end: source -> work copy -> SBOM/vulns -> licenses -> remediation plan -> (approved) patch + re-scan
-> delivery -> architecture -> industry reports -> AI proposals -> evidence files.

Every stage is timed and isolated: a failing stage is recorded in ``stage_errors`` and the rest of the run continues, so a
partial result is always visible instead of an exception that hides everything. Nothing here pushes or writes to the origin
(delivery targets that do are separate, explicit flags in ``deliver``). The analysed project's own code is never run, with
ONE opt-in exception: ``compat_runtime=True`` runs its test suite in throw-away copies (see ``compat_runtime``).
"""
from __future__ import annotations

import os
import shutil
import time
from typing import Any, Callable, Dict, List, Optional

from . import ai, arch as archmod, changes as changesmod, compat as compatmod, compat_runtime as compatrt, conformance, deliver as delivermod, engine, impact as impactmod, licenses, patch as patchmod, remediate, review as reviewmod, sbom, sectors, workspace
from .llm import ChatClient
from bts_sbom.supply_chain import SupplyChainAnalyzer
from .util import safe_name, tree_hash, write_json

PROJECT_SCHEMA = "bts-sbom.project.v1"
# Records written before the identifiers were renamed carry this older id. Same layout, so they must keep loading;
# nothing writes it any more.
PROJECT_SCHEMAS_ACCEPTED = (PROJECT_SCHEMA, "sbomplus.project.v1")


class _Stages:
    """``progress``, when given, is called ``progress("step_start", name)`` before a stage and
    ``progress("step_end", name, ok=..., seconds=..., error=...)`` after it (``error`` is ``None`` on success).
    A callback that raises never breaks the analysis: the first such failure is recorded once in
    ``rec["stage_errors"]["progress_callback"]`` (a later one is not reported again - the signal is "the
    callback is unreliable", not a per-stage count) and the stage's own outcome is unaffected."""

    def __init__(self, rec: Dict[str, Any], progress: Optional[Callable[..., None]] = None, checkpoint_path: Optional[str] = None):
        self.rec = rec
        self.progress = progress
        self.checkpoint_path = checkpoint_path
        rec["timings"] = {}
        rec["stage_errors"] = {}

    def _notify(self, *args: Any, **kwargs: Any) -> None:
        if self.progress is None:
            return
        try:
            self.progress(*args, **kwargs)
        except Exception as exc:                                   # noqa: BLE001 - a progress callback must never break the analysis
            if "progress_callback" not in self.rec["stage_errors"]:
                self.rec["stage_errors"]["progress_callback"] = "%s: %s" % (type(exc).__name__, str(exc)[:240])

    def run(self, name: str, fn: Callable[[], Any], default: Any = None) -> Any:
        t = time.time()
        self._notify("step_start", name)
        ok, error = True, None
        try:
            return fn()
        except Exception as exc:                                   # noqa: BLE001 - recorded, never swallowed silently
            ok, error = False, "%s: %s" % (type(exc).__name__, str(exc)[:240])
            self.rec["stage_errors"][name] = error
            return default
        finally:
            seconds = round(time.time() - t, 2)
            self.rec["timings"][name] = seconds
            self._notify("step_end", name, ok=ok, seconds=seconds, error=error)
            self._checkpoint(name, ok, seconds, error)

    def _checkpoint(self, name: str, ok: bool, seconds: float, error: Optional[str]) -> None:
        """C65: the phase checkpoint - after EVERY stage the file says which phase last completed. A crash (or a
        SIGTERM) mid-analysis leaves this trace on disk instead of nothing: the resume question 'how far did it
        get' has a measured answer. The write is best-effort - a checkpoint failure is recorded, never fatal."""
        if not self.checkpoint_path:
            return
        try:
            import datetime
            import json as _json
            os.makedirs(os.path.dirname(self.checkpoint_path) or ".", exist_ok=True)
            with open(self.checkpoint_path, "w", encoding="utf-8", newline="\n") as fh:
                _json.dump({"project": self.rec.get("name"), "at": datetime.datetime.now().isoformat(timespec="seconds"),
                            "last_completed_stage": name if ok else self.rec.get("_last_ok_stage"),
                            "stage": name, "ok": ok, "seconds": seconds, "error": error,
                            "completed_before": list(self.rec.get("timings") or {})}, fh, ensure_ascii=False, indent=1)
            if ok:
                self.rec["_last_ok_stage"] = name
        except OSError as exc:                                     # noqa: BLE001
            self.rec["stage_errors"].setdefault("checkpoint", "%s: %s" % (type(exc).__name__, str(exc)[:120]))


def _ids(vulns: List[Dict[str, Any]]) -> set:
    return {(v["id"], v["package"].lower(), v["version"]) for v in vulns}


def severity_counts(vulns: List[Dict[str, Any]]) -> Dict[str, int]:
    return engine.severity_counts(vulns)


def run_project(src: str, *, work_root: str, out_dir: Optional[str] = None, name: Optional[str] = None, ref: Optional[str] = None,
                depth: int = 200, offline: bool = False, online_license: bool = True, license_extra_registries: bool = True, patch: bool = False, approved: bool = False,
                approval_token: Optional[str] = None, rounds: int = 2, verify_rounds: int = 3,
                compat_mode: str = "block", compat_runtime: bool = False, compat_pip_args: Optional[List[str]] = None, compat_c_provider: Any = None,
                deliver_target: str = "branch", deliver_kw: Optional[Dict[str, Any]] = None, use_llm: bool = True,
                client: Optional[ChatClient] = None, industries: Optional[List[str]] = None, policy: Optional[Dict[str, Any]] = None,
                cache_dir: Optional[str] = None, lang: str = "ko", arch_online: bool = False, scanner: Any = None,
                run_arch: bool = True, run_proposals: bool = True, engine_opts: Optional[Dict[str, Any]] = None,
                progress: Optional[Callable[..., None]] = None) -> Dict[str, Any]:
    t0 = time.time()
    rec: Dict[str, Any] = {"schema": PROJECT_SCHEMA, "name": name or safe_name(os.path.basename(src.rstrip("/\\")) or "project"),
                           "source": src, "ref": ref or "", "components": [], "vulns": [], "plans": [], "license": {}, "arch": {},
                           "sectors": {}, "patch": {}, "proposals": {}, "sbom_check": {}, "engine": {"core": ""}, "error": None}
    S = _Stages(rec, progress=progress, checkpoint_path=os.path.join(work_root, "%s.checkpoint.json" % (rec["name"] or "project")))
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

    rec["supply_chain"] = S.run("supply_chain", lambda: SupplyChainAnalyzer().analyze(rec["components"]), [])

    if run_arch:
        rec["arch"] = S.run("arch", lambda: archmod.analyze(path, online=arch_online), {})

    # ---------------------------------------------------------------- patch loop (approval gated, verified by re-scan)
    if patch:
        rec["patch"] = S.run("patch", lambda: _patch_loop(rec, path, approved=approved, token=approval_token, rounds=rounds, offline=offline,
                                                          scanner=scanner, verify_rounds=verify_rounds, engine_opts=eopts,
                                                          compat_mode=compat_mode, compat_runtime=compat_runtime, compat_pip_args=compat_pip_args,
                                                          compat_c_provider=compat_c_provider), {})
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


class _CompatState:
    """The patch loop's compatibility gate (``compat``: static, before every apply) and the opt-in runtime differential
    (``compat_runtime``: baseline before the first apply, one comparison after the last). Every failure in here is recorded
    (``error``), never fatal: the gate may hold a package back, it may never take the loop down."""

    def __init__(self, path: str, mode: str, offline: bool, provider: Any, runtime: bool, pip_args: Optional[List[str]], c_provider: Any = None) -> None:
        self.path, self.offline, self.provider, self.c_provider = path, offline, provider, c_provider
        self.mode = mode if mode in compatmod.MODES else "block"
        self.cache: Dict[tuple, Dict[str, Any]] = {}
        self.rounds: List[Dict[str, Any]] = []
        self.error: Optional[str] = None
        self.runtime_wanted, self.pip_args = bool(runtime), list(pip_args or [])
        self.rt: Optional[Any] = None
        self.runtime: Optional[Dict[str, Any]] = None

    def gate(self, plans: List[Dict[str, Any]], components: List[Dict[str, Any]]) -> Dict[str, str]:
        """Measure every upgrade BEFORE its manifest is touched; returns the plans to hold (block mode, breaking only)."""
        if self.mode == "off":
            return {}
        try:
            res = compatmod.assess(self.path, plans, components, mode=self.mode, offline=self.offline, provider=self.provider, cache=self.cache,
                                   c_provider=self.c_provider)
            compatmod.attach(plans, res)
            self.rounds.append(res)
            return res["held"]
        except Exception as exc:                                      # noqa: BLE001 - recorded, never swallowed silently
            self.error = "%s: %s" % (type(exc).__name__, str(exc)[:240])
            return {}

    def start_runtime(self, plans: List[Dict[str, Any]]) -> None:
        if not self.runtime_wanted:
            return
        self.runtime = {"schema": compatrt.SCHEMA, "honesty": compatrt.HONESTY}
        try:
            self.rt = compatrt.Differential(self.path, compatrt.requirement_files(plans), pip_args=self.pip_args)
            self.runtime["baseline"] = self.rt.baseline()
        except Exception as exc:                                      # noqa: BLE001 - advisory layer: recorded, the patch still runs
            self.runtime["baseline"] = {"status": "unverified", "reason": "%s: %s" % (type(exc).__name__, str(exc)[:200])}

    def finish_runtime(self) -> Optional[Dict[str, Any]]:
        """After the last applied round: compare against the baseline; None when there is nothing to compare."""
        if self.runtime is None or self.rt is None or (self.runtime.get("baseline") or {}).get("status") != "ready":
            return None
        try:
            self.runtime["after"] = self.rt.after()
        except Exception as exc:                                      # noqa: BLE001
            self.runtime["after"] = {"status": "unverified", "reason": "%s: %s" % (type(exc).__name__, str(exc)[:200])}
        return self.runtime["after"]

    def merged(self) -> Optional[Dict[str, Any]]:
        """One record over all rounds: the latest assessment of each plan wins; ``held`` is the union."""
        if not self.rounds:
            return None
        by: Dict[str, Dict[str, Any]] = {}
        held: Dict[str, str] = {}
        for r in self.rounds:
            for pl in r.get("plans") or []:
                by[pl.get("key") or "%s|%s" % (pl.get("component"), pl.get("from"))] = pl
            held.update(r.get("held") or {})
        plans = list(by.values())
        return {"schema": compatmod.SCHEMA, "mode": self.mode, "plans": plans, "held": held, "summary": compatmod._summary(plans, held, self.mode),
                "honesty": compatmod.HONESTY}

    def close(self) -> None:
        if self.rt is not None:
            self.rt.close()


def _patch_loop(rec: Dict[str, Any], path: str, *, approved: bool, token: Optional[str], rounds: int, offline: bool, scanner: Any,
                verify_rounds: int, engine_opts: Optional[Dict[str, Any]] = None, compat_mode: str = "block", compat_runtime: bool = False,
                compat_pip_args: Optional[List[str]] = None, compat_provider: Any = None, compat_c_provider: Any = None) -> Dict[str, Any]:
    cs = _CompatState(path, compat_mode, offline, compat_provider, compat_runtime and approved, compat_pip_args, compat_c_provider)
    try:
        return _patch_loop_core(rec, path, approved=approved, token=token, rounds=rounds, offline=offline, scanner=scanner,
                                verify_rounds=verify_rounds, engine_opts=engine_opts, cs=cs)
    finally:
        cs.close()


def _patch_loop_core(rec: Dict[str, Any], path: str, *, approved: bool, token: Optional[str], rounds: int, offline: bool, scanner: Any,
                     verify_rounds: int, engine_opts: Optional[Dict[str, Any]], cs: _CompatState) -> Dict[str, Any]:
    out: Dict[str, Any] = {"approved": bool(approved), "rounds": [], "status": None, "before": {"vulns": len(rec["vulns"])}}
    if not approved:
        cs.gate(rec["plans"], rec.get("components") or [])           # the reviewer sees the measured compatibility BEFORE approving
        pr = patchmod.apply(path, rec["plans"], approved=False)
        out.update(status="not_approved", note=pr["note"], digest=pr["digest"], plans=[p for p in rec["plans"] if p["status"] == "upgrade"][:30])
        if cs.merged():
            out["compat"] = cs.merged()
        if cs.error:
            out["compat_error"] = cs.error
        return out
    cs.start_runtime(rec["plans"])
    base = workspace.head(path).get("commit", "")
    cur_plans, cur_vulns = rec["plans"], rec["vulns"]
    seen_plan_sets: List[tuple] = []
    applied_total = 0
    last: Dict[str, Any] = {}
    last_after: Optional[Dict[str, Any]] = None                    # the last post-patch re-scan (components + vulns), for impact analysis
    all_changed_files: set = set()
    apply_status_by_key: Dict[tuple, str] = {}                     # (ecosystem, canon(component), from_version) -> patch.apply() result status
    for rnd in range(1, rounds + 1):
        key = tuple(sorted((p["component"], p["safe_version"]) for p in cur_plans if p["status"] == "upgrade"))
        if key in seen_plan_sets:                                  # spinning guard: identical plan twice = no progress possible
            out["status"] = "spinning_stopped"
            break
        seen_plan_sets.append(key)
        hold = cs.gate(cur_plans, (last_after or {}).get("components") or rec.get("components") or [])
        pr = patchmod.apply(path, cur_plans, approved=True, token=token if rnd == 1 else None, hold=hold or None)
        entry = {"round": rnd, "status": pr["status"], "applied": sum(1 for r in pr["results"] if r["status"] == "applied"),
                 "blocked": sum(1 for r in pr["results"] if r["status"] == "blocked"), "manual": sum(1 for r in pr["results"] if r["status"] == "manual"),
                 "held": sum(1 for r in pr["results"] if r["status"] == "held"),
                 "results": pr["results"][:60], "regenerate": pr.get("regenerate", [])}
        last = pr
        for r in pr["results"]:
            eco = str(r.get("ecosystem") or "")
            k = (eco.lower(), engine._canon(eco, str(r.get("component") or "")), str(r.get("from") or ""))
            apply_status_by_key[k] = r.get("status")
        out["rounds"].append(entry)
        if pr["status"] == "digest_mismatch":
            out["status"] = "digest_mismatch"
            break
        if pr["status"] != "applied":
            if entry["blocked"] and not applied_total:
                out["status"] = "blocked"
                out["note"] = ("approved patch could not be applied: %d candidate(s) blocked by manifest constraints "
                               "(see rounds[].results[].detail)" % entry["blocked"])
            elif entry["held"] and not applied_total:
                out["status"] = "compat_held"
                out["note"] = ("nothing was applied: %d upgrade(s) were held back by the compatibility gate "
                               "(see compat.plans[].findings for the exact symbols and call sites)" % entry["held"])
            else:
                out["status"] = "applied" if applied_total else "nothing_applied"
            break
        applied_total += entry["applied"]
        after = engine.analyze(path, offline=offline, scanner=scanner, **(engine_opts or {}))
        last_after = after
        b, a = _ids(cur_vulns), _ids(after["vulns"])
        # Regression is judged on the findings attributable to the files we EDITED. A lockfile we deliberately did not touch still
        # pins the old versions, so comparing grand totals blamed the patch for findings it cannot influence (measured: a
        # package.json-only npm patch of 134 packages was reverted because ONE new advisory appeared at an upgraded version).
        edited = set(pr.get("changed_files") or [])
        all_changed_files |= edited

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
    if out["status"] == "applied" and applied_total:               # opt-in runtime differential: the project's own tests, before vs after
        rt_after = cs.finish_runtime()
        if rt_after is not None and rt_after.get("status") == "regression":
            patchmod.revert(path, base)
            out["status"] = "compat_runtime_reverted"
            out["note"] = "reverted: " + str(rt_after.get("reason") or "tests regressed on the patched pins")
    if cs.runtime is not None:
        out["compat_runtime"] = cs.runtime
    if cs.merged():
        out["compat"] = cs.merged()
    if cs.error:
        out["compat_error"] = cs.error
    out.update(applied_components=applied_total, base_commit=base, last=last, branch=last.get("branch"), commit=last.get("commit"),
               regenerate=sorted({x for r in out["rounds"] for x in r.get("regenerate", [])}))
    est = {v["id"] for p in rec["plans"] if p["status"] == "upgrade" and p["verification"].get("clean") is True
           and any(r["component"] == p["component"] and r["status"] == "applied" for ro in out["rounds"] for r in ro["results"])
           for v in rec["vulns"] if v["package"] == p["component"] and v["version"] == p["current_version"] and v.get("fixed_version")}
    out["estimated_fixed_by_plan"] = len(est)
    out["after"] = {"vulns_rescan": len(cur_vulns) if out["status"] not in ("regression_reverted", "compat_runtime_reverted") else len(rec["vulns"]),
                    "vulns_estimated": max(0, len(rec["vulns"]) - len(est))}
    if base and out["status"] == "applied":
        out["diff"] = patchmod.diff(path, base)

    # ---------------------------------------------------------------- impact (4-quadrant regression) + independent review
    # Added once the patch status is decided (every path past the "not_approved" early return above, e.g. applied,
    # regression_reverted, blocked, digest_mismatch, nothing_applied, spinning_stopped). A failure here is recorded,
    # never swallowed, and never changes any field set above.
    plans_for_impact: List[Dict[str, Any]] = []
    for p in rec.get("plans") or []:
        pc = dict(p)
        eco = str(p.get("ecosystem") or "")
        k = (eco.lower(), engine._canon(eco, str(p.get("component") or "")), str(p.get("current_version") or ""))
        if k in apply_status_by_key:
            pc["apply_status"] = apply_status_by_key[k]
        plans_for_impact.append(pc)

    impact_result: Optional[Dict[str, Any]] = None
    try:
        impact_result = impactmod.classify(
            rec.get("components"), rec.get("vulns"),
            (last_after or {}).get("components") if last_after is not None else None,
            (last_after or {}).get("vulns") if last_after is not None else None,
            sorted(all_changed_files), plans_for_impact,
            regenerate=out.get("regenerate") or [], fleet=None)       # fleet is unreachable from here (see ADR-0012): shared/fleet stays unverified
        out["impact"] = impact_result
    except Exception as exc:                                          # noqa: BLE001 - recorded, never swallowed silently
        out["impact"] = {"error": "%s: %s" % (type(exc).__name__, str(exc)[:240])}

    try:
        diff_text = (out.get("diff") or {}).get("patch") or ""
        lines_changed = sum(1 for ln in diff_text.splitlines()
                            if (ln.startswith("+") or ln.startswith("-")) and not ln.startswith(("+++", "---")))
        out["review"] = reviewmod.review(
            plan_digest=last.get("digest") or "", changed_files=sorted(all_changed_files),
            planned_manifests=sorted({f for p in (rec.get("plans") or []) for f in (p.get("files") or [])}),
            diff_stats={"lines_changed": lines_changed},
            impact=impact_result if impact_result is not None else out.get("impact"),
            plan_summary=remediate.summary(rec.get("plans") or []),
            compat=out.get("compat"), compat_runtime=out.get("compat_runtime"))
    except Exception as exc:                                          # noqa: BLE001 - recorded, never swallowed silently
        out["review"] = {"error": "%s: %s" % (type(exc).__name__, str(exc)[:240])}
    try:
        out["review_convergence"] = reviewmod.convergence(            # C31: the same finding recurring across rounds is tracked
            os.path.join(os.path.dirname(path) or ".", "review_convergence.jsonl"), out["review"])
    except Exception as exc:                                          # noqa: BLE001
        out["review_convergence"] = {"error": "%s: %s" % (type(exc).__name__, str(exc)[:160])}

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
