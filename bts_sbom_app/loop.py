"""Loop engineering: measure -> change ONE variable -> accept or roll back by a regression gate.

A pass is one measured run on a fixed golden set (the e2e source list + the RAG golden queries). Between passes ONE
variable changes (recorded as ``variable``); the pass is accepted only if no blocking metric regressed by more than
``delta`` (default 0.02) against the accepted baseline. Failures are clustered by cause so the next variable is chosen
from evidence; an optional EXAONE lane proposes hypotheses, validated against the actual failure clusters (a hypothesis
that cites no real cluster is dropped). A pass history whose last N metric vectors are identical is a plateau (spinning
guard): stop instead of iterating.
"""
from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from . import ai, batch, evalguard, evals, promptreg
from .llm import ChatClient, LLMError, LLMUnavailable
from .util import code_fingerprint, now_iso, read_json, write_json

HIGHER = ("project_success_rate", "license_resolved_rate", "sbom_ref_rate", "plan_verified_rate", "fix_applied_rate", "arch_coverage",
          "cyclonedx_valid_rate", "spdx_valid_rate", "rag_recall_at_5", "rag_mrr", "rag_ndcg_at_5", "ood_rate", "citation_accuracy")
LOWER = {"analysis_s_avg": 0.5, "stage_errors": 0.0}           # metric -> allowed relative increase
BLOCKING_LOWER = {"stage_errors"}


def flatten(batch_summary: Dict[str, Any], rag_eval: Optional[Dict[str, Any]] = None, chat_eval: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    s = batch_summary["summary"] if "summary" in batch_summary and "projects" in batch_summary["summary"] else batch_summary
    m: Dict[str, Any] = {k: s.get(k) for k in HIGHER if k in s}
    m.update({k: s.get(k) for k in LOWER})
    m.update(projects=s.get("projects"), components=s.get("components"), vulns=s.get("vulns"))
    pr = s.get("proposals") or {}
    if (pr.get("exaone", 0) + pr.get("deterministic", 0)):
        m["exaone_rate"] = round(pr.get("exaone", 0) / (pr.get("exaone", 0) + pr.get("deterministic", 0)), 3)   # informational, not gated
        m["ai_keep_rate"] = pr.get("keep_rate")                                                                   # informational, not gated
    if rag_eval:
        m.update(rag_recall_at_5=rag_eval.get("recall_at_k"), rag_mrr=rag_eval.get("mrr"), rag_ndcg_at_5=rag_eval.get("ndcg_at_k"), ood_rate=rag_eval.get("ood_rate"))
    if chat_eval:
        m["citation_accuracy"] = chat_eval.get("citation_accuracy")
    return m


COUNTS = ("components", "vulns")      # detection volume on the fixed golden set: a collapse here means the scanner stopped seeing things
COLLAPSE_KEEP = 0.5                    # a candidate that keeps less than this share of the baseline count is a collapse (blocking)


def gate(base: Dict[str, Any], cand: Dict[str, Any], delta: float = 0.02) -> Dict[str, Any]:
    """Pass when every blocking metric present in both vectors satisfies  cand - base >= -delta  (lower-is-better: relative cap).

    Absent evidence is never a pass: a blocking metric the baseline has but the candidate lacks (missing or None) is
    ``undecidable`` and blocks acceptance, and so does a candidate with no comparable metric at all. Detection volume
    (``COUNTS``) is blocking when it collapses below ``COLLAPSE_KEEP`` of the baseline (a scanner that sees nothing has
    no metric left to regress) and advisory for smaller drops (merging duplicates legitimately lowers the counts).
    """
    deltas: Dict[str, float] = {}
    failed: List[str] = []
    undecidable: List[str] = []
    compared = 0
    for k in HIGHER:
        b, c = base.get(k), cand.get(k)
        if b is None:
            continue
        if c is None:
            undecidable.append("%s: baseline %.3f, candidate has no value" % (k, b))
            continue
        compared += 1
        deltas[k] = round(c - b, 4)
        if c - b < -delta - 1e-9:                         # a drop of exactly `delta` passes (float noise: 0.917 -> 0.897)
            failed.append("%s: %.3f -> %.3f" % (k, b, c))
    warnings: List[str] = []
    for k, rel in LOWER.items():
        b, c = base.get(k), cand.get(k)
        if b is None:
            continue
        if c is None:
            (undecidable if k in BLOCKING_LOWER else warnings).append("%s: baseline %s, candidate has no value" % (k, b))
            continue
        compared += 1
        deltas[k] = round(c - b, 4)
        if c > b * (1 + rel) + 1e-9:
            msg = "%s: %s -> %s (allowed +%d%%)" % (k, b, c, int(rel * 100))
            (failed if k in BLOCKING_LOWER else warnings).append(msg)       # wall-clock time is advisory (network noise)
    for k in COUNTS:
        b, c = base.get(k), cand.get(k)
        if not isinstance(b, (int, float)) or isinstance(b, bool) or b <= 0:
            continue
        if not isinstance(c, (int, float)) or isinstance(c, bool):
            undecidable.append("%s: baseline %s, candidate has no value" % (k, b))
            continue
        compared += 1
        deltas[k] = round(c - b, 4)
        if c < b * COLLAPSE_KEEP:
            failed.append("%s: %s -> %s (detection collapse, keeps < %d%%)" % (k, b, c, int(COLLAPSE_KEEP * 100)))
        elif c < b:
            warnings.append("%s: %s -> %s (lower than baseline; check engine.adjustments)" % (k, b, c))
    if not compared and not undecidable:
        undecidable.append("no metric is comparable between baseline and candidate")
    return {"pass": not failed and not undecidable, "deltas": deltas, "failed": failed, "undecidable": undecidable,
            "warnings": warnings, "delta_limit": delta}


def plateau(history: List[Dict[str, Any]], n: int = 3) -> bool:
    if len(history) < n:
        return False
    tail = [json.dumps(h["metrics"], sort_keys=True) for h in history[-n:]]
    return len(set(tail)) == 1


def cluster_failures(recs: List[Dict[str, Any]], examples: int = 4) -> List[Dict[str, Any]]:
    c: Counter = Counter()
    ex: Dict[str, List[str]] = defaultdict(list)

    def add(key: str, example: str, n: int = 1) -> None:
        c[key] += n
        if len(ex[key]) < examples and example not in ex[key]:
            ex[key].append(example)

    for r in recs:
        nm = r["name"]
        if r.get("error"):
            add("project:error", "%s: %s" % (nm, str(r["error"])[:100]))
            continue
        for st, msg in (r.get("stage_errors") or {}).items():
            add("stage:" + st, "%s: %s" % (nm, msg[:100]))
        for comp in r["components"]:
            if not comp.get("license"):
                add("license:unresolved:" + (comp["ecosystem"] or "?"), "%s %s@%s" % (nm, comp["name"], comp["version"]))
        for raw, n in (((r.get("license") or {}).get("stats") or {}).get("unmapped_raw") or {}).items():
            add("license:unmapped_raw", raw, n)
        for p in r["plans"]:
            if p["status"] == "no_fix":
                add("vuln:no_fix:" + p["ecosystem"], "%s %s@%s" % (nm, p["component"], p["current_version"]))
            elif p["verification"].get("clean") is None:
                add("vuln:unverified_plan:" + p["ecosystem"], "%s %s -> %s (%s)" % (nm, p["component"], p["safe_version"], p["verification"].get("stopped", "?")))
            elif p["verification"].get("clean") is False:
                add("vuln:candidate_still_vulnerable:" + p["ecosystem"], "%s %s -> %s" % (nm, p["component"], p["safe_version"]))
        for ro in (r.get("patch") or {}).get("rounds") or []:
            for x in ro.get("results") or []:
                if x["status"] in ("blocked", "manual"):
                    add("patch:%s:%s" % (x["status"], (x.get("ecosystem") or "?")), "%s %s: %s" % (nm, x["component"], (x.get("detail") or "")[:90]))
        for f in (r.get("engine") or {}).get("unsupported") or []:
            add("engine:unsupported_manifest:" + os.path.basename(f).lower(), "%s %s" % (nm, f))
        g = (r.get("arch") or {}).get("graph") or {}
        if r.get("arch") and not g.get("import_edges"):
            add("arch:no_import_edges", "%s languages=%s" % (nm, ",".join(((r["arch"].get("stack") or {}).get("languages") or {}).keys())))
        if (r.get("engine") or {}).get("data_status") not in (None, "complete"):
            add("engine:data_incomplete", "%s: %s" % (nm, (r["engine"] or {}).get("data_status")))
    return [{"key": k, "count": n, "examples": ex[k]} for k, n in c.most_common()]


HYP_SYSTEM = ("You help improve a software-supply-chain analysis tool. You are given failure clusters measured on a fixed golden set. "
              "Return JSON {\"hypotheses\": [{\"cluster\": <key copied exactly from the input>, \"variable\": <ONE thing to change>, "
              "\"expected_effect\": <which metric should move and in which direction>, \"risk\": \"low|medium|high\"}]}. "
              "At most 5, ordered by expected impact. Never reference a cluster that is not in the input.")


def propose_variables(clusters: List[Dict[str, Any]], *, client: Optional[ChatClient] = None, cache_dir: Optional[str] = None) -> Dict[str, Any]:
    """Hypotheses for the next pass. EXAONE when available (validated against the real cluster keys), otherwise the
    deterministic rule: biggest cluster first."""
    keys = {c["key"] for c in clusters}
    det = [{"cluster": c["key"], "variable": "investigate " + c["key"], "expected_effect": "reduce %d failures" % c["count"], "risk": "low"} for c in clusters[:3]]
    if client is None or not clusters:
        return {"source": "deterministic", "items": det, "llm_note": "no client" if client is None else "no failures"}
    payload = json.dumps([{"key": c["key"], "count": c["count"], "examples": c["examples"][:2]} for c in clusters[:8]], ensure_ascii=False)
    try:
        raw = client.complete(HYP_SYSTEM, payload, max_tokens=4096, json_mode=True)
        obj = ai._parse_json(raw)
        items = [h for h in (obj.get("hypotheses") if isinstance(obj, dict) else None) or []
                 if isinstance(h, dict) and h.get("cluster") in keys and h.get("variable") and h.get("expected_effect")]
        dropped = len((obj.get("hypotheses") or [])) - len(items) if isinstance(obj, dict) else 0
        if items:
            return {"source": "exaone", "items": items[:5], "dropped": dropped, "llm_note": ""}
        return {"source": "deterministic", "items": det, "llm_note": "no hypothesis cited a real cluster (dropped %d)" % dropped}
    except (LLMUnavailable, LLMError, ValueError, TypeError, AttributeError) as exc:
        return {"source": "deterministic", "items": det, "llm_note": "EXAONE unavailable: " + str(exc)[:160]}


def history_path(root: str) -> str:
    return os.path.join(root, "history.json")


def run_pass(tag: str, sources: List[Dict[str, Any]], out_root: str, loop_root: str, *, variable: str, hypothesis: str = "",
             settings: Optional[Dict[str, Any]] = None, client: Optional[ChatClient] = None, rag_eval: Optional[Dict[str, Any]] = None,
             chat_eval: Optional[Dict[str, Any]] = None, delta: float = 0.02, jobs: int = 1, hyp_client: Optional[ChatClient] = None,
             work_root: Optional[str] = None) -> Dict[str, Any]:
    """Run the golden batch, evaluate, gate against the accepted baseline, persist the pass record."""
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = code_fingerprint(repo)                                                           # fixed BEFORE the run starts
    prompts = promptreg.digest(repo)                                                        # which prompts produced this measurement
    u0 = dict(client.usage) if client is not None else {}
    res = batch.run_batch(sources, out_root, tag=tag, jobs=jobs, client=client, settings=settings, work_root=work_root)
    metrics = flatten(res["summary"], rag_eval, chat_eval)
    hist = read_json(history_path(loop_root), []) or []
    base_rec = next((h for h in reversed(hist) if h.get("decision") in ("baseline", "accept")), None)
    if base_rec is None:
        decision, g = "baseline", {"pass": True, "deltas": {}, "failed": [], "delta_limit": delta}
    else:
        g = gate(base_rec["metrics"], metrics, delta)
        decision = "accept" if g["pass"] else "rollback"
    clusters = cluster_failures(res["records"])
    per_case_s = {r["name"]: r.get("s") for r in res["records"] if isinstance(r.get("s"), (int, float))}
    entry = {"pass": len(hist) + 1, "tag": tag, "at": now_iso(), "variable": variable, "hypothesis": hypothesis, "decision": decision,
             "gate": g, "metrics": metrics, "failure_clusters": clusters[:25], "run_dir": res["summary"].get("run_dir"),
             "baseline_pass": base_rec["pass"] if base_rec else None, "core": res["summary"].get("core"),
             "code": code, "prompts": prompts,
             "eval_pins": {n: evalguard.fingerprint(g) for n, g in evals.rag_set_items().items()},     # lineage: WHICH eval-set versions measured this pass
             "per_case_seconds": dict(sorted(per_case_s.items(), key=lambda kv: -(kv[1] or 0))[:8]),   # C42: where the pass spent its minutes
             "llm_cost": ({"prompt_tokens": client.usage["prompt_tokens"] - u0.get("prompt_tokens", 0),   # C42: this pass's own token spend
                           "completion_tokens": client.usage["completion_tokens"] - u0.get("completion_tokens", 0)} if client is not None else None)}
    def _cv(c: Any) -> str:
        return str(c.get("version")) if isinstance(c, dict) else str(c)

    if base_rec and base_rec.get("core") and _cv(base_rec["core"]) != _cv(entry["core"]):
        entry["warning"] = "core changed between baseline and this pass (%s -> %s): the delta is confounded" % (_cv(base_rec["core"]), _cv(entry["core"]))
    if base_rec and base_rec.get("prompts") and base_rec["prompts"] != prompts:
        entry["warning"] = (entry.get("warning", "") + "; " if entry.get("warning") else "") + (
            "prompts changed between baseline and this pass (%s -> %s): the delta is confounded unless the prompt is the declared variable" % (base_rec["prompts"], prompts))
    entry["next"] = propose_variables(clusters, client=hyp_client)
    hist.append(entry)
    entry["plateau"] = plateau([h for h in hist if h["decision"] in ("baseline", "accept")], 3)
    write_json(history_path(loop_root), hist)
    write_json(os.path.join(loop_root, "pass_%02d_%s.json" % (entry["pass"], tag)), entry)
    return entry


def case_regressions(base_misses: Dict[str, List[Dict[str, Any]]], cand_misses: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, str]]:
    """Case-level regression rate (the lecture's definition: pass -> fail, per query): queries that had their expected
    document retrieved at the accepted baseline but lost it in the candidate. Aggregate metrics can stay flat while a
    single query regresses (another query improved to compensate) - that is exactly what this catches. A query that
    failed before and passes now is an improvement, never a regression; a set the baseline didn't measure is skipped."""
    out: List[Dict[str, str]] = []
    for name, cm in cand_misses.items():
        bm = base_misses.get(name)
        if bm is None:
            continue
        base_q = {m["q"] for m in bm}
        for m in cm:
            if m["q"] not in base_q:
                out.append({"set": name, "q": m["q"]})
    return out


def rag_history_path(loop_root: str) -> str:
    return os.path.join(loop_root, "rag_history.json")


def run_rag_pass(tag: str, loop_root: str, root: str, *, variable: str, hypothesis: str = "", delta: float = 0.02,
                 rebaseline: Optional[str] = None) -> Dict[str, Any]:
    """Retrieval-only loop pass: evaluate the golden/dev/test sets, gate every metric against the accepted baseline,
    and block on case-level regressions (a query that passed at baseline and fails now, even when the aggregates hold).

    Three integrity guards sit on top (``evalguard``): a SEGMENT drop blocks even when the totals are flat; a baseline
    measured on another version of an eval set is undecidable (the pin); a holdout that repeats a tuned-on query or is
    copied into the corpus blocks. ``rebaseline`` (a reason) starts a new baseline after a deliberate eval-set change -
    and is refused when no eval set changed, so it can never launder a regression."""
    res = evals.rag_sets_eval(root)
    metrics: Dict[str, Any] = {}
    for name, r in res.items():
        short = name.replace("rag_", "")
        metrics.update({short + "_recall": r["recall_at_k"], short + "_mrr": r["mrr"], short + "_ndcg": r["ndcg_at_k"], short + "_ood": r["ood_rate"],
                        short + "_found": r.get("found_rate")})
    hist = read_json(rag_history_path(loop_root), []) or []
    base = next((h for h in reversed(hist) if h.get("decision") in ("baseline", "accept")), None)
    failed: List[str] = []
    undecidable: List[str] = []
    warnings: List[str] = []
    deltas: Dict[str, float] = {}
    regressions: List[Dict[str, str]] = []
    pins = {n: r["fingerprint"] for n, r in res.items() if r.get("fingerprint")}
    segments = {n: r["segments"] for n, r in res.items() if r.get("segments")}
    pin_bad, pin_warn, changed = evalguard.pin_check(base.get("eval_sets") if base else None, pins) if base else ([], [], [])
    if rebaseline is not None:
        why = str(rebaseline).strip()
        if len(why) < 8:
            raise ValueError("a re-baseline needs a reason of at least 8 characters (what changed in the eval set and why)")
        if not base:
            raise ValueError("nothing to re-baseline: there is no accepted baseline yet (a plain pass records one)")
        if not changed and (base.get("eval_sets") or {}):
            raise ValueError("nothing to re-baseline: no eval set changed since pass %s; a regression is a reason to roll back, not to re-baseline" % base["pass"])
    integrity = evalguard.leak_check(evals.rag_set_items(root), evals.build_index(root).chunks) if os.path.isdir(os.path.join(root, "evals")) else \
        {"findings": [], "blocking": 0, "warnings": 0, "clean": True}
    if base and rebaseline is None:
        for k, b in base["metrics"].items():
            if b is None:
                continue
            v = metrics.get(k)
            if v is None:                                   # absent evidence is never a pass (a vanished eval set must not read as "no regression")
                undecidable.append("%s: baseline %.3f, candidate has no value" % (k, b))
                continue
            deltas[k] = round(v - b, 4)
            if v - b < -delta - 1e-9:
                failed.append("%s: %.3f -> %.3f" % (k, b, v))
        regressions = case_regressions(base.get("misses") or {}, {n: r["misses"] for n, r in res.items()})
        if regressions:
            failed.append("case regression: %d query(ies) passed at baseline but fail now: %s" % (
                len(regressions), "; ".join("[%s] %s" % (r["set"], r["q"]) for r in regressions[:3])))
        undecidable += pin_bad
        warnings += pin_warn
        seg_failed, seg_undecidable, thin = evalguard.segment_gate(base.get("segments"), segments)
        failed += seg_failed
        undecidable += seg_undecidable
        if thin:
            warnings.append("%d segment(s) too thin to gate (n < %d): %s" % (len(thin), evalguard.MIN_SEGMENT_N, ", ".join(thin[:4]) + (" ..." if len(thin) > 4 else "")))
        if not base.get("segments") and segments:
            warnings.append("baseline predates segment metrics: segments are gated from the next accepted pass on")
        if integrity["blocking"]:
            undecidable.append("eval set integrity: %d blocking finding(s) - %s" % (
                integrity["blocking"], "; ".join(evalguard.describe(f) for f in integrity["findings"] if f["severity"] == "blocking")[:300]))
    if base and rebaseline is None and not deltas and not undecidable and not regressions:   # nothing was compared (empty/all-None baseline, or no eval set at all): not a pass
        undecidable.append("no metric is comparable between baseline and candidate")
    ok = not failed and not undecidable
    decision = "baseline" if (base is None or rebaseline is not None) else ("accept" if ok else "rollback")
    if rebaseline is not None:
        ok, failed, undecidable = True, [], []
    seg_only = bool(base) and rebaseline is None and bool(failed) and all(f.startswith("segment ") for f in failed)
    entry = {"pass": len(hist) + 1, "tag": tag, "at": now_iso(), "variable": variable, "hypothesis": hypothesis, "decision": decision,
             "gate": {"pass": ok, "failed": failed, "undecidable": undecidable, "warnings": warnings, "deltas": deltas, "delta_limit": delta,
                      "segment_only": seg_only},       # True: every failure is a segment drop the totals hid
             "metrics": metrics, "case_regressions": regressions,
             "misses": {n: r["misses"] for n, r in res.items()},
             "eval_sets": pins, "segments": segments,
             "eval_integrity": {"blocking": integrity["blocking"], "warnings": integrity["warnings"],
                                "findings": [evalguard.describe(f) for f in integrity["findings"]][:10]},
             "code": code_fingerprint(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))}
    if rebaseline is not None:
        entry["rebaseline"] = {"reason": str(rebaseline).strip(), "replaces_pass": base["pass"], "eval_sets_changed": changed}
    hist.append(entry)
    write_json(rag_history_path(loop_root), hist)
    return entry
