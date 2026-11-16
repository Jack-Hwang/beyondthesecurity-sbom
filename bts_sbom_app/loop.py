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

from . import ai, batch, evals
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


def gate(base: Dict[str, Any], cand: Dict[str, Any], delta: float = 0.02) -> Dict[str, Any]:
    """Pass when every blocking metric present in both vectors satisfies  cand - base >= -delta  (lower-is-better: relative cap)."""
    deltas: Dict[str, float] = {}
    failed: List[str] = []
    for k in HIGHER:
        b, c = base.get(k), cand.get(k)
        if b is None or c is None:
            continue
        deltas[k] = round(c - b, 4)
        if c - b < -delta:
            failed.append("%s: %.3f -> %.3f" % (k, b, c))
    warnings: List[str] = []
    for k, rel in LOWER.items():
        b, c = base.get(k), cand.get(k)
        if b is None or c is None:
            continue
        deltas[k] = round(c - b, 4)
        if c > b * (1 + rel) + 1e-9:
            msg = "%s: %s -> %s (allowed +%d%%)" % (k, b, c, int(rel * 100))
            (failed if k in BLOCKING_LOWER else warnings).append(msg)       # wall-clock time is advisory (network noise)
    return {"pass": not failed, "deltas": deltas, "failed": failed, "warnings": warnings, "delta_limit": delta}


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
    code = code_fingerprint(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))     # fixed BEFORE the run starts
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
    entry = {"pass": len(hist) + 1, "tag": tag, "at": now_iso(), "variable": variable, "hypothesis": hypothesis, "decision": decision,
             "gate": g, "metrics": metrics, "failure_clusters": clusters[:25], "run_dir": res["summary"].get("run_dir"),
             "baseline_pass": base_rec["pass"] if base_rec else None, "core": res["summary"].get("core"),
             "code": code}
    def _cv(c: Any) -> str:
        return str(c.get("version")) if isinstance(c, dict) else str(c)

    if base_rec and base_rec.get("core") and _cv(base_rec["core"]) != _cv(entry["core"]):
        entry["warning"] = "core changed between baseline and this pass (%s -> %s): the delta is confounded" % (_cv(base_rec["core"]), _cv(entry["core"]))
    entry["next"] = propose_variables(clusters, client=hyp_client)
    hist.append(entry)
    entry["plateau"] = plateau([h for h in hist if h["decision"] in ("baseline", "accept")], 3)
    write_json(history_path(loop_root), hist)
    write_json(os.path.join(loop_root, "pass_%02d_%s.json" % (entry["pass"], tag)), entry)
    return entry


def rag_history_path(loop_root: str) -> str:
    return os.path.join(loop_root, "rag_history.json")


def run_rag_pass(tag: str, loop_root: str, root: str, *, variable: str, hypothesis: str = "", delta: float = 0.02) -> Dict[str, Any]:
    """Retrieval-only loop pass: evaluate the golden/dev/test sets, gate every metric against the accepted baseline."""
    res = evals.rag_sets_eval(root)
    metrics: Dict[str, Any] = {}
    for name, r in res.items():
        short = name.replace("rag_", "")
        metrics.update({short + "_recall": r["recall_at_k"], short + "_mrr": r["mrr"], short + "_ndcg": r["ndcg_at_k"], short + "_ood": r["ood_rate"],
                        short + "_found": r.get("found_rate")})
    hist = read_json(rag_history_path(loop_root), []) or []
    base = next((h for h in reversed(hist) if h.get("decision") in ("baseline", "accept")), None)
    failed: List[str] = []
    deltas: Dict[str, float] = {}
    if base:
        for k, v in metrics.items():
            b = base["metrics"].get(k)
            if b is None or v is None:
                continue
            deltas[k] = round(v - b, 4)
            if v - b < -delta:
                failed.append("%s: %.3f -> %.3f" % (k, b, v))
    decision = "baseline" if base is None else ("accept" if not failed else "rollback")
    entry = {"pass": len(hist) + 1, "tag": tag, "at": now_iso(), "variable": variable, "hypothesis": hypothesis, "decision": decision,
             "gate": {"pass": not failed, "failed": failed, "deltas": deltas, "delta_limit": delta}, "metrics": metrics,
             "misses": {n: r["misses"] for n, r in res.items()},
             "code": code_fingerprint(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))}
    hist.append(entry)
    write_json(rag_history_path(loop_root), hist)
    return entry
