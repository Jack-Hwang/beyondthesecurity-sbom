"""Prompt registry and drift gate: a prompt is code, so a changed prompt must be a visible, deliberate act.

The registry is built by reading the package's own source (``ast``, no imports, no network): every module-level prompt
constant (``*SYSTEM`` / ``*PROMPT``) and every LLM call site (``<client>.complete(system, user, ...)``) whose system
prompt is written inline gets a content fingerprint. The fingerprints are pinned in ``evals/prompt_registry.json``.
``check`` fails when

* a prompt changed but was not re-pinned (``drift``) - an unreviewed prompt edit;
* a prompt is new and was never pinned (``unpinned``) - a prompt that no review has seen;
* a pinned prompt is gone (``missing``) - a stale pin;
* a prompt changed while its module's ``PROMPT_VERSION`` did not (``version_not_bumped``) - cached model outputs keyed by
  that version would be served for the new prompt.

``update`` re-pins only with a reason, records it in the registry's history together with the eval-set pins that were
current, and refuses while a version is not bumped. A loop pass records ``digest`` so a result says which prompts made it.

Deployable-gate (course: ``deployable()`` only passes approved/canary/active - code enforces it, not a reviewer's
memory): a re-pin is a review act, and a review without a fresh measurement to look at is not really a review.
``update``'s ``require_loop_evidence`` makes that concrete - refused unless the most recent ``evidence/loop/history.json``
pass (or an explicitly supplied ``loop_fingerprint``) was measured on these exact prompts. It is an explicit, named
**opt-in** (default ``False``), not the default for every caller, for two documented reasons: (1) every unit test in
``tests/bts_sbom_app/test_promptreg.py`` builds a throwaway repo with no ``evidence/`` directory at all, and the
``prompts --update --reason`` CLI call in ``cli_ext.py`` does not pass it either - turning the gate on unconditionally
would refuse the exact re-pins those already-passing tests and that CLI command perform today; (2) this
repository's OWN ``evidence/loop/history.json`` predates the ``prompts`` digest field (every one of its 15 recorded
passes has ``"prompts": null``), so an unconditional gate would refuse `right now`, before anyone had a chance to run
a fresh loop pass. A caller that wants the stricter governance (e.g. a CI re-pin step) turns it on explicitly.
"""
from __future__ import annotations

import ast
import hashlib
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from .util import now_iso, read_json, write_json

REGISTRY = os.path.join("evals", "prompt_registry.json")
_NAME = re.compile(r"(^|_)(SYSTEM|PROMPT)$")
_HISTORY_CAP = 200


def _fp(text: str) -> str:
    return hashlib.sha256(" ".join(str(text).split()).encode("utf-8")).hexdigest()[:12]


def _consts(tree: ast.Module) -> Tuple[Dict[str, str], Optional[str]]:
    """Module-level prompt constants {name: text} and the module's PROMPT_VERSION."""
    out: Dict[str, str] = {}
    version: Optional[str] = None
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        name = node.targets[0].id
        try:
            val: Any = ast.literal_eval(node.value)
        except (ValueError, SyntaxError):                    # a prompt built with + / % / join: its template (source text) is what is pinned
            val = ast.unparse(node.value) if any(isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) >= 40 for n in ast.walk(node.value)) else None
        if name == "PROMPT_VERSION" and isinstance(val, str):
            version = val
        elif _NAME.search(name) and isinstance(val, str) and len(val) >= 40:
            out[name] = val
    return out, version


def _assigned(fn: ast.AST, name: str) -> List[str]:
    """Source of every assignment to ``name`` inside a function (a prompt built up in steps is one prompt)."""
    parts: List[str] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            parts.append(ast.unparse(node.value))
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            parts.append("+= " + ast.unparse(node.value))
    return parts


def _names(expr: ast.AST) -> List[str]:
    return [n.id for n in ast.walk(expr) if isinstance(n, ast.Name)]


def collect(root: str) -> Dict[str, Dict[str, Any]]:
    """{id: {kind, fingerprint, module, where, version?}} for every prompt constant and inline-prompt call site under ``<root>/bts_sbom_app``."""
    pkg = os.path.join(root, "bts_sbom_app")
    out: Dict[str, Dict[str, Any]] = {}
    for fn in sorted(os.listdir(pkg)):
        if not fn.endswith(".py"):
            continue
        mod = fn[:-3]
        try:
            with open(os.path.join(pkg, fn), encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
        except (OSError, SyntaxError, ValueError):
            continue
        consts, version = _consts(tree)
        for name, text in consts.items():
            out["%s.%s" % (mod, name)] = {"kind": "constant", "module": mod, "fingerprint": _fp(text), "chars": len(text), "version": version}
        for func in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            sites = [c for c in ast.walk(func) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "complete" and len(c.args) >= 2]
            for idx, call in enumerate(sorted(sites, key=lambda c: (c.lineno, c.col_offset)), 1):
                first = call.args[0]
                if any(n in consts for n in _names(first)):
                    continue                                  # built from a registered constant: the constant is the prompt
                parts = [ast.unparse(first)] + [p for n in dict.fromkeys(_names(first)) for p in _assigned(func, n)]
                if isinstance(first, ast.Name) and len(parts) == 1:
                    continue                              # a parameter: the callers pass registered constants
                text = "\n".join(parts)
                out["%s.%s#%d" % (mod, func.name, idx)] = {"kind": "inline", "module": mod, "fingerprint": _fp(text), "chars": len(text),
                                                           "version": version, "line": call.lineno}
    return out


_DIGEST_CACHE: Dict[str, Tuple[Any, str]] = {}


def _signature(root: str) -> Tuple[Any, ...]:
    pkg = os.path.join(root, "bts_sbom_app")
    sig = []
    try:
        for e in os.scandir(pkg):
            if e.name.endswith(".py"):
                st = e.stat()
                sig.append((e.name, st.st_mtime_ns, st.st_size))
    except OSError:
        return ()
    return tuple(sorted(sig))


def digest(root: str) -> str:
    """One short hash of every prompt now in the code: which prompts produced a measurement. Cached on the package's file
    signature (names, mtimes, sizes): re-parsing ~85 modules cost ~1 CPU-second and ran on EVERY chat turn (red-team finding)."""
    sig = _signature(root)
    hit = _DIGEST_CACHE.get(root)
    if hit is not None and hit[0] == sig and sig:
        return hit[1]
    cur = collect(root)
    value = _fp("|".join("%s=%s" % (k, cur[k]["fingerprint"]) for k in sorted(cur)))
    _DIGEST_CACHE[root] = (sig, value)
    return value


def registry_path(root: str) -> str:
    return os.path.join(root, REGISTRY)


def load(root: str) -> Dict[str, Any]:
    reg = read_json(registry_path(root), None)
    return reg if isinstance(reg, dict) and isinstance(reg.get("prompts"), dict) else {"schema": 1, "prompts": {}, "history": []}


def check(root: str) -> Dict[str, Any]:
    """Compare the prompts in the code with the pinned registry."""
    cur = collect(root)
    pinned = load(root)["prompts"]
    drift: List[Dict[str, Any]] = []
    unpinned: List[str] = []
    not_bumped: List[Dict[str, Any]] = []
    for pid, c in sorted(cur.items()):
        p = pinned.get(pid)
        if p is None:
            unpinned.append(pid)
        elif p.get("fingerprint") != c["fingerprint"]:
            drift.append({"id": pid, "pinned": p.get("fingerprint"), "now": c["fingerprint"]})
            if c.get("version") and p.get("version") == c["version"]:
                not_bumped.append({"id": pid, "version": c["version"]})
    missing = sorted(set(pinned) - set(cur))
    return {"ok": not (drift or unpinned or missing), "prompts": len(cur), "pinned": len(pinned), "drift": drift, "unpinned": unpinned, "missing": missing,
            "version_not_bumped": not_bumped, "digest": digest(root)}


def _loop_history_path(root: str) -> str:
    return os.path.join(root, "evidence", "loop", "history.json")


def loop_evidence_status(root: str, digest_value: str, loop_fingerprint: Optional[str] = None) -> Tuple[bool, str]:
    """(fresh, detail) for the re-pin evidence gate: whether a loop/eval result measured on ``digest_value`` is
    SUPPLIED (``loop_fingerprint``, compared directly) or FOUND (the most recent entry of
    ``evidence/loop/history.json``'s own ``prompts`` field). Three outcomes: fresh (match - accepted), missing (no
    pass recorded at all - refused) and mismatched (a pass was recorded but not on these prompts - refused)."""
    if loop_fingerprint is not None:
        ok = loop_fingerprint == digest_value
        return ok, ("supplied loop fingerprint %s matches the current prompt digest" % loop_fingerprint if ok else
                     "supplied loop fingerprint %s does not match the current prompt digest %s" % (loop_fingerprint, digest_value))
    hist = read_json(_loop_history_path(root), None)
    if not isinstance(hist, list) or not hist or not isinstance(hist[-1], dict):
        return False, "no pass is recorded in evidence/loop/history.json"
    last = hist[-1]
    recorded = last.get("prompts")
    if not recorded:
        return False, "the latest loop pass (#%s) recorded no prompt digest" % last.get("pass", "?")
    if recorded != digest_value:
        return False, "the latest loop pass (#%s) recorded prompts=%s, the current prompt digest is %s" % (last.get("pass", "?"), recorded, digest_value)
    return True, "the latest loop pass (#%s) matches the current prompt digest" % last.get("pass", "?")


def update(root: str, reason: str, *, eval_pins: Optional[Dict[str, str]] = None, now: Optional[str] = None,
           require_loop_evidence: bool = False, loop_fingerprint: Optional[str] = None) -> Dict[str, Any]:
    """Pin every prompt as it is now. Needs a reason; refused while a changed prompt kept its PROMPT_VERSION.

    ``require_loop_evidence`` (default False, see the module docstring for why) additionally refuses the re-pin
    unless a fresh loop/eval result backs it - ``loop_fingerprint`` lets a caller supply that result's digest
    directly instead of relying on ``evidence/loop/history.json``'s latest entry.
    """
    why = str(reason or "").strip()
    if len(why) < 8:
        raise ValueError("re-pinning prompts needs a reason of at least 8 characters (what changed in the prompt and why)")
    state = check(root)
    if state["version_not_bumped"]:
        raise ValueError("bump PROMPT_VERSION first: %s changed but kept its version, so cached model outputs would be reused" % ", ".join(
            "%s (%s)" % (x["id"], x["version"]) for x in state["version_not_bumped"]))
    if require_loop_evidence:
        fresh, detail = loop_evidence_status(root, state["digest"], loop_fingerprint)
        if not fresh:
            raise ValueError("re-pin refused: %s; run a loop pass that measures these prompts (or pass the fresh "
                              "digest explicitly via loop_fingerprint) before re-pinning" % detail)
    cur = collect(root)
    reg = load(root)
    changed = [d["id"] for d in state["drift"]] + state["unpinned"] + state["missing"]
    reg["prompts"] = {k: {f: v[f] for f in ("kind", "module", "fingerprint", "version") if f in v} for k, v in sorted(cur.items())}
    reg["history"] = (reg.get("history") or []) + [{"at": now or now_iso(), "reason": why, "changed": changed, "eval_sets": dict(eval_pins or {}), "digest": state["digest"]}]
    reg["history"] = reg["history"][-_HISTORY_CAP:]
    reg["schema"] = 1
    write_json(registry_path(root), reg)
    return {"pinned": len(cur), "changed": changed, "digest": state["digest"]}
