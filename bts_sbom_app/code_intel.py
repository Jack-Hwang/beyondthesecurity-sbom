"""Code Intel: function-level code comprehension of Python sources - the natively reimplemented core of what
SciTools Understand sells (call graph, cyclomatic complexity, dead code, duplicate-code detection), built on the
standard library's ``ast`` with no new dependency and no execution of the analysed tree (ADR-0023).

Why Python only, honestly: the parent architecture lane (``arch.py``) already analyses eight languages at
module level with per-language regexes; a real function-level graph needs a parser per language. Shipping a
half-working regex call "graph" for C/C++ would be invention, so this lane covers Python via ``ast`` and every
other language keeps its module-level analysis - the coverage line is stated in ``notes`` and surfaced in the UI.

Determinism: the same tree always yields the same result - no sampling, no LLM, bounded caps recorded in the
output. Caps exist so a 4000-file tree cannot stall the pipeline; truncation is reported, never silent.
"""
from __future__ import annotations

import ast
import hashlib
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from . import arch as archmod

MAX_FILES = 4000
MAX_FUNCTIONS = 4000
MAX_CALL_EDGES = 8000
MAX_CLONES = 200            # reported clone groups
MIN_CLONE_TOKENS = 24       # a body needs at least this many normalized tokens to count as a clone
                            # (roughly 4+ statements; tiny getters would turn every codebase into "clones")

# functions that are entry points by construction and therefore never "dead code" (Understand calls these
# root entities; our rules are explicitly listed in ``notes`` so the reader can disagree with the list)
NAME_KEEP = {"main", "cli", "run", "setup", "teardown"}


# ----------------------------------------------------------------------------------------------- collection
def _py_files(root: str) -> Tuple[List[str], List[str]]:
    files = archmod.collect_files(root)
    py = [f for f in files if f.lower().endswith(".py")]
    other = len(files) - len(py)
    return py[:MAX_FILES], [f"{other} files of other languages were not function-analysed (Python-only lane)"]


def _rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root).replace("\\", "/")
    except ValueError:
        return path


def _complexity(fn: ast.FunctionDef) -> int:
    """Cyclomatic complexity: 1 + the decision points of the function body (branches, loops, except handlers,
    boolean-operator alternatives, asserts, match cases). Recurses into nested functions - they are separate
    entities for the graph but their decisions also belong to the enclosing function, as standard tools report."""
    n = 1
    for node in ast.walk(fn):
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert)):
            n += 1
        elif isinstance(node, ast.BoolOp):
            n += max(0, len(node.values) - 1)
        elif isinstance(node, ast.match_case):
            n += 1
        elif isinstance(node, ast.comprehension):
            n += 1 + len(node.ifs)
    return n


def _max_nesting(fn: ast.FunctionDef) -> int:
    """Deepest statement nesting inside the body (Understand's MaxNesting analog) - a quick readability signal."""
    best = 0

    def depth(node: ast.AST, cur: int) -> None:
        nonlocal best
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue                          # nested definitions are their own entities
            d = cur + 1 if isinstance(child, ast.stmt) else cur
            best = max(best, d)
            depth(child, d)

    for st in fn.body:
        best = max(best, 1)
        depth(st, 1)
    return best


def _sloc(fn: ast.FunctionDef, src_lines: List[str]) -> int:
    end = getattr(fn, "end_lineno", fn.lineno)
    body = src_lines[fn.lineno - 1:end]
    return sum(1 for ln in body if ln.strip())


def _calls(fn: ast.FunctionDef) -> List[str]:
    """Called names with class context markers: ``self.method`` becomes ``self.method`` (resolvable to the
    same class), ``ClassName.method`` keeps the class prefix, plain names stay plain, other ``obj.attr``
    calls keep only the attribute (documented approximation)."""
    out: List[str] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                out.append(f.id)
            elif isinstance(f, ast.Attribute):
                if isinstance(f.value, ast.Name) and f.value.id in ("self", "cls"):
                    out.append("self." + f.attr)
                elif isinstance(f.value, ast.Name) and re.fullmatch(r"[A-Z][A-Za-z0-9_]*", f.value.id):
                    out.append(f.value.id + "." + f.attr)
                else:
                    out.append(f.attr)
    return out


def _norm_tokens(fn: ast.FunctionDef) -> List[str]:
    """The function body as a normalized token sequence for clone detection: identifiers collapse to their
    kind (NAME/ATTR/STR/NUM), so two bodies that differ only in local names and literals hash equal."""
    toks: List[str] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Name):
            toks.append("NAME" if node.id not in ("self", "cls") else node.id)
        elif isinstance(node, ast.arg):
            toks.append("NAME")
        elif isinstance(node, ast.Attribute):
            toks.append("ATTR")
        elif isinstance(node, (ast.Constant,)):
            toks.append("CONST")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            pass                            # nested defs handled as their own entities
        else:
            toks.append(type(node).__name__)
    return toks


def _parent_links(tree: ast.AST) -> Dict[int, ast.AST]:
    out: Dict[int, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            out[id(child)] = parent
    return out


def _enclosing_class(parents: Dict[int, ast.AST], node: ast.AST) -> Optional[str]:
    cur = parents.get(id(node))
    while cur is not None:
        if isinstance(cur, ast.ClassDef):
            return cur.name
        node, cur = cur, parents.get(id(cur))
    return None


# ---------------------------------------------------------------------------------------------------- analyze
def analyze(root: str, *, max_files: int = MAX_FILES, max_functions: int = MAX_FUNCTIONS,
            max_call_edges: int = MAX_CALL_EDGES, max_clones: int = MAX_CLONES) -> Dict[str, Any]:
    """Function-level comprehension of the Python sources under ``root``. Deterministic; bounded caps reported."""
    notes: List[str] = []
    py_files, other_notes = _py_files(root)
    notes.extend(other_notes)

    funcs: List[Dict[str, Any]] = []
    calls_raw: List[Tuple[str, str]] = []
    classes: List[Dict[str, Any]] = []
    truncated_functions = False
    for path in py_files:
        try:
            full = path if os.path.isabs(path) else os.path.join(root, path)
            rel = _rel(full, root)
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                src = fh.read()
            tree = ast.parse(src)
        except (OSError, SyntaxError, ValueError) as exc:
            notes.append(f"{_rel(path, root) if os.path.isabs(path) else path}: parse failed ({type(exc).__name__}) - file skipped, never invented")
            continue
        lines = src.splitlines()
        parents = _parent_links(tree)
        defs: List[Dict[str, Any]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if len(funcs) + len(defs) >= max_functions:
                    truncated_functions = True
                    break
                defs.append({
                    "id": f"{rel}::{node.name}",
                    "name": node.name,
                    "cls": _enclosing_class(parents, node),
                    "file": rel,
                    "line": node.lineno,
                    "params": len(node.args.args),
                    "loc": (getattr(node, "end_lineno", node.lineno) - node.lineno + 1),
                    "sloc": _sloc(node, lines),
                    "complexity": _complexity(node),
                    "nesting": _max_nesting(node),
                    "decorators": len(node.decorator_list),
                    "calls": _calls(node),
                    "_tokens": _norm_tokens(node),
                })
            elif isinstance(node, ast.ClassDef):
                bases = [ast.unparse(b) if hasattr(ast, "unparse") else getattr(b, "id", "?") for b in node.bases]
                methods = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                classes.append({"name": node.name, "file": rel, "line": node.lineno,
                                "bases": bases[:4], "methods": methods[:20]})
        if truncated_functions:
            break
        funcs.extend(defs)
        calls_raw.extend((d["id"], c) for d in defs for c in d["calls"])
    funcs.sort(key=lambda f: (f["file"], f["line"]))

    # resolve calls with class context: self.method -> a method of the caller's own class; Cls.method ->
    # a method of the class Cls; plain names resolve project-wide with the caller's own file first.
    # Unresolved stays "unknown" and is counted - never guessed (documented approximation).
    by_name: Dict[str, List[str]] = {}
    for f in funcs:
        by_name.setdefault(f["name"], []).append(f["id"])
    by_cls: Dict[str, Dict[str, str]] = {}
    cls_ids = {}
    for f in funcs:
        if f.get("cls"):
            cls_ids[f["cls"]] = True
            by_cls.setdefault(f["cls"], {})[f["name"]] = f["id"]
    fan_in: Dict[str, int] = {f["id"]: 0 for f in funcs}
    fan_out: Dict[str, int] = {f["id"]: 0 for f in funcs}
    unknown_calls = 0
    resolved_edges: List[Tuple[str, str]] = []
    caller_cls = {f["id"]: f.get("cls") for f in funcs}
    caller_file = {f["id"]: f["file"] for f in funcs}

    def _targets(caller: str, callee: str) -> List[str]:
        ccls = caller_cls.get(caller)
        if callee.startswith("self.") and ccls:
            tid = by_cls.get(ccls, {}).get(callee.split(".", 1)[1])
            if tid and tid != caller:
                return [tid]
            return []
        if "." in callee and callee.split(".", 1)[0] in cls_ids:
            cls, meth = callee.split(".", 1)
            tid = by_cls.get(cls, {}).get(meth)
            return [tid] if tid and tid != caller else []
        same_file = [tid for tid in by_name.get(callee, []) if tid != caller and caller_file.get(tid) == caller_file.get(caller)]
        if same_file:
            return same_file
        return [tid for tid in by_name.get(callee, []) if tid != caller]

    for caller, callee in calls_raw[:max_call_edges]:
        targets = _targets(caller, callee)
        if targets:
            fan_out[caller] += len(targets)
            for tid in targets:
                fan_in[tid] += 1
            resolved_edges.extend((caller, tid) for tid in targets)
        else:
            unknown_calls += 1
    if len(calls_raw) > max_call_edges:
        notes.append(f"call edges truncated at {max_call_edges} (measured cap)")
    for f in funcs:
        f["fan_in"], f["fan_out"] = fan_in[f["id"]], fan_out[f["id"]]
        f.pop("calls", None)

    # dead code: defined but never called and not an entry by construction (rules listed for the reader)
    dead = []
    for f in funcs:
        if f["fan_in"] == 0 and (f["name"] not in NAME_KEEP and not f["name"].startswith("__")
                                 and not f["name"].startswith("test_") and f["decorators"] == 0):
            dead.append({"name": f["name"], "file": f["file"], "line": f["line"], "sloc": f["sloc"]})
    notes.append("dead-code exclusions: main/cli/run/setup/teardown, dunders, test_*, decorated functions "
                 "(frameworks register them implicitly)")

    # clones: identical normalized token sequences (identifiers/literals collapsed) within substantial bodies
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for f in funcs:
        toks = _norm_tokens_of_cached(f)
        if len(toks) < MIN_CLONE_TOKENS:
            continue
        h = hashlib.sha256("|".join(toks).encode("utf-8")).hexdigest()[:16]
        groups.setdefault(h, []).append({"file": f["file"], "name": f["name"], "line": f["line"], "sloc": f["sloc"]})
    clones = [{"hash": h, "members": ms[:6], "count": len(ms)}
              for h, ms in sorted(groups.items(), key=lambda kv: -len(kv[1]))[:max_clones]
              if len(ms) >= 2]
    for f in funcs:
        f.pop("_tokens", None)          # internal: never published

    top = max(funcs, key=lambda f: f["complexity"]) if funcs else None
    metrics = {
        "functions": len(funcs),
        "truncated": truncated_functions,
        "avg_complexity": round(sum(f["complexity"] for f in funcs) / len(funcs), 2) if funcs else 0.0,
        "max_complexity": ({"name": top["name"], "file": top["file"], "cc": top["complexity"]} if top else None),
        "dead_count": len(dead),
        "clone_groups": len(clones),
        "resolved_calls": len(resolved_edges),
        "unknown_calls": unknown_calls,
    }
    if truncated_functions:
        notes.append(f"functions truncated at {max_functions} (measured cap)")
    return {"language": "python", "functions": funcs, "dead_code": dead, "clones": clones,
            "classes": classes[:200], "call_edges": resolved_edges[:max_call_edges],
            "metrics": metrics, "notes": notes}


def butterfly(r: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    """One function's immediate neighbourhood - callers (fan-in) and callees (fan-out) - the data behind
    Understand's Butterfly graph. Resolution matches the lane's documented approximation. Edges arrive in two
    shapes: fresh analysis yields (from, to) pairs, a stored record yields {"from": ..., "to": ...} dicts
    (the Arch Intel projection) - both are accepted, never guessed."""
    fn = next((f for f in r.get("functions") or [] if f["name"] == name), None)
    if fn is None:
        return None
    fid = fn["id"]

    def _ends(e: Any) -> Tuple[Optional[str], Optional[str]]:
        if isinstance(e, dict):
            return e.get("from"), e.get("to")
        if isinstance(e, (list, tuple)) and len(e) == 2:
            return e[0], e[1]
        return None, None

    callers = sorted({a for a, b in (_ends(e) for e in r.get("call_edges") or []) if a and b == fid})
    callees = sorted({b for a, b in (_ends(e) for e in r.get("call_edges") or []) if b and a == fid})
    return {"name": name, "file": fn["file"], "line": fn["line"], "complexity": fn["complexity"],
            "fan_in": fn["fan_in"], "fan_out": fn["fan_out"],
            "callers": [{"name": c.split("::")[-1], "file": c.split("::")[0]} for c in callers],
            "callees": [{"name": c.split("::")[-1], "file": c.split("::")[0]} for c in callees]}


def _norm_tokens_of_cached(f: Dict[str, Any]) -> List[str]:
    return f.get("_tokens") or []
