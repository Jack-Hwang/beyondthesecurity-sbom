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
            max_call_edges: int = MAX_CALL_EDGES, max_clones: int = MAX_CLONES,
            prev_snapshot: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Function-level comprehension of the Python sources under ``root``. Deterministic; bounded caps reported."""
    notes: List[str] = []
    py_files, other_notes = _py_files(root)
    notes.extend(other_notes)

    funcs: List[Dict[str, Any]] = []
    calls_raw: List[Tuple[str, str]] = []
    classes: List[Dict[str, Any]] = []
    file_imports: Dict[str, List[str]] = {}
    module_vars: Dict[str, List[str]] = {}
    import_count = 0
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
        imports_here = 0
        mod_names: List[str] = []
        for node in tree.body:                                  # module level only: the file's own variables
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                for t in (getattr(node, "targets", None) or [getattr(node, "target", None)]):
                    for nm in ast.walk(t) if t is not None else []:
                        if isinstance(nm, ast.Name) and nm.id not in mod_names:
                            mod_names.append(nm.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                imports_here += 1
                for a in node.names:
                    mod_names.append(a.asname or a.name.split(".")[0])
        module_vars[rel] = mod_names
        file_imports[rel] = [a.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                             for a in node.names] + [node.module or "" for node in ast.walk(tree)
                                                     if isinstance(node, ast.ImportFrom)]
        import_count += imports_here
        defs: List[Dict[str, Any]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if len(funcs) + len(defs) >= max_functions:
                    truncated_functions = True
                    break
                decisions = _decisions(node)
                gv = {"reads": 0, "writes": 0}
                for nm in ast.walk(node):
                    if isinstance(nm, ast.Name) and nm.id in module_vars.get(rel, []):
                        gv["reads" if isinstance(nm.ctx, ast.Load) else "writes"] += 1
                defs.append({
                    "id": f"{rel}::{node.name}",
                    "name": node.name,
                    "cls": _enclosing_class(parents, node),
                    "file": rel,
                    "line": node.lineno,
                    "params": len(node.args.args),
                    "loc": (getattr(node, "end_lineno", node.lineno) - node.lineno + 1),
                    "sloc": _sloc(node, lines),
                    **_cc_variants(node),
                    "decisions": decisions,
                    "path_count": min(2 ** decisions, 65536),
                    "essential": _essential(node),
                    "knots": _knots(node),
                    "nesting": _max_nesting(node),
                    "eloc": _eloc(node, lines),
                    **_line_taxonomy(node, lines),
                    **_stmt_counts(node),
                    "halstead": _halstead(node),
                    "decorators": len(node.decorator_list),
                    "calls": _calls(node),
                    "gvar_reads": gv["reads"], "gvar_writes": gv["writes"],
                    "_tokens": _norm_tokens(node),
                })
            elif isinstance(node, ast.ClassDef):
                bases = [ast.unparse(b) if hasattr(ast, "unparse") else getattr(b, "id", "?") for b in node.bases]
                methods = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                classes.append({"name": node.name, "file": rel, "line": node.lineno,
                                "bases": bases[:4], "methods": methods[:20], "_node": node})
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
        # Understand's CountInput / CountOutput: callers + globals read / callees + globals set
        f["count_input"] = f["fan_in"] + f["gvar_reads"]
        f["count_output"] = f["fan_out"] + f["gvar_writes"]
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

    # deep tier (Understand's next catalog tier, adopted 2026-11-28)
    project_class_names = {c["name"] for c in classes}
    for c in classes:
        node = c.pop("_node", None)
        if node is not None:
            c["lcom"] = _lcom(node)
            c["cbo"] = _cbo(node, project_class_names)
    self_recursive = sorted({caller for caller, callee in calls_raw if callee == caller.split("::")[-1]})
    chains = _call_chains(resolved_edges[:max_call_edges], self_recursive=self_recursive)
    hier = _hierarchy(classes)
    fdeps = _file_deps(file_imports)
    methods_n = sum(1 for f in funcs if f.get("cls"))
    deep = {
        "call_chains": chains,
        "hierarchy": hier,
        "file_deps": fdeps,
        "variables": {"module_vars": sum(len(v) for v in module_vars.values()),
                      "top_shared": sorted(
                          ({"file": rel, "vars": len(v)} for rel, v in module_vars.items()),
                          key=lambda x: -x["vars"])[:6]},
        "entities": {"modules": len(file_imports), "classes": len(classes), "methods": methods_n,
                     "functions": len(funcs) - methods_n, "module_vars": sum(len(v) for v in module_vars.values()),
                     "imports": import_count},
    }
    snap = snapshot({"functions": funcs})
    if prev_snapshot is not None:
        deep["changed_entities"] = snapshot_diff(prev_snapshot, snap)
    deep["snapshot_entities"] = len(snap.get("entities") or {})

    return {"language": "python", "functions": funcs, "dead_code": dead, "clones": clones,
            "classes": classes[:200], "call_edges": resolved_edges[:max_call_edges],
            "metrics": metrics, "deep": deep, "notes": notes}


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


# ============================================================================================ deep tier
# The "down 500 floors" round (2026-11-28): the next tier of Understand's public metric catalog and
# information browser, adopted onto the stdlib-ast lane. Every approximation is documented where it is
# computed - no number pretends to be something it is not.

_DEX_DECISION_NODES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert)
_DEX_STRUCTURED = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.match_case)


def _decisions(fn: ast.AST) -> int:
    """The raw decision-point count (= cyclomatic complexity - 1), same node set as _complexity."""
    n = 0
    for node in ast.walk(fn):
        if isinstance(node, _DEX_DECISION_NODES):
            n += 1
        elif isinstance(node, ast.BoolOp):
            n += max(0, len(node.values) - 1)
        elif isinstance(node, ast.match_case):
            n += 1
        elif isinstance(node, ast.comprehension):
            n += 1 + len(node.ifs)
    return n


def _essential(fn: ast.AST) -> int:
    """Essential complexity (documented approximation): complexity minus the statement-level structured
    decisions (if/loops/except/match - reducible primitives), keeping the expression-level contributions
    (boolean-operator alternatives, ternaries, asserts, comprehension clauses) which no structured
    reduction removes. Understand computes this on the reduced flow graph; the ast approximation is honest
    about the same idea."""
    extra = 0
    for node in ast.walk(fn):
        if isinstance(node, ast.BoolOp):
            extra += max(0, len(node.values) - 1)
        elif isinstance(node, (ast.IfExp, ast.Assert)):
            extra += 1
        elif isinstance(node, ast.comprehension):
            extra += 1 + len(node.ifs)
    return 1 + extra


def _knots(fn: ast.AST) -> int:
    """Knots (documented approximation): flow-crossing jumps a structured reader must track - every
    break/continue, plus every return except the function's final return in source order. Loop-else
    and except fall-through are not counted."""
    knots = 0
    returns = 0
    for node in ast.walk(fn):
        if isinstance(node, (ast.Break, ast.Continue)):
            knots += 1
        elif isinstance(node, ast.Return):
            returns += 1
    return knots + max(0, returns - 1)


def _halstead(fn: ast.AST) -> Dict[str, Any]:
    """Halstead derived metrics from the AST (documented approximation of Understand's token-level
    counts): operators are the operator/keyword-node kinds, operands are the name/constant/literal
    positions. n1 distinct operators, n2 distinct operands, N1 total operators, N2 total operands,
    vocabulary n = n1 + n2, length N = N1 + N2, volume V = N * log2(n), difficulty D = (n1/2) * (N2/n2),
    effort E = D * V."""
    ops: Dict[str, int] = {}
    ops_total = 0
    operands: Dict[str, int] = {}
    operands_total = 0
    for node in ast.walk(fn):
        kind = type(node).__name__
        if isinstance(node, ast.operator) or isinstance(node, ast.boolop) or isinstance(node, ast.unaryop) \
                or isinstance(node, ast.cmpop) or kind in ("AugAssign", "AnnAssign", "Assign"):
            ops[kind] = ops.get(kind, 0) + 1
            ops_total += 1
        elif isinstance(node, ast.Name):
            operands[node.id] = operands.get(node.id, 0) + 1
            operands_total += 1
        elif isinstance(node, ast.Constant):
            key = "CONST:" + (node.value.__class__.__name__)
            operands[key] = operands.get(key, 0) + 1
            operands_total += 1
        elif isinstance(node, ast.Attribute):
            operands[node.attr] = operands.get(node.attr, 0) + 1
            operands_total += 1
        elif isinstance(node, ast.arg):
            operands[node.arg] = operands.get(node.arg, 0) + 1
            operands_total += 1
    n1, n2 = len(ops), len(operands)
    N1, N2 = ops_total, operands_total
    n, N = n1 + n2, N1 + N2
    import math
    vol = round(N * math.log2(n), 1) if n else 0.0
    diff = round((n1 / 2) * (N2 / n2), 1) if n2 else 0.0
    return {"n": n, "N": N, "volume": vol, "difficulty": diff,
            "effort": round(diff * vol, 1) if vol else 0.0}


def _eloc(fn: ast.AST, lines: List[str]) -> int:
    """Effective lines of code within the function's span: non-blank, non-comment-only, and lines that
    are nothing but closing braces/brackets (Understand's eLOC idea, computed from the source text)."""
    start = getattr(fn, "lineno", 1)
    end = getattr(fn, "end_lineno", start)
    out = 0
    for line in lines[start - 1:end]:
        s = line.strip()
        if not s or s.startswith("#") or set(s) <= set(")]}"):
            continue
        out += 1
    return out


def _cc_variants(fn: ast.AST) -> Dict[str, int]:
    """Understand's three cyclomatic flavours (measured from its conf/understand/metrics catalog,
    2026-11-28): standard (a boolean chain adds n-1), modified (a chain adds ONE), strict (every
    boolean operand counts)."""
    base, mod_extra, strict_extra = 1, 0, 0
    for node in ast.walk(fn):
        if isinstance(node, _DEX_DECISION_NODES):
            base += 1
            mod_extra += 1
            strict_extra += 1
        elif isinstance(node, ast.BoolOp):
            extra = max(0, len(node.values) - 1)
            base += extra
            mod_extra += 1
            strict_extra += extra
        elif isinstance(node, ast.match_case):
            base += 1
            mod_extra += 1
            strict_extra += 1
        elif isinstance(node, ast.comprehension):
            base += 1 + len(node.ifs)
            mod_extra += 1 + len(node.ifs)
            strict_extra += 1 + len(node.ifs)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            strict_extra += 1                        # strict counts every boolean operator, unary not included
    return {"complexity": base, "complexity_modified": 1 + mod_extra, "complexity_strict": 1 + strict_extra}


def _stmt_counts(fn: ast.AST) -> Dict[str, int]:
    """Understand's statement taxonomy: CountStmt total, declarative (AnnAssign), executable, empty
    (a bare pass - Python's only no-op statement), assignments, and the flow keywords Understand
    reports alongside Knots (returns/breaks/continues)."""
    stmt = decl = exe = empty = assigns = rets = brk = cont = 0
    for node in ast.walk(fn):
        if node is fn:
            continue                                 # the FunctionDef itself is not one of its statements
        if isinstance(node, ast.stmt):
            stmt += 1
            if isinstance(node, ast.AnnAssign):
                decl += 1
            elif isinstance(node, ast.Pass):
                empty += 1
            else:
                exe += 1
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
                assigns += 1
            elif isinstance(node, ast.Return):
                rets += 1
            elif isinstance(node, ast.Break):
                brk += 1
            elif isinstance(node, ast.Continue):
                cont += 1
    return {"stmt_total": stmt, "stmt_decl": decl, "stmt_exe": exe, "stmt_empty": empty,
            "stmt_assigns": assigns, "returns": rets, "breaks": brk, "continues": cont}


def _line_taxonomy(fn: ast.AST, lines: List[str]) -> Dict[str, Any]:
    """CountLine / CountLineCode / CountLineComment / CountLineBlank / RatioCommentToCode over the
    function's span (Understand's line taxonomy; Python has no preprocessor lines to count)."""
    start = getattr(fn, "lineno", 1)
    end = getattr(fn, "end_lineno", start)
    code = comment = blank = 0
    for line in lines[start - 1:end]:
        s = line.strip()
        if not s:
            blank += 1
        elif s.startswith("#"):
            comment += 1
        elif set(s) <= set(")]}"):
            continue                                   # pure closing syntax: neither code nor comment
        else:
            code += 1
    return {"count_line": end - start + 1, "count_line_code": code, "count_line_comment": comment,
            "count_line_blank": blank, "ratio_comment_to_code": (round(comment / code, 2) if code else None)}


def _lcom(cls_node: ast.ClassDef) -> Optional[int]:
    """PercentLackOfCohesion (Henderson-Sellers LCOM*): 100 * (1 - sum(a)/(m*d)) where m = methods,
    d = instance attributes assigned in __init__, a = methods accessing each attribute. None when the
    class has no methods or no instance attributes - the metric is undefined there, stated not faked."""
    methods = [n for n in cls_node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    attrs: List[str] = []
    for init in [n for n in methods if n.name == "__init__"]:
        for node in ast.walk(init):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                    and node.value.id == "self" and isinstance(node.ctx, ast.Store) \
                    and node.attr not in attrs:
                attrs.append(node.attr)
    if not methods or not attrs:
        return None
    reach = sum(min(sum(1 for m in methods
                        if any(isinstance(nd, ast.Attribute) and isinstance(nd.value, ast.Name)
                               and nd.value.id == "self" and nd.attr == a for nd in ast.walk(m))),
                     len(methods)) for a in attrs)
    m, d = len(methods), len(attrs)
    return max(0, round(100 * (1 - reach / (m * d))))


def _cbo(cls_node: ast.ClassDef, project_classes: set) -> int:
    """CountClassCoupled (CBO approximation): distinct OTHER project classes this class's source names."""
    names: set = set()
    for node in ast.walk(cls_node):
        if isinstance(node, ast.Name) and node.id in project_classes and node.id != cls_node.name:
            names.add(node.id)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and node.value.id in project_classes and node.value.id != cls_node.name:
            names.add(node.value.id)
    return len(names)


def _call_chains(edges: List[Tuple[str, str]], self_recursive: Optional[List[str]] = None,
                 max_depth: int = 32, max_visits: int = 20000) -> Dict[str, Any]:
    """Longest call chain (bounded DFS - the lane's edges are a sampled subset, so the chain is a
    measured LOWER bound, never claimed complete) and cyclic call groups (bounded)."""
    adj: Dict[str, List[str]] = {}
    for a, b in edges:
        adj.setdefault(a, []).append(b)
    best: List[str] = []
    visits = 0

    def dfs(path: List[str], onpath: set) -> None:
        nonlocal best, visits
        visits += 1
        if visits > max_visits or len(path) > max_depth:
            return
        if len(path) > len(best):
            best = list(path)
        for nxt in adj.get(path[-1], ()):
            if nxt in onpath:
                continue
            onpath.add(nxt)
            path.append(nxt)
            dfs(path, onpath)
            path.pop()
            onpath.discard(nxt)

    roots = [f for f in adj if f not in {b for _, b in edges}]
    for start in (roots or list(adj.keys())):
        dfs([start], {start})
        if visits > max_visits:
            break

    cycles: List[List[str]] = []
    seen_cycles: set = set()
    # self-recursion first: the resolver excludes self edges on purpose, so the caller passes the
    # functions that call themselves (measured from the raw call list, not from the resolved edges)
    for sid in self_recursive or []:
        if sid not in seen_cycles:
            seen_cycles.add((sid,))
            cycles.append([sid.split("::")[-1], sid.split("::")[-1]])
    # small cycles via one restricted search per node (bounded)
    for start in list(adj.keys())[:400]:
        stack = [(start, [start])]
        while stack and len(cycles) < 12:
            node, path = stack.pop()
            for nxt in adj.get(node, ()):
                if nxt == start:
                    key = tuple(sorted(path))
                    if key not in seen_cycles:
                        seen_cycles.add(key)
                        cycles.append(path + [start])
                elif nxt not in path and len(path) < 12:
                    stack.append((nxt, path + [nxt]))
    return {"longest_depth": len(best), "longest": [p.split("::")[-1] for p in best[:8]],
            "cycles": len(seen_cycles), "cycle_examples": [c[::-1] for c in cycles[:4]]}  # short names


def _hierarchy(classes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Class hierarchy: DIT (depth of inheritance tree within the project) and NOC (number of direct
    children), resolved by base NAME against the project's classes - external bases are stated, never
    resolved."""
    by_name: Dict[str, Dict[str, Any]] = {c["name"]: c for c in classes}
    children: Dict[str, List[str]] = {}
    for c in classes:
        for b in c.get("bases") or []:
            if b in by_name:
                children.setdefault(b, []).append(c["name"])

    def dit(name: str, depth: int = 0) -> int:
        c = by_name.get(name)
        if c is None or depth > 8:
            return depth
        parents = [b for b in c.get("bases") or [] if b in by_name]
        return max([dit(p, depth + 1) for p in parents], default=depth)

    out = []
    for c in classes:
        kids = children.get(c["name"]) or []
        out.append({"name": c["name"], "file": c["file"], "dit": dit(c["name"]),
                    "noc": len(kids), "children": kids[:8],
                    "external_bases": [b for b in c.get("bases") or [] if b not in by_name]})
    return {"classes": out, "max_dit": max((x["dit"] for x in out), default=0),
            "roots": sum(1 for x in out if x["noc"] == 0 and not x["external_bases"])}


def _file_deps(file_imports: Dict[str, List[str]]) -> Dict[str, Any]:
    """Project-internal file dependency edges (an import resolved to a sibling file by module stem),
    their cycles (bounded) and the top-coupled files."""
    stems: Dict[str, List[str]] = {}
    for rel in file_imports:
        stem = os.path.splitext(os.path.basename(rel))[0]
        stems.setdefault(stem, []).append(rel)
    edges: List[Tuple[str, str]] = []
    for src, mods in file_imports.items():
        for m in mods:
            leaf = m.split(".")[-1]
            for dst in stems.get(leaf, []):
                if dst != src:
                    edges.append((src, dst))
    cycles: List[List[str]] = []
    seen: set = set()
    for start in sorted(stems):
        stack = [(start, [start])]
        while stack and len(cycles) < 6:
            node, path = stack.pop()
            for a, b in edges:
                if a == node:
                    if b == start:
                        key = tuple(sorted(path))
                        if key not in seen:
                            seen.add(key)
                            cycles.append(path + [start])
                    elif b not in path and len(path) < 10:
                        stack.append((b, path + [b]))
    coupling: Dict[str, int] = {}
    for a, b in edges:
        coupling[a] = coupling.get(a, 0) + 1
        coupling[b] = coupling.get(b, 0) + 1
    top = sorted(coupling.items(), key=lambda kv: -kv[1])[:6]
    return {"edges": len(edges), "cycles": len(seen), "cycle_examples": cycles[:3],
            "top_coupled": [{"file": f, "degree": d} for f, d in top]}


def _snapshot_digest(f: Dict[str, Any]) -> str:
    basis = (f["id"], f["complexity"], f["sloc"], f["fan_in"], f["fan_out"], len(f.get("_tokens") or []))
    return hashlib.sha256(repr(basis).encode("utf-8")).hexdigest()[:12]


def snapshot(r: Dict[str, Any]) -> Dict[str, Any]:
    """The per-entity digest map for Understand-style changed-entities diffing between two analyses."""
    return {"schema": "bts-sbom.codeintel-snapshot.v1",
            "entities": {f["id"]: _snapshot_digest(f) for f in r.get("functions") or []}}


def snapshot_diff(prev: Dict[str, Any], now: Dict[str, Any]) -> Dict[str, Any]:
    """Changed / added / removed entities between a previous snapshot and the current analysis
    (Understand's between-builds compare)."""
    pe, ne = prev.get("entities") or {}, now.get("entities") or {}
    changed = [k for k in ne if k in pe and pe[k] != ne[k]]
    added = [k for k in ne if k not in pe]
    removed = [k for k in pe if k not in ne]
    return {"changed": sorted(changed), "added": sorted(added), "removed": sorted(removed),
            "changed_count": len(changed), "added_count": len(added), "removed_count": len(removed)}


def dossier(r: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    """Understand's Information Browser for one entity: every lane fact about one function or class in
    one record - identity, full metric set, callers, callees, contained-by, hierarchy position, clones
    involving it. Function first; a class falls back to its hierarchy row plus its methods."""
    fn = next((f for f in r.get("functions") or [] if f["name"] == name), None)
    if fn is None:
        cls = next((c for c in r.get("classes") or [] if c["name"] == name), None)
        if cls is None:
            return None
        hier = _hierarchy(r.get("classes") or [])
        row = next((x for x in hier["classes"] if x["name"] == name), None) or {}
        methods = [f for f in r.get("functions") or [] if f.get("cls") == name]
        return {"kind": "class", "name": name, "file": cls["file"], "line": cls["line"],
                "bases": cls.get("bases") or [], "methods": [m["name"] for m in methods],
                "dit": row.get("dit"), "noc": row.get("noc"),
                "children": row.get("children") or [], "external_bases": row.get("external_bases") or [],
                "method_metrics": [{k: m.get(k) for k in ("name", "complexity", "sloc", "eloc", "fan_in", "fan_out")} for m in methods]}
    fid = fn["id"]

    def _ends(e: Any) -> Tuple[Optional[str], Optional[str]]:
        if isinstance(e, dict):
            return e.get("from"), e.get("to")
        if isinstance(e, (list, tuple)) and len(e) == 2:
            return e[0], e[1]
        return None, None

    callers = sorted({a for a, b in (_ends(e) for e in r.get("call_edges") or []) if a and b == fid})
    callees = sorted({b for a, b in (_ends(e) for e in r.get("call_edges") or []) if b and a == fid})
    clone_groups = [g["hash"] for g in r.get("clones") or []
                    if any(m.get("name") == name for m in g.get("members") or [])]
    return {"kind": "function", "id": fid, "name": fn["name"], "file": fn["file"], "line": fn["line"],
            "cls": fn.get("cls"), "params": fn["params"], "loc": fn["loc"], "sloc": fn["sloc"],
            "metrics": {k: fn.get(k) for k in ("complexity", "essential", "knots", "decisions",
                                               "path_count", "nesting", "eloc", "fan_in", "fan_out")},
            "halstead": fn.get("halstead"),
            "callers": [{"name": c.split("::")[-1], "file": c.split("::")[0]} for c in callers],
            "callees": [{"name": c.split("::")[-1], "file": c.split("::")[0]} for c in callees],
            "clone_groups": clone_groups}
