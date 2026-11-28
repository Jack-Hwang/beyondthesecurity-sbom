"""Measured UML design pack for the clean-room reimplementation lane (Sparx EA 17.2 REA round 2, docs/UML_REA_FINDINGS.md).

The point: reimplementing real legacy code is a DESIGN activity - the developer designs while LOOKING AT UML, the way
Enterprise Architect has always worked. EA defines its diagrams as a closed vocabulary + a normalised storage contract
(t_object/t_attribute/t_operation/t_connectortypes: elements, features, connectors as string-keyed tables), and our pack
follows the same discipline: parse the legacy source into that normalised shape with ast (elements/features/relations -
never implementation text), then PROJECT the measurement into Mermaid using the EA notation mapping:

* visibility  Public/Private/Protected/Package  ->  ``+`` / ``-`` / ``#`` / ``~`` (Python convention: bare = +, _name = -);
* connectors  Generalisation/Association/Aggregation/Composition/Dependency  ->  ``--|>`` / ``-->`` / ``o--`` / ``*--`` / ``..>``;
* sequence    UML::Interaction Lifeline/Fragment/activation  ->  ``participant`` / ``alt``-family / ``activate``;
* state       UML::State Initial/Final/Choice/Junction  ->  ``[*]`` / ``choice`` / note.

Four diagrams, all measured, all bounded:
* **class**    - classes with features, and only relationships the AST proves (generalisation from bases, composition
                 from ``self.x = Other(...)`` where Other is a parsed class, association from a typed attribute, dependency
                 from a transient use);
* **sequence** - one entry's call chain (the function with the most outbound calls, or the ``__main__`` guard), depth- and
                 message-capped, with activations;
* **package**  - the module tree + import edges of the source root;
* **state**    - ONLY when a state pattern is measurable (an Enum base, or a field assigned a finite set of literals and
                 branched on); otherwise an honest None with the reason - a state diagram without states is a lie.

The class pack is also what Wall 1 hands Wall 2 as the spec's design view: structure is contract (signatures and
relationships), the same information the interface spec already carries, drawn - never implementation text.
"""
from __future__ import annotations

import ast
import os
import re
from typing import Any, Dict, List, Optional, Tuple

MAX_CLASSES = 12
MAX_FEATURES = 10
MAX_ATTRS = 8
MAX_RELATIONS = 15
MAX_MESSAGES = 14
MAX_FILES = 30
MAX_DEPTH = 4

EA_BASIS = {
    "class": "EA UML::Class toolbox (EA.exe embedded profile 5AC79957-8): Class/Interface/DataType/Enumeration/Primitive/Signal; "
             "'UML Class Diagrams capture the logical structure of a system as a series of classes, their features and the relationships between them'",
    "sequence": "EA UML::Interaction toolbox (3180369F-0): Lifeline/InteractionFragment/Gate; 'specify element behavior as a sequential series of "
                "messages passing back and forth, against a vertical time scale'",
    "package": "EA UML Structural Package diagram: 'describe the organization of packages, their elements and their corresponding relationships'",
    "state": "EA UML::State toolbox (A7FEB956-B): Initial/Final/History/Synch/Choice/Junction/EntryPoint/ExitPoint; 'model the internal behavior of "
             "an element as a graph of states and transitions'",
}


def _vis(name: str) -> str:
    """EA visibility letter for a Python feature name (the convention is declared, not pretended to be Java)."""
    return "-" if name.startswith("_") else "+"


def _cname(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _arg_names(fn: ast.FunctionDef) -> List[str]:
    a = fn.args
    names = [p.arg for p in (a.posonlyargs + a.args + a.kwonlyargs)]
    if a.vararg:
        names.append("*" + a.vararg.arg)
    if a.kwarg:
        names.append("**" + a.kwarg.arg)
    return names


def _walk_calls(node: ast.AST) -> List[Tuple[str, Optional[str]]]:
    """(callee, qualifier) for every direct call in a body - X(), m.X(), self.m() kept apart."""
    out: List[Tuple[str, Optional[str]]] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, (ast.Name, ast.Attribute)):
            f = sub.func
            if isinstance(f, ast.Attribute):
                q = f.value.id if isinstance(f.value, ast.Name) else ("self" if isinstance(f.value, ast.Attribute) and f.value.attr == "self" else "")
                out.append((f.attr, q))
            else:
                out.append((f.id, None))
    return out


def _class_infos(tree: ast.Module) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        attrs: List[Dict[str, Any]] = []
        methods: List[Dict[str, Any]] = []
        comp_targets: List[str] = []
        uses: set = set()
        for stmt in node.body:
            if isinstance(stmt, ast.FunctionDef):
                calls = _walk_calls(stmt)
                methods.append({"name": stmt.name, "args": len(_arg_names(stmt))})
                for callee, q in calls:
                    if q == "self" and callee:
                        continue
                    if callee and callee[0].isupper():
                        uses.add(callee)
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name) \
                    and isinstance(stmt.value, (ast.Constant, ast.List, ast.Dict, ast.Set)):
                attrs.append({"name": stmt.targets[0].id, "kind": type(stmt.value).__name__})
        # __init__ body: self.x = Other(...) is composition on Other; self.x = literal is a plain attribute
        for stmt in node.body:
            if not isinstance(stmt, ast.FunctionDef) or stmt.name != "__init__":
                continue
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Assign) and isinstance(sub.targets[0], ast.Attribute) \
                        and isinstance(sub.targets[0].value, ast.Name) and sub.targets[0].value.id == "self" \
                        and isinstance(sub.value, ast.Call) and isinstance(sub.value.func, ast.Name):
                    comp_targets.append(sub.value.func.id)
                elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Attribute) \
                        and isinstance(sub.target.value, ast.Name) and sub.target.value.id == "self" \
                        and sub.annotation is not None:
                    t = _cname(sub.annotation)
                    if t:
                        attrs.append({"name": sub.target.attr, "kind": "ann:" + t})
        out.append({"name": node.name, "bases": [_cname(b) for b in node.bases], "attrs": attrs,
                    "methods": methods, "composes": sorted(set(comp_targets)), "uses": sorted(uses)})
    return out


def _module_functions(tree: ast.Module) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append({"name": node.name, "node": node, "args": len(_arg_names(node)),
                        "calls": _walk_calls(node)})
    return out


# ------------------------------------------------------------------ class diagram
def _class_mmd(path: str, tree: ast.Module) -> Tuple[str, Dict[str, int]]:
    infos = _class_infos(tree)[:MAX_CLASSES]
    names = {c["name"] for c in infos}
    lines = ["classDiagram"]
    relations: List[str] = []
    for c in infos:
        enums = [b for b in c["bases"] if b in ("Enum", "IntEnum", "StrEnum", "Flag", "IntFlag")]
        body: List[str] = []
        if enums:
            body.append("<<enumeration>>")
        for a in c["attrs"][:MAX_ATTRS]:
            kind = a["kind"]
            body.append("%s%s%s" % (_vis(a["name"]), a["name"], (": " + kind.split(":", 1)[1]) if kind.startswith("ann:") else ""))
        for m in c["methods"][:MAX_FEATURES]:
            body.append("%s%s(%s)" % (_vis(m["name"]), m["name"], "" if m["args"] <= 1 else "…"))
        if len(c["methods"]) > MAX_FEATURES:
            body.append("…%d more()" % (len(c["methods"]) - MAX_FEATURES))
        label = c["name"] + ("~" if len(c["name"]) + len(max(body, key=len, default="")) > 46 else "")
        lines.append("class %s {" % c["name"])
        lines += ["  " + b for b in body]
        lines.append("}")
    for c in infos:
        for b in c["bases"]:
            if b in names and b not in ("Enum", "object", "IntEnum", "StrEnum", "Flag", "IntFlag"):
                relations.append("%s --|> %s : generalisation" % (c["name"], b))
        for t in c["composes"]:
            if t in names:
                relations.append("%s *-- %s : composition" % (c["name"], t))
            elif t not in names and len([1 for i in infos]) and t[0].isupper():
                relations.append("%s ..> %s : dependency (external)" % (c["name"], t))
        for u in c["uses"][:3]:
            if u in names and u not in {r.split()[0] for r in relations} and u not in c["composes"]:
                relations.append("%s ..> %s : dependency" % (c["name"], u))
    # typed attributes naming another parsed class = association
    for c in infos:
        for a in c["attrs"]:
            if a["kind"].startswith("ann:"):
                t = a["kind"].split(":", 1)[1]
                if t in names:
                    relations.append("%s --> %s : association (%s)" % (c["name"], t, a["name"]))
    relations = relations[:MAX_RELATIONS]
    lines += relations
    measured = {"classes": len(infos), "relations": len(relations)}
    if len(infos) < 1:
        return "", measured
    return "\n".join(lines), measured


# ------------------------------------------------------------------ sequence diagram
def _entry_function(funcs: List[Dict[str, Any]], tree: ast.Module) -> Optional[Dict[str, Any]]:
    for node in tree.body:                                    # the __main__ guard names the entry by construction
        if isinstance(node, ast.If) and "main" in ast.unparse(node.test):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                    f = next((x for x in funcs if x["name"] == sub.func.id), None)
                    if f:
                        return f
    return max(funcs, key=lambda f: len(f["calls"]), default=None)


def _sequence_mmd(tree: ast.Module, funcs: List[Dict[str, Any]], parsed: set) -> Tuple[str, int]:
    entry = _entry_function(funcs, tree)
    if entry is None:
        return "", 0
    msgs: List[str] = []
    seen: set = set()

    def emit(caller: str, callee: str, label: str, depth: int) -> None:
        if len(msgs) >= MAX_MESSAGES or (caller, callee) in seen:
            return
        seen.add((caller, callee))
        msgs.append("%s->>%s: %s" % (caller, callee, label))
        if depth < MAX_DEPTH:
            f = next((x for x in funcs if x["name"] == callee), None)
            if f is not None:
                msgs.append("activate %s" % callee)
                for callee2, q in f["calls"][:MAX_MESSAGES]:
                    if callee2 in ("get", "append", "print", "str", "len", "sorted", "set", "open", "range"):
                        continue
                    tgt = callee2 if (callee2 in parsed or (q or "") in parsed) else None
                    if tgt is None:
                        continue
                    if tgt == callee:
                        continue
                    emit(callee, tgt, callee2 + "()", depth + 1)
                    break                                  # one representative call per level: the shape, not a trace
                msgs.append("deactivate %s" % callee)

    emit("caller", entry["name"], entry["name"] + "()", 0)
    if not msgs:
        return "", 0
    return "\n".join(["sequenceDiagram"] + msgs), len(msgs)


# ------------------------------------------------------------------ package diagram
def _package_mmd(source_root: str, self_module: str) -> Tuple[str, Dict[str, int]]:
    files: List[str] = []
    for dirpath, _dirs, names in os.walk(source_root):
        if any(part in ("reimpl", "published", ".git", "__pycache__", "node_modules") for part in dirpath.replace("\\", "/").split("/")):
            continue
        for n in names:
            if n.endswith(".py"):
                rel = os.path.relpath(os.path.join(dirpath, n), source_root).replace("\\", "/")
                if rel != self_module:
                    files.append(rel)
        if len(files) > MAX_FILES * 4:
            break
    files = sorted(files)[:MAX_FILES]
    if not files:
        return "", {"files": 0, "edges": 0}
    nodes: List[str] = []
    edges: List[str] = []
    seen_pkgs: set = set()

    def _node(rel: str) -> str:
        pkg = os.path.dirname(rel).replace("/", "_")
        return pkg if pkg else "m_" + rel[:-3].replace("/", "_")

    def _imports_of(tree: ast.Module, rel: str) -> None:
        pkg = _node(rel)
        for node in tree.body:
            mod = node.module if isinstance(node, ast.ImportFrom) else None
            if not mod:
                continue
            cand = {mod + ".py", mod.rsplit(".", 1)[0] + ".py"}
            for c in cand:
                if c in files or c == self_module:
                    tgt = _node(c)
                    edges.append('%s --> %s' % (pkg, tgt))
                    break

    if os.path.isdir(source_root):
        try:
            self_tree = ast.parse(open(os.path.join(source_root, *self_module.split("/")), encoding="utf-8", errors="replace").read())
            _imports_of(self_tree, self_module)               # the SELF module's imports are the design's top edges
        except (OSError, SyntaxError, ValueError):
            pass
    for rel in files[:MAX_FILES]:
        try:
            tree = ast.parse(open(os.path.join(source_root, *rel.split("/")), encoding="utf-8", errors="replace").read())
        except (OSError, SyntaxError, ValueError):
            continue
        _imports_of(tree, rel)
    for p in sorted({_node(f) for f in files}):
        if p.startswith("m_"):
            nodes.append('%s["module: %s"]' % (p, p[2:] + ".py"))
        else:
            seen_pkgs.add(p)
    lines = ["graph TB", 'root["self: %s"]' % self_module]
    for p in sorted(seen_pkgs):
        lines.append('subgraph %s["package: %s"]' % (p, p.replace("_", "/")))
        lines.append("end")
    lines += nodes
    lines += list(dict.fromkeys(edges))[:MAX_RELATIONS]
    return "\n".join(lines), {"files": len(files), "edges": len(set(edges))}


# ------------------------------------------------------------------ state diagram
_STR_FIELD = re.compile(r"self\.(\w+)\s*=\s*[\"']([A-Za-z_][\w-]*)[\"']")


def _state_mmd(tree: ast.Module, class_infos: List[Dict[str, Any]]) -> Tuple[Optional[str], str, Dict[str, int]]:
    """A state machine is claimed ONLY when measured: a class whose field takes a finite set of literals AND a method
    that branches on that field. Otherwise the honest None with the reason (EA UML::State vocabulary is not drawn from
    guesses)."""
    for c in class_infos:
        node = next((n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == c["name"]), None)
        if node is None:
            continue
        fields: Dict[str, set] = {}
        for sub in ast.walk(node):
            if isinstance(sub, ast.Assign) and isinstance(sub.targets[0], ast.Attribute) \
                    and isinstance(sub.targets[0].value, ast.Name) and sub.targets[0].value.id == "self" \
                    and isinstance(sub.value, ast.Constant) and isinstance(sub.value.value, str):
                fields.setdefault(sub.targets[0].attr, set()).add(sub.value.value)
        if not fields:
            continue
        fname, states = max(fields.items(), key=lambda kv: len(kv[1]))
        transitions: List[Tuple[str, str, str]] = []
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.FunctionDef):
                for sub in ast.walk(stmt):
                    if isinstance(sub, ast.Compare) and isinstance(sub.left, ast.Attribute) \
                            and sub.left.attr == fname and isinstance(sub.comparators[0], ast.Constant):
                        left = sub.comparators[0].value
                        for sibling in ast.walk(stmt):       # a branch body that assigns a new literal = a transition
                            if isinstance(sibling, ast.Assign) and isinstance(sibling.targets[0], ast.Attribute) \
                                    and sibling.targets[0].attr == fname and isinstance(sibling.value, ast.Constant) \
                                    and sibling.value.value in states and sibling.value.value != left:
                                transitions.append((left, sibling.value.value, stmt.name))
        if len(states) >= 2 and transitions:
            lines = ["stateDiagram-v2", "[*] --> %s" % sorted(states)[0]]
            for a, b, via in transitions[:MAX_MESSAGES]:
                lines.append("%s --> %s: %s" % (a, b, via))
            lines.append("%s --> [*]" % sorted(states)[-1])
            return "\n".join(lines), "measured: self.%s literals %s" % (fname, sorted(states)), \
                {"states": len(states), "transitions": len(transitions)}
    return None, "no measurable state pattern (no field with a finite literal set branched on) - the state diagram is not drawn", {"states": 0, "transitions": 0}


# ------------------------------------------------------------------ the pack
def design_pack(path: str, source_root: Optional[str] = None) -> Dict[str, Any]:
    """The measured UML design pack for one legacy module: four diagrams + the measurements + the EA notation basis.
    Every diagram is bounded; a diagram that cannot be measured honestly is absent with its reason."""
    source_root = source_root or os.path.dirname(os.path.abspath(path))
    self_module = os.path.basename(path)
    try:
        tree = ast.parse(open(path, encoding="utf-8", errors="replace").read())
    except (OSError, SyntaxError, ValueError) as exc:
        return {"module": self_module, "error": "cannot parse legacy source: %s: %s" % (type(exc).__name__, str(exc)[:120])}
    class_infos = _class_infos(tree)
    funcs = _module_functions(tree)
    parsed = {c["name"] for c in class_infos} | {f["name"] for f in funcs}
    class_mmd, cm = _class_mmd(path, tree)
    seq_mmd, sm = _sequence_mmd(tree, funcs, parsed)
    pkg_mmd, pm = _package_mmd(source_root, self_module)
    state_mmd, state_note, stm = _state_mmd(tree, class_infos)
    out: Dict[str, Any] = {"module": self_module,
                           "ea_basis": EA_BASIS,
                           "measured": {"classes": cm["classes"], "relations": cm["relations"], "sequence_messages": sm,
                                        "package_files": pm.get("files", 0), "package_edges": pm.get("edges", 0),
                                        "functions": len(funcs), **stm},
                           "caps": {"classes": MAX_CLASSES, "relations": MAX_RELATIONS, "messages": MAX_MESSAGES,
                                    "files": MAX_FILES, "depth": MAX_DEPTH},
                           "clean_room": "structure only (signatures + relationships) - implementation text never leaves Wall 1"}
    out["diagrams"] = {}
    if class_mmd:
        out["diagrams"]["class"] = class_mmd
    if seq_mmd:
        out["diagrams"]["sequence"] = seq_mmd
    if pkg_mmd:
        out["diagrams"]["package"] = pkg_mmd
    if state_mmd:
        out["diagrams"]["state"] = state_mmd
    else:
        out["state_note"] = state_note
    return out


def spec_section(pack: Dict[str, Any]) -> str:
    """The Wall-1 -> Wall-2 design view: the class diagram (structure = contract) as spec text. The section states
    its own clean-room rule so the generator knows what this section is and is not."""
    mmd = (pack.get("diagrams") or {}).get("class")
    if not mmd:
        return ""
    return "\n".join([
        "", "## Design view (UML class diagram - measured structure)",
        "", "Relationship key: `--|>` generalisation, `-->` association, `*--` composition, `..>` dependency, `+`/`-` visibility.",
        "This is the measured SHAPE of the target's interface - keep it; it carries no implementation.",
        "", "```", mmd, "```", "",
    ])


def ui_items(pack: Dict[str, Any]) -> List[Dict[str, str]]:
    """The pack as UI rows: (kind, title, mermaid) in EA kind order - the workbench renders each as a diagram card."""
    titles = {"class": "UML Class (EA UML::Class)", "sequence": "UML Sequence (EA UML::Interaction)",
              "package": "UML Package (EA UML Structural)", "state": "UML State (EA UML::State)"}
    return [{"kind": k, "title": titles.get(k, k), "mermaid": m} for k, m in (pack.get("diagrams") or {}).items()]
