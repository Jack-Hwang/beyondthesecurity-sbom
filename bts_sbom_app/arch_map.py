"""Architecture map exchange + layer validation (Visual Studio Code Maps / dependency-diagram round).

Two capabilities adopted from the VS modelling toolset and mapped onto the measured import graph this
project already builds (arch.import_graph over Py/JS/Java/Go/C/Rust/Ruby):

* **DGML export** — ``to_dgml`` renders nodes/links as a Directed Graph Markup Language document, the same
  format Visual Studio's Code Maps save as (*.dgml), so the measured architecture opens directly in VS or
  any DGML reader. Pure XML via stdlib ElementTree-equivalent string building; no extra dependency.
* **Layer validation** — ``layer_validate`` is the dependency-diagram check: a declarative layer spec maps
  nodes (fnmatch on path) to layers with deny-by-default ``may_depend_on`` allow-lists; violations come
  back in VS's two categories — *illegal reference* (target layer not allowed for the source) and
  *bypassed intermediate layer* (an edge skips an allowed neighbour that itself is allowed to reach the
  target). Unknown-layer nodes are counted, never silently mapped.

Deterministic, offline, no LLM — the same rules VS validates at build time, enforced here on every arch run.
"""
from __future__ import annotations

import fnmatch
import json
import xml.sax.saxutils as saxutils
from typing import Any, Dict, Iterable, List, Set, Tuple

DGML_NS = "http://schemas.microsoft.com/vs/2009/dgml"
SCHEMA = "bts-sbom.arch-map.v1"


def to_dgml(title: str, nodes: Iterable[str], edges: Iterable[Tuple[str, str]],
            node_labels: Optional[Dict[str, str]] = None) -> str:
    """Nodes and (source, target) edges as one DGML document (DirectedGraph 8.0.0)."""
    def esc(v: str) -> str:
        return saxutils.escape(str(v), {'"': "&quot;"})

    ns = DGML_NS
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           '<DirectedGraph xmlns="%s" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
           'Title="%s" Kind="%s">' % (ns, esc(title), esc(SCHEMA))]
    seen: Set[str] = set()
    for n in nodes:
        if n in seen:
            continue
        seen.add(n)
        label = (node_labels or {}).get(n, n)
        out.append('  <Node Id="%s" Label="%s" />' % (esc(n), esc(label)))
    for a, b in edges:
        if a == b:
            continue                                          # self-loops render as noise on a code map
        out.append('  <Link Source="%s" Target="%s" />' % (esc(a), esc(b)))
    out.append('</DirectedGraph>')
    return "\n".join(out) + "\n"


def _layer_of(node: str, rules: Dict[str, Any]) -> Optional[str]:
    for name, spec in (rules.get("layers") or {}).items():
        for pat in (spec.get("match") or []):
            if fnmatch.fnmatch(node, pat):
                return name
    return None


def layer_validate(edges: Iterable[Tuple[str, str]], rules: Dict[str, Any]) -> Dict[str, Any]:
    """Dependency-diagram validation over the measured import graph.

    Rules JSON: {"layers": {"<name>": {"match": [<fnmatch on path>], "may_depend_on": [<layer names>]}},
                 "default": "deny"}  (deny-by-default is the only supported default - matching VS).
    Violations: illegal (target layer not allowed for the source layer, including unknown layers) and
    bypassed (an edge to a layer that IS allowed directly while an allowed intermediate neighbour is also
    depended on and itself allowed to reach the target - the architecture wanted the hop through it)."""
    layers = rules.get("layers") or {}
    allow = {name: set(spec.get("may_depend_on") or []) for name, spec in layers.items()}
    node_layer: Dict[str, str] = {}
    illegal: List[Dict[str, Any]] = []
    bypassed: List[Dict[str, Any]] = []
    unknown = 0
    edge_list = sorted(set((a, b) for a, b in edges if a != b))
    for a, b in edge_list:
        if a not in node_layer:
            node_layer[a] = _layer_of(a, rules) or "unknown"
        if b not in node_layer:
            node_layer[b] = _layer_of(b, rules) or "unknown"
    for a, b in edge_list:
        la, lb = node_layer[a], node_layer[b]
        if la == "unknown" or lb == "unknown":
            unknown += 1
        if la != lb and lb not in allow.get(la, set()):
            illegal.append({"edge": [a, b], "from_layer": la, "to_layer": lb,
                            "why": "the target layer is not in %s's may_depend_on" % la})
    # bypassed intermediate: a->c where a is allowed to c directly, a also depends on an allowed
    # intermediate b, and b is itself allowed to reach c - the declared path goes through b.
    out_by_layer: Dict[str, Set[str]] = {}
    for a, b in edge_list:
        out_by_layer.setdefault(node_layer[a], set()).add(node_layer[b])
    seen: Set[Tuple[str, str, str]] = set()
    for a, c in edge_list:
        la, lc = node_layer[a], node_layer[c]
        if la == lc or lc not in allow.get(la, set()):
            continue                                        # illegal already, or a self-layer edge
        for b in sorted(allow.get(la, set())):
            lb = b
            if lb == la or lb == lc or lb not in out_by_layer.get(la, set()):
                continue                                    # no actual edge through b, or degenerate
            if lc in allow.get(lb, set()) and (la, lb, lc) not in seen:
                seen.add((la, lb, lc))
                bypassed.append({"edge": [a, c], "through_layer": lb,
                                 "why": "%s may reach %s through %s - the direct edge bypasses the declared hop" % (la, lc, lb)})
                break                                       # one bypass report per offending edge
    verdict = "pass" if not illegal and not bypassed else "fail"
    if verdict == "pass" and edge_list and unknown == len(edge_list):
        verdict = "inconclusive"                        # every edge unmapped: the rules matched nothing - say so
    return {"schema": SCHEMA, "checked": len(edge_list), "unknown_layer_edges": unknown,
            "layers_declared": len(layers), "violations": illegal, "bypassed": bypassed,
            "verdict": verdict}


def rules_example() -> str:
    """A documented example spec (also used by the CLI help and tests as the format contract)."""
    return json.dumps({
        "layers": {
            "ui": {"match": ["web/*", "*/web/*"], "may_depend_on": ["services"]},
            "services": {"match": ["bts_sbom_app/*", "*/services/*"], "may_depend_on": ["core", "services"]},
            "core": {"match": ["bts_sbom/*", "*/core/*"], "may_depend_on": ["core"]},
        },
        "default": "deny",
    }, indent=1)
