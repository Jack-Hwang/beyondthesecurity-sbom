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
            node_labels: Optional[Dict[str, str]] = None, hotspots: Iterable[str] = (),
            cycle_edges: Iterable[Tuple[str, str]] = (), groups: bool = True) -> str:
    """Nodes and (source, target) edges as one DGML document (DirectedGraph 8.0.0), VS Code Maps rich form.

    Beyond bare nodes/links (DGML reference: Groups/Categories/Styles/Contains): nodes cluster into
    directory Groups (Expanded) wired with Category="Contains" links, hotspot nodes carry the "Hotspot"
    category (styled red by the map's own Categories block), and cycle edges carry the "Cycle" category
    (styled red dashed) - so the map renders an architecture reading, not a hairball, straight in VS."""
    def esc(v: str) -> str:
        return saxutils.escape(str(v), {'"': "&quot;"})

    ns = DGML_NS
    node_list = sorted(set(nodes))
    edge_list = sorted(set((a, b) for a, b in edges if a != b))       # self-loops render as map noise
    cycle = set(tuple(e) for e in cycle_edges) & set(edge_list)
    hot = set(hotspots) & set(node_list)
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           '<DirectedGraph xmlns="%s" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
           'Title="%s" Kind="%s" Layout="Sugiyama" GraphDirection="TopToBottom">' % (ns, esc(title), esc(SCHEMA))]
    groups_of: Dict[str, str] = {}
    if groups:
        for n in node_list:
            grp = n.split("/")[0] if "/" in n else "(root)"
            groups_of[n] = grp
        out.append('  <Nodes>')
        for g in sorted(set(groups_of.values())):
            out.append('    <Node Id="%s" Label="%s" Group="Expanded" />' % (esc(g), esc(g)))
        for n in node_list:
            label = (node_labels or {}).get(n, n)
            attrs = ' Category="Hotspot"' if n in hot else ""
            out.append('    <Node Id="%s" Label="%s"%s />' % (esc(n), esc(label), attrs))
        out.append('  </Nodes>')
        out.append('  <Links>')
        for n in node_list:                                           # containment first: groups hold their members
            out.append('    <Link Source="%s" Target="%s" Category="Contains" />' % (esc(groups_of[n]), esc(n)))
        for a, b in edge_list:
            cat = ' Category="Cycle"' if (a, b) in cycle else ""
            out.append('    <Link Source="%s" Target="%s"%s />' % (esc(a), esc(b), cat))
        out.append('  </Links>')
    else:
        out.append('  <Nodes>')
        for n in node_list:
            label = (node_labels or {}).get(n, n)
            attrs = ' Category="Hotspot"' if n in hot else ""
            out.append('    <Node Id="%s" Label="%s"%s />' % (esc(n), esc(label), attrs))
        out.append('  </Nodes>')
        out.append('  <Links>')
        for a, b in edge_list:
            cat = ' Category="Cycle"' if (a, b) in cycle else ""
            out.append('    <Link Source="%s" Target="%s"%s />' % (esc(a), esc(b), cat))
        out.append('  </Links>')
    out.append('  <Categories>')
    out.append('    <Category Id="Contains" Label="Contains" IsContainment="True" />')
    out.append('    <Category Id="Hotspot" Label="Hotspot" Background="#FF5A2D" />')
    out.append('    <Category Id="Cycle" Label="Cycle edge" Stroke="#FF2A00" StrokeDashArray="4 2" />')
    out.append('  </Categories>')
    out.append('</DirectedGraph>')
    return "\n".join(out) + "\n"


def to_layer_dgml(title: str, nodes: Iterable[str], edges: Iterable[Tuple[str, str]], rules: Dict[str, Any]) -> str:
    """The layer validation as one DGML map: declared layers as Group nodes containing their members,
    cross-layer links categorised legal/illegal/bypassed with violations styled red/amber - the validation
    verdict you can SEE in Visual Studio or any DGML viewer. DGML-spec-compliant companion to
    layer_validate (the .layerdiag schema is undocumented, so we stay on the documented format)."""
    result = layer_validate(edges, rules)
    def esc(v: str) -> str:
        return saxutils.escape(str(v), {'"': "&quot;"})

    ns = DGML_NS
    node_list = sorted(set(nodes))
    layer_of: Dict[str, str] = {}
    for n in node_list:
        layer_of[n] = _layer_of(n, rules) or "unknown"
    declared = sorted((rules.get("layers") or {}).keys())
    groups = declared + (["unknown"] if any(v == "unknown" for v in layer_of.values()) else [])
    illegal_srcs = {tuple(v["edge"]) for v in result["violations"]}
    bypassed_srcs = {tuple(v["edge"]) for v in result["bypassed"]}
    edge_list = sorted(set((a, b) for a, b in edges if a != b))
    out = ['<?xml version="1.0" encoding="utf-8"?>',
           '<DirectedGraph xmlns="%s" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
           'Title="%s" Kind="%s.layers" Layout="Sugiyama" GraphDirection="TopToBottom">' % (ns, esc(title), esc(SCHEMA))]
    out.append('  <Nodes>')
    for g in groups:
        out.append('    <Node Id="layer:%s" Label="%s" Group="Expanded" />' % (esc(g), esc(g)))
    for n in node_list:
        out.append('    <Node Id="%s" Label="%s" />' % (esc(n), esc(n)))
    out.append('  </Nodes>')
    out.append('  <Links>')
    for n in node_list:
        out.append('    <Link Source="layer:%s" Target="%s" Category="Contains" />' % (esc(layer_of[n]), esc(n)))
    for a, b in edge_list:
        if (a, b) in illegal_srcs:
            cat = ' Category="Illegal"'
        elif (a, b) in bypassed_srcs:
            cat = ' Category="Bypassed"'
        else:
            cat = ' Category="Legal"'
        out.append('    <Link Source="%s" Target="%s"%s />' % (esc(a), esc(b), cat))
    out.append('  </Links>')
    out.append('  <Categories>')
    out.append('    <Category Id="Contains" Label="Contains" IsContainment="True" />')
    out.append('    <Category Id="Legal" Label="Allowed dependency" Stroke="#1A7F37" />')
    out.append('    <Category Id="Illegal" Label="Illegal reference" Background="#FF5A2D" Stroke="#D1242F" />')
    out.append('    <Category Id="Bypassed" Label="Bypassed intermediate layer" Stroke="#BF8700" StrokeDashArray="4 2" />')
    out.append('  </Categories>')
    out.append('  <Properties>')
    out.append('    <Property Id="verdict" Label="Validation verdict" DataType="System.String" />')
    out.append('  </Properties>')
    out.append('</DirectedGraph>')
    return "\n".join(out) + "\n"


def _layer_of(node: str, rules: Dict[str, Any]) -> Optional[str]:
    for name, spec in (rules.get("layers") or {}).items():
        for pat in (spec.get("match") or []):
            if fnmatch.fnmatch(node, pat):
                return name
    return None


def layer_validate(edges: Iterable[Tuple[str, str]], rules: Dict[str, Any]) -> Dict[str, Any]:
    """Dependency-diagram validation over the measured import graph, semantics aligned with the REAL
    Visual Studio layer model (REA of Microsoft.VisualStudio.Layer 18.11: layers carry ForbiddenNamespace /
    ForbiddenNamespaceDependencies deny-rules, artifacts outside any layer do not participate, and the
    ValidateLayerHasNoOrObsoleteArtifacts rule flags layers whose patterns match nothing).

    Rules JSON: {"layers": {"<name>": {"match": [<fnmatch on path>],
                                       "may_depend_on": [<layer names>],        (allow-list, deny-by-default)
                                       "forbidden": [<fnmatch on imported node path>],  (deny-list, VS semantics)
                                       "exclude": [<fnmatch on path>]}},        (participation opt-out, VS SupportsValidation=false)
                 "default": "deny"}
    Violations: illegal (target layer not allowed for the source layer, including unknown layers), bypassed
    (a direct edge skips an allowed intermediate that itself may reach the target), forbidden (an import
    into a namespace the source layer declares forbidden). Ambiguous monikers (VS:
    ValidateMonikerAmbiguity) - node paths matching several layers - are reported instead of silently
    resolved; validation proceeds on the first match.
    Unknown-layer edges are counted; layers whose match patterns hit zero nodes are reported obsolete
    (VS: ValidateLayerHasNoOrObsoleteArtifacts); excluded nodes (participation opt-out) are counted and
    named, never checked."""
    layers = rules.get("layers") or {}
    names_in_order = list(layers.keys())
    allow = {name: set(spec.get("may_depend_on") or []) for name, spec in layers.items()}
    forbidden = {name: [p for p in (spec.get("forbidden") or [])] for name, spec in layers.items()}
    exclude = [p for spec in layers.values() for p in (spec.get("exclude") or [])]
    node_layer: Dict[str, str] = {}
    illegal: List[Dict[str, Any]] = []
    bypassed: List[Dict[str, Any]] = []
    forbidden_hits: List[Dict[str, Any]] = []
    ambiguous: List[Dict[str, Any]] = []
    unknown = 0
    all_nodes = sorted({n for e in edges for n in e if n})
    excluded = sorted({n for n in all_nodes if any(fnmatch.fnmatch(n, p) for p in exclude)})
    edge_list = sorted(set((a, b) for a, b in edges if a != b and a not in excluded and b not in excluded))
    # VS ValidateMonikerAmbiguity: a node matching several layer patterns is reported; first match wins
    # for validation, but the ambiguity itself is a finding - never a silent choice.
    for n in all_nodes:
        if n in excluded:
            continue
        matching = [name for name in names_in_order
                    if any(fnmatch.fnmatch(n, p) for p in (layers[name].get("match") or []))]
        if len(matching) > 1:
            ambiguous.append({"node": n, "layers": matching})
    for a, b in edge_list:
        if a not in node_layer:
            node_layer[a] = _layer_of(a, rules) or "unknown"
        if b not in node_layer:
            node_layer[b] = _layer_of(b, rules) or "unknown"
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
        for pat in forbidden.get(la, []):                          # VS ForbiddenNamespace semantics
            if fnmatch.fnmatch(b, pat):
                forbidden_hits.append({"edge": [a, b], "layer": la, "forbidden": pat,
                                       "why": "%s declares %s forbidden" % (la, pat)})
                break
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
    # VS ValidateLayerHasNoOrObsoleteArtifacts: a declared layer whose patterns matched no node is obsolete.
    matched_layers = {v for v in node_layer.values()}
    obsolete = [n for n in names_in_order if n not in matched_layers]
    stripped = [n.strip() for n in names_in_order]                      # VS: LayerNamesMustBeUnique (display names)
    duplicate_names = len(stripped) != len(set(stripped))
    if duplicate_names:
        obsolete.insert(0, "duplicate layer names in the spec (VS: LayerNamesMustBeUnique)")
    verdict = "pass" if not (illegal or bypassed or forbidden_hits or obsolete or duplicate_names or ambiguous) else "fail"
    if verdict == "pass" and edge_list and unknown == len(edge_list):
        verdict = "inconclusive"                        # every edge unmapped: the rules matched nothing - say so
    return {"schema": SCHEMA, "checked": len(edge_list), "unknown_layer_edges": unknown,
            "layers_declared": len(names_in_order), "violations": illegal, "bypassed": bypassed,
            "forbidden": forbidden_hits, "obsolete_layers": obsolete,
            "ambiguous_monikers": ambiguous, "excluded_nodes": excluded,
            "vs_alignment": {"semantics": "ForbiddenNamespace / ForbiddenNamespaceDependencies / "
                                          "ValidateLayerHasNoOrObsoleteArtifacts / LayerNamesMustBeUnique / "
                                          "ValidateMonikerAmbiguity / SupportsValidation",
                             "source": "Microsoft.VisualStudio.Layer 18.11.12306.13 "
                                       "(REA: extracted from the VS 2026 LTSC 18.11 channel manifest)"},
            "verdict": verdict}


def rules_example() -> str:
    """A documented example spec (also used by the CLI help and tests as the format contract). The
    ``forbidden`` deny-list mirrors the REAL Visual Studio layer semantics (ForbiddenNamespace /
    ForbiddenNamespaceDependencies, extracted by REA from Microsoft.VisualStudio.Layer 18.11)."""
    return json.dumps({
        "layers": {
            "ui": {"match": ["web/*", "*/web/*"], "may_depend_on": ["services"], "forbidden": ["bts_sbom/*"],
                   "exclude": ["*/tests/*", "*/__pycache__/*"]},
            "services": {"match": ["bts_sbom_app/*", "*/services/*"], "may_depend_on": ["core", "services"]},
            "core": {"match": ["bts_sbom/*", "*/core/*"], "may_depend_on": ["core"]},
        },
        "default": "deny",
    }, indent=1)
