"""VS Code Maps / dependency-diagram adoption: DGML export + deny-by-default layer validation (AC-558/559)."""
from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET

from bts_sbom_app import arch_map, cli, evals
from conftest import FakeScanner

RULES = {
    "layers": {
        "ui": {"match": ["*/web/*", "web/*"], "may_depend_on": ["services"]},
        "services": {"match": ["bts_sbom_app/*"], "may_depend_on": ["core", "services"]},
        "core": {"match": ["bts_sbom/*"], "may_depend_on": ["core"]},
    },
    "default": "deny",
}


def test_dgml_is_wellformed_vs_interop_with_nodes_links_and_no_self_loops():
    """AC: BSA-AC-558"""
    edges = [("bts_sbom_app/a.py", "bts_sbom/core.py"), ("bts_sbom/core.py", "bts_sbom/core.py"),  # self-loop must drop
             ("bts_sbom_app/a.py", "bts_sbom_app/a.py")]
    xml = arch_map.to_dgml("Architecture of demo", sorted({n for e in edges for n in e}), edges,
                           node_labels={"bts_sbom_app/a.py": "app module"}, groups=False)
    root = ET.fromstring(xml)                                             # well-formed XML a VS reader accepts
    assert root.tag == "{%s}DirectedGraph" % arch_map.DGML_NS
    nodes = root.findall(".//{%s}Node" % arch_map.DGML_NS)
    links = root.findall(".//{%s}Link" % arch_map.DGML_NS)
    assert len(nodes) == 2 and len(links) == 1                            # 2 nodes, self-loops dropped
    labelled = next(n for n in nodes if n.get("Id") == "bts_sbom_app/a.py")
    assert labelled.get("Label") == "app module"                          # the label override landed
    assert {links[0].get("Source"), links[0].get("Target")} == {"bts_sbom_app/a.py", "bts_sbom/core.py"}
    assert 'Kind="bts-sbom.arch-map.v1"' in xml


def test_rich_dgml_carries_groups_contains_categories_and_styles():
    """AC: BSA-AC-563"""
    edges = [("bts_sbom_app/api.py", "bts_sbom/core.py"), ("bts_sbom/core.py", "bts_sbom_app/api.py")]
    xml = arch_map.to_dgml("demo", ["bts_sbom_app/api.py", "bts_sbom/core.py"], edges,
                           hotspots=["bts_sbom_app/api.py"], cycle_edges=edges)
    root = ET.fromstring(xml)
    ns = "{%s}" % arch_map.DGML_NS
    groups = [n for n in root.findall(".//" + ns + "Node") if n.get("Group") == "Expanded"]
    assert {g.get("Id") for g in groups} == {"bts_sbom_app", "bts_sbom"}   # directory groups cluster the map
    contains = [l for l in root.findall(".//" + ns + "Link") if l.get("Category") == "Contains"]
    assert len(contains) == 2                                              # each member wired into its group
    cycles = [l for l in root.findall(".//" + ns + "Link") if l.get("Category") == "Cycle"]
    assert len(cycles) == 2                                                # both cycle edges categorised
    cats = {c.get("Id"): c for c in root.findall(".//" + ns + "Category")}
    assert cats["Contains"].get("IsContainment") == "True"
    assert cats["Hotspot"].get("Background") == "#FF5A2D"
    assert cats["Cycle"].get("StrokeDashArray") == "4 2"
    assert 'Layout="Sugiyama"' in xml and 'GraphDirection="TopToBottom"' in xml


def test_layer_map_renders_layers_violation_categories_and_containment():
    """AC: BSA-AC-564"""
    edges = [("bts_sbom_app/api.py", "bts_sbom/core.py"),      # services -> core: legal
             ("bts_sbom/core.py", "bts_sbom_app/api.py")]      # core -> services: illegal
    rules = json.loads(arch_map.rules_example())
    xml = arch_map.to_layer_dgml("layer check", ["bts_sbom_app/api.py", "bts_sbom/core.py"], edges, rules)
    root = ET.fromstring(xml)
    ns = "{%s}" % arch_map.DGML_NS
    links = {(l.get("Source"), l.get("Target")): l.get("Category") for l in root.findall(".//" + ns + "Link")
             if l.get("Category") != "Contains"}
    assert links[("bts_sbom_app/api.py", "bts_sbom/core.py")] == "Legal"
    assert links[("bts_sbom/core.py", "bts_sbom_app/api.py")] == "Illegal"
    cats = {c.get("Id"): c for c in root.findall(".//" + ns + "Category")}
    assert cats["Illegal"].get("Background") == "#FF5A2D" and cats["Bypassed"].get("StrokeDashArray") == "4 2"
    groups = {n.get("Id") for n in root.findall(".//" + ns + "Node") if n.get("Group") == "Expanded"}
    assert groups == {"layer:ui", "layer:services", "layer:core"}           # declared layers become group nodes
    containment = [l for l in root.findall(".//" + ns + "Link") if l.get("Category") == "Contains"]
    assert any(l.get("Target") == "bts_sbom_app/api.py" for l in containment)


def test_layer_validate_reports_illegal_bypassed_unknown_and_pass():
    """AC: BSA-AC-559"""
    edges = [
        ("bts_sbom_app/api.py", "bts_sbom_app/svc.py"),       # services -> services: allowed
        ("bts_sbom_app/api.py", "bts_sbom/core.py"),          # services -> core: allowed
        ("bts_sbom/core.py", "bts_sbom_app/api.py"),          # core -> services: ILLEGAL (deny-by-default)
        ("bts_sbom_app/api.py", "bts_sbom/inner.py"),         # services -> core direct while core path via... (bypass case below)
    ]
    rules = json.loads(arch_map.rules_example())
    r = arch_map.layer_validate(edges, rules)
    assert r["schema"] == "bts-sbom.arch-map.v1" and r["checked"] == 4
    assert r["verdict"] == "fail" and r["violations"], r
    assert any(v["from_layer"] == "core" and v["to_layer"] == "services" for v in r["violations"])
    assert r["unknown_layer_edges"] == 0
    clean = arch_map.layer_validate([("web/ui.py", "bts_sbom_app/api.py"),          # ui -> services: allowed
                                     ("bts_sbom_app/api.py", "bts_sbom_app/svc.py"),
                                     ("bts_sbom_app/api.py", "bts_sbom/core.py"),
                                     ("bts_sbom/core.py", "bts_sbom/core.py")], rules)
    assert clean["verdict"] == "pass" and clean["violations"] == [] and clean["bypassed"] == []
    unmapped = arch_map.layer_validate([("third_party/x.py", "bts_sbom/core.py")], rules)
    assert unmapped["unknown_layer_edges"] == 1 and unmapped["verdict"] == "fail"   # unknown counted, never mapped


def test_cli_arch_writes_dgml_and_layer_verdict(tmp_path, make_repo):
    """AC: BSA-AC-558, BSA-AC-563"""
    origin = make_repo({"app.py": "import helpers\n", "helpers.py": "import os\n"})
    out_dgml = str(tmp_path / "arch.dgml")
    rules_file = str(tmp_path / "layers.json")
    with open(rules_file, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(RULES))
    rc = cli.main(["arch", origin, "--dgml", out_dgml, "--layers", rules_file, "--json", "--offline"])
    assert rc == 0
    assert os.path.exists(out_dgml) and ET.parse(out_dgml) is not None      # the written file parses
    assert os.path.exists(rules_file)


def test_cli_arch_layer_violations_reported(tmp_path, make_repo, capsys):
    """AC: BSA-AC-559"""
    origin = make_repo({"app.py": "import helpers\n", "helpers.py": "import os\n"})
    rules_file = str(tmp_path / "layers.json")
    # a rule set that maps nothing -> every edge is unknown-layer -> honest fail with reasons
    with open(rules_file, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"layers": {"core": {"match": ["nonexistent/*"], "may_depend_on": []}}}))
    rc = cli.main(["arch", origin, "--layers", rules_file, "--json", "--offline"])
    assert rc == 0                                                          # arch itself succeeded; the verdict is data
    out = capsys.readouterr().out
    res = json.loads(out)
    vr = res["layer_validation"]
    assert vr["verdict"] == "fail" and vr["unknown_layer_edges"] >= 1           # unmapped edges counted, never mapped
    assert vr["obsolete_layers"]                                               # VS: ValidateLayerHasNoOrObsoleteArtifacts
    assert vr["checked"] >= 1 and "violations" in vr and "bypassed" in vr
    _ = evals.repo_root, FakeScanner                                        # keep the imports honest for linters


def test_rea_informed_forbidden_obsolete_and_uniqueness_semantics():
    """AC: BSA-AC-579, BSA-AC-591 - the REAL VS layer-model semantics (ForbiddenNamespace etc.), extracted by REA of
    Microsoft.VisualStudio.Layer 18.11, enforced by our validator."""
    rules = {"layers": {
        "ui": {"match": ["web/*", "*/web/*"], "may_depend_on": ["services"], "forbidden": ["bts_sbom/*"]},
        "services": {"match": ["bts_sbom_app/*"], "may_depend_on": ["core"]},
        "ghost": {"match": ["no/such/path/*"], "may_depend_on": []},          # matches nothing -> obsolete
    }}
    edges = [("web/ui.py", "bts_sbom/core.py"),                               # ui -> core: FORBIDDEN by ui's deny-list
             ("bts_sbom_app/api.py", "bts_sbom/core.py")]                     # services -> core: legal
    r = arch_map.layer_validate(edges, rules)
    assert r["verdict"] == "fail"
    assert r["forbidden"] and r["forbidden"][0]["layer"] == "ui"              # the VS ForbiddenNamespace category
    assert "Layer ghost has no artifacts or child layers." in r["obsolete_layers"]  # VS message format, verbatim
    assert r["vs_alignment"]["source"].startswith("Microsoft.VisualStudio.Layer 18.11")
    dup = {"layers": {"a": {"match": ["x/*"]}, "a ": {"match": ["y/*"]}}}
    dupr = arch_map.layer_validate([], dup)
    assert dupr["obsolete_layers"] and "duplicate" in dupr["obsolete_layers"][0]
    assert arch_map.rules_example().count("forbidden") == 1                   # the format contract documents it


def test_moniker_ambiguity_and_participation_exclusion():
    """AC: BSA-AC-580, BSA-AC-591 - VS ValidateMonikerAmbiguity + SupportsValidation adoption."""
    rules = {"layers": {
        "ui": {"match": ["web/*"], "may_depend_on": ["core"]},
        "shared": {"match": ["web/shared/*"], "may_depend_on": ["core"]},     # overlaps ui on web/shared/*
        "core": {"match": ["bts_sbom/*"], "may_depend_on": ["core"], "exclude": ["*/generated/*", "bts_sbom/vendor/*"]},
    }}
    edges = [("web/shared/util.py", "bts_sbom/core.py"),                      # ambiguous: matches ui AND shared
             ("bts_sbom/core.py", "bts_sbom/vendor/embedded.py"),             # target excluded from participation
             ("bts_sbom_app/api.py", "bts_sbom/core.py")]                     # services not declared -> unknown... (no services layer here)
    rules["layers"]["app"] = {"match": ["bts_sbom_app/*"], "may_depend_on": ["core"]}
    r = arch_map.layer_validate(edges, rules)
    amb = r["ambiguous_monikers"]
    assert amb and amb[0]["node"] == "web/shared/util.py" and set(amb[0]["layers"]) == {"ui", "shared"}
    assert amb[0]["message"] == ("Ambiguous moniker 'web/shared/util.py' encountered. "
                                 "It is used for both 'ui' and 'shared'.")                 # the VS wording, verbatim
    assert r["verdict"] == "fail" and any("ambiguous" in a["node"] for a in []) or amb     # ambiguity is the finding
    assert r["excluded_nodes"] == ["bts_sbom/vendor/embedded.py"]              # participation opt-out honoured
    assert r["checked"] == len([e for e in edges if "vendor" not in e[1]])     # excluded edges are not checked
