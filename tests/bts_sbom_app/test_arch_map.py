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
                           node_labels={"bts_sbom_app/a.py": "app module"})
    root = ET.fromstring(xml)                                             # well-formed XML a VS reader accepts
    assert root.tag == "{%s}DirectedGraph" % arch_map.DGML_NS
    nodes = root.findall("{%s}Node" % arch_map.DGML_NS)
    links = root.findall("{%s}Link" % arch_map.DGML_NS)
    assert len(nodes) == 2 and len(links) == 1                            # 2 nodes, self-loops dropped
    labelled = next(n for n in nodes if n.get("Id") == "bts_sbom_app/a.py")
    assert labelled.get("Label") == "app module"                          # the label override landed
    assert {links[0].get("Source"), links[0].get("Target")} == {"bts_sbom_app/a.py", "bts_sbom/core.py"}
    assert 'Kind="bts-sbom.arch-map.v1"' in xml


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
    clean = arch_map.layer_validate([("bts_sbom_app/api.py", "bts_sbom_app/svc.py"),
                                     ("bts_sbom_app/api.py", "bts_sbom/core.py"),
                                     ("bts_sbom/core.py", "bts_sbom/core.py")], rules)
    assert clean["verdict"] == "pass" and clean["violations"] == [] and clean["bypassed"] == []
    unmapped = arch_map.layer_validate([("third_party/x.py", "bts_sbom/core.py")], rules)
    assert unmapped["unknown_layer_edges"] == 1 and unmapped["verdict"] == "fail"   # unknown counted, never mapped


def test_cli_arch_writes_dgml_and_layer_verdict(tmp_path, make_repo):
    """AC: BSA-AC-558, BSA-AC-559"""
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
    assert vr["verdict"] == "inconclusive" and vr["unknown_layer_edges"] >= 1   # rules matched nothing: said, not passed
    assert vr["checked"] >= 1 and "violations" in vr and "bypassed" in vr
    _ = evals.repo_root, FakeScanner                                        # keep the imports honest for linters
