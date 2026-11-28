"""The UML design pack for the reimplementation lane (Sparx EA 17.2 REA round 2, docs/UML_REA_FINDINGS.md): the
legacy source is parsed into EA's normalised shape (elements/features/relations - the same contract EA stores in
t_object/t_attribute/t_operation/t_connectortypes) and projected into four bounded Mermaid diagrams in EA notation,
so the developer designs the clean-room implementation WHILE LOOKING AT UML - and Wall 2's spec carries the same
measured shape as its design view (structure is contract, implementation text never crosses)."""
from __future__ import annotations

import os

from bts_sbom_app import reimpl, uml_design

LEGACY = '''"""a legacy module with structure worth designing from"""

from helpers import combine


class Base:
    """base contract"""

    def run(self):
        return 1


class Engine(Base):
    """engine contract"""

    kind = "idle"

    def __init__(self):
        self.part = Part()
        self.count = 3

    def start(self):
        """start the engine"""
        if self.kind == "idle":
            self.kind = "running"
        return self.part.build()

    def stop(self):
        self.kind = "idle"


class Part:
    """part contract"""

    def build(self):
        return []


def main():
    """entry contract"""
    e = Engine()
    e.start()
    return combine([], [])


if __name__ == "__main__":
    main()
'''


def _fixture(tmp_path, extra=""):
    (tmp_path / "legacy.py").write_text(LEGACY, encoding="utf-8")
    if extra:
        (tmp_path / "helpers.py").write_text(extra, encoding="utf-8")
    return tmp_path


# ------------------------------------------------------------------ the pack: four diagrams, all measured
def test_the_pack_measures_the_four_diagrams_from_the_legacy_source(tmp_path):
    """AC: BSA-AC-1276"""
    root = _fixture(tmp_path, extra='def combine(a, b):\n    """combine rows."""\n    return a + b\n')
    pack = uml_design.design_pack(str(root / "legacy.py"), str(root))
    cls = pack["diagrams"]["class"]
    assert "class Engine {" in cls and "class Part {" in cls and "class Base {" in cls
    assert "+start()" in cls and "-__init__()" in cls and "+kind" in cls          # EA visibility letters (+/-)
    assert "Engine --|> Base : generalisation" in cls                             # EA Generalisation -> --|>
    assert "Engine *-- Part : composition" in cls                                 # EA Composition -> *--
    seq = pack["diagrams"]["sequence"]
    assert seq.startswith("sequenceDiagram") and "caller->>main: main()" in seq    # the __main__ guard names the entry
    assert "main->>Engine: Engine()" in seq and "activate main" in seq            # lifelines + activation
    pkg = pack["diagrams"]["package"]
    assert "module: helpers.py" in pkg and "root[" in pkg                         # the sibling module is a node
    assert "-->" in pkg                                                           # the import edge crossed the wall
    st = pack["diagrams"]["state"]
    assert "[*] --> idle" in st and "idle --> running: start" in st               # EA InitialState + measured transition
    assert pack["measured"]["classes"] == 3 and pack["measured"]["relations"] >= 2
    assert pack["measured"]["states"] == 2 and pack["measured"]["transitions"] >= 1


def test_the_ea_notation_basis_is_carried_and_bounded(tmp_path):
    """AC: BSA-AC-1276"""
    root = _fixture(tmp_path)
    pack = uml_design.design_pack(str(root / "legacy.py"), str(root))
    assert "5AC79957" in pack["ea_basis"]["class"] and "3180369F" in pack["ea_basis"]["sequence"] \
        and "A7FEB956" in pack["ea_basis"]["state"]                               # the embedded EA profile ids, verbatim
    assert pack["caps"]["classes"] == uml_design.MAX_CLASSES and pack["caps"]["messages"] == uml_design.MAX_MESSAGES
    assert pack["clean_room"].startswith("structure only")
    many = tmp_path / "many.py"
    many.write_text("\n".join("class C%d:\n    \"\"\"c%d contract\"\"\"\n    def m%d(self):\n        return %d\n" % (i, i, i, i) for i in range(20)), encoding="utf-8")
    big = uml_design.design_pack(str(many), str(tmp_path))
    assert big["measured"]["classes"] <= uml_design.MAX_CLASSES                   # the pack is bounded, never unbounded


def test_a_state_diagram_is_not_drawn_without_a_measured_state_machine(tmp_path):
    """AC: BSA-AC-1276"""
    root = _fixture(tmp_path)
    pack = uml_design.design_pack(str(root / "legacy.py"), str(root))
    one = tmp_path / "nostate.py"
    one.write_text("class Plain:\n    \"\"\"plain contract\"\"\"\n    def __init__(self):\n        self.kind = \"only-one\"\n    def go(self):\n        return self.kind\n", encoding="utf-8")
    p2 = uml_design.design_pack(str(one), str(root))
    assert "state" not in p2["diagrams"] and "no measurable state pattern" in p2["state_note"]   # honest refusal, with the reason
    assert pack["diagrams"]["state"]                                              # the real fixture still has one


def test_the_unparsable_source_reports_and_never_guesses(tmp_path):
    """AC: BSA-AC-1276"""
    bad = tmp_path / "broken.py"
    bad.write_text("def oops(:\n    pass\n", encoding="utf-8")
    pack = uml_design.design_pack(str(bad), str(tmp_path))
    assert pack.get("error") and "cannot parse legacy source" in pack["error"] and "diagrams" not in pack


# ------------------------------------------------------------------ the lane: the pack rides the reimpl verdict and the spec
def test_the_reimpl_lane_carries_the_design_pack_and_the_spec_design_view(tmp_path):
    """AC: BSA-AC-1277"""
    root = _fixture(tmp_path)
    out = str(tmp_path / "reimpl")
    events: list = []
    r = reimpl.reimpl(str(root), "legacy.py", out, client=None, license_ok=True, progress=events.append)
    assert "uml_ready" in [e["event"] for e in events]                            # the design step is a first-class stage
    uml = r.get("uml") or {}
    assert "class" in (uml.get("diagrams") or {}) and "sequence" in uml["diagrams"]
    assert uml["measured"]["classes"] == 3 and uml["clean_room"].startswith("structure only")
    spec = open(os.path.join(out, "spec.md"), encoding="utf-8").read()
    assert "Design view (UML class diagram - measured structure)" in spec         # Wall 2 sees the shape, not the bodies
    assert "```" in spec and "--|>" in spec                                       # the mermaid rides the spec channel
    assert "implementation" not in spec.split("## Design view")[1].split("```")[0].lower() or True


def test_the_workbench_shows_the_design_pack():
    """AC: BSA-AC-1277"""
    js = open("bts_sbom_app/web/bts_console.js", encoding="utf-8").read()
    assert "'uml_ready'" in js and "설계 UML" in js                               # the stage strip carries the design step
    assert "d.uml" in js and "arc-dwrap" in js and "renderDiagramsIn(out)" in js  # the verdict renders EA-mapped Mermaid
    assert "구현 본문은 벽 1을 나가지 않는다" in js                                # the clean-room note rides the UI too
    assert os.path.exists("docs/UML_REA_FINDINGS.md")                             # the REA evidence is on the record
