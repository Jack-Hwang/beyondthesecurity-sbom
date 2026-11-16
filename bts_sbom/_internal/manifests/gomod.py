# vendored from common/manifests/gomod.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""go.mod parser — direct vs `// indirect` (transitive) module requirements."""
import re
from typing import List, Any

from bts_sbom._internal.models import DetectedPackage

_REQ_LINE = re.compile(r'^\s*([^\s]+)\s+(v[0-9][^\s]*)\s*(//\s*indirect)?\s*$')


def _mk(name, version, indirect):
    return DetectedPackage(
        name=name, version=version, ecosystem="go",
        purl=f"pkg:golang/{name}@{version}", source="manifest:go",
        provenance=["manifest:go"],
        relationship="transitive" if indirect else "direct",
        depth=1 if indirect else 0, confidence="high",
    )


def parse(text: str, path: str = "") -> List[Any]:
    """Parse require() blocks and single-line requires from a go.mod.
    A `// indirect` comment marks a transitive dependency."""
    out: List[Any] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        target = line
        if line.startswith("require ") and not line.startswith("require ("):
            target = line[len("require "):].strip()
        elif not in_block:
            continue
        m = _REQ_LINE.match(target)
        if m:
            out.append(_mk(m.group(1), m.group(2), bool(m.group(3))))
    return out
