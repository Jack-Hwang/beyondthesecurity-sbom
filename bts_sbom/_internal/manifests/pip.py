# vendored from common/manifests/pip.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""Python dependency parsers: requirements.txt (direct) + poetry.lock (full tree)."""
import re
from typing import List, Any

from bts_sbom._internal.models import DetectedPackage

try:
    import tomllib          # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._!+-]+)")


def _mk(name, version, relationship):
    name = name.lower()
    return DetectedPackage(
        name=name, version=version, ecosystem="pypi",
        purl=f"pkg:pypi/{name}@{version}", source="manifest:pypi",
        provenance=["manifest:pypi"], relationship=relationship, depth=0,
        confidence="high",
    )


def parse_requirements(text: str, path: str = "") -> List[Any]:
    """requirements.txt — only PINNED (==) lines yield an exact, matchable version.
    Everything listed is treated as direct; transitive info is not available here."""
    out: List[Any] = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_RE.match(line)
        if m:
            out.append(_mk(m.group(1), m.group(2), "direct"))
    return out


def parse_poetry_lock(text: str, path: str = "") -> List[Any]:
    """poetry.lock — exact versions for the WHOLE tree.

    Poetry 1.2+ replaced the per-package ``category`` string with a
    ``groups`` list (e.g. ``groups = ["main"]`` / ``["dev"]``).  We try
    ``groups`` first and fall back to ``category`` for lockfiles produced
    by Poetry < 1.2.  Packages in the "main" or "default" group are
    treated as direct; everything else (dev, test, docs, …) is transitive.
    This remains a best-effort classification because poetry.lock does not
    carry a root-declared / pulled-in bit."""
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except Exception:
        return []
    out: List[Any] = []
    for pkg in data.get("package", []) or []:
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version:
            continue
        # Poetry 1.2+: "groups" list supersedes the old "category" string.
        groups = pkg.get("groups")
        if groups is not None:
            # Any package whose groups include "main" or "default" is direct.
            rel = "direct" if any(g in ("main", "default") for g in groups) else "transitive"
        else:
            # Poetry < 1.2 legacy field; defaults to "main" when absent.
            cat = pkg.get("category", "main")
            rel = "direct" if cat == "main" else "transitive"
        out.append(_mk(name, version, rel))
    return out
