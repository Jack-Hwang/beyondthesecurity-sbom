"""Supply-chain name checks for the components of one project, with their limits stated.

The core's analyzer compares package NAMES with a small list of popular packages: a name one edit away (``reqeusts``), a confusable
spelling (``1odash``), an adjacent swap, a suspicious affix (``requests-official``), a scoped name that shadows a popular one
(``@evil/lodash``), a crate that differs only in case, a Maven groupId/artifactId near a popular coordinate - and, for names the
caller declares INTERNAL, dependency confusion. It is deterministic and offline. What it cannot do, and what this module therefore
keeps visible instead of hiding behind "0 findings":

* a finding is a NAME RESEMBLANCE, not proof of malice (measured on the demo projects: ``mquery`` is flagged as a look-alike of
  ``jquery`` and is a legitimate package) - so findings can be reviewed (false positive / accepted) and the verdict is stored;
* an ecosystem without a popular-name list (Go, NuGet, ...) is not checked at all, and "no finding" never means "safe";
* dependency confusion is only asserted for names on the internal list, and the registry a package resolves from is not known here;
* a failing analyzer is reported as ``failed`` / ``partial`` - never as a clean result (the core's own report turns an exception into
  risk level SAFE).

Pure computation on the record's components, done when the view is built (so it always matches the installed core), no network.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import engine

MAX_INTERNAL = 200
NAME_RE = re.compile(r"^[A-Za-z0-9@/_.:+~-]{1,214}$")
_CONF_RANK = {"high": 0, "medium": 1, "low": 2}
DEP_CONFUSION_NOTE = ("BTS-SBOM does not know which registry this package resolves from: the finding only says the name is on your internal "
                      "list and appears as a dependency of this project.")


def review_key(ecosystem: str, name: str, max_len: int = 200) -> str:
    """The id under which a verdict on one package is stored in the shared triage store ('' when it would not fit)."""
    key = "supply:%s:%s" % (ecosystem, name)
    return key if len(key) <= max_len else ""


def valid_internal(names: Any) -> Tuple[List[str], Optional[str]]:
    """(clean list, None) or ([], reason). Names are trimmed and de-duplicated; anything that is not a plausible package name is refused."""
    if not isinstance(names, list):
        return [], "internal_names must be a list of package names"
    out: List[str] = []
    seen = set()
    for n in names:
        if not isinstance(n, str):
            return [], "internal_names must contain only strings"
        n = n.strip()
        if not n:
            continue
        if not NAME_RE.match(n):
            return [], "not a plausible package name: %r" % n[:60]
        if n.lower() not in seen:
            seen.add(n.lower())
            out.append(n)
    if len(out) > MAX_INTERNAL:
        return [], "at most %d internal names are accepted" % MAX_INTERNAL
    return out, None


def policy_path(evidence: str) -> str:
    return os.path.join(evidence, ".supply_policy.json")


def load_internal(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return []
    clean, bad = valid_internal(d.get("internal_names") if isinstance(d, dict) else None)
    return [] if bad else clean


def save_internal(path: str, names: List[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"internal_names": names}, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def analyse(components: Iterable[Dict[str, Any]], internal_names: Iterable[str] = ()) -> Dict[str, Any]:
    """Run the core analyzer over the unique (ecosystem, name) pairs. Never raises: a problem becomes ``status`` failed / partial."""
    internal = list(internal_names or [])
    out: Dict[str, Any] = {"status": "ok", "error": "", "core": "", "internal": internal, "packages": 0, "checked": 0, "errors": 0,
                           "ecosystems": [], "findings": []}
    try:
        kit = engine.supply_analyzer(internal)
    except Exception as exc:                                           # noqa: BLE001 - reported, never turned into "no findings"
        out.update(status="failed", error="%s: %s" % (type(exc).__name__, str(exc)[:160]))
        return out
    an, canon, seeds = kit["analyzer"], kit["canon"], kit["seeds"]
    out["core"] = kit["version"]
    pairs: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for c in components:
        name, eco = str(c.get("name") or ""), str(c.get("ecosystem") or "")
        if not name:
            continue
        e = pairs.setdefault((canon(eco), name), {"raw": eco, "versions": set(), "files": set()})
        e["versions"].add(str(c.get("version") or ""))
        e["files"].update(str(f) for f in (c.get("files") or []))
    per_eco: Dict[str, int] = {}
    first_error = ""
    for (eco, name), meta in pairs.items():
        per_eco[eco] = per_eco.get(eco, 0) + 1
        try:
            r = an.analyze_one(name, meta["raw"])
        except Exception as exc:                                       # noqa: BLE001
            out["errors"] += 1
            first_error = first_error or "%s: %s" % (type(exc).__name__, str(exc)[:120])
            continue
        if not r:
            continue
        f = {k: r.get(k) for k in ("package", "ecosystem", "kind", "resembles", "confidence", "description", "cwe", "recommendation")}
        f.update(ecosystem=eco, versions=sorted(v for v in meta["versions"] if v), files=sorted(meta["files"])[:8], key=review_key(eco, name))
        if r.get("kind") == "dependency-confusion":
            f["note"] = DEP_CONFUSION_NOTE
        out["findings"].append(f)
    out["findings"].sort(key=lambda f: (_CONF_RANK.get(str(f.get("confidence")), 3), str(f.get("kind")), str(f.get("package"))))
    out["packages"] = len(pairs)
    out["ecosystems"] = [{"ecosystem": e, "packages": n, "seed": seeds.get(e, 0), "covered": seeds.get(e, 0) > 0} for e, n in sorted(per_eco.items())]
    out["checked"] = sum(x["packages"] for x in out["ecosystems"] if x["covered"])
    if pairs and out["errors"] == len(pairs):
        out.update(status="failed", error=first_error or "the analyzer failed for every package", findings=[])
    elif out["errors"]:
        out.update(status="partial", error=first_error)
    return out


def annotate(doc: Dict[str, Any], triage: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Attach the stored verdict (false-positive / accepted / ...) to each finding and count the findings still open."""
    counts = {"high": 0, "medium": 0, "open": 0, "reviewed": 0}
    for f in doc.get("findings") or []:
        t = (triage or {}).get(f.get("key") or "")
        if t and t.get("status") and t.get("status") != "open":
            f["review"] = {"status": t.get("status"), "note": t.get("note", "")}
            counts["reviewed"] += 1
            continue
        counts["open"] += 1
        if f.get("confidence") in ("high", "medium"):
            counts[f["confidence"]] += 1
    doc["counts"] = counts
    return doc
