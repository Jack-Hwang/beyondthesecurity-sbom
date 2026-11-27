"""Coverage gaps of one analysis record: what the scan did NOT cover, so that "nothing found" is never read as "nothing there".

Course source (MetaNet advanced course, week 5 lesson 4 and week 6 lesson 1, error propagation / uncertainty preservation): a
partial failure is reported as a partial result with a coverage-gap annotation - never hidden behind a generic "unavailable", never
turned into a successful empty result, and never allowed to stop the whole workflow. The core scanner already keeps the two facts
apart (``data_status`` and ``vulnerability_presence``; its rule: only ``complete`` + ``none`` is a verified clean result), but the
app layer printed "No vulnerabilities were found" for an offline scan too. This module turns the recorded facts into gap entries
that the chatbot and the fleet lookup append to their answers.

Pure and deterministic: a record in, entries out. Nothing is guessed - a record without the fields (older records) has no gaps
rather than invented ones, and every entry names the recorded fact it comes from.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import handoff

#: data_status values of the core scanner (bts_sbom.osvscanner.DATA_STATUSES) -> what the reader must understand
_DATA_STATUS = {
    "target_missing": "the scan target did not exist, so nothing was checked",
    "empty_project": "no recognisable dependency source was found, so there was nothing to check",
    "unsupported_manifest": "a manifest has no parser, so its packages were not checked",
    "parse_failed": "a manifest could not be parsed, so its packages were not checked",
    "query_missing": "some packages were not queried for advisories",
    "network_failure": "the advisory service could not be reached",
    "stale_db": "the advisory data is older than the freshness limit",
}
NOTE = "the absence of findings is not evidence of absence while the coverage is incomplete"


def _gap(code: str, detail: str, source: str) -> Dict[str, str]:
    return {"code": code, "detail": detail, "source": source}


def of(rec: Dict[str, Any]) -> List[Dict[str, str]]:
    """The coverage gaps recorded for one project record, in a fixed order. ``[]`` = nothing recorded as uncovered."""
    eng = rec.get("engine") if isinstance(rec.get("engine"), dict) else {}
    st = eng.get("status") if isinstance(eng.get("status"), dict) else {}
    out: List[Dict[str, str]] = []
    ds = eng.get("data_status")
    if ds in _DATA_STATUS:
        out.append(_gap("data_status:" + ds, _DATA_STATUS[ds], "engine.data_status"))
    if eng.get("vulnerability_presence") == "unknown":
        out.append(_gap("presence_unknown", "whether the project has vulnerabilities is unknown", "engine.vulnerability_presence"))
    mode = st.get("mode")
    if mode and mode != "online":
        out.append(_gap("mode:" + str(mode), "the scan ran %s: advisories were not looked up online" % mode, "engine.status.mode"))
    n_fb = int(st.get("network_fallback_offline") or 0)
    if n_fb > 0:
        out.append(_gap("network_fallback_offline", "%d package(s) fell back to offline data after a network failure" % n_fb, "engine.status.network_fallback_offline"))
    n_unq = int(st.get("unqueried") or 0)
    if n_unq > 0:
        out.append(_gap("unqueried", "%d package(s) were never queried" % n_unq, "engine.status.unqueried"))
    n_ver = int(st.get("version_unresolved") or 0)
    if n_ver > 0:
        out.append(_gap("version_unresolved", "%d package(s) have no resolved version, so no version-specific check was possible" % n_ver,
                        "engine.status.version_unresolved"))
    unsupported = eng.get("unsupported") or []
    if unsupported:
        out.append(_gap("unsupported_files", "%d file(s) have no supported parser (%s)" % (len(unsupported), ", ".join(str(x) for x in list(unsupported)[:3])),
                        "engine.unsupported"))
    errs = rec.get("stage_errors") if isinstance(rec.get("stage_errors"), dict) else {}
    if errs:
        out.append(_gap("stage_errors", "pipeline stage(s) failed: %s" % ", ".join(sorted(errs)), "stage_errors"))
    return out


def status(rec: Dict[str, Any]) -> str:
    """``complete`` when no gap is recorded, else ``partial``."""
    return "partial" if of(rec) else "complete"


def lines(rec: Dict[str, Any]) -> List[str]:
    """Reader-facing lines for the answers: one for the status, one per gap. Empty when there is no gap."""
    g = of(rec)
    if not g:
        return []
    out = ["Coverage of %s is partial: %s." % (rec.get("name", "the project"), NOTE)]
    out += ["Coverage gap [%s]: %s." % (x["code"], x["detail"]) for x in g]
    return out


def summary(rec: Dict[str, Any]) -> Dict[str, Any]:
    g = of(rec)
    return {"status": "partial" if g else "complete", "gaps": g, "note": NOTE if g else ""}


def envelope(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The recoverable error envelope (handoff.py) for a partial record - ``None`` when nothing is uncovered (no lie of an envelope)."""
    g = of(rec)
    if not g:
        return None
    failed = set((rec.get("stage_errors") or {}))
    done = [k for k in (rec.get("timings") or {}) if k not in failed]
    return handoff.error_envelope("coverage_gap", "recoverable", completed_steps=sorted(done),
                                  partial_result={"components": len(rec.get("components") or []), "findings": len(rec.get("vulns") or [])},
                                  coverage_gap="; ".join(x["detail"] for x in g))


__all__ = ["of", "status", "lines", "summary", "envelope", "NOTE"]
