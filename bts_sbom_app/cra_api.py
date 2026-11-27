"""The EU CRA compliance screen's HTTP surface (server.py routes it through ``Handler._cra``).

Routes (the app's own honesty contract holds: a check that needs data the scan does not produce is a gap with
its fix, never a pass):
  GET  /.well-known/security.txt            -> RFC 9116 file (contact from BTS_SBOM_CVD_CONTACT; 404 with the fix when unset)
  GET  /api/cra/<project>                   -> readiness scorecard (guide annex I, automatable subset) + support declaration
  GET  /api/cra/<project>/ledgers?which=1-5 -> the guide's five SBOM ledgers (annex J) as CSV downloads
  GET  /api/cra/<project>/article14         -> recorded awareness entries with their Article 14 clocks
  POST /api/cra/<project>/article14         -> record one awareness moment (T0); exploitation verdicts stay human
  POST /api/cra/<project>/support           -> declare/clear the support period (YYYY-MM; validated against Article 13(8))
  POST /api/cra/<project>/eol-maintained    -> flag the EOL ledger as the team's maintained copy
"""
from __future__ import annotations

import os
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from .oss_api import Response, _err, _host_allowed, _ok, _same_origin

_CVD_CONTACT_ENV = "BTS_SBOM_CVD_CONTACT"                    # a mailto: or URL - the generator never invents one
_REDIRECT_ACCT_ENV = "BTS_SBOM_CVD_POLICY_URL"               # optional Policy: field (CVD policy document URL)
_REDIRECT_CSAF_ENV = "BTS_SBOM_CVD_CSAF_URL"                 # optional CSAF: field


def _contact() -> str:
    return os.environ.get(_CVD_CONTACT_ENV, "").strip()


def _history_rows(st: Any, name: str) -> List[Dict[str, Any]]:
    """Every recorded analysis run of one project (rows for the update-history ledger)."""
    try:
        from .server import _history_row, project_records
        return [_history_row(n, f, r) for n, (f, r) in project_records(st.evidence).items() if n == name]
    except Exception:                                        # noqa: BLE001 - history is auxiliary: degrade to an empty list
        return []


def route(method: str, path: str, query: Dict[str, List[str]], body: Dict[str, Any], headers: Any, st: Any,
          bind: Optional[Tuple[Any, ...]] = None) -> Optional[Response]:
    """Return a response for the CRA routes, or None when the path is not ours."""
    if path == "/.well-known/security.txt":
        if method != "GET":
            return _err(405, "security.txt answers GET only")
        contact = _contact()
        if not contact:
            return _err(404, "security.txt is not deployed: set %s (a mailto: or a URL) - a guessed address would be worse than none" % _CVD_CONTACT_ENV)
        from . import cra
        from . import __version__
        txt = cra.security_txt(contact, policy=os.environ.get(_REDIRECT_ACCT_ENV, "").strip(),
                               csaf=os.environ.get(_REDIRECT_CSAF_ENV, "").strip())
        return 200, txt, "text/plain", {}
    if not path.startswith("/api/cra/"):
        return None
    if headers is not None and not _host_allowed(headers.get("Host", "") or "", bind):
        return _err(403, "unexpected Host header (the service answers only at its own address)")
    if method == "POST" and not _same_origin(headers, bind):
        return _err(403, "cross-origin request refused")
    rest = path[len("/api/cra/"):].strip("/")
    from . import conformance, cra
    if method == "GET":
        if "/" not in rest:
            return _project_view(st, urllib.parse.unquote(rest))
        name, _, sub = rest.partition("/")
        sub = sub.strip("/")
        if sub == "ledgers":
            which = (query.get("which") or [""])[0].strip()
            if which not in ("1", "2", "3", "4", "5"):
                return _err(400, "which must be one of 1..5 (the guide's five SBOM ledgers)")
            return _ledger_csv(st, urllib.parse.unquote(name), which)
        if sub == "article14":
            hit = st.project(urllib.parse.unquote(name))
            if hit is None:
                return _err(404, "unknown project")
            folder, _rec = hit
            return _ok({"project": name, "entries": cra.load_awareness(folder)})
        return _err(404, "not found")
    if method == "POST":
        name, _, sub = rest.partition("/")
        sub = sub.strip("/")
        hit = st.project(urllib.parse.unquote(name))
        if hit is None:
            return _err(404, "unknown project")
        folder, _rec = hit
        if sub == "article14":
            try:
                rec = cra.record_awareness(folder, body or {})
            except ValueError as exc:
                return _err(400, str(exc))
            return _ok({"project": name, "entry": rec})
        if sub == "support":
            declared = str((body or {}).get("support_end") or "").strip()
            if not declared:
                res = cra.declare_support(folder, "")         # empty clears the declaration
                return _ok({"project": name, "cleared": True, "validation": res})
            res = cra.declare_support(folder, declared)
            if res["status"] == "invalid":
                return _err(400, "%s (Annex II 7: 최소 연·월 YYYY-MM)" % res["note"])
            return _ok({"project": name, "validation": res})
        if sub == "eol-maintained":
            maintained = bool((body or {}).get("maintained"))
            cra.set_ledger_maintained(folder, "3", maintained)
            return _ok({"project": name, "eol_maintained": maintained})
        return _err(404, "not found")
    return _err(405, "method not supported")


def _project_view(st: Any, name: str) -> Response:
    from . import conformance, cra
    hit = st.project(name)
    if hit is None:
        return _err(404, "unknown project")
    folder, rec = hit
    doc, _note = conformance.load_document(_record_file(folder))
    rows = _history_rows(st, name)
    contact = _contact()
    payload = cra.readiness(rec, folder=folder, doc=doc, triage=st.triage(),
                            security_txt_deployed=bool(contact), history_rows=len(rows) or 1)
    preview = ""
    if contact:
        try:
            preview = cra.security_txt(contact, policy=os.environ.get(_REDIRECT_ACCT_ENV, "").strip(),
                                       csaf=os.environ.get(_REDIRECT_CSAF_ENV, "").strip())
        except Exception:                                    # noqa: BLE001 - preview is auxiliary
            preview = ""
    return _ok({"project": name,
                "readiness": payload,
                "security_txt": {"deployed": bool(contact), "url": "/.well-known/security.txt", "preview": preview,
                                 "note": "" if contact else "BTS_SBOM_CVD_CONTACT 미설정 - 주소를 추측하지 않으므로 배포되지 않은 상태"},
                "support": (cra.load_store(folder) or {}).get("support_validation") or None,
                "eol_maintained": bool((cra.load_store(folder) or {}).get("eol_maintained")),
                "awareness": cra.load_awareness(folder)})


def _ledger_csv(st: Any, name: str, which: str) -> Response:
    from . import conformance, cra
    hit = st.project(name)
    if hit is None:
        return _err(404, "unknown project")
    folder, rec = hit
    doc, _note = conformance.load_document(_record_file(folder))
    rows = _history_rows(st, name)
    led = cra.ledger(which, rec, folder=folder, doc=doc, triage=st.triage(), history_rows=rows)
    if led is None:
        return _err(400, "which must be one of 1..5")
    fname = urllib.parse.quote(led["filename"])
    return 200, led["csv"], "text/csv", {"Content-Disposition": "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (led["filename"], fname)}


def _record_file(folder: str) -> str:
    from .server import _record_file as _rf                    # lazy import: server imports this module too
    return _rf(folder)
