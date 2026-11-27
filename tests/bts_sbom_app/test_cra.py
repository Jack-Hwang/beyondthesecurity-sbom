"""EU CRA compliance lane (ac-645-650): the RFC 9116 security.txt generator, the Article 13(8) support-period
validation, the Article 14 reporting clock (in force since 2026-09-11), the readiness scorecard over the
automatable subset of the K-OSSC guide's annex-I checklist, and the five SBOM ledgers of guide annex J - every
number computed from the records, every unmeasured field a gap with its fix, never an invented pass."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from bts_sbom_app import cra, sbom, server

_NOW = "2026-11-28T09:00:00Z"


def _seed(tmp_path):
    """A project record + its sibling CycloneDX file in a fresh evidence folder."""
    ev = tmp_path / "evidence"
    folder = ev / "demo"
    folder.mkdir(parents=True)
    rec = {"schema": "bts-sbom.project.v1", "name": "demo", "analysed_at": _NOW,
           "components": [{"name": "requests", "version": "2.31.0", "license": "Apache-2.0",
                           "purl": "pkg:pypi/requests@2.31.0", "ecosystem": "pypi"}],
           "vulns": [{"id": "CVE-2024-9999", "package": "requests", "version": "2.31.0", "severity": "HIGH",
                      "purl": "pkg:pypi/requests@2.31.0"}]}
    (folder / "demo.json").write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")
    doc = sbom.cyclonedx("demo", rec["components"], [])
    (folder / "demo.cdx.json").write_text(json.dumps(doc), encoding="utf-8")
    return str(ev), str(folder), rec, doc


def test_security_txt_is_valid_rfc9116_with_a_real_contact_only():
    """AC: BSA-AC-1242. Contact and Expires are RFC 9116 mandatory; the generator refuses to invent a contact."""
    txt = cra.security_txt("mailto:sec@example.com", policy="https://x/policy", now=_NOW)
    assert "Contact: mailto:sec@example.com" in txt
    assert "Expires: 2027-02-26T23:59:59Z" in txt          # now + 90d, the guide's 사내 정책 예시 renewal
    assert "Preferred-Languages: ko, en" in txt
    assert "Policy: https://x/policy" in txt
    try:
        cra.security_txt("   ")
    except ValueError as exc:
        assert "BTS_SBOM_CVD_CONTACT" in str(exc)
    else:
        raise AssertionError("an empty contact must be refused, never guessed")


def test_support_period_validates_the_five_year_minimum():
    """AC: BSA-AC-1243. Annex II 7 wants at least year·month; Article 13(8) wants at least 5 years - the shortfall is measured."""
    assert cra.validate_support_period(None, today=_NOW)["status"] == "not_declared"
    assert cra.validate_support_period("2032-06", today=_NOW)["status"] == "ok"
    bad = cra.validate_support_period("2029-01", today=_NOW)
    assert bad["status"] == "below_minimum" and bad["shortfall_months"] == 34   # 2031-11-28 floor vs 2029-01-31
    assert cra.validate_support_period("June 2032", today=_NOW)["status"] == "invalid"


def test_article14_clock_runs_both_clocks():
    """AC: BSA-AC-1244. awareness +24h early warning, +72h notification; the aev final report runs from the mitigation
    moment (+14d), the incident one from the notification (+1 month); deadlines go overdue against ``now``."""
    c = cra.article14_clock("aev", _NOW, now="2026-11-28T10:00:00Z")
    assert c["early_warning"]["due"] == "2026-11-29T09:00:00Z" and c["early_warning"]["status"] == "open"
    assert c["notification"]["due"] == "2026-12-01T09:00:00Z"
    assert c["final_report"]["status"] == "awaiting_input"          # the mitigation moment is not known yet
    c2 = cra.article14_clock("aev", _NOW, mitigation_available="2026-12-10T12:00:00Z", now="2026-11-28T10:00:00Z")
    assert c2["final_report"]["due"] == "2026-12-24T12:00:00Z"
    c3 = cra.article14_clock("incident", _NOW, now="2026-11-28T10:00:00Z")
    assert c3["final_report"]["due"] == "2027-01-01T09:00:00Z"      # 72h notification + 1 month
    old = cra.article14_clock("aev", "2026-11-01T00:00:00Z", now=_NOW)
    assert old["early_warning"]["status"] == "overdue" and old["early_warning"]["hours_left"] == 0.0


def test_eol_priority_bands():
    assert cra.eol_priority(-3) == "immediate" and cra.eol_priority(0) == "urgent"
    assert cra.eol_priority(180) == "urgent" and cra.eol_priority(181) == "planned"
    assert cra.eol_priority(365) == "planned" and cra.eol_priority(366) == "monitor"
    assert cra.eol_priority(None) == "unknown"


def test_readiness_scores_the_automatable_subset_and_honest_gaps(tmp_path):
    """AC: BSA-AC-1241. a minimal SBOM scores exactly what the records prove; declaring support, recording an awareness
    entry and flagging the EOL ledger flip their checks from gap to pass - nothing else moves."""
    ev, folder, rec, doc = _seed(tmp_path)
    r0 = cra.readiness(rec, folder=folder, doc=doc, triage={}, security_txt_deployed=True, history_rows=1, today=_NOW)
    st0 = {c["id"]: c["status"] for c in r0["checks"]}
    assert st0["support_period"] == "gap" and st0["reporting_process"] == "gap" and st0["eol_ledger_maintained"] == "gap"
    assert st0["vex_document"] == "pass"                            # the OpenVEX statement exists for the finding
    assert len(r0["checks"]) == 8
    cra.declare_support(folder, "2032-06", today=_NOW)
    cra.record_awareness(folder, {"id": "CVE-2024-9999", "kind": "aev", "aware_at": _NOW}, now=_NOW)
    cra.set_ledger_maintained(folder, "3", True)
    r1 = cra.readiness(rec, folder=folder, doc=doc, triage={}, security_txt_deployed=True, history_rows=2, today=_NOW)
    st1 = {c["id"]: c["status"] for c in r1["checks"]}
    assert st1["support_period"] == "pass" and st1["reporting_process"] == "pass" and st1["eol_ledger_maintained"] == "pass"
    assert r1["score"]["pct"] > r0["score"]["pct"]
    for c in r1["checks"]:
        assert c["ref"] and c["title"]                              # every check names its CRA article / guide section


def test_ledgers_carry_the_recorded_facts_and_the_unmeasured_columns():
    """AC: BSA-AC-1245. the vuln ledger marks exploitation "not assessed" (KEV/EUVD are not wired), the EOL ledger lists
    every component with blank upstream dates, the submissions ledger stays honestly empty."""
    rec = {"name": "demo", "analysed_at": _NOW,
           "components": [{"name": "requests", "version": "2.31.0", "license": "Apache-2.0",
                           "purl": "pkg:pypi/requests@2.31.0", "ecosystem": "pypi"}],
           "vulns": [{"id": "CVE-2024-9999", "package": "requests", "version": "2.31.0", "severity": "HIGH",
                      "purl": "pkg:pypi/requests@2.31.0"}]}
    doc = sbom.cyclonedx("demo", rec["components"], [])
    with tempfile.TemporaryDirectory() as tmp:
        ld = cra.ledgers(rec, folder=tmp, doc=doc, triage={})
    assert "CVE-2024-9999" in ld["2"] and "미판정 (KEV·EUVD 미연동)" in ld["2"] and "VEX상태" in ld["2"]
    assert "requests" in ld["3"] and "상류EOL일" in ld["3"]
    assert "bts_sbom" in ld["1"] and "CycloneDX" in ld["1"]
    assert ld["4"].count("\n") >= 2                                  # one analysis run recorded
    assert "제출 이력 없음" in ld["5"]


def test_awareness_records_persist_and_replace(tmp_path):
    with tempfile.TemporaryDirectory() as tmp:
        e1 = cra.record_awareness(tmp, {"id": "CVE-2024-9999", "kind": "aev", "aware_at": _NOW}, now=_NOW)
        e2 = cra.record_awareness(tmp, {"id": "CVE-2024-9999", "kind": "aev", "aware_at": "2026-11-28T12:00:00Z"}, now=_NOW)
        entries = cra.load_awareness(tmp, now=_NOW)
        assert len(entries) == 1 and entries[0]["aware_at"] == "2026-11-28T12:00:00Z"    # replaced, never duplicated
        assert e1["clock"]["early_warning"]["due"] == "2026-11-29T09:00:00Z"
        try:
            cra.record_awareness(tmp, {"id": "x", "kind": "bogus"})
        except ValueError:
            pass
        else:
            raise AssertionError("unknown kinds are refused")


# ---------------------------------------------------------------- HTTP surface

def _serve(tmp_path):
    ev = tmp_path / "evidence"
    folder = ev / "demo"
    folder.mkdir(parents=True)
    rec = {"schema": "bts-sbom.project.v1", "name": "demo", "analysed_at": _NOW,
           "components": [{"name": "requests", "version": "2.31.0", "license": "Apache-2.0",
                           "purl": "pkg:pypi/requests@2.31.0", "ecosystem": "pypi"}],
           "vulns": [{"id": "CVE-2024-9999", "package": "requests", "version": "2.31.0", "severity": "HIGH",
                      "purl": "pkg:pypi/requests@2.31.0"}]}
    (folder / "demo.json").write_text(json.dumps(rec, ensure_ascii=False), encoding="utf-8")
    (folder / "demo.cdx.json").write_text(json.dumps(sbom.cyclonedx("demo", rec["components"], [])), encoding="utf-8")
    st = server.State(".", str(ev), None, False)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, "http://127.0.0.1:%d" % httpd.server_address[1]


def _get(base, path):
    try:
        with urllib.request.urlopen(base + path, timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _post(base, path, body):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Origin": base})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_cra_http_surface(tmp_path, monkeypatch):
    """AC: BSA-AC-1246, BSA-AC-1241, BSA-AC-1242, BSA-AC-1243, BSA-AC-1244, BSA-AC-1245. /.well-known/security.txt serves the RFC 9116 file when the contact is configured and answers an
    honest 404 when it is not; /api/cra/<p> returns the scorecard; the support declaration validates against the
    5-year floor; the awareness POST stores T0 with its clock; the ledgers download as CSV."""
    monkeypatch.delenv("BTS_SBOM_CVD_CONTACT", raising=False)
    httpd, base = _serve(tmp_path)
    try:
        code, _, body = _get(base, "/api/cra/demo")
        assert code == 200 and json.loads(body)["readiness"]["score"]["total"] == 8
        code, _, _ = _get(base, "/.well-known/security.txt")
        assert code == 404                                        # no contact configured: no invented file
        monkeypatch.setenv("BTS_SBOM_CVD_CONTACT", "https://github.com/Jack-Hwang/beyondthesecurity-sbom/security")
        code, hdrs, body = _get(base, "/.well-known/security.txt")
        assert code == 200 and hdrs["Content-Type"].startswith("text/plain")
        assert b"Contact: https://github.com/Jack-Hwang/beyondthesecurity-sbom/security" in body
        code, _, body = _get(base, "/api/cra/demo")
        assert code == 200 and json.loads(body)["security_txt"]["deployed"] is True
        code, _, body = _post(base, "/api/cra/demo/support", {"support_end": "2032-06"})
        assert code == 200 and json.loads(body)["validation"]["status"] == "ok"
        code, _, body = _post(base, "/api/cra/demo/support", {"support_end": "2029-01"})
        assert code == 200 and json.loads(body)["validation"]["status"] == "below_minimum"
        code, _, _ = _post(base, "/api/cra/demo/support", {"support_end": "garbage"})
        assert code == 400
        code, _, body = _post(base, "/api/cra/demo/article14",
                              {"id": "CVE-2024-9999", "kind": "aev", "aware_at": _NOW})
        assert code == 200 and json.loads(body)["entry"]["clock"]["early_warning"]["due"] == "2026-11-29T09:00:00Z"
        code, _, body = _get(base, "/api/cra/demo/article14")
        assert code == 200 and len(json.loads(body)["entries"]) == 1
        code, hdrs, body = _get(base, "/api/cra/demo/ledgers?which=2")
        assert code == 200 and hdrs["Content-Type"].startswith("text/csv") and b"CVE-2024-9999" in body
        code, _, _ = _get(base, "/api/cra/demo/ledgers?which=9")
        assert code == 400
        code, _, _ = _get(base, "/api/cra/nope")
        assert code == 404
        code, _, body = _post(base, "/api/cra/demo/eol-maintained", {"maintained": True})
        assert code == 200 and json.loads(body)["eol_maintained"] is True
    finally:
        httpd.shutdown()
