"""Fix verification: EPSS/KEV feed outage must never look like measured data.

Defect (docs/ANALYSIS_2026-11-17.md, section 3 item 5 / appendix B,
bts_sbom/_internal/epss_kev.py:93): on a total feed outage, enrich_cves()
used to return {"epss": 0.0, "percentile": 0.0, "kev": False} for every
requested CVE, labelled (by the caller) as "live-api" -- identical in shape
to a legitimate "CVE has zero EPSS and is not KEV" result. Log4Shell
(CVE-2021-44228) would then show epss 0.0 / not-KEV during an outage, even
though the curated offline table has real data for it (epss 0.9765, KEV
True) and fix_planner's priority sort ranks by -kev.

Required behaviour verified here: an outage (network error, non-200, bad
JSON, or timeout) must
  (1) fall back to the offline curated table when it has the CVE, labelling
      the source accurately ("offline-table"), else
  (2) return an explicit unknown: epss=None, kev=None, source="unavailable",
      plus a "reason" -- never 0.0/False and never "live-api".

No network is touched: urllib.request.urlopen is monkeypatched in every test.
"""
from __future__ import annotations

import json
import socket
import urllib.error

import pytest

from bts_sbom._internal import epss_kev
from bts_sbom._internal.epss_offline import EPSS_OFFLINE, KEV_OFFLINE

LOG4SHELL = "CVE-2021-44228"  # in both EPSS_OFFLINE and KEV_OFFLINE, kev=True
UNKNOWN_CVE = "CVE-1999-9999"  # deliberately absent from both offline tables


class _FakeResp:
    """Minimal context-manager stand-in for urllib.request.urlopen()'s result."""

    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self._body


def _epss_payload(cve: str, epss: float, pct: float) -> bytes:
    return json.dumps({"data": [{"cve": cve, "epss": epss, "percentile": pct}]}).encode("utf-8")


def _kev_payload(cves) -> bytes:
    return json.dumps({"vulnerabilities": [{"cveID": c} for c in cves]}).encode("utf-8")


def _reset_kev_cache(monkeypatch):
    """Each test starts with a cold in-process KEV cache so outages are
    actually exercised instead of silently served from a previous test's
    cached set."""
    monkeypatch.setattr(epss_kev, "_kev_cache", None)
    monkeypatch.setattr(epss_kev, "_kev_cached_at", 0.0)


# ── offline-table sanity (the fixture this whole defect is about) ───────────


def test_log4shell_is_in_the_curated_offline_table():
    assert LOG4SHELL in EPSS_OFFLINE
    assert LOG4SHELL in KEV_OFFLINE
    assert EPSS_OFFLINE[LOG4SHELL]["epss"] > 0.9


# ── RED: reproduce the defect shape without the fix (documented, not run) ───
#
# Before the fix, enrich_cves() always built:
#   out[cu] = {"epss": e.get("epss", 0.0), "percentile": ..., "kev": cu in kev}
# with no success/failure flag, so a total urlopen failure (epss={}, kev=
# falls back to cached/empty set) produced exactly
#   {"epss": 0.0, "percentile": 0.0, "kev": False}
# for CVE-2021-44228 -- indistinguishable from a real "0 EPSS, not KEV"
# result, and the caller (sca_report.py) stamped that "live-api" and never
# consulted the offline table. The tests below assert the fixed behaviour:
# the outage case must come back as "offline-table" (with real Log4Shell
# data) or an explicit "unavailable", never 0.0/False/"live-api".


# ── outage: URLError ─────────────────────────────────────────────────────


def test_enrich_cves_falls_back_to_offline_table_on_urlerror(monkeypatch):
    _reset_kev_cache(monkeypatch)

    def fake_urlopen(url, timeout=None):
        raise urllib.error.URLError("network is unreachable")

    monkeypatch.setattr(epss_kev.urllib.request, "urlopen", fake_urlopen)

    out = epss_kev.enrich_cves([LOG4SHELL])
    r = out[LOG4SHELL]
    assert r["source"] == "offline-table"
    assert r["epss"] == pytest.approx(0.9765)
    assert r["kev"] is True
    # never the pre-fix shape
    assert not (r["epss"] == 0.0 and r["kev"] is False)


# ── outage: timeout ──────────────────────────────────────────────────────


def test_enrich_cves_falls_back_to_offline_table_on_timeout(monkeypatch):
    _reset_kev_cache(monkeypatch)

    def fake_urlopen(url, timeout=None):
        raise socket.timeout("timed out")

    monkeypatch.setattr(epss_kev.urllib.request, "urlopen", fake_urlopen)

    out = epss_kev.enrich_cves([LOG4SHELL])
    r = out[LOG4SHELL]
    assert r["source"] == "offline-table"
    assert r["epss"] == pytest.approx(0.9765)
    assert r["kev"] is True


# ── outage: HTTP 500 (no exception, just a bad status) ──────────────────


def test_enrich_cves_falls_back_to_offline_table_on_http_500(monkeypatch):
    _reset_kev_cache(monkeypatch)

    def fake_urlopen(url, timeout=None):
        return _FakeResp(500, b"{}")

    monkeypatch.setattr(epss_kev.urllib.request, "urlopen", fake_urlopen)

    out = epss_kev.enrich_cves([LOG4SHELL])
    r = out[LOG4SHELL]
    assert r["source"] == "offline-table"
    assert r["epss"] == pytest.approx(0.9765)
    assert r["kev"] is True


# ── outage: malformed JSON (200 status, unparsable body) ────────────────


def test_enrich_cves_falls_back_to_offline_table_on_bad_json(monkeypatch):
    _reset_kev_cache(monkeypatch)

    def fake_urlopen(url, timeout=None):
        return _FakeResp(200, b"this is not json{{{")

    monkeypatch.setattr(epss_kev.urllib.request, "urlopen", fake_urlopen)

    out = epss_kev.enrich_cves([LOG4SHELL])
    r = out[LOG4SHELL]
    assert r["source"] == "offline-table"
    assert r["epss"] == pytest.approx(0.9765)
    assert r["kev"] is True


# ── outage + CVE absent from the offline table too: explicit unknown ────


def test_enrich_cves_reports_explicit_unknown_when_offline_table_also_lacks_cve(monkeypatch):
    _reset_kev_cache(monkeypatch)
    assert UNKNOWN_CVE not in EPSS_OFFLINE
    assert UNKNOWN_CVE not in KEV_OFFLINE

    def fake_urlopen(url, timeout=None):
        raise urllib.error.URLError("network is unreachable")

    monkeypatch.setattr(epss_kev.urllib.request, "urlopen", fake_urlopen)

    out = epss_kev.enrich_cves([UNKNOWN_CVE])
    r = out[UNKNOWN_CVE]
    assert r["source"] == "unavailable"
    assert r["epss"] is None
    assert r["kev"] is None
    assert r["percentile"] is None
    assert r.get("reason")  # a non-empty reason string, naming the failure


# ── success path: both feeds answer normally -> "live-api" ──────────────


def test_enrich_cves_reports_live_api_on_success(monkeypatch):
    _reset_kev_cache(monkeypatch)

    def fake_urlopen(url, timeout=None):
        if "first.org" in url:
            return _FakeResp(200, _epss_payload(LOG4SHELL, 0.5, 0.5))
        return _FakeResp(200, _kev_payload([LOG4SHELL]))

    monkeypatch.setattr(epss_kev.urllib.request, "urlopen", fake_urlopen)

    out = epss_kev.enrich_cves([LOG4SHELL])
    r = out[LOG4SHELL]
    assert r["source"] == "live-api"
    assert r["epss"] == pytest.approx(0.5)
    assert r["kev"] is True


def test_enrich_cves_live_api_zero_epss_not_kev_is_a_real_zero(monkeypatch):
    """A genuine 'live feed says 0 EPSS, not KEV' result must still come
    through as source live-api/epss 0.0 -- the fix must not turn every zero
    into an "unavailable"."""
    _reset_kev_cache(monkeypatch)
    other = "CVE-2030-00001"

    def fake_urlopen(url, timeout=None):
        if "first.org" in url:
            return _FakeResp(200, _epss_payload(other, 0.0, 0.0))
        return _FakeResp(200, _kev_payload([]))

    monkeypatch.setattr(epss_kev.urllib.request, "urlopen", fake_urlopen)

    out = epss_kev.enrich_cves([other])
    r = out[other]
    assert r["source"] == "live-api"
    assert r["epss"] == 0.0
    assert r["kev"] is False


# ── fetch_epss / load_kev_set stay backwards compatible (old signatures) ──


def test_fetch_epss_backward_compat_degrades_to_empty_dict_on_failure(monkeypatch):
    def fake_urlopen(url, timeout=None):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(epss_kev.urllib.request, "urlopen", fake_urlopen)
    assert epss_kev.fetch_epss([LOG4SHELL]) == {}


def test_load_kev_set_backward_compat_degrades_to_empty_set_on_failure(monkeypatch):
    _reset_kev_cache(monkeypatch)

    def fake_urlopen(url, timeout=None):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(epss_kev.urllib.request, "urlopen", fake_urlopen)
    assert epss_kev.load_kev_set() == set()


# ── consumer: sca_report.py must handle epss=None/kev=None honestly ─────


def test_sca_report_consumer_handles_unavailable_without_crashing():
    from bts_sbom import sca_report

    findings = [{
        "cve": LOG4SHELL, "severity": "CRITICAL", "score": 10.0, "id": "OSV-1",
        "name": "log4j-core", "version": "2.14.1", "fixed": "2.17.1", "location": "pom.xml:10",
    }]

    def stub_live_fn(ids):
        return {cu: {"epss": None, "percentile": None, "kev": None,
                     "source": "unavailable", "reason": "EPSS feed unreachable; KEV feed unreachable"}
                for cu in ids}

    epss_map = sca_report._enrich_findings_epss_kev(findings, offline=False, live_fn=stub_live_fn)

    assert epss_map[LOG4SHELL]["epss"] is None
    assert epss_map[LOG4SHELL]["kev"] is None
    assert findings[0]["epss"] is None
    assert findings[0]["kev"] is None
    assert findings[0]["epss_source"] == "unavailable"

    # must render as an honest "unknown", never a fabricated PATCH-NOW/LOW
    assert sca_report._priority_label(findings[0], epss_map) == "⚪ UNKNOWN"

    md = sca_report._markdown(
        target="demo", packages=[{"name": "log4j-core", "version": "2.14.1"}],
        findings=findings, sev=sca_report._severity_summary(findings),
        licenses=None, remediation=None, status={"packages": 1, "sources": 1, "mode": "online"},
        lic_enrich={}, epss_map=epss_map,
    )
    assert "unknown" in md
    assert "unavailable" in md.lower()
    # the honest unknown must never render as the real Log4Shell measurement
    assert "0.9765" not in md


def test_sca_report_consumer_passes_through_offline_table_label():
    from bts_sbom import sca_report

    findings = [{
        "cve": LOG4SHELL, "severity": "CRITICAL", "score": 10.0, "id": "OSV-1",
        "name": "log4j-core", "version": "2.14.1", "fixed": "2.17.1", "location": "pom.xml:10",
    }]

    def stub_live_fn(ids):
        return {cu: {"epss": 0.9765, "percentile": 0.999, "kev": True, "source": "offline-table"}
                for cu in ids}

    epss_map = sca_report._enrich_findings_epss_kev(findings, offline=False, live_fn=stub_live_fn)

    assert epss_map[LOG4SHELL]["kev"] is True
    assert findings[0]["epss_source"] == "offline-table"
    assert sca_report._priority_label(findings[0], epss_map) == "\U0001f534 PATCH NOW"
