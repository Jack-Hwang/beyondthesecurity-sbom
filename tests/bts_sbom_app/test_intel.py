"""EPSS (FIRST.org) and CISA KEV for the findings: honest statuses, strict ids, offline tables, the endpoint and the stored result."""
from __future__ import annotations

import json
import os
import re
import urllib.parse

import pytest

from bts_sbom_app import intel, net
import test_console_ui
from test_console_ui import _get, _post

ui = test_console_ui.ui                                # the analysed-project + running-service fixture of the console tests, shared

EPSS_ROWS = {"CVE-2020-1111": ("0.91234", "0.99001"), "CVE-2020-2222": ("0.00042", "0.08000")}


class IntelWorld:
    """FIRST.org and CISA on top of the fake OSV / registry world; everything else is delegated."""

    def __init__(self, world) -> None:
        self.world, self.epss_calls, self.kev_calls = world, [], []
        self.epss_fail_from = None          # fail every EPSS request from this (0-based) request number on
        self.kev_fail = False
        self.kev_ids = {"CVE-2020-1111"}

    def http(self, url, headers, body):
        if "api.first.org" in url:
            self.epss_calls.append(url)
            if self.epss_fail_from is not None and len(self.epss_calls) - 1 >= self.epss_fail_from:
                return 503, None
            asked = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["cve"][0].split(",")
            rows = [{"cve": c, "epss": EPSS_ROWS[c][0], "percentile": EPSS_ROWS[c][1], "date": "2026-11-16"} for c in asked if c in EPSS_ROWS]
            return 200, {"status": "OK", "data": rows}
        if "cisa.gov" in url:
            self.kev_calls.append(url)
            if self.kev_fail:
                return 503, None
            return 200, {"catalogVersion": "2026.11.16", "dateReleased": "2026-11-16T15:00:00Z",
                         "vulnerabilities": [{"cveID": c, "dateAdded": "2024-01-01", "dueDate": "2024-01-22", "knownRansomwareCampaignUse": "Known",
                                              "vendorProject": "Vendor", "product": "Product", "vulnerabilityName": "Name"} for c in sorted(self.kev_ids)]}
        return self.world.http(url, headers, body)


@pytest.fixture
def iw(world):
    w = IntelWorld(world)
    net.TRANSPORT = w.http
    return w


def _findings(base, name):
    return {f["cve"]: f for f in json.loads(_get(base + "/api/view/" + name)[2])["report"]["findings"]}


def test_lookup_stores_scores_and_kev_and_the_view_shows_them(ui, iw):
    """AC: BSA-AC-103"""
    base, name, ev = ui["base"], ui["rec"]["name"], ui["ev"]
    before = json.loads(_get(base + "/api/view/" + name)[2])
    assert before["intel"] is None and not [k for f in before["report"]["findings"] for k in ("epss", "epss_percentile", "kev") if k in f]   # 0 of 6 fields
    code, out = _post(base + "/api/intel", {"project": name})
    s = out["intel"]
    assert code == 200 and s["asked"] == 2 and s["epss"]["status"] == "ok" and s["epss"]["scored"] == 2 and s["kev"]["status"] == "ok" and s["kev"]["listed"] == 1
    f = _findings(base, name)
    assert f["CVE-2020-1111"]["epss"] == 0.91234 and f["CVE-2020-1111"]["epss_percentile"] == 0.99001 and f["CVE-2020-1111"]["kev"] is True
    assert f["CVE-2020-1111"]["kev_info"]["due"] == "2024-01-22"
    assert f["CVE-2020-2222"]["epss"] == 0.00042 and f["CVE-2020-2222"]["kev"] is False             # the whole catalog was read: measured "not listed"
    assert os.path.isdir(os.path.join(str(ev), ".intel")) and len(os.listdir(os.path.join(str(ev), ".intel"))) == 1
    assert [r["name"] for r in json.loads(_get(base + "/api/history")[2])["history"]] == [name]       # the stored result is not a second project
    doc = intel.load(intel.sidecar_path(str(ev), name))
    extra = [{"cve": "CVE-2099-0001"}]
    intel.annotate(extra, doc)
    assert extra == [{"cve": "CVE-2099-0001"}]                                                         # a CVE that was never asked gets nothing


def test_a_source_that_does_not_answer_adds_no_value_not_even_zero(ui, iw):
    """AC: BSA-AC-104"""
    base, name = ui["base"], ui["rec"]["name"]
    iw.epss_fail_from, iw.kev_fail = 0, True
    code, out = _post(base + "/api/intel", {"project": name})
    s = out["intel"]
    assert code == 200 and s["epss"]["status"] == "unavailable" and s["kev"]["status"] == "unavailable" and "503" in s["epss"]["error"] and "503" in s["kev"]["error"]
    assert s["known"] == []
    assert not [k for f in _findings(base, name).values() for k in ("epss", "epss_percentile", "kev") if k in f]                          # 0 of 6 fields
    iw.epss_fail_from, iw.kev_fail = None, False
    iw.kev_ids = set()                                                                                 # an empty catalog is a broken answer
    s = _post(base + "/api/intel", {"project": name})[1]["intel"]
    f = _findings(base, name)
    assert s["kev"]["status"] == "unavailable" and s["epss"]["status"] == "ok"
    assert all("kev" not in x for x in f.values()) and f["CVE-2020-1111"]["epss"] == 0.91234          # EPSS still shown, KEV neither true nor false
    iw.kev_ids = {"CVE-2020-1111"}
    _post(base + "/api/intel", {"project": name})                                                      # a good result is stored ...
    iw.epss_fail_from, iw.kev_fail = 0, True
    code, out = _post(base + "/api/intel", {"project": name})                                          # ... and a lookup where nothing answers does not erase it
    assert code == 200 and out["kept_previous"] is True and out["intel"]["epss"]["status"] == "unavailable"
    assert _findings(base, name)["CVE-2020-1111"]["kev"] is True


def test_only_well_formed_cve_ids_reach_the_url_in_pages_of_100(iw):
    """AC: BSA-AC-105"""
    good = ["CVE-2021-%05d" % i for i in range(250)] + ["cve-2020-5555"]
    bad = ["CVE-2020-1; DROP", "GHSA-xxxx-yyyy-zzzz", "CVE-2020-12", "", "CVE-2020-1111&x=1"]
    doc = intel.lookup(good + bad + good[:10])
    asked = doc["asked"]
    assert len(asked) == 251 and asked == sorted(set(asked)) and "CVE-2020-5555" in asked                  # unique, upper-cased, 251 of 251
    sent = [c for u in iw.epss_calls for c in urllib.parse.parse_qs(urllib.parse.urlsplit(u).query)["cve"][0].split(",")]
    assert len(iw.epss_calls) == 3 and sorted(sent) == asked and all(re.match(r"^CVE-[0-9]{4}-[0-9]{4,}$", c) for c in sent)
    assert not [u for u in iw.epss_calls if "DROP" in u or "GHSA" in u or "&x=" in u]                   # 0 of 5 malformed ids sent
    iw.epss_calls.clear()
    iw.epss_fail_from = 1                                                                              # the second page fails
    part = intel.lookup(good)["epss"]
    assert part["status"] == "partial" and len(part["covered"]) == 100 and len(iw.epss_calls) == 2 and "503" in part["error"]   # stopped, did not retry page 3


def test_offline_lookup_uses_only_the_curated_tables_and_never_says_not_listed():
    """AC: BSA-AC-106"""
    doc = intel.lookup(["CVE-2021-44228", "CVE-2020-1111"], offline=True)                              # any network call would fail the test (no_network)
    assert doc["mode"] == "offline-table" and doc["epss"]["status"] == "table" and doc["kev"]["status"] == "table"
    assert "curated" in doc["epss"]["source"] and "curated" in doc["kev"]["source"]
    fs = [{"cve": "CVE-2021-44228"}, {"cve": "CVE-2020-1111"}]
    intel.annotate(fs, doc)
    assert fs[0]["epss"] == 0.9765 and fs[0]["kev"] is True                                           # a table hit is real
    assert "epss" not in fs[1] and "kev" not in fs[1]                                                  # a miss says nothing: not 0, not "not listed"
    assert intel.summarize(doc)["known"] == ["CVE-2021-44228"]


def test_endpoint_refuses_unknown_projects_and_asks_nothing_when_there_is_no_cve(ui, iw, tmp_path):
    """AC: BSA-AC-107"""
    base, ev, rec = ui["base"], ui["ev"], ui["rec"]
    assert [_post(base + "/api/intel", b)[0] for b in ({"project": "no-such"}, {}, {"project": 5})] == [404, 404, 404]
    d = ev / "ghsaonly"
    d.mkdir()
    only = dict(rec, name="ghsaonly", vulns=[dict(v, id="GHSA-aaaa-bbbb-cccc", aliases=[], osv_ids=[]) for v in rec["vulns"]])
    (d / "ghsaonly.json").write_text(json.dumps(only), encoding="utf-8")
    code, out = _post(base + "/api/intel", {"project": "ghsaonly"})
    assert code == 200 and out["intel"]["asked"] == 0 and iw.epss_calls == [] and iw.kev_calls == []     # nothing to ask, nothing sent
    p = intel.sidecar_path(str(ev), "../../evil name")
    base_name = os.path.basename(p)
    assert os.path.dirname(p) == os.path.join(str(ev), ".intel") and not base_name.startswith(".") and "/" not in base_name and "\\" not in base_name   # a name cannot leave the folder
