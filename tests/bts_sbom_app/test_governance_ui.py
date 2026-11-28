"""The SBOM-governance panes of the open-source security screen: conformance, what changed, OpenVEX with decisions, the decision form,
fleet and "who is affected".

The page scripts bts_ui.js / bts_governance.js hold pure render and form functions; they run here under Node (tests/bts_sbom_app/js/
render_harness.js) on the JSON the real service returns for a project that was analysed twice. bts_console.js (fetch + wiring) needs a
browser and is covered by the page-shape checks below plus a manual run. Tests that need Node skip when it is not installed.
"""
from __future__ import annotations

import datetime
import html as htmllib
import itertools
import json
import os
import re
import shutil
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import console, evals, pipeline, server, triage
from conftest import FakeScanner

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "js", "render_harness.js")
WEB = server.WEB_DIR
TODAY = "2026-11-17"
SCRIPTS = ["/static/sca_app.js", "/static/bts_ui.js", "/static/bts_governance.js", "/static/bts_report.js", "/static/bts_console.js",
           "/static/bts_chat_panel.js", "/static/oss_scanner.js", "/static/arch_intel_render.js", "/static/arch_intel.js",
           "/static/bts_books.js", "/static/bts_ccd.js"]   # + the OSS Scanner, Arch Intel, Book KB, Report screens, and the bottom chat dock


# ------------------------------------------------------------------ helpers
def js(*calls):
    """Run (module, function, args...) calls in Node; one result per call."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    payload = json.dumps([{"mod": m, "fn": f, "args": list(a)} for m, f, *a in calls])
    p = subprocess.run([node, HARNESS], input=payload, capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def render(fn, *args):
    return js(("gov", fn, *args))[0]


def ok(data, status=200):
    return {"ok": True, "status": status, "data": data}


def text(markup):
    return htmllib.unescape(re.sub(r"<[^>]+>", " ", markup))


def row_with(markup, needle):
    rows = [r for r in re.findall(r"<tr>(.*?)</tr>", markup, re.S) if needle in r]
    assert rows, "no table row contains %r" % needle
    return rows[0]


def cards(markup):
    return dict((m[1], m[0]) for m in re.findall(r'<div class="bts-card"><div class="v"[^>]*>(.*?)</div><div class="l">(.*?)</div></div>', markup))


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def jget(url):
    code, _, body = _get(url)
    return code, json.loads(body)


def _post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.fixture
def gov(tmp_path, make_repo, world):
    """'proj' analysed twice (an upgrade clears 2 advisories, flask appears), 'other' once (3 findings, shares the flask advisory)."""
    ev = tmp_path / "ev"

    def run(src, name):
        rec = pipeline.run_project(src, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False, scanner=FakeScanner(), run_arch=False,
                                   cache_dir=str(tmp_path / "c"), name=name)
        assert rec["error"] is None, rec
        return rec

    a = make_repo({"requirements.txt": "requests==2.19.1\n"}, name="proj_src")
    run(a, "proj")
    with open(os.path.join(a, "requirements.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("requests==2.31.0\nflask==0.12\n")
    run(a, "proj")
    run(make_repo({"requirements.txt": "requests==2.19.1\nflask==0.12\n"}, name="other_src"), "other")
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "ev": ev}
    httpd.shutdown()


def _ages(base):
    return {h["name"]: h["analysed_at"] for h in jget(base + "/api/history")[1]["history"]}


# ------------------------------------------------------------------ the page
def test_page_loads_the_governance_scripts_in_order_and_every_id_the_scripts_read_exists(gov):
    """AC: BSA-AC-226"""
    base = gov["base"]
    code, hdr, page = _get(base + "/")
    page = page.decode("utf-8")
    assert code == 200 and re.findall(r'<script src="([^"]+)"></script>', page) == SCRIPTS
    for rel in SCRIPTS[1:4]:                                                              # the 3 governance files: served byte for byte
        code, _, body = _get(base + rel)
        with open(os.path.join(WEB, os.path.basename(rel)), "rb") as fh:
            assert code == 200 and body == fh.read()
    assert "script-src 'self'" in hdr["Content-Security-Policy"] and "form-action 'none'" in hdr["Content-Security-Policy"]
    live = re.sub(r"<!--.*?-->", "", page, flags=re.S)                                    # comments are not markup
    assert not re.search(r"<script(?![^>]*\ssrc=)", live) and not re.search(r"\son[a-z]+\s*=", live) and "<form" not in live.lower()   # nothing a strict CSP would block
    ids = set(re.findall(r'\bid="([^"]+)"', page))
    wanted = {"paneConformance", "paneChanges", "paneVex", "paneTriage", "paneFleet", "paneAffected", "tfFinding", "tfStatus", "tfJust", "tfReason", "tfExpires",
              "tfScope", "tfBy", "tfOutcome", "tfResult", "tfCount", "tfStatusHint", "afCve", "afComp", "afVer"}
    assert wanted <= ids                                                                  # 20 of 20 ids exist in the page
    for sv in ("changes", "conformance", "fleet"):
        assert 'class="rpane" data-sv="%s"' % sv in page
    src = open(os.path.join(WEB, "bts_console.js"), encoding="utf-8").read()
    read = {x for x in re.findall(r"""['"]#([A-Za-z][\w-]*)['"]""", src) if not re.fullmatch(r"[0-9a-fA-F]{3,8}", x)}      # '#e6edf3' is a colour
    assert read - ids - {"scaWorkflow", "ackPlan", "sxSbomFmt", "railSessions", "chatDockBar", "chatDockQ", "dbQ", "dbQBtn", "dbSchemaBtn", "paneDbOut", "riSource", "riComponent", "riRun", "riLlm", "riStages", "riPatterns", "riOut", "distSel", "policyOut", "craAevAware", "craAevId", "craAevKind", "craSupportEnd", "irOrg", "irTitle", "irAssignee", "irSrc", "irIocV_", "irIocT_", "irFKey_", "irFVal_", "irImpact_"} == set()   # every '#id' the glue reads exists (19+4 are built at run time: step bar, patch checkbox, sca_app.js select, rail session list, the chat dock's bar/input, the db pane's input/buttons/out, the clean-room workbench's form/stages/pattern checkbox/out, the licence pane's selector/out)
    for api in ("/api/conformance/", "/api/changes/", "/api/vex/", "/api/fleet", "/api/affected", "/api/triage"):
        assert api in src or api in open(os.path.join(WEB, "bts_governance.js"), encoding="utf-8").read()
    assert "not yet written into the OpenVEX" not in src                                   # decisions now reach the document; the old claim must be gone


def test_every_rail_pane_has_its_rpane_div_and_every_pane_renderer_its_target():
    """AC: BSA-AC-605. A rail chip whose pane div is missing blanks the whole content column: the db pane shipped with
    renderer, binding and label but no rpane div in index.html, so clicking 🗄 DB 질의 hid every pane (measured 2026-11-23).
    GROUPS, the renderPanes map and the page must therefore agree, statically."""
    src = open(os.path.join(WEB, "bts_console.js"), encoding="utf-8").read()
    page = open(os.path.join(WEB, "index.html"), encoding="utf-8").read()
    groups_block = re.search(r"var GROUPS = \{(.*?)\};", src, re.S).group(1)
    pane_ids = [pid.strip().strip("'\"") for pair in re.findall(r"'[^']+':\s*\[([^\]]*)\]", groups_block) for pid in pair.split(",")]
    assert len(pane_ids) >= 26
    missing = [p for p in pane_ids if 'data-sv="%s"' % p not in page]
    assert missing == [], "rail panes without an rpane div in index.html: %s" % missing
    render_map = re.search(r"var map = \{([^}]*)\};", src).group(1)
    targets = re.findall(r"(pane[A-Z]\w*):", render_map)
    assert targets and all('id="%s"' % t in page for t in targets), "renderPanes targets missing from the page: %s" % \
        [t for t in targets if 'id="%s"' % t not in page]
    for api in ("/api/conformance/", "/api/changes/", "/api/vex/", "/api/fleet", "/api/affected", "/api/triage"):
        assert api in src or api in open(os.path.join(WEB, "bts_governance.js"), encoding="utf-8").read()
    assert "not yet written into the OpenVEX" not in src                                   # decisions now reach the document; the old claim must be gone


def test_the_page_scripts_define_one_escape_function_and_markup_helpers_exactly_once():
    """AC: BSA-AC-239"""
    files = {fn: open(os.path.join(WEB, fn), encoding="utf-8").read() for fn in ("bts_ui.js", "bts_governance.js", "bts_console.js")}
    for helper in ("esc", "table", "pill", "note", "heading", "kv"):
        owners = [fn for fn, s in files.items() if re.search(r"function %s\(" % helper, s)]
        assert owners == ["bts_ui.js"], (helper, owners)                                  # 6 of 6 helpers live in 1 file
    assert len(re.findall(r"innerHTML\s*=", files["bts_governance.js"])) == 0             # the pure module never touches the DOM


# ------------------------------------------------------------------ conformance
def test_conformance_pane_shows_5_verdicts_the_draft_flag_and_the_legal_line(gov):
    """AC: BSA-AC-227"""
    code, conf = jget(gov["base"] + "/api/conformance/proj")
    assert code == 200 and conf["status"] == "OK" and len(conf["regimes"]) == 5
    out = render("renderConformance", ok(conf))
    for rid, r in conf["regimes"].items():
        row = row_with(out, "<code>%s</code>" % rid)
        assert re.search(r'bts-pill \w+">%s<' % r["verdict"], row), rid                  # 5 of 5 verdicts
    assert out.count('bts-pill warn">DRAFT<') == 1 and 'bts-pill warn">DRAFT<' in row_with(out, "<code>cisa-2025-draft</code>")   # the draft flag on 1 of 5
    assert text(out).count("Not a legal assessment") == 1 and "not a legal conformity assessment" in text(out)
    for eid in conf["elements"]:                                                          # per-element coverage, one row each
        assert "<code>%s</code>" % eid in out
    assert len(re.findall(r'class="bts-cov"', out)) == len(conf["elements"]) + len(conf["fix_once"])
    top = conf["fix_once"][0]
    assert "<code>%s</code>" % top["element"] in row_with(out, top["hint"][:30]) and out.index(top["hint"][:30]) > out.index("Fix once")


def test_conformance_pane_without_a_result_shows_no_verdict_and_still_the_legal_line():
    """AC: BSA-AC-228"""
    states = [ok({"status": "NO_DATA", "reason": "the SBOM lists no components, so no element can be scored"}), {"ok": False, "status": 404, "data": {"error": "x"}}, None]
    for res in states:
        out = render("renderConformance", res)
        assert "Not a legal assessment" in text(out)                                      # 3 of 3 states
        assert not re.search(r"bts-pill \w+\">(conformant|gaps|partial|pass|gap)<", out) and "bts-cov" not in out
    assert "not a pass" in text(render("renderConformance", states[0])) and "no components" in text(render("renderConformance", states[0]))
    assert "No conformance result. x" in re.sub(r"\s+", " ", text(render("renderConformance", states[1]))) and "Loading" in text(render("renderConformance", None))


def test_conformance_pane_says_review_due_when_the_regime_table_is_old(gov):
    """AC: BSA-AC-240"""
    conf = jget(gov["base"] + "/api/conformance/proj")[1]
    assert set(conf["table"]) >= {"reviewed", "age_months", "stale", "note"}              # the service reports how old its regime table is
    live = text(render("renderConformance", ok(conf)))
    assert ("review due" in live.lower()) == conf["table"]["stale"] and conf["table"]["reviewed"] in live       # the pane follows the service, whatever today is
    old = dict(conf, table={"reviewed": "2026-01", "age_months": 10, "stale": True, "note": "regime table last reviewed 2026-01 - REVIEW DUE: check it against the official texts"})
    out = render("renderConformance", ok(old))
    t = re.sub(r"\s+", " ", text(out))
    assert out.count('bts-pill bad">review due<') == 1 and "Review due. regime table last reviewed 2026-01" in t and "2026-01 (10 month(s) ago)" in t
    fresh = dict(conf, table={"reviewed": "2026-11", "age_months": 1, "stale": False, "note": "regime table last reviewed 2026-11"})
    t = re.sub(r"\s+", " ", text(render("renderConformance", ok(fresh))))
    assert "review due" not in t.lower() and "2026-11 (1 month(s) ago)" in t                # a current table is not flagged
    gone = dict(conf)
    gone.pop("table")
    t = re.sub(r"\s+", " ", text(render("renderConformance", ok(gone))))
    assert "Regime table reviewed —" in t and "review due" not in t.lower()                 # an absent field is a dash, not a claim either way


# ------------------------------------------------------------------ what changed
def test_changes_pane_of_a_project_analysed_twice_matches_the_record(gov):
    """AC: BSA-AC-229"""
    code, ch = jget(gov["base"] + "/api/changes/proj")
    assert code == 200 and ch["summary"]["vulns_resolved"] == 2 and ch["summary"]["vulns_new"] == 1 and ch["verdict"] == "mixed"
    out = render("renderChanges", ok(ch))
    c, s = cards(out), ch["summary"]
    expected = {"New findings": s["vulns_new"], "Resolved": s["vulns_resolved"], "Rescored": s["vulns_rescored"], "Alerts": s["alerts"], "Critical alerts": s["alerts_critical"],
                "Components added": s["components_added"], "Components removed": s["components_removed"], "Version changes": s["components_changed"]}
    assert {k: int(v) for k, v in c.items()} == expected                                  # 8 of 8 cards equal the record's numbers
    assert expected == {"New findings": 1, "Resolved": 2, "Rescored": 0, "Alerts": 1, "Critical alerts": 0, "Components added": 1, "Components removed": 0, "Version changes": 1}
    assert "flask" in row_with(out, "New finding at or above the threshold") and ch["alerts"][0]["id"] in text(row_with(out, "New finding at or above the threshold"))
    new_rows = [text(r).split() for r in re.findall(r"<tr>(.*?)</tr>", out, re.S) if "flask" in r and "bts-sev" in r]
    assert len(new_rows) == 1 and new_rows[0][1:] == ["flask", "0.12", "HIGH", "7.5", "1.0"]       # the new finding: package, version, severity, CVSS, fixed in
    assert re.search(r"requests.*2\.19\.1.*2\.31\.0.*upgrade", text(re.sub(r"\s+", " ", out)))
    assert 'bts-pill warn">mixed<' in out and "new and resolved findings" in text(out)


def test_changes_pane_says_nothing_is_recorded_and_shows_absent_numbers_as_dashes(gov):
    """AC: BSA-AC-230"""
    code, ch = jget(gov["base"] + "/api/changes/other")
    assert code == 200 and "summary" not in ch                                           # one analysis only: the service says so
    out = render("renderChanges", ok(ch))
    assert "Nothing to compare" in out and "no earlier analysis" in out and "bts-card" not in out and not re.search(r"\b0\b", text(out))
    partial = {"summary": {"vulns_new": 25}, "new": [{"id": "CVE-1", "package": "p", "version": "1", "severity": "HIGH", "score": None, "fixed_version": ""}] * 3,
               "alerts": [], "resolved": [], "rescored": [], "components": {}}
    out = render("renderChanges", ok(partial))
    c = cards(out)
    assert c["New findings"] == "25" and [k for k, v in c.items() if v == "—"] == ["Resolved", "Rescored", "Alerts", "Critical alerts", "Components added",
                                                                                 "Components removed", "Version changes"]      # 7 of 7 absent fields are dashes
    assert "first 3 of 25 new findings" in text(out)
    assert text(row_with(out, "CVE-1")).split() == ["CVE-1", "p", "1", "HIGH", "—", "no", "fix", "known"]              # a missing score is a dash, not 0.0
    floor = render("renderChanges", ok({"summary": {"vulns_new": 1}, "new": [{"id": "X", "package": "p", "version": "1", "severity": "HIGH", "score": 7.0,
                                                                              "score_basis": "label-floor", "fixed_version": "2"}]}))
    assert "≥ 7.0 (label)" in text(floor)                                                 # the label floor is shown as a bound


# ------------------------------------------------------------------ OpenVEX with decisions
def test_vex_pane_shows_what_each_decision_did_to_its_statement(gov):
    """AC: BSA-AC-231"""
    base = gov["base"]
    posts = [{"check_id": "CVE-2020-1111", "status": "false-positive", "justification": "vulnerable_code_not_present",
              "note": "grep: the vulnerable adapter is not imported", "by": "carol"},
             {"check_id": "CVE-2020-2222", "status": "false-positive", "note": "never reached"},
             {"check_id": "CVE-2020-3333", "status": "accepted", "note": "tracked in JIRA-7, fix next release", "by": "dave", "expires": "2099-01-01"},
             {"check_id": "CVE-2019-0001", "status": "accepted", "note": "an old acceptance that ran out", "expires": "2020-01-01"}]
    assert [_post(base + "/api/triage", b)[0] for b in posts] == [200, 200, 200, 200]
    code, doc = jget(base + "/api/vex/other")
    assert code == 200 and len(doc["statements"]) == 3
    out = render("renderVex", ok(doc))
    t = re.sub(r"\s+", " ", text(out))
    assert out.count('bts-pill ok">not_affected<') == 1 and out.count('bts-pill bad">affected<') == 2        # 1 not_affected, 2 affected of 3
    assert out.count("decision not applied") == 1 and "needs a VEX justification" in t and "Risk accepted by dave until 2099-01-01" in t
    assert "vulnerable_code_not_present" in row_with(out, "CVE-2020-1111") and "carol" in text(row_with(out, "CVE-2020-1111"))
    assert "Risk acceptances (stay affected) 1" in t and "Decisions that did not change a statement 1" in t
    assert "stays affected" in t and "10 characters" in t                                  # the fail-closed rule is stated on the pane
    store = jget(base + "/api/triage")[1]["triage"]
    dec = render("renderDecisions", store, TODAY)
    assert len(re.findall(r"<code>CVE-", dec)) == 4 and dec.count('bts-pill bad">expired<') == 1      # 4 decisions listed, 1 of them past its end date
    assert render("renderDecisions", {}, TODAY).count("No decision has been recorded yet") == 1


# ------------------------------------------------------------------ the decision form
def test_decision_form_offers_the_five_justifications_and_says_what_keeps_a_finding_affected():
    """AC: BSA-AC-232"""
    just, statuses, minimum, opts, status_opts = js(("gov", "JUSTIFICATIONS"), ("gov", "STATUSES"), ("gov", "MIN_REASON"), ("gov", "justificationOptions"),
                                                    ("gov", "statusOptions"))
    assert [j["id"] for j in just] == list(triage.JUSTIFICATIONS) and len(just) == 5            # 5 of 5, same order as the service
    assert sorted(s["id"] for s in statuses) == sorted(console.TRIAGE_STATUSES) and minimum == triage.MIN_REASON == 10
    values = re.findall(r'<option value="([^"]*)"', opts)
    assert values == [""] + list(triage.JUSTIFICATIONS)
    assert re.findall(r'<option value="([^"]*)"', status_opts) == [""] + [s["id"] for s in statuses]      # no decision is preselected
    page = open(os.path.join(WEB, "index.html"), encoding="utf-8").read()
    assert "Without a VEX justification and a reason of at least 10 characters, a false positive stays <i>affected</i>" in page
    fp = render("triageOutcome", {"status": "false-positive", "justification": "", "reason": "too short"}, TODAY)
    assert fp["state"] == "rejected" and fp["vex"] == "affected" and "STAYS AFFECTED" in render("triageOutcome", {"status": "false-positive", "reason": "x"}, TODAY)["text"]
    good = render("triageOutcome", {"status": "false-positive", "justification": "component_not_present", "reason": "not shipped in the image"}, TODAY)
    assert good["state"] == "not_affected" and good["vex"] == "not_affected"


def test_the_forms_prediction_equals_the_services_decision_for_375_inputs():
    """AC: BSA-AC-233"""
    reasons = ["", "123456789", "1234567890", "𝒳" * 10, "   abc      "]                    # 0, 9, 10, 10 code points (20 UTF-16 units), 3 after trimming
    expiries = ["", "2020-01-01", "2099-12-31", "2026-02-30", TODAY]                      # none, past, future, not a calendar day, today
    cases = [{"status": s, "justification": j, "reason": r, "expires": e}
             for s, j, r, e in itertools.product([x for x in console.TRIAGE_STATUSES], ["", "component_not_present", "not-a-justification"], reasons, expiries)]
    assert len(cases) == 375
    got = js(*[("gov", "triageOutcome", c, TODAY) for c in cases])
    v = {"id": "CVE-1", "aliases": [], "osv_ids": [], "package": "p", "ecosystem": "PyPI", "purl": "pkg:pypi/p@1"}
    day = datetime.date.fromisoformat(TODAY)
    for c, o in zip(cases, got):
        entry = {"status": c["status"], "note": c["reason"], "justification": c["justification"], "expires": c["expires"]}
        d = triage.decide(v, {"CVE-1": entry}, today=day)
        assert (o["state"], o["vex"]) == (d["state"], d["vex"]), c                          # 375 of 375 agree


def test_the_request_the_form_builds_is_accepted_and_read_back_and_bad_input_never_leaves(gov):
    """AC: BSA-AC-234"""
    base = gov["base"]
    form = {"finding": "CVE-2020-1111", "status": "false-positive", "justification": "component_not_present", "reason": "  not part of the shipped image  ",
            "expires": "2099-01-01", "scope": "requests", "by": " erin "}
    req = render("triageRequest", form)
    assert req["body"] == {"check_id": "CVE-2020-1111", "status": "false-positive", "note": "not part of the shipped image", "justification": "component_not_present",
                           "expires": "2099-01-01", "scope": "requests", "by": "erin"}
    assert _post(base + "/api/triage", req["body"])[0] == 200
    saved = jget(base + "/api/triage")[1]["triage"]["CVE-2020-1111"]
    assert [saved[k] for k in ("justification", "expires", "scope", "by")] == ["component_not_present", "2099-01-01", "requests", "erin"]      # 4 of 4 fields persisted
    st = {s["vulnerability"]["name"]: s["status"] for s in jget(base + "/api/vex/other")[1]["statements"]}
    assert list(st.values()).count("not_affected") == 1
    accepted = render("triageRequest", dict(form, status="accepted"))
    assert "justification" not in accepted["body"]                                         # a justification only travels with a false positive
    bad = [dict(form, finding=""), dict(form, status=""), dict(form, reason="x" * 501), dict(form, expires="2026-02-30"), dict(form, scope="two words"),
           dict(form, by="b" * 81), dict(form, justification="made_up")]
    outs = js(*[("gov", "triageRequest", b) for b in bad])
    assert all("error" in o and "body" not in o for o in outs) and len(outs) == 7           # 7 of 7 refused before any request is made


# ------------------------------------------------------------------ fleet and affected
def test_fleet_pane_ranks_the_projects_with_the_age_of_each_analysis(gov):
    """AC: BSA-AC-235"""
    base = gov["base"]
    code, fleet = jget(base + "/api/fleet")
    assert code == 200 and fleet["projects"] == 2 and [r["project"] for r in fleet["ranking"]] == ["other", "proj"]
    out = render("renderFleet", ok(fleet), _ages(base))
    names = [text(r).split()[1] for r in re.findall(r"<tr>(.*?)</tr>", out, re.S)[1:3]]
    assert names == ["other", "proj"]                                                      # same order as the service
    for n in ("other", "proj"):
        assert re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", text(row_with(out, 'data-name="%s"' % n)))     # 2 of 2 rows carry the analysis time
    shared = row_with(out, "CVE-2020-3333")
    assert text(shared).split()[-2:] == ["other,", "proj"]                                  # both projects are named
    assert "last analysis" in text(out) and "lower bound" in text(out) and "weighted findings" in text(out)
    assert "No project has been analysed yet" in text(render("renderFleet", ok({"projects": 0})))
    assert "no roll-up" in text(render("renderFleet", ok({})))


def test_affected_search_lists_the_hits_and_never_calls_the_rest_unaffected(gov):
    """AC: BSA-AC-236"""
    base = gov["base"]
    ages = _ages(base)
    q = render("affectedQuery", {"cve": " CVE-2020-3333 ", "component": "", "version": ""})
    assert q == {"url": "/api/affected?cve=CVE-2020-3333"}
    code, res = jget(base + q["url"])
    out = render("renderAffected", ok(res), ages)
    assert code == 200 and res["project_count"] == 2 and len(re.findall(r"<tr>", out)) == 3        # header + 1 row per project
    assert "fixed in 1.0" in text(out)
    q2 = render("affectedQuery", {"cve": "", "component": "requests", "version": "<2.20,>=2.0"})
    assert q2["url"] == "/api/affected?component=requests&version=%3C2.20%2C%3E%3D2.0"
    res2 = jget(base + q2["url"])[1]
    out2 = render("renderAffected", ok(res2), ages)
    assert res2["not_found_in"] == ["proj"] and "No matching component within the constraint in:" in text(out2) and "proj (" in text(out2)
    miss = render("renderAffected", ok(jget(base + "/api/affected?cve=CVE-1999-0001")[1]), ages)
    assert "not proof they are unaffected" in text(miss) and "Not found among the findings of the last analysis" in text(miss)
    assert "unaffected" not in text(out) and "No analysed project reports this advisory" in text(miss)
    assert "error" in render("affectedQuery", {"cve": " ", "component": "", "version": "<2"}) and "url" not in render("affectedQuery", {})   # 2 of 2 empty searches stay local
    code, err = jget(base + "/api/affected?component=requests&version=oops%3E")
    assert code == 400 and "not a version constraint" in text(render("renderAffected", {"ok": False, "status": 400, "data": err}))
    unknown = {"query": {"id": "", "component": "x", "version": "<2"}, "analysed_projects": 1, "project_count": 1, "match_count": 1, "not_found_in": [],
               "projects": [{"project": "p", "matches": [{"kind": "version_unknown", "package": "x", "version": "", "ecosystem": "PyPI", "vulns": 0}]}]}
    assert "version unknown" in render("renderAffected", ok(unknown), {}) and "cannot be checked against <2" in text(render("renderAffected", ok(unknown), {}))


# ------------------------------------------------------------------ escaping and absent data
EVIL = '<img src=x onerror=alert(1)>'
EVIL2 = '"><script>alert(2)</script>'


def test_hostile_values_are_escaped_in_every_pane_and_a_json_object_cannot_pose_as_markup():
    """AC: BSA-AC-237"""
    conf = {"status": "OK", "format": EVIL, "components": 1, "honesty": EVIL2, "regimes": {EVIL: {"title": EVIL2, "authority": EVIL, "stage": EVIL2, "as_of": EVIL, "draft": True,
            "verdict": EVIL, "elements": {EVIL2: EVIL}, "pass": 0, "partial": 0, "gap": 1, "total": 1}},
            "elements": {EVIL2: {"title": EVIL, "scope": EVIL2, "pct": 0, "status": EVIL, "basis": EVIL}},
            "fix_once": [{"element": EVIL2, "title": EVIL, "status": EVIL2, "pct": 0, "missing": 1, "regimes": [EVIL], "hint": EVIL2}]}
    vrow = {"id": EVIL, "package": EVIL2, "version": EVIL, "severity": EVIL2, "score": 7.5, "score_basis": EVIL, "fixed_version": EVIL, "previous_score": 1, "crossing": EVIL}
    chg = {"summary": {"vulns_new": 1}, "verdict": EVIL, "threshold": 7.0, "compared_at": EVIL, "before": {"components": EVIL, "vulns": EVIL2},
           "alerts": [{"kind": EVIL, "severity": EVIL2, "id": EVIL, "package": EVIL2, "version": EVIL, "detail": EVIL}], "new": [vrow], "resolved": [vrow], "rescored": [vrow],
           "components": {"added": [{"name": EVIL, "version": EVIL2, "ecosystem": EVIL}], "removed": [], "changed": [{"name": EVIL, "ecosystem": EVIL2, "from": [EVIL], "to": [EVIL2],
                          "direction": EVIL}], "license_changed": [{"name": EVIL, "version": EVIL2, "from": EVIL, "to": EVIL2}],
                          "copyleft_introduced": [{"name": EVIL, "version": EVIL2, "license": EVIL, "category": EVIL2, "reason": EVIL}]}}
    vex = {"@id": EVIL, "timestamp": EVIL2, "statements": [{"vulnerability": {"name": EVIL}, "products": [{"@id": EVIL2}], "status": EVIL, "justification": EVIL2,
                                                            "impact_statement": EVIL, "status_notes": EVIL2, "action_statement": EVIL}]}
    dec = {EVIL: {"status": EVIL2, "note": EVIL, "justification": EVIL2, "by": EVIL, "expires": EVIL2, "scope": EVIL, "ts": EVIL2}}
    fleet = {"projects": 1, "components": 1, "vulns": 1, "unfixed_findings": 1, "projects_with_malicious": [EVIL], "severity": {"HIGH": 1}, "license_categories": {EVIL: 1},
             "ranking_basis": EVIL2, "ranking": [{"project": EVIL, "components": 1, "vulns": 1, "worst": EVIL2, "weighted": 1, "unfixed": 1, "malicious": 1}],
             "shared_advisories": [{"id": EVIL, "package": EVIL2, "worst": EVIL, "fixed_version": EVIL2, "project_count": 2, "projects": [EVIL, EVIL2]}],
             "shared_components": [{"name": EVIL, "version": EVIL2, "project_count": 2, "vulns": 1, "projects": [EVIL]}]}
    aff = {"query": {"id": EVIL, "component": EVIL2, "version": EVIL}, "analysed_projects": 1, "project_count": 1, "match_count": 2, "note": EVIL2, "not_found_in": [EVIL2],
           "projects": [{"project": EVIL, "matches": [{"kind": "finding", "id": EVIL2, "package": EVIL, "version": EVIL2, "severity": EVIL, "fixed_version": EVIL2},
                                                      {"kind": "component", "package": EVIL, "version": EVIL2, "relationship": EVIL, "vulns": EVIL2}]}]}
    findings = [{"cve": EVIL, "name": EVIL2, "version": EVIL, "severity": EVIL2, "triage_status": EVIL}]
    ages = {EVIL: EVIL2, EVIL2: EVIL}
    outs = js(("gov", "renderConformance", ok(conf)), ("gov", "renderChanges", ok(chg)), ("gov", "renderVex", ok(vex)), ("gov", "renderDecisions", dec, TODAY),
              ("gov", "renderFleet", ok(fleet), ages), ("gov", "renderAffected", ok(aff), ages), ("gov", "findingOptions", findings, EVIL),
              ("gov", "renderConformance", {"ok": False, "status": 404, "data": {"error": EVIL}}), ("gov", "renderChanges", ok({"note": EVIL})),
              ("gov", "renderFleet", {"ok": False, "status": 500, "data": {"error": EVIL}}))
    assert len(outs) == 10
    for o in outs:                                                                         # 10 of 10 outputs: no injected element, the text is still shown
        assert "<img" not in o and "<script" not in o.lower()
        assert "&lt;img src=x onerror=alert(1)&gt;" in o or "&lt;script&gt;" in o
    obj_cell, named = js(("ui", "table", ["A"], [[{"html": "<b>x</b>"}]]), ("ui", "pill", EVIL, "<b>"))
    assert "<b>x</b>" not in obj_cell and "[object Object]" in obj_cell                     # a parsed-JSON object with an "html" key is text
    assert "<img" not in named["html"] and 'class="bts-pill muted"' in named["html"]       # an unknown pill class falls back to a fixed one


def test_absent_fields_are_dashes_and_never_a_default_zero():
    """AC: BSA-AC-238"""
    fleet = render("renderFleet", ok({"projects": 2}), {})
    c = cards(fleet)
    assert c["Projects"] == "2" and [k for k, v in c.items() if v == "—"] == ["Components", "Findings", "Without a known fix", "With a malicious package"]     # 4 of 4
    conf = render("renderConformance", ok({"status": "OK", "regimes": {"r1": {"title": "R1"}}, "elements": {"e1": {"title": "E1"}}, "fix_once": None}))
    t = re.sub(r"\s+", " ", text(conf))
    assert "bts-cov" not in conf and "not recorded" in t and "No fix list was returned" in t        # no coverage bar, no draft claim, no fabricated verdict
    assert not re.search(r"bts-pill \w+\">(conformant|gaps|partial)<", conf) and "— / — / — of —" in t
    vex = render("renderVex", ok({"statements": [{"vulnerability": {}, "products": []}]}))
    assert "Statements by status" in vex and text(row_with(vex, "<td>—</td>")).split().count("—") >= 3
    fleet_rows = render("renderFleet", ok({"projects": 1, "ranking": [{"project": "p"}]}), {})
    assert text(row_with(fleet_rows, 'data-name="p"')).split()[:2] == ["1", "p"] and text(row_with(fleet_rows, 'data-name="p"')).count("—") >= 7        # 7 of 7 missing cells


def test_clean_room_workbench_wiring_and_honest_scan_progress_are_wired():
    """AC: BSA-AC-611, BSA-AC-612, BSA-AC-613. The clean-room workbench pane, its stage strip and the scan job's
    live stage messaging are wired in the console glue; the pinned report banner is rewritten to an honest
    unknown whenever the projection is not an authoritative pass."""
    src = open(os.path.join(WEB, "bts_console.js"), encoding="utf-8").read()
    page = open(os.path.join(WEB, "index.html"), encoding="utf-8").read()
    assert 'data-sv="reimpl"' in page and 'id="paneReimpl"' in page
    assert "REIMPL_STAGES" in src and "copy_gate" in src and "adopted_tests_passed" in src      # the stage strip
    assert "REIMPL_FAIL_AT" in src and "copy_gate_failed" in src                                 # failures map onto stages
    assert "watchJobEvents(id" in src and "'/api/jobs/'" in src                                  # the scan step bar consumes SSE
    assert "analysis engines are running" in src                                                 # the no-event fallback stays
    assert "Unknown — not a pass" in src and "vulnerability_presence" in src                     # the honest banner
    assert ".sx-banner.warn" in open(os.path.join(WEB, "bts_console.css"), encoding="utf-8").read()
