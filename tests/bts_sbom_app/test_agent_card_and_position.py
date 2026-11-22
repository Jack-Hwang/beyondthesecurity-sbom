"""Agent card (A2A-style discovery) + lost-in-the-middle passage ordering (brief-5 books integration)."""
from __future__ import annotations

import json
import os

from bts_sbom_app import chat, evals
from conftest import FakeScanner

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_order_passages_puts_most_relevant_first_and_is_deterministic():
    """AC: BSA-AC-536"""
    docs = [("weak", "totally unrelated filler text about gardening tools and seasons"),
            ("strong", "CVE-2020-1111 affects requests 2.19.1; the fix upgrades requests to 2.20"),
            ("mid", "requests is a popular http library with many advisories over the years")]
    out = chat.order_passages_for_prompt("CVE-2020-1111 requests 업그레이드", docs)
    assert [sid for sid, _ in out][:2] == ["strong", "mid"]          # best evidence first, never buried mid-context
    assert len(out) == 3 and out[-1][0] == "weak"
    again = chat.order_passages_for_prompt("CVE-2020-1111 requests 업그레이드", docs)
    assert again == out                                              # deterministic: ties break by source id
    capped = chat.order_passages_for_prompt("CVE-2020-1111 requests",
                                            [("d%d" % i, "CVE-2020-1111 filler %d" % i) for i in range(10)])
    assert len(capped) == 6                                          # the prompt budget is enforced here, not at the join


def test_agent_card_declares_skills_gates_and_honest_security(tmp_path, make_repo):
    """AC: BSA-AC-535"""
    import threading
    import urllib.request
    from http.server import ThreadingHTTPServer

    from bts_sbom_app import pipeline, server
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, cache_dir=str(tmp_path / "cache"))
    assert rec["error"] is None, rec
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/api/agent-card" % httpd.server_address[1], timeout=10) as r:
            card = json.loads(r.read())
    finally:
        httpd.shutdown()
    assert card["name"] == "bts-sbom" and card["capabilities"]["streaming"] is True
    assert card["handoffSchema"] == "bts-sbom.handoff.v1"
    ids = [s["id"] for s in card["skills"]]
    assert {"scan", "patch", "license_council", "chat", "book_search", "nl2sql", "supply_chain_gate"} <= set(ids)
    patch = next(s for s in card["skills"] if s["id"] == "patch")
    assert patch["gate"] == "approval-token"                          # the effect gate is declared, not hidden
    assert "no authentication" in card["securitySchemes"]["none"]["description"]   # honesty: none, localhost only
    assert "python -m bts_sbom_app mcp" in card["endpoints"]["mcp"]   # the MCP surface is discoverable too
