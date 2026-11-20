"""FOSSLight Scanner features integrated (guide fosslight.org/fosslight-guide/scanner/): source scan, binary scan, self-check sheet."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import binscan, cli, evals, selfcheck, server, srcscan
from bts_sbom_app.util import write_json


def _tree(tmp_path):
    root = tmp_path / "src"
    (root / "node_modules" / "dep").mkdir(parents=True)
    (root / "pkg.py").write_text("# SPDX-License-Identifier: MIT\n# Copyright (c) 2024 Example Corp. All rights reserved.\nprint('x')\n", encoding="utf-8")
    (root / "LICENSE").write_text("MIT License\n\nCopyright (c) 2024 Example Corp.\n", encoding="utf-8")
    (root / "lib.so").write_bytes(b"\x00\x01" + b"Copyright 2020 Embedded Corp. All rights reserved.\n" + b"Apache License Version 2.0\n" + b"\x00" * 64)
    (root / "plain.txt").write_text("just text, no markers\n", encoding="utf-8")
    (root / "node_modules" / "dep" / "x.py").write_text("# SPDX-License-Identifier: GPL-3.0-only\n", encoding="utf-8")
    return str(root)


def test_srcscan_records_spdx_and_copyrights_and_lists_exclusions(tmp_path):
    """AC: BSA-AC-223"""
    root = _tree(tmp_path)
    c = srcscan.build(root)
    assert c["status"] == "OK" and c["scanner_info"]["stats"]["walked"] == 4                      # node_modules is pruned before walking
    by = {f["file"]: f for f in c["files"]}
    assert by["pkg.py"]["spdx"] == ["MIT"] and any("2024 Example Corp." in x for x in by["pkg.py"]["copyrights"])
    assert "LICENSE" in by and by["LICENSE"]["file"] == "LICENSE"                                        # license-named file is part of the scan
    ex = c["scanner_info"]["excluded"]
    assert "node_modules" in ex["skipped_dirs"] and "lib.so" in ex["binaries"] and "plain.txt" not in [f["file"] for f in c["files"]]
    csv_text = srcscan.to_csv(c)
    assert csv_text.startswith("File,License (detected),SPDX identifiers,Copyright lines") and "pkg.py" in csv_text
    assert "MIT" in srcscan.to_md(c)
    assert cli.main(["srcscan", root, "--json"]) == 0 and cli.main(["srcscan", str(tmp_path / "missing")]) == 2


def test_binscan_reports_string_evidence_only_and_keeps_text_out(tmp_path):
    """AC: BSA-AC-224"""
    root = _tree(tmp_path)
    c = binscan.build(root)
    assert c["scanner_info"]["stats"]["binaries"] == 1 and "plain.txt" in c["scanner_info"]["excluded"]["text"] and "lib.so" not in c["scanner_info"]["excluded"]["text"]
    b = c["binaries"][0]
    assert b["file"] == "lib.so" and "Apache License" in b["license_strings"]
    assert any("Copyright 2020 Embedded Corp." in x for x in b["copyrights"])
    assert any("no binary database" in h for h in c["honesty"])                                          # evidence, never identification
    csv_text = binscan.to_csv(c)
    assert csv_text.startswith("Binary,Bytes,License strings,Copyright lines") and "lib.so" in csv_text
    assert cli.main(["binscan", root]) == 0


def test_selfcheck_sheet_csv_cli_and_api(tmp_path):
    """AC: BSA-AC-225"""
    rec = evals.synthetic_project()
    csv_text = selfcheck.to_csv(rec)
    lines = csv_text.strip().split("\n")
    assert lines[0] == "OSS Name,OSS Version,License,License Category,License Source,Ecosystem,Vulnerabilities,Files"
    assert any(r.startswith("requests,2.19.1,Apache-2.0") for r in lines[1:])
    assert any(r.startswith("leftpad,1.0.0,,") for r in lines[1:])                                       # unresolved stays empty, never guessed
    ev = tmp_path / "ev" / "demo"
    ev.mkdir(parents=True)
    write_json(str(ev / "demo.json"), dict(rec, schema="bts-sbom.project.v1"))
    out_file = tmp_path / "sheet.csv"
    assert cli.main(["selfcheck", "demo", "--evidence", str(tmp_path / "ev"), "--out", str(out_file)]) == 0
    assert out_file.read_text(encoding="utf-8").startswith("OSS Name,OSS Version")
    st = server.State(evals.repo_root(), str(tmp_path / "ev"), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/api/selfcheck/demo" % httpd.server_address[1], timeout=10) as r:
            assert r.headers["Content-Type"].startswith("text/csv") and "attachment" in r.headers.get("Content-Disposition", "")
            body = r.read().decode("utf-8")
        assert body == selfcheck.to_csv(rec)
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/api/selfcheck/ghost" % httpd.server_address[1], timeout=10)
            raise AssertionError("unknown project should 404")
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        httpd.shutdown()
