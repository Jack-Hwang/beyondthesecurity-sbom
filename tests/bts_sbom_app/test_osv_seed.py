"""The OSV snapshot is copied once from the evidence volume to local disk: SQLite cannot take concurrent writes on an SMB share."""
from __future__ import annotations

import os

from bts_sbom_app import server


def test_the_snapshot_is_copied_once_to_the_local_path_and_never_overwritten(tmp_path):
    """AC: BSA-AC-1226"""
    seed = tmp_path / "share" / "osv.db"
    seed.parent.mkdir()
    seed.write_bytes(b"SQLite format 3\x00" + b"x" * 200)
    dest = tmp_path / "local" / "osv.db"
    env = {server.SEED_ENV: str(seed), "BTS_SBOM_OSV_DB_PATH": str(dest)}
    assert server.seed_local_osv_db(env) == "copied" and dest.read_bytes() == seed.read_bytes() and not os.path.exists(str(dest) + ".part")       # 1 of 1 atomic copy
    dest.write_bytes(b"locally grown cache")
    assert server.seed_local_osv_db(env) == "present" and dest.read_bytes() == b"locally grown cache"                                            # 0 of 1 overwritten


def test_nothing_happens_without_both_settings_or_a_seed_and_a_failed_copy_is_reported_not_fatal(tmp_path, monkeypatch, capsys):
    """AC: BSA-AC-1227"""
    dest = str(tmp_path / "local" / "osv.db")
    assert server.seed_local_osv_db({}) == "" and server.seed_local_osv_db({server.SEED_ENV: str(tmp_path / "s.db")}) == "" and server.seed_local_osv_db({"BTS_SBOM_OSV_DB_PATH": dest}) == ""
    assert server.seed_local_osv_db({server.SEED_ENV: dest, "BTS_SBOM_OSV_DB_PATH": dest}) == ""                                                  # same file: nothing to copy
    assert server.seed_local_osv_db({server.SEED_ENV: str(tmp_path / "missing.db"), "BTS_SBOM_OSV_DB_PATH": dest}) == "no-seed" and not os.path.exists(dest)
    seed = tmp_path / "osv.db"
    seed.write_bytes(b"data")
    monkeypatch.setattr(server.shutil, "copyfile", lambda a, b: (_ for _ in ()).throw(OSError("disk full")))
    assert server.seed_local_osv_db({server.SEED_ENV: str(seed), "BTS_SBOM_OSV_DB_PATH": dest}) == "failed" and not os.path.exists(dest)
    assert "could not copy the OSV snapshot" in capsys.readouterr().out
