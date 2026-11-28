"""BTS_SBOM_LLM_LEDGER: the LLM call ledger follows the env when set (2026-11-28 — on a scale-to-zero
deployment the default <root>/evidence path dies with the container, so an operator points it at the
Azure Files volume; the default stays the old location)."""
from __future__ import annotations

import os

import bts_sbom_app.server as srv


def test_llm_ledger_follows_env(monkeypatch, tmp_path):
    monkeypatch.setenv("BTS_SBOM_LLM_LEDGER", str(tmp_path / "vol" / "ledger.json"))
    monkeypatch.delenv("BTS_SBOM_LLM_CONFIG", raising=False)
    monkeypatch.delenv("BTS_SBOM_ACCESS_TOKEN", raising=False)
    st = srv.State(str(tmp_path), str(tmp_path / "ev"), None)
    assert st.client.ledger.endswith(os.path.join("vol", "ledger.json"))


def test_llm_ledger_default_stays_root_evidence(monkeypatch, tmp_path):
    monkeypatch.delenv("BTS_SBOM_LLM_LEDGER", raising=False)
    monkeypatch.delenv("BTS_SBOM_LLM_CONFIG", raising=False)
    monkeypatch.delenv("BTS_SBOM_ACCESS_TOKEN", raising=False)
    st = srv.State(str(tmp_path), str(tmp_path / "ev"), None)
    assert st.client.ledger.endswith(os.path.join("evidence", ".llm_ledger.json"))
