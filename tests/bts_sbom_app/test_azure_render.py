"""scripts/azure_render_app.py fills the Container Apps template from the environment without leaving a placeholder or a non-ASCII byte."""
from __future__ import annotations

import os
import re
import subprocess
import sys

from bts_sbom_app import evals

ROOT = evals.repo_root()
SCRIPT = os.path.join(ROOT, "scripts", "azure_render_app.py")
TEMPLATE = os.path.join(ROOT, "deploy", "azure", "containerapp.yaml")
ENV = {"IMAGE": "reg.azurecr.io/bts-sbom-app:t1", "FQDN": "bts-sbom.env.koreacentral.azurecontainerapps.io", "LLM_KEY": "k-llm-secret-value", "LLM_BASE": "https://res.openai.azure.com",
       "ACCESS_TOKEN": "tok-access-secret-value-0123456789", "ACR_SERVER": "reg.azurecr.io", "ACR_USER": "reg", "ACR_PASSWORD": "pw-acr-secret-value"}


def _render(tmp_path, **extra):
    out = tmp_path / "rendered.yaml"
    env = dict(os.environ, **ENV, **extra)
    p = subprocess.run([sys.executable, "-X", "utf8", "-I", SCRIPT, TEMPLATE, str(out)], capture_output=True, text=True, env=env, timeout=60)
    return p, out


def test_the_rendered_declaration_is_ascii_placeholder_free_and_keeps_every_secret_behind_a_secretref(tmp_path):
    """AC: BSA-AC-1224"""
    p, out = _render(tmp_path)
    assert p.returncode == 0 and "rendered" in p.stdout and not any(v in p.stdout + p.stderr for v in ("k-llm-secret-value", "tok-access-secret-value", "pw-acr-secret-value"))   # never printed
    raw = out.read_bytes()
    assert all(b < 128 for b in raw)                                                                              # az reads the file with the ANSI code page
    text = raw.decode("ascii")
    assert not re.search(r"<[A-Za-z][^>\n]*>", text)                                                              # 0 placeholders left
    assert text.startswith("location: koreacentral") and "image: \"reg.azurecr.io/bts-sbom-app:t1\"" in text
    assert text.count("k-llm-secret-value") == 1 and text.count("tok-access-secret-value") == 1 and text.count("pw-acr-secret-value") == 1     # each secret appears once, in the secrets block
    for name in ("AZURE_OPENAI_API_KEY", "BTS_SBOM_ACCESS_TOKEN"):
        m = re.search(r"- name: %s\n\s+secretRef: (\S+)" % name, text)
        assert m, name                                                                                            # 2 of 2 secret-bearing env vars come from a secretRef
    assert "passwordSecretRef: acr-password" in text and "minReplicas: 0" in text and "BTS_SBOM_ALLOWED_ROOTS" in text and "BTS_SBOM_OSV_DB_PATH" in text
    assert text.count("type: Startup") == 1 and text.count("type: Liveness") == 1 and text.count("type: Readiness") == 1      # the probes survive the rendering


def test_the_replica_floor_week_and_owner_are_parameters_and_a_missing_secret_stops_the_render(tmp_path):
    """AC: BSA-AC-1225"""
    p, out = _render(tmp_path, MIN_REPLICAS="1", WEEK="2026-W49", OWNER="ops-team")
    text = out.read_text(encoding="ascii")
    assert p.returncode == 0 and "minReplicas: 1" in text and 'week: "2026-W49"' in text and 'owner: "ops-team"' in text
    env = {k: v for k, v in os.environ.items()}
    env.update({k: v for k, v in ENV.items() if k != "LLM_KEY"})
    env.pop("LLM_KEY", None)
    bad = subprocess.run([sys.executable, "-X", "utf8", "-I", SCRIPT, TEMPLATE, str(tmp_path / "x.yaml")], capture_output=True, text=True, env=env, timeout=60)
    assert bad.returncode != 0 and "LLM_KEY" in bad.stderr and not (tmp_path / "x.yaml").exists()                 # no half-rendered file with a missing secret
