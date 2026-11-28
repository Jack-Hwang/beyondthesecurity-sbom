"""GitOps deploy lane (scripts/gitops_deploy.py): the URecA2.0-pattern adoption - blue/green revision
traffic weights, a rollback lane driven by the ledger, and the committed-YAML vs live drift gate.
AC: BSA-AC-1272 (the seven lane cases: record, rollback flip, rollback image-rebuild, the two
refusals, smoke-failure auto flip-back, promotion flow), AC: BSA-AC-1273 (drift diffing with value
masking). All fixtures are fake az runners so no live Azure is touched; the live drill is recorded
separately in the ledger and docs/GIT_STRATEGY.md."""
from __future__ import annotations

import importlib.util
import json
import os
import sys

import pytest

from bts_sbom_app import evals

ROOT = evals.repo_root()


def _load():
    spec = importlib.util.spec_from_file_location("gitops_deploy", os.path.join(ROOT, "scripts", "gitops_deploy.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gitops_deploy"] = mod
    spec.loader.exec_module(mod)
    return mod


class FakeAz:
    """A fake az runner: canned revision/show/traffic answers, records every call."""

    def __init__(self, revisions, app=None):
        self.revisions = revisions                       # [{name, image, traffic, active}]
        self.app = app or {"properties": {"configuration": {"ingress": {"traffic": []}},
                                          "template": {"containers": [], "scale": {}}}}
        self.calls: list = []
        self.traffic_updates: list = []
        self.updates: list = []

    def __call__(self, cmd):
        self.calls.append(cmd)
        joined = " ".join(cmd)
        if "revision" in joined and "list" in joined:
            return 0, json.dumps([{"name": r["name"],
                                   "properties": {"image": r["image"], "trafficWeight": r["traffic"],
                                                  "active": r.get("active", True)}} for r in self.revisions]), ""
        if "containerapp" in joined and " show " in " %s " % joined:
            return 0, json.dumps(self.app), ""
        if "traffic" in joined and ("set" in joined or "update" in joined):
            self.traffic_updates.append(joined)
            self.revisions = [dict(r) for r in self.revisions]
            dist = joined.split("--revision-weight ")[1].rsplit(" -o ", 1)[0]
            for r in self.revisions:
                r["traffic"] = 0                                # a set is total: unlisted revisions go 0
            for pair in dist.split():
                name, w = pair.rsplit("=", 1)
                for r in self.revisions:
                    if r["name"] == name:
                        r["traffic"] = int(w)
            return 0, "{}", ""
        if "containerapp" in joined and "update" in joined:
            self.updates.append(joined)
            sfx = joined.split("--revision-suffix ")[1].split()[0]
            img = joined.split("--image ")[1].split()[0]
            self.revisions = [dict(r) for r in self.revisions]
            self.revisions.append({"name": "bts-sbom--" + sfx, "image": img, "traffic": 0, "active": True})
            # MEASURED (2026-11-28 live): az containerapp update --revision-suffix MOVES ALL TRAFFIC
            # to the new revision at once - the fake mirrors the platform, not the wish.
            for r in self.revisions:
                r["traffic"] = 100 if r["name"] == "bts-sbom--" + sfx else 0
            return 0, "{}", ""
        return 0, "{}", ""


def _distribution(revisions):
    return [{"revisionName": r["name"], "weight": r["traffic"]} for r in revisions if r["traffic"] > 0]


@pytest.fixture()
def mod(tmp_path, monkeypatch):
    m = _load()
    monkeypatch.setattr(m, "LEDGER", str(tmp_path / "deploy_ledger.jsonl"))
    monkeypatch.setenv("BTS_AZ_FQDN", "http://127.0.0.1:1")     # probes must never hit a real host here
    return m


def test_record_and_rollback_lane_flips_to_previous_revision(mod, monkeypatch):
    revs = [{"name": "bts-sbom--0000016", "image": "reg/app:ir-20261128b", "traffic": 100, "active": True}]
    az = FakeAz(revs)
    az.app["properties"]["configuration"]["ingress"]["traffic"] = _distribution(az.revisions)
    assert mod.cmd_record(az) == 0
    rows = mod._read_ledger()
    assert rows[0]["event"] == "record" and rows[0]["promoted_image"] == "reg/app:ir-20261128b"

    # a promoted blue/green row (as the live drill would leave): previous still alive -> flip only
    mod._append_ledger({"ts": "t", "event": "promoted", "image": "reg/app:sha-next",
                        "revision": "bts-sbom--bg1", "previous_image": "reg/app:ir-20261128b",
                        "previous_revision": "bts-sbom--0000016"})
    revs.append({"name": "bts-sbom--bg1", "image": "reg/app:sha-next", "traffic": 100, "active": True})
    revs[0]["traffic"] = 0
    az2 = FakeAz(revs)
    monkeypatch.setattr(mod, "_smoke", lambda expect: {"expect": expect, "seen": [expect] * 6, "failures": [], "ok": True})
    assert mod.cmd_rollback(az2) == 0
    assert any("--revision-weight bts-sbom--0000016=100" in c for c in az2.traffic_updates)
    tail = mod._read_ledger()[-1]
    assert tail["event"] == "rolled_back_to" and tail["revision"] == "bts-sbom--0000016"


def test_rollback_rebuilds_from_recorded_image_when_revision_is_gone(mod, monkeypatch):
    mod._append_ledger({"ts": "t", "event": "promoted", "image": "reg/app:sha-next",
                        "revision": "bts-sbom--bg1", "previous_image": "reg/app:v0.6.0",
                        "previous_revision": "bts-sbom--0000016"})
    az = FakeAz([{"name": "bts-sbom--bg1", "image": "reg/app:sha-next", "traffic": 100, "active": True}])
    monkeypatch.setattr(mod, "_smoke", lambda expect: {"expect": expect, "seen": [expect] * 6, "failures": [], "ok": True})
    assert mod.cmd_rollback(az) == 0
    assert any("--image reg/app:v0.6.0" in c for c in az.updates)      # the IMAGE lane, not a guess
    assert any("rb" in c for c in az.updates)                          # a fresh rb suffix revision
    assert mod._read_ledger()[-1]["event"] == "rolled_back_to"


def test_rollback_refuses_without_a_ledger(mod, tmp_path):
    assert mod.cmd_rollback(FakeAz([])) == 2
    mod._append_ledger({"ts": "t", "event": "promoted", "image": "x", "revision": "r"})  # no previous_image
    assert mod.cmd_rollback(FakeAz([])) == 2


def test_deploy_smoke_failure_auto_flips_back_and_records(mod, monkeypatch):
    az = FakeAz([{"name": "bts-sbom--0000016", "image": "reg/app:old", "traffic": 100, "active": True}])
    monkeypatch.setattr(mod, "_smoke", lambda expect: {"expect": expect, "seen": ["wrong"] * 6,
                                                       "failures": ["round 0: revision wrong"], "ok": False})
    assert mod.cmd_deploy(az, "reg/app:new") == 1
    flips = [c for c in az.traffic_updates if "bts-sbom--0000016=100" in c]
    assert flips                                                       # the auto flip-back happened
    row = mod._read_ledger()[-1]
    assert row["event"] == "auto_rolled_back" and row["restored_to"] == "bts-sbom--0000016"


def test_drift_gate_names_image_scale_and_env_keys_and_masks_values(mod, tmp_path):
    applied = tmp_path / "containerapp.applied.yaml"
    applied.write_text(
        "properties:\n"
        "  template:\n"
        "    containers:\n"
        "    - image: reg/app:committed\n"
        "      env:\n"
        "      - name: BTS_OSS_ALLOWED_HOSTS\n"
        "        value: secret-ish-value\n"
        "      - name: GONE_IN_LIVE\n"
        "        value: x\n"
        "    scale:\n"
        "      minReplicas: 0\n"
        "      maxReplicas: 1\n",
        encoding="utf-8")
    live_app = {"properties": {"configuration": {"ingress": {"traffic": []}},
                               "template": {"containers": [{"image": "reg/app:live",
                                                            "env": [{"name": "BTS_OSS_ALLOWED_HOSTS",
                                                                     "value": "different"}]}],
                                           "scale": {"minReplicas": 0, "maxReplicas": 2}}}}
    az = FakeAz([], app=live_app)
    old = mod.APPLIED_YAML
    mod.APPLIED_YAML = str(applied)
    try:
        rc = mod.cmd_drift(az)
    finally:
        mod.APPLIED_YAML = old
    assert rc == 1
    out = mod._read_ledger()[-1]
    joined = json.dumps(out)
    assert "image: committed=reg/app:committed live=reg/app:live" in joined
    assert "scale.maxReplicas: committed=1 live=2" in joined
    assert "GONE_IN_LIVE" in joined                                    # the key is named
    assert "secret-ish-value" not in joined and "different" not in joined   # the VALUE never leaves


def test_drift_clean_passes(mod, tmp_path):
    applied = tmp_path / "containerapp.applied.yaml"
    applied.write_text("properties:\n  template:\n    containers:\n    - image: reg/app:same\n"
                       "      env:\n      - name: A_KEY\n        value: v\n"
                       "    scale:\n      minReplicas: 0\n      maxReplicas: 1\n", encoding="utf-8")
    live_app = {"properties": {"configuration": {"ingress": {"traffic": []}},
                               "template": {"containers": [{"image": "reg/app:same",
                                                            "env": [{"name": "A_KEY", "value": "v"}]}],
                                           "scale": {"minReplicas": 0, "maxReplicas": 1}}}}
    old = mod.APPLIED_YAML
    mod.APPLIED_YAML = str(applied)
    try:
        assert mod.cmd_drift(FakeAz([], app=live_app)) == 0
    finally:
        mod.APPLIED_YAML = old


def test_deploy_refuses_when_nothing_is_serving(mod):
    assert mod.cmd_deploy(FakeAz([{"name": "r0", "image": "i", "traffic": 0, "active": False}]),
                          "reg/app:new") == 2
