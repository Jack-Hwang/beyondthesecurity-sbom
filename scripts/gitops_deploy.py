"""GitOps deploy lane for the Azure Container Apps app - the URecA2.0 DevOps/GitOps pattern adopted
and measured (2026-11-28): the CI column's rollback lane ("이전 이미지는 최신 빌드 시 이전 Tag로"),
the CD column's Blue/Green via revision traffic weights, and "Git 배포 정보 -> sync -> 적용" as a
committed-YAML vs live drift gate.

Verbs (ledger: evidence/deploy_ledger.jsonl, one JSON row per state change):
  record    snapshot the LIVE revisions+traffic+image as one ledger row
  status    live summary + the last ledger rows
  drift     committed containerapp.applied.yaml vs the live app - honest diff, exit gate
            (env var VALUES are never printed, keys only; the whole point is naming drift, not leaking config)
  deploy    blue/green: create a new revision with the image -> flip traffic to it -> smoke /healthz
            (asserts the served K_REVISION equals the new revision) -> promoted or AUTO FLIP-BACK;
            every step and every failure lands in the ledger, nothing silent
  rollback  flip traffic back to the previous promoted revision (still alive under blue/green);
            if it is gone, update with its recorded image instead - the image lane, not a guess
Every az call runs through ``_run()`` (injectable in tests); a failed command is an honest non-zero
exit with its stderr kept, never retried into a pretend success.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

RG = os.environ.get("BTS_AZ_RG", "bts-sbom-rg")
APP = os.environ.get("BTS_AZ_APP", "bts-sbom")
FQDN = os.environ.get("BTS_AZ_FQDN", "")            # live probe target; resolved from `show` when empty
APPLIED_YAML = os.path.join("deploy", "azure", "containerapp.applied.yaml")
LEDGER = os.path.join("evidence", "deploy_ledger.jsonl")
SMOKE_ROUNDS = 6                                     # /healthz reads after a traffic flip
SMOKE_TIMEOUT_S = 40                                 # per request; scale-0 cold start is the long pole
Runner = Callable[[List[str]], Tuple[int, str, str]]


def _run(cmd: List[str]) -> Tuple[int, str, str]:
    """The real runner: az on PATH (Windows needs the resolved .cmd path - CreateProcess does no
    PATHEXT resolution), UTF-8 out. Tests inject a fake here."""
    import shutil
    import subprocess
    argv = list(cmd)
    if argv and argv[0] == "az":
        exe = shutil.which("az") or shutil.which("az.cmd") or shutil.which("az.bat")
        if not exe:
            raise RuntimeError("az not found on PATH - install the Azure CLI or set BTS_AZ_* overrides")
        argv[0] = exe
    p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", timeout=300)
    return p.returncode, p.stdout or "", p.stderr or ""


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_out(out: str) -> Any:
    txt = (out or "").strip()
    try:
        return json.loads(txt)
    except ValueError:
        # az warns on stderr but json comes on stdout; a stray prefix line is tolerated by trimming
        # to the first brace or bracket - lists (revision list) must survive this, not just objects
        starts = [i for i in (txt.find("{"), txt.find("[")) if i >= 0]
        cut = txt[min(starts):] if starts else txt
        try:
            return json.loads(cut)
        except ValueError as exc:
            raise ValueError("az returned non-JSON stdout (%s): %r" % (exc, txt[:200]))


def _az(runner: Runner, args: List[str]) -> Any:
    rc, out, err = runner(["az"] + args + ["-o", "json"])
    if rc != 0:
        raise RuntimeError("az %s failed rc=%d: %s" % (" ".join(args[:4]), rc, (err or out).strip()[-400:]))
    return _json_out(out)


def _append_ledger(row: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    with open(LEDGER, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _read_ledger() -> List[Dict[str, Any]]:
    if not os.path.isfile(LEDGER):
        return []
    rows = []
    for line in open(LEDGER, encoding="utf-8"):
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass                                              # a torn tail line is skipped, honestly
    return rows


def _revisions(runner: Runner) -> List[Dict[str, Any]]:
    revs = _az(runner, ["containerapp", "revision", "list", "-g", RG, "-n", APP])
    if not isinstance(revs, list):
        raise ValueError("revision list did not return a list")
    out = []
    for r in revs:
        props = r.get("properties") or {}
        # the image lives under the revision's own template, not a flat property (measured 2026-11-28)
        tpl = props.get("template") or {}
        conts = tpl.get("containers") or []
        image = (conts[0].get("image") if conts else None) or props.get("image")
        out.append({"name": r.get("name"), "image": image,
                    "traffic": int(props.get("trafficWeight") or 0), "active": bool(props.get("active"))})
    return out


def _distribution(runner: Runner) -> List[Dict[str, Any]]:
    app = _az(runner, ["containerapp", "show", "-g", RG, "-n", APP])
    ingress = (app.get("properties") or {}).get("configuration", {}).get("ingress", {})
    traffic = ingress.get("traffic") or []
    return [{"revision": t.get("revisionName"), "weight": int(t.get("weight") or 0),
             "suffix": t.get("revisionSuffix"), "label": t.get("label")} for t in traffic]


def _set_traffic(runner: Runner, dist: List[Tuple[str, int]]) -> None:
    """Pin weights by revision NAME; az wants --distribution name=weight pairs summing to 100."""
    # measured 2026-11-28: the az extension names this verb SET ("update" is misspelled there);
    # full revision NAMES are accepted by --distribution
    # measured 2026-11-28: the flag is --revision-weight (space-separated name=weight pairs);
    # --distribution does not exist on this verb
    args = ["containerapp", "ingress", "traffic", "set", "-g", RG, "-n", APP,
            "--revision-weight"] + ["%s=%d" % (name, w) for name, w in dist]
    rc, out, err = runner(["az"] + args)
    if rc != 0:
        raise RuntimeError("traffic set failed rc=%d: %s" % (rc, (err or out).strip()[-400:]))


def _http(path: str, timeout: float = SMOKE_TIMEOUT_S) -> Tuple[int, Dict[str, Any]]:
    import urllib.request
    base = FQDN or ""
    if not base:
        raise ValueError("probe target unknown: pass BTS_AZ_FQDN or let `show` resolve it")
    url = base.rstrip("/") + path
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, json.loads(r.read().decode("utf-8"))


def _suffix(kind: str) -> str:
    return "%s%s" % (kind, datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S"))


# ── verbs ────────────────────────────────────────────────────────────────────

def cmd_record(runner: Runner) -> int:
    revs = _revisions(runner)
    dist = _distribution(runner)
    live = [r for r in revs if r["traffic"] > 0]
    row = {"ts": _now(), "event": "record", "resource_group": RG, "app": APP,
           "revisions": sorted(revs, key=lambda r: -(r["traffic"])),
           "distribution": dist, "promoted_image": (live[0]["image"] if live else None)}
    _append_ledger(row)
    print(json.dumps({"recorded": True, "promoted_image": row["promoted_image"],
                      "revisions": [r["name"] for r in row["revisions"]]}, ensure_ascii=False))
    return 0


def cmd_status(runner: Runner) -> int:
    revs = _revisions(runner)
    rows = _read_ledger()
    for r in revs:
        print("%-28s %3d%%  %s  %s" % (r["name"], r["traffic"], "active" if r["active"] else "off", r["image"]))
    print("--- ledger (%d rows, last 5)" % len(rows))
    for row in rows[-5:]:
        print(" %s %-12s %s" % (row.get("ts"), row.get("event"), str(row.get("promoted_image") or row.get("reason") or "")[:90]))
    return 0


# -- drift: committed yaml vs live ------------------------------------------------
def _applied_summary(path: str) -> Dict[str, Any]:
    """The fields that matter, from the committed YAML. YAML parsed by the stdlib-adjacent rule we
    already use in deploy docs: image line + scale + env KEYS via regex (full YAML parsing without
    PyYAML is exactly the kind of pretend we refuse; the applied file is machine-written and stable)."""
    if not os.path.isfile(path):
        raise ValueError("committed applied yaml missing: %s" % path)
    txt = open(path, encoding="utf-8").read()
    img = None
    m = re.search(r"(?m)^\s*-?\s*image:\s*(\S+)\s*$", txt)
    if m:
        img = m.group(1).strip("'\"")
    scale = {}
    for key in ("minReplicas", "maxReplicas"):
        m2 = re.search(r"%s:\s*(\d+)" % key, txt)
        if m2:
            scale[key] = int(m2.group(1))
    env_keys = sorted(set(re.findall(r"(?m)^\s+- name:\s*([A-Za-z_][A-Za-z0-9_]*)\s*$", txt)))
    return {"image": img, "scale": scale, "env_keys": env_keys, "path": path}


def _live_summary(runner: Runner) -> Dict[str, Any]:
    app = _az(runner, ["containerapp", "show", "-g", RG, "-n", APP])
    props = app.get("properties") or {}
    tpl = props.get("template") or {}
    conts = tpl.get("containers") or []
    img = conts[0].get("image") if conts else None
    scale = {k: tpl.get("scale", {}).get(k) for k in ("minReplicas", "maxReplicas")
             if tpl.get("scale", {}).get(k) is not None}
    env_keys = sorted({e.get("name") for e in (conts[0].get("env") or []) if e.get("name")})
    return {"image": img, "scale": scale, "env_keys": env_keys}


def cmd_drift(runner: Runner) -> int:
    committed = _applied_summary(APPLIED_YAML)
    live = _live_summary(runner)
    diffs: List[str] = []
    if committed["image"] != live["image"]:
        diffs.append("image: committed=%s live=%s" % (committed["image"], live["image"]))
    for key in ("minReplicas", "maxReplicas"):
        c, l = committed["scale"].get(key), live["scale"].get(key)
        if c != l:
            diffs.append("scale.%s: committed=%s live=%s" % (key, c, l))
    only_c = [k for k in committed["env_keys"] if k not in live["env_keys"]]
    only_l = [k for k in live["env_keys"] if k not in committed["env_keys"]]
    if only_c:
        diffs.append("env keys only in committed yaml: %s" % ", ".join(only_c))
    if only_l:
        diffs.append("env keys only in live: %s" % ", ".join(only_l))
    if diffs:
        print("DRIFT (%d):" % len(diffs))
        for d in diffs:
            print("  - " + d)
        _append_ledger({"ts": _now(), "event": "drift", "app": APP, "diffs": diffs})
        return 1
    print("no drift: committed applied yaml matches the live app (image, scale, env keys)")
    return 0


# -- deploy / rollback: the blue/green + rollback lanes --------------------------
WARMUP_ROUNDS = 2                                    # a scale-0 revision cold-starts; timeouts here are not
                                                     # a wrong-revision verdict, but a WRONG revision always is


def _smoke(expect_revision: str) -> Dict[str, Any]:
    seen, fails, wrong = [], [], []
    for i in range(SMOKE_ROUNDS):
        try:
            code, body = _http("/healthz")
            seen.append(body.get("revision"))
            if code != 200 or body.get("revision") != expect_revision:
                fail = "round %d: %s from revision %r" % (i, code, body.get("revision"))
                fails.append(fail)
                wrong.append(fail)                             # an answer from another revision can never warm up
        except Exception as exc:                              # noqa: BLE001 - the smoke IS the observation
            fails.append("round %d: %s" % (i, str(exc)[:120]))  # warm-up timeout, retried by the next round
        time.sleep(2)
    good = sum(1 for r in seen if r == expect_revision)
    ok = not wrong and good >= (SMOKE_ROUNDS - WARMUP_ROUNDS)
    return {"expect": expect_revision, "seen": seen, "failures": fails, "good": good, "ok": ok}


def cmd_deploy(runner: Runner, image: str, no_flip: bool = False) -> int:
    revs = _revisions(runner)
    serving = [r for r in revs if r["traffic"] > 0]
    if not serving:
        print("refused: no serving revision to blue/green from", file=sys.stderr)
        return 2
    current = serving[0]
    sfx = _suffix("bg")
    print("blue/green: %s -> %s (new revision suffix %s)" % (current["image"], image, sfx))
    rc, out, err = runner(["az", "containerapp", "update", "-g", RG, "-n", APP,
                           "--revision-suffix", sfx, "--image", image])
    if rc != 0:
        _append_ledger({"ts": _now(), "event": "deploy_failed", "reason": "update", "image": image,
                        "stderr": (err or out).strip()[-300:]})
        print("deploy FAILED at update: %s" % (err or out).strip()[-300:], file=sys.stderr)
        return 1
    # MEASURED (2026-11-28 live): `containerapp update --revision-suffix` MOVES ALL TRAFFIC to the new
    # revision at once - there is no staged-at-0 default. So the pin BACK to blue happens right after
    # the update, then the flip stages green explicitly. A 0%-traffic revision may be deactivated by
    # ACA while it waits; the rollback lane's image path covers exactly that.
    new_rev = "%s--%s" % (APP, sfx)
    try:
        _set_traffic(runner, [(current["name"], 100)])
        _set_traffic(runner, [(current["name"], 0), (new_rev, 100)])
    except Exception as exc:                                  # noqa: BLE001 - a failed flip must be ledgered
        _append_ledger({"ts": _now(), "event": "deploy_failed", "reason": "traffic_flip",
                        "image": image, "revision": new_rev, "previous_image": current["image"],
                        "previous_revision": current["name"], "error": str(exc)[:200]})
        print("deploy FAILED at traffic flip: %s (see ledger; rollback can now act)" % exc, file=sys.stderr)
        return 1
    smoke = _smoke(new_rev)
    if smoke["ok"]:
        row = {"ts": _now(), "event": "promoted", "image": image, "revision": new_rev,
               "previous_image": current["image"], "previous_revision": current["name"],
               "smoke_seen": smoke["seen"]}
        _append_ledger(row)
        print("PROMOTED %s (%s) - previous %s still alive for instant rollback" % (new_rev, image, current["name"]))
        return 0
    # the smoke failed: flip back NOW and record everything (the rollback lane is the point)
    _set_traffic(runner, [(current["name"], 100)])
    row = {"ts": _now(), "event": "auto_rolled_back", "image": image, "revision": new_rev,
           "restored_to": current["name"], "smoke": smoke}
    _append_ledger(row)
    print("SMOKE FAILED - auto flip-back to %s; failures:" % current["name"], file=sys.stderr)
    for f in smoke["failures"][:4]:
        print("   " + f, file=sys.stderr)
    return 1


def cmd_rollback(runner: Runner) -> int:
    rows = [r for r in _read_ledger() if r.get("event") in ("promoted", "auto_rolled_back")]
    if len(rows) < 1:
        print("refused: no promoted row in the ledger to roll back FROM", file=sys.stderr)
        return 2
    last = rows[-1]
    target_image = last.get("previous_image")
    target_rev = last.get("previous_revision")
    if not target_image:
        print("refused: the last promoted row carries no previous_image", file=sys.stderr)
        return 2
    revs = _revisions(runner)
    rev_names = {r["name"] for r in revs}
    if target_rev and target_rev in rev_names:
        print("rollback lane: previous revision %s is still alive - traffic flip only" % target_rev)
        _set_traffic(runner, [(target_rev, 100)])
    else:
        sfx = _suffix("rb")
        print("rollback lane: previous revision gone - updating with the recorded image %s" % target_image)
        rc, out, err = runner(["az", "containerapp", "update", "-g", RG, "-n", APP,
                               "--revision-suffix", sfx, "--image", target_image])
        if rc != 0:
            _append_ledger({"ts": _now(), "event": "rollback_failed", "reason": "update",
                            "stderr": (err or out).strip()[-300:]})
            print("rollback FAILED at update: %s" % (err or out).strip()[-300:], file=sys.stderr)
            return 1
        target_rev = "%s--%s" % (APP, sfx)
    smoke = _smoke(target_rev)
    row = {"ts": _now(), "event": "rolled_back_to", "revision": target_rev, "image": target_image,
           "smoke_ok": smoke["ok"]}
    _append_ledger(row)
    if smoke["ok"]:
        print("ROLLED BACK to %s (%s)" % (target_rev, target_image))
        return 0
    print("rollback smoke FAILED: %s" % smoke["failures"][:3], file=sys.stderr)
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="GitOps deploy lane (blue/green + rollback + drift gate)")
    ap.add_argument("verb", choices=["record", "status", "drift", "deploy", "rollback"])
    ap.add_argument("--image", help="deploy verb: full image ref (registry/name:tag)")
    args = ap.parse_args(argv)
    if args.verb == "deploy" and not args.image:
        ap.error("deploy needs --image registry/name:tag")
    if args.verb == "record":
        return cmd_record(_run)
    if args.verb == "status":
        return cmd_status(_run)
    if args.verb == "drift":
        return cmd_drift(_run)
    if args.verb == "deploy":
        return cmd_deploy(_run, args.image)
    return cmd_rollback(_run)


if __name__ == "__main__":
    sys.exit(main())
