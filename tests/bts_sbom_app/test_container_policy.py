"""Static policy checks on Dockerfile.bts-sbom-app (lecture 4-1's container hardening rules, scoped to what this
product's image actually needs). These read the Dockerfile's TEXT with regular expressions; they never invoke the
Docker daemon or build an image (see docs/RUNBOOK.md "Delivery State" for why: the daemon is not reachable here)."""
from __future__ import annotations

import os
import re
from typing import List

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOCKERFILE_PATH = os.path.join(ROOT, "Dockerfile.bts-sbom-app")


def _instructions(text: str) -> List[str]:
    """Logical Dockerfile instructions: backslash line continuations joined into one line, comments and blank
    lines dropped - so a regex only ever has to match one instruction's full text at a time."""
    out: List[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        buf = (buf + " " + stripped) if buf else line
        if buf.rstrip().endswith("\\"):
            buf = buf.rstrip()[:-1].rstrip()
            continue
        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _read(path: str = DOCKERFILE_PATH) -> List[str]:
    with open(path, "r", encoding="utf-8") as fh:
        return _instructions(fh.read())


# ---------------------------------------------------------------------------------------------------- policy checks


def check_non_root_numeric_user(instr: List[str]) -> List[str]:
    users = [line for line in instr if re.match(r"^USER\s+", line)]
    problems = []
    if not users:
        return ["no USER instruction (image would run as root by default)"]
    for u in users:
        val = u.split(None, 1)[1].strip()
        if val in ("root", "0"):
            problems.append("USER %r is root" % val)
        elif not re.fullmatch(r"[1-9]\d*", val):
            problems.append("USER %r is not a plain non-root numeric UID" % val)
    return problems


def check_base_image_pinned(instr: List[str]) -> List[str]:
    froms = [line for line in instr if re.match(r"^FROM\s+", line)]
    problems = []
    if not froms:
        return ["no FROM instruction"]
    for f in froms:
        ref = f.split(None, 1)[1].split()[0]
        if ":" not in ref:
            problems.append("%r has no explicit tag (defaults to latest)" % ref)
            continue
        tag = ref.split(":", 1)[1]
        if tag == "latest":
            problems.append("%r uses the latest tag" % ref)
        elif not re.match(r"^\d+\.\d+", tag):
            problems.append("%r tag %r is not pinned to a major.minor version" % (ref, tag))
    return problems


def check_healthcheck(instr: List[str]) -> List[str]:
    hc = [line for line in instr if re.match(r"^HEALTHCHECK\b", line)]
    if not hc:
        return ["no HEALTHCHECK instruction"]
    problems = []
    for h in hc:
        if re.search(r"\bcurl\b", h):
            problems.append("HEALTHCHECK shells out to curl")
        if "/readyz" not in h:
            problems.append("HEALTHCHECK does not call /readyz")
    return problems


_SECRET_NAME = re.compile(r"\b([A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)[A-Za-z0-9_]*)\s*=", re.IGNORECASE)


def check_no_secret_env_or_arg(instr: List[str]) -> List[str]:
    problems = []
    for line in instr:
        if re.match(r"^(ENV|ARG)\s+", line):
            for m in _SECRET_NAME.finditer(line):
                problems.append("%s declares a secret-shaped name %r" % (line.split()[0], m.group(1)))
    return problems


def check_expose_matches_cmd_port(instr: List[str]) -> List[str]:
    exposes = [line for line in instr if re.match(r"^EXPOSE\s+", line)]
    cmds = [line for line in instr if re.match(r"^CMD\s+", line)]
    if not exposes:
        return ["no EXPOSE instruction"]
    if not cmds:
        return ["no CMD instruction"]
    expose_port = exposes[-1].split()[1].split("/")[0]
    cmd_line = cmds[-1]
    m = re.search(r"--port[\"']?\s*,?\s*[\"']?(\d+)", cmd_line)
    if not m:
        return ["CMD does not pass an explicit --port"]
    if m.group(1) != expose_port:
        return ["EXPOSE %s does not match CMD --port %s" % (expose_port, m.group(1))]
    return []


ALL_CHECKS = (check_non_root_numeric_user, check_base_image_pinned, check_healthcheck,
             check_no_secret_env_or_arg, check_expose_matches_cmd_port)


def test_shipped_dockerfile_passes_all_five_policy_rules():
    """AC: BSA-AC-352, BSA-AC-353, BSA-AC-354, BSA-AC-355, BSA-AC-356"""
    instr = _read()
    problems = {fn.__name__: fn(instr) for fn in ALL_CHECKS}
    assert all(not p for p in problems.values()), problems


def test_shipped_dockerfile_has_exactly_one_numeric_non_root_user():
    """AC: BSA-AC-352"""
    instr = _read()
    users = [line for line in instr if re.match(r"^USER\s+", line)]
    assert len(users) == 1
    assert re.fullmatch(r"USER\s+[1-9]\d*", users[0])


@pytest.mark.parametrize("bad_user", ["USER root", "USER 0", "USER nobody"])
def test_rejects_root_or_non_numeric_user(bad_user):
    """AC: BSA-AC-352"""
    assert check_non_root_numeric_user([bad_user])


def test_rejects_missing_user_instruction():
    """AC: BSA-AC-352"""
    assert check_non_root_numeric_user([]) == ["no USER instruction (image would run as root by default)"]


@pytest.mark.parametrize("bad_from", ["FROM python:latest", "FROM python"])
def test_rejects_latest_or_untagged_base_image(bad_from):
    """AC: BSA-AC-353"""
    assert check_base_image_pinned([bad_from])


def test_shipped_dockerfile_pins_a_major_minor_python_tag():
    """AC: BSA-AC-353"""
    instr = _read()
    assert check_base_image_pinned(instr) == []
    froms = [line for line in instr if line.startswith("FROM ")]
    assert any(re.search(r":\d+\.\d+", f) for f in froms)
    assert not any("latest" in f for f in froms)


@pytest.mark.parametrize("bad_instr", [[], ["HEALTHCHECK CMD curl -f http://127.0.0.1:8800/readyz || exit 1"]])
def test_rejects_missing_healthcheck_or_one_using_curl(bad_instr):
    """AC: BSA-AC-354"""
    assert check_healthcheck(bad_instr)


def test_shipped_dockerfile_healthcheck_calls_readyz_without_curl():
    """AC: BSA-AC-354"""
    instr = _read()
    assert check_healthcheck(instr) == []
    hc_text = " ".join(line for line in instr if line.startswith("HEALTHCHECK"))
    assert "curl" not in hc_text and "/readyz" in hc_text and "python" in hc_text


@pytest.mark.parametrize("bad_instr", [
    ["ENV API_KEY=abc123"], ["ARG SECRET_TOKEN=xyz"], ["ENV DB_PASSWORD=hunter2"], ["ARG MY_SECRET=1"],
])
def test_rejects_secret_shaped_env_or_arg_names(bad_instr):
    """AC: BSA-AC-355"""
    assert check_no_secret_env_or_arg(bad_instr)


def test_shipped_dockerfile_has_no_secret_shaped_env_or_arg():
    """AC: BSA-AC-355"""
    instr = _read()
    assert check_no_secret_env_or_arg(instr) == []


def test_rejects_expose_cmd_port_mismatch():
    """AC: BSA-AC-356"""
    problems = check_expose_matches_cmd_port(["EXPOSE 8800", 'CMD ["python", "-m", "bts_sbom_app", "serve", "--port", "9999"]'])
    assert problems and "8800" in problems[0] and "9999" in problems[0]


def test_shipped_dockerfile_expose_matches_cmd_port():
    """AC: BSA-AC-356"""
    instr = _read()
    assert check_expose_matches_cmd_port(instr) == []
    exposes = [line for line in instr if line.startswith("EXPOSE ")]
    assert exposes[-1].split()[1].split("/")[0] == "8800"
