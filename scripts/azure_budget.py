"""Azure cost-safety budget command (BSA-AC-1192): print, never run, an `az consumption budget create` line.

Course rule (bundle C37, 과제4/5_가이드.html.txt 09 "비용 안전 수칙"): a redeploy carries 3 governance tags
(team/week/owner - see deploy/azure/containerapp.yaml) and a cost budget with notifications at 50/80/100
percent of the monthly amount. This script only COMPUTES and PRINTS the exact `az consumption budget
create` command line for a human to review and run themselves; it has no code path that invokes `az` or
any network call, by design (a budget is a billing side effect - this repo's tooling never takes one on
its own authority). `--dry-run` is required for exactly that reason: it documents, in the invocation
itself, that nothing is executed.

IMPORTANT (fixes a confirmed defect): the printed, copy-pasteable `az consumption budget create` line
below uses ONLY the flags that command genuinely accepts. Verified directly against the INSTALLED az CLI
(azure-cli 2.93.0) via `az consumption budget create --help` on 2026-11-26: the full argument list is
--amount, --budget-name, --category, --end-date/-e, --start-date/-s, --time-grain, --meter-filter,
--resource-filter, --resource-group/-g, --resource-group-filter (plus global args). There is NO
--notifications flag and NO --tags flag on this command - `az costmanagement budget create` was also
checked and is not usable here without installing an extension (this script deliberately never installs
one). So the 50/80/100 percent alert thresholds and the 3 governance tags - required by the course but
not expressible on this az CLI's budget-create line - are never put into the executable argv; they are
printed separately below as clearly-labelled, non-executable follow-up guidance (comment lines, inert to
a shell) instead. AZ_CONSUMPTION_BUDGET_CREATE_FLAGS is the verified whitelist; a test asserts every flag
in the generated argv is a member, so an unsupported flag can never silently creep back onto the
executable line.

Usage:  python scripts/azure_budget.py --dry-run --resource-group bts-sbom-rg --amount 80 \
            --team bts-sbom --week 2026-W48 --owner ops@example.invalid
"""
from __future__ import annotations

import argparse
import shlex
from typing import Dict, List, Optional

# The 3 required governance tag keys (course: "태그3종: team/week/owner"). Kept here as the single source of
# truth; deploy/azure/containerapp.yaml's `tags:` block and tests/bts_sbom_app/test_azure_redeploy.py both
# key off this tuple so the three names can never drift apart silently.
REQUIRED_TAGS = ("team", "week", "owner")

# The 3 required notification thresholds, percent of the monthly budget amount (course: "예산경보 50/80/100%").
THRESHOLDS_PERCENT = (50, 80, 100)

DEFAULT_BUDGET_NAME = "bts-sbom-monthly-budget"
DEFAULT_TIME_GRAIN = "Monthly"

# az CLI version this whitelist was verified against (`az version`).
AZ_CLI_VERSION_VERIFIED = "2.93.0"

# The exact flag names the INSTALLED `az consumption budget create` accepts (transcribed from
# `az consumption budget create --help`, azure-cli 2.93.0, 2026-11-26). Anything not in this set must
# never appear in the argv budget_command() returns - see test_azure_redeploy.py's whitelist assertion.
AZ_CONSUMPTION_BUDGET_CREATE_FLAGS = frozenset({
    "--resource-group", "--budget-name", "--amount", "--time-grain", "--start-date", "--end-date", "--category",
})


def budget_command(resource_group: str, amount: float, tags: Dict[str, str], *, budget_name: str = DEFAULT_BUDGET_NAME,
                    time_grain: str = DEFAULT_TIME_GRAIN, start_date: str = "<YYYY-MM-01>", end_date: str = "<YYYY-MM-01, +10 years>",
                    contact_email: str = "<OWNER_EMAIL>") -> List[str]:
    """The `az consumption budget create` argv (never executed - see module docstring), using ONLY flags in
    AZ_CONSUMPTION_BUDGET_CREATE_FLAGS. Raises ValueError when a required tag key is missing or empty, so a
    caller cannot silently print a non-compliant command (the tags themselves ride in the follow-up
    guidance, not this argv - see notification_followup_lines/tags_followup_lines)."""
    missing = [k for k in REQUIRED_TAGS if not (tags.get(k) or "").strip()]
    if missing:
        raise ValueError("missing required governance tag(s): %s" % ", ".join(missing))
    cmd = [
        "az", "consumption", "budget", "create",
        "--resource-group", resource_group,
        "--budget-name", budget_name,
        "--amount", str(amount),
        "--time-grain", time_grain,
        "--start-date", start_date,
        "--end-date", end_date,
        "--category", "Cost",
    ]
    used_flags = {c for c in cmd if c.startswith("--")}
    assert used_flags <= AZ_CONSUMPTION_BUDGET_CREATE_FLAGS, "unverified flag(s) in az argv: %s" % (used_flags - AZ_CONSUMPTION_BUDGET_CREATE_FLAGS)
    return cmd


def notification_followup_lines(thresholds_percent=THRESHOLDS_PERCENT, contact_email: str = "<OWNER_EMAIL>") -> List[str]:
    """Non-executable (comment) lines: the installed az CLI's `az consumption budget create` has no
    --notifications flag (verified against azure-cli AZ_CLI_VERSION_VERIFIED - see module docstring), so the
    course-required 50/80/100 percent alert thresholds cannot ride on the executable line above. These are
    guidance only, never part of an argv this script prints as a command to run."""
    pct = "/".join(str(p) + "%" for p in thresholds_percent)
    return [
        "# FOLLOW-UP (manual, NOT executed by the line below): az consumption budget create has no",
        "#   --notifications flag on this az CLI (verified: azure-cli %s, `az consumption budget" % AZ_CLI_VERSION_VERIFIED,
        "#   create --help`; az costmanagement budget create was also checked and needs an extension this",
        "#   script will not install). After the budget above is created, add alert thresholds %s" % pct,
        "#   manually: Azure Portal > Cost Management + Billing > Budgets > <budget-name> > Edit > Alert",
        "#   conditions (recipient: %s)." % contact_email,
    ]


def tags_followup_lines(tags: Dict[str, str]) -> List[str]:
    """Non-executable (comment) lines: az consumption budget create has no --tags flag either (a budget is
    not a taggable resource the way a Container App is), so the 3 governance tags never ride on the
    executable line above. They belong on the Container App resource - see README section 9.1."""
    tag_str = " ".join("%s=%s" % (k, tags[k]) for k in REQUIRED_TAGS)
    return [
        "# governance tags %s are NOT a flag on az consumption budget create (no --tags there either);" % tag_str,
        "#   apply them to the Container App resource instead, e.g.:",
        "#   az containerapp update --resource-group <rg> --name bts-sbom --tags %s" % tag_str,
    ]


def render(cmd: List[str]) -> str:
    """One copy-pastable shell line (shlex-quoted so an odd character in a tag value cannot break the command)."""
    return " ".join(shlex.quote(c) for c in cmd)


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    p.add_argument("--dry-run", action="store_true", help="required: print the command, never run it")
    p.add_argument("--resource-group", default="bts-sbom-rg")
    p.add_argument("--amount", type=float, default=80.0, help="monthly budget amount (matches BTS_SBOM_LLM_DAILY_BUDGET's order of magnitude, course ac-617 era)")
    p.add_argument("--budget-name", default=DEFAULT_BUDGET_NAME)
    p.add_argument("--team", default="bts-sbom")
    p.add_argument("--week", default="<ISO week, e.g. 2026-W48>")
    p.add_argument("--owner", default="<on-call contact: email or chat handle>")
    p.add_argument("--contact-email", default="<OWNER_EMAIL>", help="budget alert recipient (never a secret, just an address)")
    args = p.parse_args(argv)
    if not args.dry_run:
        print("refusing to run: this script only prints the command (pass --dry-run)")
        return 2
    tags = {"team": args.team, "week": args.week, "owner": args.owner}
    try:
        cmd = budget_command(args.resource_group, args.amount, tags, budget_name=args.budget_name, contact_email=args.contact_email)
    except ValueError as exc:
        print("error: %s" % exc)
        return 2
    print("# dry-run only - nothing below is executed")
    for line in tags_followup_lines(tags):
        print(line)
    for line in notification_followup_lines(THRESHOLDS_PERCENT, args.contact_email):
        print(line)
    print("# executable line (verified flags only - see AZ_CONSUMPTION_BUDGET_CREATE_FLAGS):")
    print(render(cmd))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
