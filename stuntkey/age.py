"""`stuntkey age`: how old is each saved key, and which are worth replacing.

The dates come from the small record stuntkey already keeps (ledger.py: when a
key was added or last replaced). It holds no key and no part of a key. A key
that has no record (added before stuntkey kept dates) is said to have an
"unknown age" - never guessed.

Nothing here prints a key. No network.
"""
from __future__ import annotations

import json
import os
import sys

DEFAULT_WARN = 90
WARN_VAR = "STUNTKEY_AGE_WARN"


def warn_days(given=None, environ=None) -> int:
    """The age, in days, after which a key is called old: --warn, else the
    STUNTKEY_AGE_WARN setting, else 90. Anything that is not a number of 1 or
    more means the default."""
    for raw in (given, (environ if environ is not None else os.environ).get(WARN_VAR)):
        if raw is None or raw == "":
            continue
        try:
            n = int(str(raw).strip())
        except (TypeError, ValueError):
            continue
        if n >= 1:
            return n
    return DEFAULT_WARN


def _newest_ages(projects: dict, now=None) -> dict:
    """{service: age in days} using the most recent record across every
    project folder (a key kept in the keychain is shared by all of them)."""
    from . import ledger
    best: dict = {}
    for services in (projects or {}).values():
        if not isinstance(services, dict):
            continue
        for service, entry in services.items():
            if not isinstance(entry, dict):
                continue
            age = ledger.age_days(entry, now)
            if age is None:
                continue
            if service not in best or age < best[service]:
                best[service] = age
    return best


def collect(catalog: dict | None = None, warn: int | None = None, now=None,
            projects: dict | None = None, saved: list | None = None) -> dict:
    """{"warn_days", "keys": [{"service", "age_days" (None = unknown), "old"}],
    "old": [services]}. `projects` and `saved` are for tests."""
    from . import fixcmd, ledger
    from . import recipes as recipes_mod
    warn = warn_days(warn)
    if saved is None:
        try:
            saved = list(fixcmd.key_places_full(catalog, "")["safe"])
        except Exception:           # noqa: BLE001 - an unreadable keychain means no list
            saved = []
    if projects is None:
        try:
            projects = ledger.load(resign=False)
        except Exception:           # noqa: BLE001
            projects = {}
    ages = _newest_ages(projects, now)
    keys = []
    for service in sorted(saved):
        age = ages.get(service)
        keys.append({"service": recipes_mod.printable(service), "age_days": age,
                     "old": age is not None and age >= warn})
    return {"warn_days": warn, "keys": keys,
            "old": [k["service"] for k in keys if k["old"]]}


def old_count(catalog: dict | None = None, warn: int | None = None) -> int:
    try:
        return len(collect(catalog, warn)["old"])
    except Exception:               # noqa: BLE001 - a status line must never fail
        return 0


def status_line(catalog: dict | None = None, warn: int | None = None) -> str:
    """For `stuntkey status`: "" when no key is old."""
    try:
        data = collect(catalog, warn)
    except Exception:               # noqa: BLE001
        return ""
    n = len(data["old"])
    if not n:
        return ""
    return (f"{n} key{'s' if n != 1 else ''} older than {data['warn_days']} days: "
            + ", ".join(data["old"][:6]) + (" ..." if n > 6 else "")
            + ". `stuntkey age` lists them.")


def render(data: dict) -> str:
    warn = data["warn_days"]
    keys = data["keys"]
    lines = [""]
    if not keys:
        lines.append("  No key is saved in your keychain yet, so there is nothing to age.")
        lines.append("  `stuntkey get github` adds one.")
        return "\n".join(lines) + "\n"
    lines.append(f"  How old your saved keys are (older than {warn} days is worth replacing):")
    for k in keys:
        if k["age_days"] is None:
            when = "unknown age (added before stuntkey kept dates)"
        else:
            when = f"{k['age_days']} day{'s' if k['age_days'] != 1 else ''}"
            if k["old"]:
                when += "  <- older than the limit"
        lines.append(f"    {k['service']:<18} {when}")
    if data["old"]:
        n = len(data["old"])
        lines.append("")
        lines.append(f"  {n} key{'s are' if n != 1 else ' is'} older than {warn} days. "
                     "Replace one with `stuntkey rotate <service>` "
                     "(or `stuntkey panic <service>` if it may have leaked).")
    else:
        unknown = sum(1 for k in keys if k["age_days"] is None)
        lines.append("")
        lines.append("  No key is older than the limit."
                     + (f" {unknown} have no date, so I cannot say." if unknown else ""))
    return "\n".join(lines) + "\n"


def cmd_age(args, catalog: dict | None = None, out=None, **kw) -> int:
    out = out or sys.stdout
    warn = warn_days(getattr(args, "warn", None))
    data = collect(catalog, warn, **kw)
    if getattr(args, "json", False):
        out.write(json.dumps(data, indent=2) + "\n")
    else:
        out.write(render(data))
    return 0
