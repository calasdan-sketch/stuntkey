"""`stuntkey explain`: what happened lately, in a few plain sentences.

It reads the activity log (and the small usage, caps and notice files next to
it) and says: how many calls went through and to which service, how many were
blocked and why, how today's use compares with the limits, whether `panic` or
`stop` was used, and which saved keys have not been used for 30 days.

Changes no log, key or setting (it only makes the empty usage folder if it is
missing). Never prints a key: the activity log holds none, and only service
names and counts are used here. A damaged or empty log is said in words, not a
crash.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

UNUSED_DAYS = 30
MAX_SENTENCES = 10
MAX_LINES = 200_000          # newest lines read from a huge log

_REASONS = {
    "refused": "refused by your rules (a service, method or address that is not allowed)",
    "denied": "turned down in the permission window",
    "refused-wrong-placeholder": "tried with a wrong or missing stand-in password",
    "network-error": "stopped by a network problem",
}


def parse_since(text, default_days: int = 7) -> float:
    """"7d", "24h", "2w", "90m" or a bare number of days -> seconds. Raises
    ValueError (with a plain message) for anything else."""
    if text is None or str(text).strip() == "":
        return default_days * 86400.0
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*", str(text).lower())
    if not m or float(m.group(1)) <= 0:
        raise ValueError("--since wants a length of time such as 7d, 24h or 2w")
    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800, "": 86400}[m.group(2)]
    return float(m.group(1)) * unit


def read_entries(path: str) -> tuple:
    """([entry dicts], number of lines that could not be read). A missing file
    is an empty list. Only the newest MAX_LINES lines are read."""
    entries, bad = [], 0
    try:
        with open(path, "rb") as f:
            lines = f.read().splitlines()[-MAX_LINES:]
    except OSError:
        return [], 0
    for raw in lines:
        if not raw.strip():
            continue
        try:
            e = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            bad += 1
            continue
        if isinstance(e, dict):
            entries.append(e)
        else:
            bad += 1
    return entries, bad


def _name(x) -> str:
    from . import recipes as recipes_mod
    return recipes_mod.printable(str(x))[:40]


def _ts(e) -> float | None:
    v = e.get("ts")
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v)


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _panic_events(since_ts: float, now: float) -> list:
    """Services where `stuntkey panic` left a note inside the window."""
    import datetime
    found = []
    try:
        from . import ledger
        projects = ledger.load(resign=False)
    except Exception:               # noqa: BLE001 - the notes are a convenience
        return []
    for services in projects.values():
        if not isinstance(services, dict):
            continue
        for service, entry in services.items():
            events = entry.get("events") if isinstance(entry, dict) else None
            for ev in events if isinstance(events, list) else []:
                try:
                    if "panic" not in str(ev.get("step", "")).lower():
                        continue
                    when = datetime.datetime.fromisoformat(ev["at"]).timestamp()
                except (AttributeError, KeyError, TypeError, ValueError):
                    continue
                if since_ts <= when <= now and service not in found:
                    found.append(service)
    return found


def _usage_today(home: str, services: list) -> list:
    """[(service, calls today, call cap per day, tokens today, token cap or 0)]."""
    out = []
    try:
        from . import caps
    except Exception:               # noqa: BLE001
        return out
    for s in services:
        try:
            u = caps.usage(home, s)
            eff = caps.effective_caps(home, s)
        except Exception:           # noqa: BLE001 - a damaged usage file is not the answer here
            continue
        out.append((s, u.get("calls", 0), eff.get("calls_day", 0),
                    u.get("tokens", 0), eff.get("tokens_day", 0)))
    return out


def explain(home: str, since_seconds: float, now: float | None = None,
            saved: list | None = None, log_name: str = "audit.log") -> dict:
    """{"sentences": [...], "calls": n, "blocked": n, "window_days": x}."""
    now = time.time() if now is None else now
    since_ts = now - since_seconds
    entries, bad = read_entries(os.path.join(home, log_name))
    real = [e for e in entries if e.get("service")]
    window = [e for e in real if (_ts(e) or 0) >= since_ts]
    days = since_seconds / 86400.0
    span = (f"the last {int(days)} day{'s' if int(days) != 1 else ''}" if days >= 1
            and abs(days - round(days)) < 0.01 else
            f"the last {max(1, round(since_seconds / 3600))} hours")
    s: list = []
    ok = [e for e in window if e.get("result") == "ok"]
    blocked = [e for e in window if e.get("result") != "ok"]

    # 1 and 2: calls and services
    if not entries and not bad:
        s.append("Nothing has gone through stuntkey yet: the activity log is empty or "
                 "missing, so no AI has used a key this way.")
    elif not window:
        s.append(f"No call went through stuntkey in {span}.")
    else:
        s.append(f"{_plural(len(window), 'call')} went through stuntkey in {span}"
                 f" ({len(ok)} worked).")
        per: dict = {}
        for e in window:
            per[_name(e.get("service"))] = per.get(_name(e.get("service")), 0) + 1
        top = sorted(per.items(), key=lambda kv: (-kv[1], kv[0]))
        shown = ", ".join(f"{n}: {c}" for n, c in top[:5])
        s.append("Calls per service: " + shown + (f" (and {len(top) - 5} more)"
                                                    if len(top) > 5 else "") + ".")

    # 3: blocked and why
    if blocked:
        why: dict = {}
        for e in blocked:
            r = str(e.get("result", "unknown"))
            why[r] = why.get(r, 0) + 1
        parts = [f"{c} {_REASONS.get(r, _name(r))}" for r, c in
                 sorted(why.items(), key=lambda kv: (-kv[1], kv[0]))[:4]]
        s.append(f"{_plural(len(blocked), 'call was', 'calls were')} blocked: "
                 + "; ".join(parts) + ".")
    elif window:
        s.append("No call was blocked.")

    # 4: spend against the caps
    services_today = sorted({_name(e.get("service")) for e in real})
    use = _usage_today(home, services_today)
    lines = []
    for name, calls, cap, tokens, tcap in use:
        if not calls and not tokens:
            continue
        piece = f"{name} used {calls} of {cap} calls" if cap else f"{name} used {calls} calls"
        if tcap:
            piece += f" and {tokens} of {tcap} tokens"
        lines.append(piece)
    if lines:
        s.append("Today against the limits: " + "; ".join(lines[:5]) + ".")
    elif real:
        s.append("Today nothing has been used yet, so nothing is near a limit.")

    # 5: panic and stop
    panics = _panic_events(since_ts, now)
    if panics:
        s.append("You used `stuntkey panic` for " + ", ".join(_name(p) for p in panics[:5])
                 + f" in {span}.")
    else:
        s.append(f"No panic was used in {span}.")
    try:
        from . import caps
        if os.path.lexists(caps.stop_path(home)):
            s.append("stuntkey is STOPPED right now: no call goes through until you run "
                     "`stuntkey resume`.")
    except Exception:               # noqa: BLE001
        pass

    # 6: keys not used for 30 days
    if saved is None:
        try:
            from . import fixcmd
            saved = list(fixcmd.key_places_full(None, "")["safe"])
        except Exception:           # noqa: BLE001
            saved = []
    last_use: dict = {}
    for e in real:
        t = _ts(e)
        if t is not None:
            n = _name(e.get("service"))
            last_use[n] = max(last_use.get(n, 0), t)
    cutoff = now - UNUSED_DAYS * 86400
    try:                            # a key saved only a few days ago is not "unused for 30 days"
        from . import age as age_mod
        from . import ledger
        import datetime
        ages = age_mod._newest_ages(
            ledger.load(resign=False),
            datetime.datetime.fromtimestamp(now, datetime.timezone.utc))
    except Exception:               # noqa: BLE001 - no age known: judge by the log alone
        ages = {}
    stale = [_name(k) for k in sorted(saved)
             if last_use.get(_name(k), 0) < cutoff
             and not (ages.get(k) is not None and ages[k] < UNUSED_DAYS)]
    if saved:
        if stale:
            s.append(f"{_plural(len(stale), 'saved key')} not used through stuntkey for "
                     f"{UNUSED_DAYS} days: " + ", ".join(stale[:6])
                     + (" ..." if len(stale) > 6 else "")
                     + ". An unused key is a risk for nothing: consider `stuntkey forget <service>`.")
        else:
            s.append(f"No saved key has sat unused for {UNUSED_DAYS} days.")

    # 7: the log's own health
    problems = [e for e in entries if e.get("result") in ("LOG-PROBLEM-FOUND", "CHAIN-UNKEYED")]
    if bad or problems:
        s.append("The activity log has damaged or flagged lines"
                 + (f" ({bad} could not be read)" if bad else "")
                 + ", so run `stuntkey audit` to check it.")
    return {"sentences": s[:MAX_SENTENCES], "calls": len(window), "blocked": len(blocked),
            "window_days": round(days, 2)}


def cmd_explain(args, home: str | None = None, out=None, now=None, saved=None) -> int:
    out = out or sys.stdout
    try:
        seconds = parse_since(getattr(args, "since", None))
    except ValueError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2
    if home is None:
        from . import remote
        home = remote.home_dir()
    data = explain(home, seconds, now=now, saved=saved)
    if getattr(args, "json", False):
        out.write(json.dumps(data, indent=2) + "\n")
    else:
        out.write("\n" + "\n".join("  " + x for x in data["sentences"]) + "\n")
    return 0
