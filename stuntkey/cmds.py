"""Command-line doors onto the broker: status, call, audit, serve, start.

Exit codes (stable, for scripts and AIs): 0 ok, 1 problem, 2 bad usage,
3 not found, 5 refused by policy, 7 network.
"""
from __future__ import annotations

import json
import os
import sys

from . import broker
from . import approve as approve_mod
from . import recipes as recipes_mod

OK, PROBLEM, USAGE, NOT_FOUND, POLICY, NETWORK = 0, 1, 2, 3, 5, 7


def _home() -> str:
    from . import remote
    return remote.home_dir()


def _have_key(recipe: dict, env_file: str) -> bool:
    from . import remote
    try:
        remote.collect_values(recipe, env_file)
        return True
    except remote.RemoteError:
        return False


def _emit(obj, as_json: bool, text: str) -> None:
    print(json.dumps(obj, indent=2) if as_json else text)


from .logfacts import BIG_LOG_ENTRIES, log_facts, log_lines  # noqa: E402,F401  (leaf module)


# ---- status ---------------------------------------------------------------------

def _next_step() -> str:
    """The same advice `status` and `fix` give. Where `fix` cannot plug stuntkey
    into Claude Code (no `claude` program), the exact command is shown here, not
    "run fix" (which would only print it)."""
    try:
        from . import claudecode
        if claudecode.detected() and claudecode.state() != "ok" and claudecode.cli_path() is None:
            return ("  Next: for Claude Code, type this one command: "
                    + claudecode.one_command()
                    + "\n        (`stuntkey setup` does the rest.)")
    except Exception:           # noqa: BLE001 - advice only
        pass
    return "  Next: `stuntkey setup` to switch it on in your AI app, or `stuntkey status` to check."


def cmd_status(catalog: dict, env_file: str, as_json: bool) -> int:
    from . import fixcmd
    # Only keys really in the keychain count as stored. A key found only in a
    # .env file (not protected) is said separately; an example value there
    # (sk-xxxx, your_key_here) is not a key at all.
    safe, loose = fixcmd.key_places(catalog, env_file)
    alog = broker.AuditLog(os.path.join(_home(), "audit.log"))
    ok, n = alog.verify()
    warn = alog.describe()
    facts = log_facts(alog)
    info = {"python": sys.version.split()[0], "services": len(catalog),
            "with_keys": len(safe),
            "audit_log_ok": ok, "audit_entries": n,
            "connected": safe, "env_file_only": loose,
            "audit_bytes": facts["bytes"], "audit_last_write": facts["last_write"]}
    # ONE state for status, overview, doctor and test (fixcmd.state): the same
    # checks, so the words here can never disagree with `stuntkey status`.
    try:
        items = fixcmd.collect(catalog, env_file=env_file)
        state_name, state_words = fixcmd.state(items)
        first_open = next((i for i in sorted(items, key=lambda i: i.level != fixcmd.RED)
                           if i.level != fixcmd.GREEN), None)
    except Exception:           # noqa: BLE001 - the overview must still answer
        state_name, state_words, first_open = (fixcmd.ATTENTION if not info["with_keys"]
                                               else fixcmd.READY), "", None
    info["state"] = state_name
    if state_name == fixcmd.READY:
        head = "stuntkey is ready."
    elif not info["with_keys"] and state_name == fixcmd.ALMOST:
        head = "Not ready yet: no key is saved in your keychain."
    elif state_name == fixcmd.ALMOST:
        head = f"Almost ready: {state_words}."
    else:
        head = f"Not ready yet: needs attention ({state_words or 'run `stuntkey status`'})."
    if first_open is not None and state_name != fixcmd.READY \
            and not (not info["with_keys"] and first_open.key == "keys"):
        info["first_open"] = first_open.text
        head += f"\n  First: {recipes_mod.printable(first_open.text)}"
    text = (f"{head}\n"
            f"  services known: {info['services']}   with a key stored in the keychain: "
            f"{info['with_keys']}\n"
            f"  connected: {', '.join(info['connected']) or 'none yet'}\n"
            + (f"  found only in a .env file, not protected: {', '.join(loose)}"
               " (`stuntkey setup` moves them into the keychain)\n" if loose else "")
            +
            f"  activity log: {'intact' if ok else 'check FAILED - run `stuntkey audit show`'} "
            f"({n} entries)")
    extra = log_lines(facts)
    if extra:
        text += "\n" + extra
    if warn:
        text += f"\n  {warn}"
        info["audit_note"] = warn
    if not info["with_keys"]:
        nxt = "  Next: `stuntkey get <service>` to connect a key, or `stuntkey try` to practise."
    elif state_name != fixcmd.READY and first_open is not None and first_open.step:
        nxt = "  Next: " + recipes_mod.printable(first_open.step)
    else:
        nxt = _next_step()
    text += "\n" + nxt
    stale = fixcmd.stale_program_warning()
    if stale and not as_json:
        text += "\n  Note: " + stale
    _emit(info, as_json, text)
    return OK if ok else PROBLEM


# ---- asking the person (call, resume) ----------------------------------------------

WINDOW_NOTICE = "A permission window has opened - look for it (or type the code here)."


def _say(text: str) -> None:
    try:
        print(text, file=sys.stderr, flush=True)
    except (OSError, ValueError):
        pass


def ask_with_notice(summary: str, ask=None, say=None, wait=None, grace: int = 5) -> bool:
    """Ask the person, but never in silence and never forever: first say that a
    window has opened, then wait at most the time the approval window itself
    allows (STUNTKEY_APPROVE_TIMEOUT, read by approve.py) and treat no answer
    as no. `ask`, `say` and `wait` are for tests."""
    import threading
    ask = ask or approve_mod.ask_person
    say = say or _say
    limit = approve_mod.timeout_seconds() if wait is None else wait
    say(WINDOW_NOTICE)
    box: dict = {}

    def run():
        try:
            box["answer"] = bool(ask(summary))
        except BaseException:       # noqa: BLE001 - any failure to ask means no
            box["answer"] = False

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(limit + grace)           # approve.py's own wait ends first; this is the backstop
    if t.is_alive():
        say(f"No answer in {limit} seconds, so the answer is no. Nothing was done.")
        return False
    return bool(box.get("answer"))


def cmd_resume(args=None, home: str | None = None, ask=None, interactive=None) -> int:
    """`stuntkey resume`: allow calls again after `stuntkey stop`. A window asks
    first. --yes skips that question ONLY when you typed the command in a real
    terminal; from a script or an AI's shell a window still decides, so an AI
    cannot switch the kill switch off on its own."""
    from . import caps
    home = home or _home()
    chooser = ask
    if getattr(args, "yes", False) and ask is None:
        if interactive is None:
            from . import safeprompt
            interactive = safeprompt.stdin_is_terminal()
        if interactive:
            chooser = lambda _summary: True      # noqa: E731
        else:
            _say("--yes only works when you type this in a terminal window yourself; "
                 "here a permission window decides instead.")
    try:
        return caps.cmd_resume(home, chooser or ask_with_notice)
    except broker.BrokerError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code


# ---- call -----------------------------------------------------------------------

def cmd_call(recipe: dict, args) -> int:
    from . import remote
    word = str(args.method or "")
    if word.upper() not in broker.READ_METHODS | broker.WRITE_METHODS:
        from .recipes import printable
        print(f"{printable(word).upper()} is not a method I know. "
              "Use GET, POST, PUT, PATCH or DELETE.", file=sys.stderr)
        return USAGE
    query = {}
    for item in args.query or []:
        k, sep, v = item.partition("=")
        if not sep:
            print("error: --query needs name=value, for example --query page=2", file=sys.stderr)
            return USAGE
        query[k] = v
    body = None
    if args.data:
        try:
            body = json.loads(args.data)
        except ValueError:
            print("error: --data is not valid JSON (a typing mistake in the braces or quotes). Example: --data '{\"name\": \"x\"}'", file=sys.stderr)
            return USAGE
    policy = broker.Policy(allow_write=False, approve=ask_with_notice)
    audit = broker.AuditLog(os.path.join(_home(), "audit.log"))
    try:
        values = remote.collect_values(recipe, args.env_file)
        out = broker.call(recipe, values, args.method, args.path, query or None,
                          body, policy=policy, audit=audit)
    except remote.RemoteError:
        print(f"error: no key stored for '{recipe['service']}'. Run "
              f"`stuntkey get {recipe['service']}` first.", file=sys.stderr)
        return NOT_FOUND
    except broker.BrokerError as e:
        print(f"error: {e}", file=sys.stderr)
        return e.code if e.code in (POLICY, NETWORK) else PROBLEM
    if args.json:
        print(json.dumps(out, separators=(",", ":")))
    else:
        print(f"[{out['status']}]")
        print(str(out["body"]).strip("\r\n"))
    if out["status"] in (401, 403):
        # one plain next step (to stderr, so a script reading the output is not disturbed)
        print(f"The key was rejected. Run `stuntkey rotate {recipe['service']}`.", file=sys.stderr)
    return OK if out["status"] < 400 else PROBLEM


# ---- audit ----------------------------------------------------------------------

def cmd_audit(action: str, as_json: bool, last: int = 20, warden: bool = False,
              since: str | None = None, out_path: str | None = None) -> int:
    log = broker.AuditLog(os.path.join(_home(), "audit.log"))
    if action == "export":
        from . import wardenfeed
        if not warden:
            print("error: say which format: `stuntkey audit export --warden`.", file=sys.stderr)
            return USAGE
        target = out_path or os.path.join(_home(), wardenfeed.FEED_NAME)
        try:
            n = wardenfeed.export(log.path, target, since)
        except wardenfeed.FeedError as e:
            print(f"error: {e}", file=sys.stderr)
            return USAGE if "--since" in str(e) else PROBLEM
        intact, _n = log.verify()
        _emit({"written": target, "events": n, "log_intact": intact}, as_json,
              f"wrote {n} lines to {target} and {wardenfeed.planok_path(target)} (shaped for "
              "warden's `report --from mcp-jail|planok --file`; not tried against a live "
              "warden). The activity log was only read, not changed."
              + ("" if intact else "\nWARNING: the activity log does not check out "
                 "(run `stuntkey audit`); this copy may be false."))
        return OK
    if action == "reset":
        try:
            kept = log.reset()
        except broker.BrokerError as e:
            print(f"error: {e}", file=sys.stderr)
            return PROBLEM
        print("started a fresh activity log." +
              (f" The old one was kept as {kept}" if kept else ""))
        return OK
    if action == "show":
        import time as _t
        intact, _n = log.verify()
        if not intact and not as_json:
            print("WARNING: the activity log does not check out - entries may "
                  "have been edited, cut off or deleted. What follows may be "
                  "false.\n")
        rows = []
        try:
            with open(log.path, "rb") as f:
                for line in f.read().splitlines()[-max(1, last):]:
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass
        except OSError:
            pass
        if as_json:
            print(json.dumps({"intact": intact,
                              "problem": None if intact else
                              (log.broken_reason() or "the log does not check out"),
                              "entries": rows}, indent=2))
        elif not rows:
            print("nothing yet - no AI has used a key through stuntkey.")
        for e in ([] if as_json else rows):
            when = _t.strftime("%Y-%m-%d %H:%M", _t.localtime(e.get("ts", 0)))
            c = broker._clean
            print(f"{when}  {c(e.get('service'))}  {c(e.get('method'), 10)} "
                  f"{c(e.get('host'))}{c(e.get('path'))}  -> {c(e.get('status'), 6)} "
                  f"({c(e.get('result'), 20)})")
        return OK if intact else PROBLEM
    ok, n = log.verify()
    why = "" if ok else f" - {log.broken_reason() or 'the log does not check out'}"
    note = log.describe()
    _emit({"intact": ok, "entries": n, **({"note": note} if note else {})}, as_json,
          f"activity log: {'intact' if ok else 'TAMPERED'} ({n} entries){why}"
          + (f"\n{note}" if note else ""))
    return OK if ok else PROBLEM


# ---- serve (local web door) ---------------------------------------------------

def cmd_serve(catalog: dict, port: int, env_file: str) -> int:
    from . import httpd, remote
    tokfile = os.path.join(_home(), "http.token")
    token = httpd.load_or_make_token(tokfile)
    policy = broker.Policy(approve=approve_mod.ask_person)
    audit = broker.AuditLog(os.path.join(_home(), "audit.log"))
    import stuntkey

    def page_status() -> dict:
        # names only, never a key or the token
        return {"keys": [{"name": r.get("display") or s}
                         for s, r in sorted(catalog.items()) if _have_key(r, env_file)],
                "practice_cmd": "stuntkey try"}
    try:
        srv = httpd.make_server(catalog, lambda r: remote.collect_values(r, env_file),
                                token, policy, audit, port=port,
                                page_status=page_status, version=stuntkey.__version__)
    except httpd.PortBusy as e:
        print(str(e), flush=True)
        return 1
    p = srv.server_address[1]
    print(f"stuntkey web door is open at http://127.0.0.1:{p}\n"
          f"  Your page (one-time link, works once, for 2 minutes):\n"
          f"    http://127.0.0.1:{p}/?c={srv.new_launch_code()}\n"
          f"  token file (keep private): {tokfile}\n"
          f"  AIs send:  Authorization: Bearer <token>   GET /tools   POST /call\n"
          f"  Only this computer can reach it. Ctrl+C to close.", flush=True)
    httpd.serve_forever(srv)
    return OK


# ---- start: the first five minutes ------------------------------------------------

def cmd_start(catalog: dict, env_file: str) -> int:
    from . import gitscan as scan_mod
    print("\nstuntkey - through the broker the key never enters your AI's environment.\n")
    d = scan_mod.doctor()
    shown = scan_mod.format_doctor(d)
    # "Start here" comes once, at the end: not also as the doctor's own "Next:" line
    print(shown.replace("  Ready. Next: stuntkey setup (then stuntkey get github)", "  Ready."))
    # The same look `stuntkey scan` takes, so the two always agree. A value
    # that looks like a key but is an example is said out loud, not skipped
    # in silence.
    from . import findkeys
    loose = findkeys.find_loose(".", catalog)
    n = len(loose["findings"])
    home_hits = scan_mod.scan([], include_home=True)["findings"]
    if n:
        print(f"\nHeads up: {n} place(s) where a key is lying around in plain "
              "text. Run `stuntkey scan` to see where (it never shows the "
              "key).")
    else:
        print("\nNo loose keys found nearby. Good.")
    if loose["incomplete"]:
        print("  (The look was cut short, so a clean result cannot be trusted. "
              "Run `stuntkey scan` for details.)")
    if home_hits:
        files = sorted({h["file"] for h in home_hits})
        print(f"  Also {len(home_hits)} key-looking value(s) in your own history or "
              "settings files. Look at: "
              + ", ".join(recipes_mod.printable(f) for f in files[:4])
              + ("..." if len(files) > 4 else "")
              + ". `stuntkey scan <file>` shows where in each.")
    text = findkeys.examples_text(loose["examples"])
    if text:
        print("\n" + text.rstrip("\n"))
    from . import fixcmd
    # Only keys really in the keychain are "connected". A key that sits only
    # in a .env file is said apart (it is not protected); an example is neither.
    have, loose_env = fixcmd.key_places(catalog, env_file)
    if have:
        print(f"\nConnected already (in your keychain): {', '.join(sorted(have))}.")
    if loose_env:
        print(f"\nFound only in a .env file, not protected: {', '.join(sorted(loose_env))}. "
              "`stuntkey setup` moves them into the keychain.")
    stale = fixcmd.stale_program_warning()
    if stale:
        print("\n  Note: " + stale)
    print("\n" + fixcmd.render_start_here().rstrip("\n"))
    return OK if d["ok"] else PROBLEM


# ---- start --simple: for people building with Lovable, Bolt, Replit or Vercel ----

BUILDERS = [
    ("Lovable", "In Lovable, open the Cloud tab, then Secrets, and add it there.",
     ["https://docs.lovable.dev/features/secrets"]),
    ("Bolt", "In Bolt, click the database icon, open Secrets, and add it there. If "
             "your site is on Netlify, add it in Netlify too: Site settings, then "
             "Environment variables.",
     ["https://bolt.new/resources/ai-builder-glossary/environment-variables",
      "https://docs.netlify.com/build/environment-variables/overview/"]),
    ("Replit", "In Replit, open the Secrets tool and add it there.",
     ["https://docs.replit.com/core-concepts/project-editor/app-setup/secrets"]),
    ("Vercel (or v0)", "In Vercel, open your project, then Settings, then "
                       "Environment Variables, and add it there.",
     ["https://vercel.com/docs/environment-variables"]),
    ("Something else", "Look for \"Secrets\" or \"Environment variables\" in your "
                       "host's settings and add it there. For a Supabase edge "
                       "function, see the page below.",
     ["https://supabase.com/docs/guides/functions/secrets"]),
]


def _cli(argv: list) -> int:
    from . import cli
    return cli.main(argv)


def cmd_start_simple(catalog: dict, ask=input, out=print, run=_cli) -> int:
    """One question at a time, in plain words. Enter on its own stops."""
    out("\nstuntkey - let's set up one key for your app. Press Enter on its own to stop.\n")
    out("Which app builder do you use?")
    for i, (name, _how, _links) in enumerate(BUILDERS, 1):
        out(f"  {i}. {name}")
    pick = ask("Type a number: ").strip()
    if not pick:
        return OK
    if pick not in [str(i) for i in range(1, len(BUILDERS) + 1)]:
        out("Please type one of the numbers. Run `stuntkey start --simple` to try again.")
        return USAGE
    name, how, links = BUILDERS[int(pick) - 1]
    while True:
        slug = ask("\nWhich service is the key for (for example openai, stripe, "
                   "resend)? ").strip().lower()
        if not slug:
            return OK
        if slug in catalog:
            break
        import difflib
        close = difflib.get_close_matches(slug, list(catalog), n=3, cutoff=0.5)
        out("I don't know that one." + (f" Did you mean: {', '.join(close)}?" if close else
                                        " `stuntkey list` shows them all."))
    recipe = catalog[slug]
    env = " and ".join(recipes_mod.env_vars(recipe))
    out(f"\nStep 1 of 3: get your {recipe.get('display', slug)} key. A page opens where "
        "you make the key; copy it, and stuntkey checks it and keeps it safe on this "
        "computer. Keep that page open.")
    code = run(["get", slug])
    if code != OK:
        out(f"\nThat did not finish. Try again any time with: stuntkey get {slug}")
        return code
    out("\nStep 2 of 3: give the key to your app.\n"
        "Keep this key on the server side. Never put it in a setting whose name "
        "starts with VITE_ or NEXT_PUBLIC_: those are copied into your web page, "
        "where every visitor can read them.")
    out(f"{how} Name it {env}. Copy the key once more from the page you kept open "
        "and paste it in as the value.")
    if name.startswith("Vercel"):
        out(f"Or let stuntkey send it for you (needs the vercel tool, signed in): "
            f"stuntkey export {slug} --to vercel")
    out("How-to: " + "  ".join(links))
    url = ask("\nStep 3 of 3: is your app online? Type its address (https://...) and "
              "I'll check it does not give your key away to visitors: ").strip()
    if not url:
        out("Done. You can check it later with: stuntkey scan --bundle https://your-site")
        return OK
    if "://" not in url:
        url = "https://" + url
    return run(["scan", "--bundle", url])
