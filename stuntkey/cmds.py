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


# ---- status ---------------------------------------------------------------------

def cmd_status(catalog: dict, env_file: str, as_json: bool) -> int:
    rows = [{"service": s, "key_stored": _have_key(r, env_file)}
            for s, r in sorted(catalog.items())]
    ok, n = broker.AuditLog(os.path.join(_home(), "audit.log")).verify()
    info = {"python": sys.version.split()[0], "services": len(rows),
            "with_keys": sum(r["key_stored"] for r in rows),
            "audit_log_ok": ok, "audit_entries": n,
            "connected": [r["service"] for r in rows if r["key_stored"]]}
    head = ("stuntkey is ready." if info["with_keys"]
            else "Not ready yet: no key is saved. Run `stuntkey start`.")
    text = (f"{head}\n"
            f"  services known: {info['services']}   with a key stored: "
            f"{info['with_keys']}\n"
            f"  connected: {', '.join(info['connected']) or 'none yet'}\n"
            f"  activity log: {'intact' if ok else 'check FAILED - run `stuntkey audit show`'} "
            f"({n} entries)")
    _emit(info, as_json, text)
    return OK if ok else PROBLEM


# ---- call -----------------------------------------------------------------------

def cmd_call(recipe: dict, args) -> int:
    from . import remote
    query = {}
    for item in args.query or []:
        k, sep, v = item.partition("=")
        if not sep:
            print("error: --query needs name=value", file=sys.stderr)
            return USAGE
        query[k] = v
    body = None
    if args.data:
        try:
            body = json.loads(args.data)
        except ValueError:
            print("error: --data must be valid JSON", file=sys.stderr)
            return USAGE
    policy = broker.Policy(allow_write=False, approve=approve_mod.ask_person)
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
        print(json.dumps(out))
    else:
        print(f"[{out['status']}]")
        print(out["body"])
    return OK if out["status"] < 400 else PROBLEM


# ---- audit ----------------------------------------------------------------------

def cmd_audit(action: str, as_json: bool, last: int = 20) -> int:
    log = broker.AuditLog(os.path.join(_home(), "audit.log"))
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
    _emit({"intact": ok, "entries": n}, as_json,
          f"activity log: {'intact' if ok else 'TAMPERED'} ({n} entries){why}")
    return OK if ok else PROBLEM


# ---- serve (local web door) ---------------------------------------------------

def cmd_serve(catalog: dict, port: int, env_file: str) -> int:
    from . import httpd, remote
    tokfile = os.path.join(_home(), "http.token")
    token = httpd.load_or_make_token(tokfile)
    policy = broker.Policy(approve=approve_mod.ask_person)
    audit = broker.AuditLog(os.path.join(_home(), "audit.log"))
    srv = httpd.make_server(catalog, lambda r: remote.collect_values(r, env_file),
                            token, policy, audit, port=port)
    p = srv.server_address[1]
    print(f"stuntkey web door is open at http://127.0.0.1:{p}\n"
          f"  token file (keep private): {tokfile}\n"
          f"  AIs send:  Authorization: Bearer <token>   GET /tools   POST /call\n"
          f"  Only this computer can reach it. Ctrl+C to close.")
    httpd.serve_forever(srv)
    return OK


# ---- start: the first five minutes ------------------------------------------------

def cmd_start(catalog: dict, env_file: str) -> int:
    from . import gitscan as scan_mod
    print("\nstuntkey - your AI can use your keys, and never see them.\n")
    d = scan_mod.doctor()
    print(scan_mod.format_doctor(d))
    res = scan_mod.scan(["."], include_home=True)
    n = len(res["findings"])
    if n:
        print(f"\nHeads up: {n} place(s) where a key is lying around in plain "
              "text. Run `stuntkey scan` to see where (it never shows the "
              "key), `stuntkey adopt` to move the .env ones into the keychain "
              "with no copying, or `stuntkey guard` to protect them where they are.")
    else:
        print("\nNo loose keys found nearby. Good.")
    have = [s for s, r in catalog.items() if _have_key(r, env_file)]
    if have:
        print(f"\nConnected already: {', '.join(sorted(have))}.")
        print("Next: run `stuntkey install` to plug it into Claude, Cursor or "
              "VS Code (or `stuntkey serve` for other AI tools). Then fully "
              "quit and reopen that app.")
    else:
        print("\nNext: connect your first service, for example:\n"
              "  stuntkey get github")
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
