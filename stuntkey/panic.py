"""`stuntkey panic <service>`: "I leaked a key."

1. show the plan and ask the person (terminal y, or the consent window);
2. kill the old key - the vendor's official revoke API when the recipe has
   one, else its revoke page with steps, then wait for the person to say done;
3. get a new key through the normal guided `get` flow (validated before it
   replaces the old one);
4. look for the OLD key everywhere stuntkey knows (project files, .env files,
   MCP configs, git history) by a fingerprint taken before it was replaced;
5. note every step in the local ledger (words only, never a key).

CLI ONLY. It is never offered over MCP, `serve` or the proxy: an agent must
not be able to revoke a key or receive a new one.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request
import webbrowser

from . import broker, dialog, gitscan, keychain as keychain_mod, ledger, safeprompt
from . import validate as validate_mod
from .recipes import env_vars, printable

PREFIX = 6          # chars of the old key kept to find candidates; never shown
MIN_LEN = 12        # shorter values are not searched for (too many false hits)


def add_parser(sub) -> None:
    pn = sub.add_parser(
        "panic", help="I leaked a key: revoke it, get a new one, find where "
                      "the old one is still written down.",
        description="Shows the plan and asks first. Revokes the stored key "
                    "through the vendor's official API when there is one "
                    "(else opens the revoke page and waits for you), gets a "
                    "new key with the guided `get` flow, then looks for the "
                    "OLD key in this project, its .env files, MCP configs "
                    "and git history. Never prints a key. Terminal only.")
    pn.add_argument("service", help="Service slug.")
    pn.add_argument("--dry-run", action="store_true",
                    help="Show the plan; change nothing, send nothing.")
    pn.add_argument("--env-file", default=None,
                    help="The .env file (default: the manifest's env_file, else .env).")
    pn.add_argument("--no-browser", action="store_true",
                    help="Don't auto-open the revoke and key pages.")


# --------------------------------------------------------------- fingerprint

def fingerprint(value: str) -> tuple[str, int, str]:
    return value[:PREFIX], len(value), hashlib.sha256(value.encode()).hexdigest()


def matcher(fps: list[tuple[str, int, str]]):
    """line -> [(kind, masked hint)] for every place an old value appears.
    Only the prefix, length and hash are kept, not the value."""
    def match(line: str) -> list[tuple[str, str]]:
        hits = []
        for prefix, n, digest in fps:
            i = line.find(prefix)
            while i != -1:
                if hashlib.sha256(line[i:i + n].encode()).hexdigest() == digest:
                    hits.append(("the OLD key", f"{prefix[:4]}... ({n} chars)"))
                    break
                i = line.find(prefix, i + 1)
        return hits
    return match


def find_old(fps, root: str, home: str | None = None, git=gitscan.scan_git,
             env=None) -> list[dict]:
    """Every place stuntkey knows to look: the project tree (.env files
    included), each AI client's MCP config, shell history, git history."""
    from . import mcpwrap
    home = home or os.path.expanduser("~")
    m = matcher(fps)
    configs = [p for c in mcpwrap.CLIENTS
               for p, _ in mcpwrap.config_files(c, home, root, env)]
    found = [dict(f, where="file") for f in
             gitscan.scan([root] + configs, home=home, matcher=m)["findings"]]
    if os.path.isdir(os.path.join(root, ".git")):
        found += [dict(f, where="git") for f in git(root, matcher=m).get("findings", [])]
    return found


# -------------------------------------------------------------------- revoke

class RevokeFailed(Exception):
    pass


def revoke_api(recipe: dict, key: str, send=None, resolver=None,
               timeout: float = 20.0) -> int:
    """Call the vendor's revoke endpoint over the broker's pinned HTTPS (public
    address only, no proxy, no redirect). Returns the status; raises
    RevokeFailed. The response body is never shown (it may echo the key)."""
    api = recipe["revoke"]["api"]
    host = urllib.parse.urlsplit(api["url"]).hostname
    headers = validate_mod._base_headers(api)
    data = None
    if api["auth"]["type"] == "bearer":
        headers["Authorization"] = f"Bearer {key}"
    else:
        data = json.dumps({api["auth"]["field"]: [key]}).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(api["url"], data=data, headers=headers,
                                 method=api["method"])
    try:
        ip = broker.resolve_public(host, 443, resolver)
        status, _, _ = (send or broker._real_send)(req, ip, timeout)
    except (broker.BrokerError, OSError) as e:
        raise RevokeFailed(printable(str(e).replace(key, "[key]"))) from None
    if status not in api["expect"]:
        raise RevokeFailed(f"{host} answered HTTP {status}")
    return status


# ---------------------------------------------------------------------- ask

def _ask(question: str, out) -> bool:
    """Terminal y (read without echo, a pasted key is never a yes), else the
    consent window. Anything but a clear yes is no."""
    try:
        tty = bool(sys.stdin and sys.stdin.isatty())
    except (OSError, ValueError):
        tty = False
    if tty:
        return safeprompt.ask(f"  {question} [y/N]: ", out, enter_means=False) is True
    return dialog.confirm("stuntkey panic", question) is True


def _plan(recipe: dict, rv: dict, has_key: bool) -> list[str]:
    name = printable(recipe["display"], words=True)
    if rv.get("api") and has_key:
        host = urllib.parse.urlsplit(rv["api"]["url"]).hostname
        kill = f"revoke the stored {name} key through {host} (the vendor's own API)"
    else:
        kill = f"open {printable(rv['page'])} so you revoke the old key, and wait for you"
    return [kill,
            f"get a new {name} key (opens the key page, takes it from your copy, "
            "tests it; the old one is replaced only once the new one works)",
            "look for the OLD key in this project, .env files, MCP configs and "
            "git history, and say where it is (masked)"]


# -------------------------------------------------------------------- command

def cmd_panic(args, catalog: dict, connect_fn, env_file: str, root: str,
              out=None, ask=None, open_page=None, read_values=None,
              send=None, resolver=None, home=None, git=gitscan.scan_git) -> int:
    out = out or sys.stdout
    ask = ask or (lambda q: _ask(q, out))
    open_page = open_page or ((lambda url: None) if args.no_browser else webbrowser.open)
    recipe = catalog.get(args.service)
    if not recipe:
        from . import extras
        return extras.unknown_service(catalog, "(not shown)" if len(args.service) > 24
                                      else printable(args.service))
    service = recipe["service"]
    rv = dict(recipe.get("revoke") or {})
    rv.setdefault("page", recipe["key_url"])
    rv.setdefault("steps", ["Find the old key in the list and delete (revoke) it"])
    locked = False
    try:
        old = (read_values or (lambda r: keychain_mod.gather(r, None, None, env_file)))(recipe)
    except keychain_mod.KeychainError:
        old = {}
        locked = True               # the vault would not answer: that is NOT "no key stored"
    fps = [fingerprint(v) for v in old.values() if isinstance(v, str) and len(v) >= MIN_LEN]
    key = old.get(recipe["env_var"]) if len(env_vars(recipe)) == 1 else None
    old = None                                  # only the fingerprints are kept

    def note(step: str, result: str) -> None:
        ledger.event(root, service, step, result)

    out.write(f"\n  panic: {printable(recipe['display'], words=True)}\n")
    if locked:
        out.write("  The keychain was locked or could not be reached, so stuntkey cannot tell "
                  "whether a key is stored, and cannot revoke it by API or search for it.\n"
                  "  To revoke by hand: unlock the keychain (sign in to this computer again) and "
                  "run this again; or open the vendor's key page (step 1 below), delete the old "
                  "key there, then run `stuntkey rotate " + service + "` once the keychain is back.\n")
    elif key is None:
        out.write("  (no stored key found here, so it cannot be revoked by API "
                  "or searched for)\n")
    for i, line in enumerate(_plan(recipe, rv, key is not None), 1):
        out.write(f"    {i}. {line}\n")
    if args.dry_run:
        out.write("\n  --dry-run: nothing was changed or sent.\n")
        return 0
    if not ask(f"Revoke and replace your {service} key now?"):
        note("panic", "declined")
        out.write("  stopped: nothing was changed or sent.\n")
        return 1
    note("panic", "started")

    # 2. revoke
    if rv.get("api") and key is not None:
        try:
            status = revoke_api(recipe, key, send, resolver)
        except RevokeFailed as e:
            note("revoke", "failed")
            out.write(f"  ✗ revoke failed: {e}.\n"
                      "    STOPPED. The old key may still work and is still stored. "
                      f"Revoke it yourself at {printable(rv['page'])}, then run "
                      f"`stuntkey rotate {service}`.\n")
            return 1
        note("revoke", f"api {status}")
        out.write("  ✓ the old key was revoked by the vendor's API.\n")
    else:
        out.write(f"\n  Revoke the old key here: {printable(rv['page'])}\n")
        for i, step in enumerate(rv["steps"], 1):
            out.write(f"    {i}. {printable(step, words=True)}\n")
        open_page(rv["page"])
        if not ask(f"Have you revoked the old {service} key?"):
            note("revoke", "not confirmed")
            out.write("  STOPPED: the old key was not confirmed revoked; nothing "
                      "else was changed.\n")
            return 1
        note("revoke", "confirmed by person")
    key = None

    # 3. re-issue (validated before it replaces the old one)
    if connect_fn(recipe) != 0:
        note("reissue", "failed")
        out.write("  ✗ no new key was saved. The old (revoked) key is still "
                  f"stored; run `stuntkey rotate {service}` to try again.\n")
        return 1
    note("reissue", "ok")

    # 4. where is the old key still written down?
    found = find_old(fps, root, home, git) if fps else []
    note("scan", f"{len(found)} found")
    if not found:
        out.write("  ✓ the old key was not found in this project, its .env "
                  "files, MCP configs or git history.\n")
        return 0
    out.write(f"\n  The OLD key is still written in {len(found)} place(s). It no "
              "longer works, but delete it anyway:\n")
    for f in found:
        at = (f"commit {f.get('commit')} {f['file']}" if f["where"] == "git"
              else f"{f['file']}:{f.get('line')}")
        out.write(f"    {printable(at)}  {f['hint']}\n")
    if any(f["where"] == "git" for f in found):
        out.write("    In git history it stays readable to anyone with the repo; it "
                  "is revoked, so that is the fix. Rewrite history only if you must.\n")
    return 0
