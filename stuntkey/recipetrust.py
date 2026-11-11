"""Which recipes made on this computer may be used: the person's yes, kept safely.

A recipe says which stored key goes to which server. The built-in ones ship with
StuntKey and were reviewed with it. A recipe in ~/.stuntkey/recipes was made on
this computer by a person OR by a program: a planted one could name any variable
you keep (a database address, a webhook secret) and a server of its own, and ask
StuntKey to send the one to the other. So a recipe from that folder is NOT used
until the person approves it:

    stuntkey recipe approve <service>      (a person, in a terminal)

An approval is the sha256 fingerprint of the recipe file, kept in
~/.stuntkey/recipe-approvals.json and signed with a key held in the keychain (the
same kind of key that signs the activity log). Change one byte of the file and the
approval no longer matches: it is "not approved yet" again. A recipe of this kind
also reads ONLY the keychain entries stored under its own service name; a .env
file is never read for it unless the recipe names the variable in "allow_env" AND
the approval lists it.

Honest limit: a program that runs AS YOU and can reach your keychain could sign an
approval itself. What this stops is the realistic attack - a planted recipe file,
or an AI tool's call - because an AI tool's own calls (the MCP server) can never
approve, and a recipe saved by anything but the person at a terminal stays unapproved.

This module imports no keychain code (that would make an import cycle): functions
that sign take `key_fn`, which is keychain.integrity_key. remote.py wraps them so
callers do not have to (remote.recipe_use_problem, remote.recipe_approve ...).
"""
from __future__ import annotations

import contextlib
import datetime
import hashlib
import hmac
import json
import os
import sys
import threading

from . import recipes as recipes_mod
from . import schema as schema_mod
from . import store as store_mod

FILE_NAME = "recipe-approvals.json"
PURPOSE = "recipes"                     # its own signing key
CURRENT_VERSION = 1
MIGRATIONS: dict = {}                   # {old_version: fn(doc) -> doc}; none needed yet
MAX_BYTES = 1024 * 1024


class TrustError(OSError):
    """An approval could not be read or saved. str() is plain words."""

    def __init__(self, message: str):
        super().__init__(22, message)
        self.plain = message

    def __str__(self) -> str:
        return self.plain


# ---- "is an AI tool the one asking?" ---------------------------------------------
#
# The MCP server runs inside agent_context(). Nothing that runs there may approve a
# recipe, whatever it passes in.

_agent_depth = 0
_agent_lock = threading.Lock()


@contextlib.contextmanager
def agent_context():
    global _agent_depth
    with _agent_lock:
        _agent_depth += 1
    try:
        yield
    finally:
        with _agent_lock:
            _agent_depth -= 1


def in_agent_context() -> bool:
    return _agent_depth > 0


def is_interactive() -> bool:
    """A person at a terminal: input AND output are consoles. (Advisory: a program
    can fake a terminal; see the note at the top.)"""
    try:
        return bool(sys.stdin and sys.stdout and sys.stdin.isatty() and sys.stdout.isatty())
    except (AttributeError, ValueError, OSError):
        return False


# ---- the signed approvals file -----------------------------------------------------

def home() -> str:
    return os.path.dirname(recipes_mod.user_recipes_dir())


def approvals_path() -> str:
    return os.path.join(home(), FILE_NAME)


def _canonical(version: int, approvals: dict) -> bytes:
    return json.dumps({"version": version, "approvals": approvals},
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def _signing(key_fn, create: bool):
    try:
        return key_fn(home(), create, PURPOSE)
    except Exception:
        return None, "unavailable"


def _sign(key: bytes, version: int, approvals: dict) -> str:
    return hmac.new(key, _canonical(version, approvals), hashlib.sha256).hexdigest()


_NOTHING = ("so no recipe of yours counts as approved. Run `stuntkey recipe approve "
            "<service>` again for each one you use.")


def read(key_fn, path: str | None = None) -> tuple[dict, str]:
    """(approvals, problem). `approvals` is {service: {sha256, approved_at,
    env_bound, hosts, variables}}; EMPTY whenever the file cannot be trusted.
    `problem` is "" when all is well (no file counts as well: nothing approved),
    else plain words saying why nothing is approved."""
    path = path or approvals_path()
    if not os.path.exists(path):
        return {}, ""
    try:
        if store_mod.private_path_problem(path) or not os.path.isfile(path):
            return {}, f"The recipe approvals file is not somewhere StuntKey can trust, {_NOTHING}"
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("too large")
        doc = json.loads(raw.decode("utf-8"))
        if not isinstance(doc, dict):
            raise ValueError("not an object")
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        return {}, f"The recipe approvals file could not be read, {_NOTHING}"
    signed_version = schema_mod.version_of(doc)       # the signature covers THIS version
    try:
        doc = schema_mod.load_versioned(doc, CURRENT_VERSION, MIGRATIONS,
                                        "The recipe approvals file", path)
    except schema_mod.SchemaError as e:
        return {}, f"{e} Until then {_NOTHING}"
    approvals, sig = doc.get("approvals"), doc.get("sig")
    if not isinstance(approvals, dict) or not isinstance(sig, str):
        return {}, f"The recipe approvals file is not signed, {_NOTHING}"
    key, _where = _signing(key_fn, False)
    if key is None:
        return {}, ("StuntKey cannot reach the key that signs recipe approvals (a locked or "
                    f"cleared keychain?), {_NOTHING}")
    if not hmac.compare_digest(sig, _sign(key, signed_version, approvals)):
        return {}, ("The recipe approvals file does not match its signature: something other "
                    f"than StuntKey changed it, {_NOTHING}")
    return {k: v for k, v in approvals.items() if isinstance(v, dict)}, ""


def _update(key_fn, change) -> None:
    """Read, apply change(approvals) -> approvals, sign and save, under a lock.
    Raises TrustError when the signing key cannot be had."""
    path = approvals_path()
    key, _where = _signing(key_fn, True)
    if key is None:
        raise TrustError("StuntKey cannot reach the key that signs recipe approvals (a locked "
                         "or cleared keychain?), so nothing was saved. Unlock it and try again.")
    problem = store_mod.private_path_problem(path)
    if problem:
        raise TrustError(f"The recipe approvals file cannot be written: {problem}")
    os.makedirs(home(), exist_ok=True)
    with store_mod.file_lock(path):
        approvals, _problem = read(key_fn, path)       # a file that does not verify starts clean
        approvals = change(dict(approvals))
        doc = {"version": CURRENT_VERSION, "approvals": approvals,
               "sig": _sign(key, CURRENT_VERSION, approvals)}
        store_mod.write_private(path, json.dumps(doc, indent=2, sort_keys=True) + "\n")


# ---- is this recipe usable? ---------------------------------------------------------

def state(recipe: dict, key_fn) -> str:
    """"ok" (nothing to approve: built in, or not from the user folder), "approved",
    "new" (never approved), "changed" (approved once, the file is different now) or
    "unverifiable" (the approvals cannot be checked)."""
    if not recipe.get("_needs_approval"):
        return "ok"
    sha = recipe.get("_sha256")
    approvals, problem = read(key_fn)
    entry = approvals.get(recipe.get("service"))
    if sha and entry and hmac.compare_digest(str(entry.get("sha256", "")), str(sha)):
        return "approved"
    if problem:
        return "unverifiable"
    return "changed" if entry else "new"


def _name(recipe: dict) -> str:
    return recipes_mod.printable(recipe.get("service", "?"))


def use_problem(recipe: dict, key_fn) -> str | None:
    """None when the recipe may be used. Else a plain message (for a person AND for
    an AI tool reading it) with the one command to run."""
    st = state(recipe, key_fn)
    if st in ("ok", "approved"):
        return None
    svc = _name(recipe)
    tail = (f" Only you can approve it: run `stuntkey recipe approve {svc}` in a terminal, "
            "read what it says, and answer yes. Do not retry.")
    if st == "changed":
        return (f"The recipe '{svc}' has changed since you approved it, so stuntkey will not "
                f"use it.{tail}")
    if st == "unverifiable":
        _approvals, why = read(key_fn)
        return f"The recipe '{svc}' cannot be used: {why}{tail}"
    return (f"The recipe '{svc}' was made by a person or program on this computer and has not "
            f"been approved yet, so stuntkey will not use it.{tail}")


def flag(recipe: dict, key_fn) -> str:
    """"" when fine, else a short label for listings: "not approved yet" or
    "changed since approved"."""
    st = state(recipe, key_fn)
    return {"new": "not approved yet", "changed": "changed since approved",
            "unverifiable": "not approved yet (approvals cannot be checked)"}.get(st, "")


def env_allowed(recipe: dict, key_fn) -> set | None:
    """The variables a .env file may be read for. None = no limit (built-in
    recipes, and recipes that did not come from the user folder). A recipe from the
    user folder gets: variables it names in "allow_env" AND that the approval lists,
    plus, for a same-name replacement of a built-in recipe, the variables the
    built-in one reads there already."""
    if not recipe.get("_needs_approval"):
        return None
    mine = set(recipes_mod.env_vars(recipe))
    allowed: set = set()
    if recipe.get("_overrides_builtin"):
        allowed |= mine & set(recipe.get("_builtin_env_vars") or [])
    approvals, _problem = read(key_fn)
    entry = approvals.get(recipe.get("service")) or {}
    if recipe.get("_sha256") and entry.get("sha256") == recipe.get("_sha256"):
        bound = entry.get("env_bound")
        listed = recipe.get("allow_env") or []
        if isinstance(bound, list):
            allowed |= mine & set(listed) & {b for b in bound if isinstance(b, str)}
    return allowed


# ---- what the person is shown ---------------------------------------------------------

def explain(recipe: dict, now: float | None = None) -> list[str]:
    """The lines `recipe approve` shows before the one yes. Plain words; every
    name from the recipe goes through printable()."""
    p = recipes_mod.printable
    hosts = ", ".join(sorted(p(h) for h in recipes_mod.hosts_of(recipe))) or "(none)"
    lines = [f"Recipe '{_name(recipe)}' ({p(recipe.get('display', ''))})",
             f"  Made by:      {recipes_mod.origin_words(recipe, now)}",
             f"  File:         {p(recipe.get('_file') or '(not a file)')}",
             f"  Sends to:     {hosts}"]
    for var, how in recipes_mod.attachments(recipe):
        lines.append(f"  Would use:    {p(var)}, {how}")
    allow = [a for a in (recipe.get("allow_env") or []) if isinstance(a, str)]
    if allow:
        lines.append(f"  .env file:    it also asks to read {', '.join(p(a) for a in allow)} from a "
                     ".env file. That is how a recipe could send something else you keep there "
                     "to the server above.")
    else:
        lines.append(f"  Where from:   only the keychain entry stored for '{_name(recipe)}'. "
                     "A .env file is never read for this recipe.")
    lines.append("  If you did not make this recipe yourself, or do not know the server, say no.")
    return lines


# ---- approving (a person, at a terminal) -----------------------------------------------

def _refusal(interactive: bool | None) -> str | None:
    if in_agent_context():
        return ("Only you can approve a recipe, in a terminal. An AI tool cannot, so nothing "
                "was approved.")
    if not (is_interactive() if interactive is None else interactive):
        return ("A recipe can only be approved by you at a terminal (a window where you type), "
                "not from a script or an AI tool, so nothing was approved. Open a terminal and "
                "run the command there.")
    return None


def _record(recipe: dict, key_fn) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    entry = {"sha256": recipe["_sha256"], "approved_at": now,
             "env_bound": sorted(recipe.get("allow_env") or []),
             "hosts": sorted(recipes_mod.hosts_of(recipe)),
             "variables": recipes_mod.env_vars(recipe)}

    def change(approvals: dict) -> dict:
        approvals[recipe["service"]] = entry
        return approvals
    _update(key_fn, change)


def approve(service: str, key_fn, ask=None, out=print, interactive: bool | None = None,
            now: float | None = None) -> int:
    """`stuntkey recipe approve <service>`: show what the recipe would do and ask
    once. Returns 0 when approved, 1 when not (and says why). `ask(question) -> bool`
    is the answer (default: type "yes" at the terminal). Refused for an AI tool
    (agent_context) and when no person is at a terminal."""
    why = _refusal(interactive)
    if why:
        out(why)
        return 1
    recipe, problem = recipes_mod.load_user_recipe(service)
    if recipe is None:
        out(f"Nothing was approved: {problem}.")
        return 1
    for line in explain(recipe, now):
        out(line)
    if ask is None:
        def ask(question: str) -> bool:
            try:
                return input(question).strip().lower() in ("y", "yes")
            except (EOFError, OSError):
                return False
    if not ask(f"Approve '{_name(recipe)}' exactly as it is now? Type yes to approve, "
               "anything else to cancel: "):
        out("Not approved. The recipe stays unused.")
        return 1
    try:
        _record(recipe, key_fn)
    except (TrustError, OSError) as e:
        out(f"Not approved: {e}")
        return 1
    out(f"Approved '{_name(recipe)}'. This covers exactly this file: if it changes in any "
        "way you will be asked again.")
    return 0


def approve_saved(service: str, key_fn, interactive: bool | None = None) -> bool:
    """For a flow where the PERSON just made this recipe themselves at a terminal
    (`stuntkey add`, `connect`, `get <site>`): record it as approved without asking
    again. True when recorded. Does nothing (False) for an AI tool, when no person
    is at a terminal, for a recipe that asks to read a .env file (`allow_env`: that
    one needs the explicit `recipe approve`), or if the file is not what it should be."""
    if _refusal(interactive):
        return False
    recipe, problem = recipes_mod.load_user_recipe(service)
    if recipe is None or recipe.get("allow_env"):
        return False
    try:
        _record(recipe, key_fn)
    except (TrustError, OSError):
        return False
    return True


def save_and_approve(data: dict, key_fn, directory: str | None = None,
                     interactive: bool | None = None) -> tuple[str, bool]:
    """recipes.save_recipe, then approve_saved when the person is at a terminal
    and `directory` is their own recipe folder. (path, approved)."""
    path = recipes_mod.save_recipe(data, directory)
    mine = directory is None or recipes_mod._is_user_dir(directory)
    return path, bool(mine and approve_saved(data["service"], key_fn, interactive))


def revoke(service: str, key_fn) -> bool:
    """Take back an approval. True when there was one."""
    had = {"x": False}

    def change(approvals: dict) -> dict:
        had["x"] = approvals.pop(service, None) is not None
        return approvals
    try:
        _update(key_fn, change)
    except (TrustError, OSError):
        return False
    return had["x"]


def listing(catalog: dict, key_fn) -> dict:
    """{service: flag} for recipes that need a word in a listing."""
    out = {}
    for slug, recipe in catalog.items():
        f = flag(recipe, key_fn)
        if f:
            out[slug] = f
    return out
