"""`stuntkey keep NAME`: save ANY secret in the keychain, no recipe needed.

`get` and `connect` need a recipe for the service (there are about 40). For
a service stuntkey has never heard of, `keep` is the one-minute path:

    stuntkey keep ACME_API_KEY        # paste the key (hidden); done

What it does: asks for the key with the hidden paste prompt (or reads one line
from a pipe), saves it in the OS keychain under the name you gave, reads it
back, and tells the hook which key to hide (fingerprints only). What it does
not do: test the key (it has no idea which web address would prove it), or
make AI calls with it (`stuntkey call` needs a recipe). Use it with
`stuntkey run acme -- some-program`, which puts the key in that one program's
environment and hides it in the output.

It never writes the key to a file: with no keychain it stops and says how to
get one. A small list of the names you kept (names only, never values) lives
in ~/.stuntkey/kept.json so that `run`, `forget` and `keep --list` find them.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import sys
import tempfile

from . import fsutil
from . import keychain as keychain_mod
from . import recipes as recipes_mod
from . import safeprompt
from . import scrub as scrub_mod

FILE = "kept.json"
MAX_KEY = 4096
MIN_KEY = 8
_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}\Z")
_TAILS = ("_API_KEY", "_ACCESS_TOKEN", "_AUTH_TOKEN", "_TOKEN", "_SECRET_KEY",
          "_SECRET", "_KEY", "_PASSWORD")


def kept_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".stuntkey", FILE)


def load() -> dict:
    """{slug: {"env_var": ..., "added": ...}}. A missing or damaged file is
    an empty list (the keychain entries are not touched either way)."""
    try:
        with open(kept_path(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    good = {}
    for slug, item in data.items():
        if (isinstance(slug, str) and recipes_mod.SLUG_RE.match(slug)
                and isinstance(item, dict) and isinstance(item.get("env_var"), str)
                and _ENV_RE.match(item["env_var"])):
            good[slug] = {"env_var": item["env_var"],
                          "added": str(item.get("added", ""))[:32]}
    return good


def _save(data: dict) -> None:
    path = kept_path()
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".kept-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
            f.write("\n")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        fsutil.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def names_for(name: str) -> tuple[str, str]:
    """(slug, ENV_VAR) from what the person typed: ACME_API_KEY -> (acme,
    ACME_API_KEY); "acme" -> (acme, ACME_API_KEY). Raises ValueError (plain
    words)."""
    raw = (name or "").strip()
    if _ENV_RE.match(raw):
        env_var = raw
        slug = raw
        for tail in _TAILS:
            if slug.endswith(tail) and len(slug) > len(tail):
                slug = slug[: -len(tail)]
                break
        slug = slug.lower().replace("_", "-")
    else:
        slug = raw.lower()
        if not recipes_mod.SLUG_RE.match(slug):
            raise ValueError(
                "use a short name made of letters, digits, '-' or '_', such as "
                "acme or ACME_API_KEY")
        env_var = re.sub(r"[^A-Z0-9]", "_", slug.upper()) + "_API_KEY"
        if not _ENV_RE.match(env_var):
            raise ValueError("that name does not make a usable variable name; "
                             "give the variable name too, e.g. ACME_API_KEY")
    slug = slug.strip("-_") or raw.lower()
    if not recipes_mod.SLUG_RE.match(slug):
        raise ValueError("that name does not make a usable service name")
    reserved = recipes_mod.device_name_problem(slug)
    if reserved:
        raise ValueError(reserved)
    return slug, env_var


def recipe(slug: str) -> dict | None:
    """A stand-in recipe for a kept key, good for `run` and `forget` only
    (it has no validation, so `connect`/`call` refuse it)."""
    item = load().get(slug)
    if not item:
        return None
    return {"service": slug, "display": slug, "env_var": item["env_var"],
            "kept": True}


def _read_key(read=None) -> str:
    read = read or safeprompt.read_hidden
    raw = read("  Paste the key (hidden, then Enter): ")
    key = safeprompt.strip_paste_marks(raw or "").strip()
    return key


def _problem_with(key: str) -> str | None:
    if not key:
        return "nothing was pasted"
    if len(key) < MIN_KEY:
        return f"that is only {len(key)} characters; a key is normally longer"
    if len(key) > MAX_KEY:
        return f"that is {len(key)} characters; too long to be a key"
    if any(ord(c) < 32 or ord(c) == 127 for c in key):
        return "it holds a line break or a control character (was more than one line pasted?)"
    if key.lower() in ("y", "yes", "n", "no"):
        return "that looks like an answer, not a key"
    return None


def cmd_keep(args, catalog: dict, out=None, err=None, read=None, ask=None) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    kept = load()
    if getattr(args, "list", False) or not args.name:
        if not kept:
            out.write("  Nothing kept yet. Save a key with: stuntkey keep ACME_API_KEY\n")
            return 0
        out.write("\n  Keys you saved with `keep` (names only):\n\n")
        for slug in sorted(kept):
            out.write(f"    {recipes_mod.printable(slug):<24} -> {kept[slug]['env_var']}"
                      f"   (use: stuntkey run {recipes_mod.printable(slug)} -- COMMAND)\n")
        return 0
    try:
        slug, env_var = names_for(args.name)
    except ValueError as e:
        err.write(f"stuntkey keep: {e}.\n")
        return 2
    env_var = getattr(args, "env_var", None) or env_var
    if not _ENV_RE.match(env_var):
        err.write("stuntkey keep: --env-var must be CAPITAL letters, digits and '_', "
                  "starting with a letter.\n")
        return 2
    if slug in catalog:
        err.write(f"stuntkey keep: stuntkey already knows '{slug}' and can test the key "
                  f"for you. Use: stuntkey get {slug}\n")
        return 3
    backend = keychain_mod.detect_backend()
    if backend is None:
        err.write("stuntkey keep: this computer has no keychain stuntkey can use, and "
                  "`keep` never writes a key to a file. Run `stuntkey doctor` to see "
                  "what to install.\n")
        return 1
    if slug in kept:
        ask = ask or safeprompt.ask
        answer = ask(f"  '{slug}' is already kept. Replace its key? [y/N]: ", out,
                     enter_means=False)
        if answer is not True:
            out.write("  Nothing changed.\n")
            return 0
    out.write(f"\n  Keeping '{recipes_mod.printable(slug)}' as {env_var} in the "
              f"{keychain_mod.label(backend)}.\n"
              "  stuntkey cannot test this key (it does not know the service). "
              "Nothing is shown or written to a file.\n\n")
    try:
        key = _read_key(read)
    except (EOFError, KeyboardInterrupt):
        out.write("cancelled.\n")
        return 1
    why = _problem_with(key)
    if why:
        err.write(f"stuntkey keep: not saved - {why}.\n")
        return 1
    try:
        keychain_mod.store(slug, env_var, key, backend)
    except keychain_mod.KeychainError as e:
        err.write(f"stuntkey keep: not saved - {recipes_mod.printable(e)}\n")
        return 1
    finally:
        del key
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        # read again under the lock: two `keep`s at once must not drop a name
        with scrub_mod._locked(kept_path()):
            fresh = load()
            fresh[slug] = {"env_var": env_var, "added": stamp}
            _save(fresh)
    except OSError as e:
        err.write("stuntkey keep: the key is saved, but the list of kept names could not be "
                  f"written ({e.strerror or type(e).__name__}); `stuntkey run` will not find "
                  "it until it can.\n")
        return 1
    out.write(f"  Saved. Use it with:  stuntkey run {recipes_mod.printable(slug)} -- YOUR-COMMAND\n"
              f"  Remove it with:      stuntkey forget {recipes_mod.printable(slug)}\n")
    return 0


def forget_entry(slug: str) -> None:
    """Drop a name from the list once its key is forgotten."""
    try:
        with scrub_mod._locked(kept_path()):
            kept = load()
            if slug in kept:
                del kept[slug]
                _save(kept)
    except OSError:
        pass
