"""`stuntkey try`: a practice run with a pretend key.

Walks a beginner through add -> use -> forget, one step at a time, so the
real commands are no longer new when the real key arrives. Nothing real is
touched: for the whole run HOME, USERPROFILE, APPDATA, LOCALAPPDATA and the
XDG folders point at a temporary folder, STUNTKEY_KEYCHAIN is the in-memory
test store (never the OS keychain) and the working folder is a temporary
one too (so no stuntkey.json, .env, key record or activity log of the
person's is read or written). Everything is put back, and the temporary
folder deleted, at the end - also after Ctrl-C or an error.

The key is a made-up string. It is the only "key" in this module.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import sys
import tempfile

FAKE_KEY = "sk-FAKE-TEST-0000-practice-only-not-a-real-key"
VAR = "PRACTICE_API_KEY"

_ENV_NAMES = ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
              "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME")


def _rmtree(path: str) -> None:
    import stat

    def onerr(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            func(p)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda f, p, e: onerr(f, p, e))
    else:
        shutil.rmtree(path, onerror=onerr)


@contextlib.contextmanager
def sandbox():
    """Point everything that could reach the person's real data at a
    throwaway folder; yields that folder; restores it all on the way out."""
    from . import keychain
    root = tempfile.mkdtemp(prefix="skpractice")
    saved_env = {k: os.environ.get(k) for k in
                 [*_ENV_NAMES, keychain.TEST_ENV]
                 + [k for k in os.environ if k.startswith("STUNTKEY_")]}
    saved_cwd = os.getcwd()
    try:
        for name in _ENV_NAMES:
            os.environ[name] = root
        for name in [k for k in os.environ if k.startswith("STUNTKEY_")]:
            del os.environ[name]
        os.environ[keychain.TEST_ENV] = "memory"
        os.chdir(root)
        yield root
    finally:
        try:
            os.chdir(saved_cwd)
        except OSError:
            pass
        for name, value in saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        try:
            keychain._memory.clear()
        except Exception:
            pass
        _rmtree(root)


def _recipe() -> dict:
    from . import recipes
    return recipes.validate_recipe({
        "service": "practice",
        "display": "Practice service",
        "key_url": "https://practice.example.com/keys",
        "env_var": VAR,
        "steps": ["Pretend you are on the website's key page",
                  "Copy the key (here, I do that part for you)"],
        "validate": {"method": "GET", "url": "https://api.practice.example.com/",
                     "auth": {"type": "bearer"}, "expect": [200]},
        "untested": True,
    })


def cmd_try(auto: bool = False, ask=input, out=None) -> int:
    out = out or sys.stdout
    interactive = not auto

    def pause(text: str = "Press Enter to continue (Ctrl-C to stop)") -> bool:
        if not interactive:
            return True
        try:
            ask(f"\n  {text} ")
        except (EOFError, KeyboardInterrupt):
            out.write("\n  Stopped. Nothing was saved anywhere.\n")
            return False
        return True

    out.write(
        "\n  Practice run - nothing real is touched.\n"
        "  I use a throwaway store and a temporary folder. Your real keys, your\n"
        "  keychain and your activity log are not opened. When this ends,\n"
        "  everything I made here is deleted.\n"
        f"  The key is made up: it is not a real key. (You will see the words\n"
        f"  \"not secure\" below: that is on purpose, it is only the practice store.)\n")
    if not pause():
        return 0
    from . import cli
    from . import connect as connect_mod
    from . import keychain
    with sandbox():
        recipe = _recipe()
        backend = keychain.detect_backend()
        if backend is None or not backend.startswith(keychain.TEST_PREFIX):
            # cannot happen while the sandbox is on; refuse rather than risk it
            out.write("  Stopped: the practice store is not available.\n")
            return 1
        out.write("\n  Step 1 of 3: ADD a key\n"
                  "  The real command is:  stuntkey get <site>\n"
                  "  It opens the key page, you copy the key, stuntkey tests it and\n"
                  "  saves it in your computer's keychain. Here I copy a pretend key for you.\n")
        if not pause():
            return 0
        code = connect_mod.connect(
            recipe, env_file=os.path.join(os.getcwd(), ".env"),
            browser_open=lambda url: None, prompt=lambda _t: FAKE_KEY,
            out=out, store_fn=cli.keychain_store(recipe, ".env", out=out,
                                                 backend=backend),
            opens_browser=False)
        if code != 0:
            out.write("  The practice add did not work.\n")
            return 1
        out.write("\n  Step 2 of 3: USE the key\n"
                  "  The real command is:  stuntkey run <service> -- <your command>\n"
                  "  Your program gets the key; the screen never shows it. Watch: the\n"
                  "  little program below tries to print the key.\n")
        if not pause():
            return 0
        out.flush()
        code = cli._cmd_run(
            [recipe], [sys.executable, "-c",
                       f"import os; print('the key is:', os.environ['{VAR}'])"],
            env_file=".env", redact=True, prefer="keychain")
        out.write("  The key was hidden from the output, as shown above.\n"
                  if code == 0 else "  (the practice program could not run here)\n")
        out.write("\n  Step 3 of 3: FORGET the key\n"
                  "  The real command is:  stuntkey forget <service>\n"
                  "  It removes the key from the keychain (and asks first).\n")
        if not pause():
            return 0
        code = cli._cmd_forget(recipe, ".env", out=out, keychain=keychain)
        if code != 0:
            out.write("  The practice forget did not work.\n")
            return 1
    out.write("\n  Done. The practice folder is deleted. Now the real thing:\n"
              "    stuntkey get <the site you want a key for>   e.g. stuntkey get github\n")
    return 0
