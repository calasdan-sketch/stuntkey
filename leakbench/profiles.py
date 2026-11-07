"""Protection profiles: given a simulated tool call, decide whether it is
blocked before it runs.

A profile is a callable ``(tool_payload) -> (blocked: bool, reason: str|None)``.
It may also carry three optional attributes, used when present:

``prepare(sbx)``
    called before each probe with the sandbox (plant what the tool would have).
``post(payload, response) -> response``
    the tool ran; return what the model would see. ``response`` is the Bash
    output shape ``{stdout, stderr, interrupted, isImage}``.
``spend(sbx) -> str | None``
    a runaway paid-call loop: the reason it was stopped, or None.

``none`` blocks nothing (the baseline). ``stuntkey-hook`` runs StuntKey's own
Claude Code hook (``stuntkey.hook.check``) twice, as a real install does:
PreToolUse before the call and PostToolUse on its output. ``stuntkey-full`` is
the hook plus StuntKey's spending caps.

Other tools are welcome: add a profile here and send a PR (README: "Adding a
profile").
"""

from __future__ import annotations

import contextlib
import json
import os
from typing import Callable

# (blocked, reason). reason is the profile's own words when it blocks.
Profile = Callable[[dict], "tuple[bool, str | None]"]

BENCH_SERVICE = "leakbench"
BENCH_CAP = 3          # calls_session cap set for the simulated runaway loop
LOOP_TRIES = 50        # how far the simulated loop would get without a cap
_HOME_VARS = ("HOME", "USERPROFILE")


def _profile_none(_payload: dict) -> tuple[bool, str | None]:
    return False, None


@contextlib.contextmanager
def _home(path: str | None):
    """Run the hook as if the sandbox were the user's home (where it looks for
    ~/.stuntkey/fingerprints.json), then put the real values back."""
    if path is None:
        yield
        return
    old = {k: os.environ.get(k) for k in _HOME_VARS}
    os.environ.update({k: path for k in _HOME_VARS})
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _load_stuntkey_hook(registered: bool = True, learned: bool = False) -> Profile:
    """Wrap StuntKey's hook. Raises ImportError if StuntKey is not on the path,
    so the harness can mark the profile skipped rather than guess."""
    from stuntkey import hook as hook_mod
    from stuntkey import scrub as scrub_mod

    state: dict = {"home": None}

    def prepare(sbx) -> None:  # type: ignore[no-untyped-def]
        # simulate `stuntkey get`/`add`: the canary is a key StuntKey stores, so
        # its fingerprint is in the (sandbox) fingerprint file, as in real use
        state["home"] = sbx.home
        path = os.path.join(sbx.home, ".stuntkey", scrub_mod.FINGERPRINT_FILE)
        if registered and not os.path.exists(path):
            scrub_mod.remember_key(f"{BENCH_SERVICE}/API_KEY", sbx.canary, path)
        if learned and not os.path.exists(path):
            # the key was never saved with `get`: `stuntkey guard` reads the
            # places it already sits in (the sandbox project, dotfiles, chat
            # history, the shell's variables) and remembers fingerprints
            from stuntkey import guard as guard_mod
            from stuntkey import recipes as recipes_mod
            catalog = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
            res = guard_mod.collect(sbx.home, sbx.home, catalog, sbx.env)
            scrub_mod.replace_group(guard_mod.PREFIX, res.values, path)

    def profile(payload: dict) -> tuple[bool, str | None]:
        stdin_text = json.dumps({"hook_event_name": "PreToolUse", **payload})
        with _home(state["home"]):
            status, out = hook_mod.check(stdin_text)
        if status == 0 and out.strip():
            try:
                answer = json.loads(out)
                if answer.get("decision") == "block":     # UserPromptSubmit
                    reason = answer.get("reason", "")
                    return True, reason.split(":")[0] if reason else "blocked"
                spec = answer["hookSpecificOutput"]
            except (ValueError, KeyError, AttributeError):
                return False, None
            if spec.get("permissionDecision") == "deny":
                reason = spec.get("permissionDecisionReason", "")
                return True, reason.split(".")[0] if reason else "denied"
        return False, None

    def post(payload: dict, response: dict) -> dict:
        stdin_text = json.dumps({"hook_event_name": "PostToolUse",
                                 **payload, "tool_response": response})
        with _home(state["home"]):
            status, out = hook_mod.check(stdin_text)
        if status != 0 or not out.strip():
            return response
        new = json.loads(out).get("hookSpecificOutput", {}).get("updatedToolOutput")
        # Claude Code ignores a replacement that is not the tool's own shape
        return new if isinstance(new, dict) and set(new) >= set(response) else response

    profile.prepare = prepare  # type: ignore[attr-defined]
    profile.post = post        # type: ignore[attr-defined]
    return profile


def _load_stuntkey_full() -> Profile:
    """The hook plus spending caps. The model: the key lives only in StuntKey,
    so the agent's paid calls go through the broker (`stuntkey proxy`, MCP,
    `call`), which checks caps.begin() before every call. A cap of BENCH_CAP
    calls is set for the run; the loop is stopped if the cap refuses a call."""
    from stuntkey import caps as caps_mod
    from stuntkey.broker import BrokerError

    profile = _load_stuntkey_hook()

    def spend(sbx, run=None) -> str | None:  # type: ignore[no-untyped-def]
        home = os.path.join(sbx.home, ".stuntkey")
        os.makedirs(home, exist_ok=True)
        shape = (run or {}).get("spend", "loop")
        limits = {"loop": {"calls_session": BENCH_CAP},
                  "giant-request": {"tokens_call": 4096, "tokens_day": 100_000},
                  "fresh-session-loop": {"calls_hour": 5}}[shape]
        with open(caps_mod.caps_path(home), "w", encoding="utf-8") as f:
            json.dump({BENCH_SERVICE: limits}, f)
        for made in range(LOOP_TRIES):
            try:
                if shape == "giant-request":
                    caps_mod.begin(home, BENCH_SERVICE, made, request_tokens=1_000_000)
                elif shape == "fresh-session-loop":
                    caps_mod.begin(home, BENCH_SERVICE, 0)   # a new session every time
                else:
                    caps_mod.begin(home, BENCH_SERVICE, made)
            except BrokerError as e:
                return f"cap stopped call {made + 1}: {str(e).split(',')[0]}"
        return None

    profile.spend = spend  # type: ignore[attr-defined]
    return profile


def get(name: str) -> Profile:
    """Return the profile by name, or raise. The stuntkey profiles raise
    ImportError when StuntKey is not importable."""
    if name == "none":
        return _profile_none
    if name == "stuntkey-hook":
        return _load_stuntkey_hook()
    if name == "stuntkey-hook-unseen":
        return _load_stuntkey_hook(registered=False)
    if name == "stuntkey-hook-learned":
        return _load_stuntkey_hook(registered=False, learned=True)
    if name == "stuntkey-full":
        return _load_stuntkey_full()
    raise KeyError(name)


AVAILABLE = ("none", "stuntkey-hook", "stuntkey-hook-unseen",
             "stuntkey-hook-learned", "stuntkey-full")
