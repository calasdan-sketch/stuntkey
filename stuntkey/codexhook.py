"""stuntkey for OpenAI Codex CLI hooks.

BUILT FROM CODEX'S PUBLISHED HOOK DOCUMENTATION (developers.openai.com/codex/hooks, read 2026-11-19). Codex is not installed where this
was written, so it has been tested only against the JSON that page documents, NOT inside the real app. Run `stuntkey hook codex-status`
after installing, and read the limits below.

How Codex differs from Claude Code, and what this does about it:
  - PreToolUse: same fields (`tool_name`, `tool_input`) and the same deny answer, so stuntkey's own check is reused as it is.
    `apply_patch` carries its patch text in `tool_input.command`; it is checked as a shell command, which refuses a patch that
    names a .env file or carries a stored key.
  - Codex cannot rewrite a tool's output (`updatedToolOutput` is not supported). Claude Code gets keys masked in place; here the
    whole result is WITHHELD instead: a blocking PostToolUse replaces the result with the reason. So a command whose output held a
    stored key shows the model nothing but "withheld", not a redacted copy.
  - Codex does not support `ask`; stuntkey's check only ever denies, so that does not matter.
  - A hook that fails or times out lets the call through in Codex. Here every failure answers deny (exit 2), the fail-closed choice
    the Claude Code installer makes by default.
Limits (Codex's own words: "a useful guardrail, not a complete enforcement boundary"): hosted tools such as WebSearch do not run hooks;
some specialised tool paths opt out; Codex asks you to review and trust each hook before it runs (`/hooks`), which cannot be
automated; and the shape of `tool_response` is not specified, so output is checked by scanning every string in it."""
import json
import os
import shutil
import sys
import time

REASON_FAILED = "stuntkey could not check this call, so it was blocked (a hook that fails would let the call through)."
REASON_WITHHELD = ("stuntkey withheld this tool output because it contained a key it protects. Codex cannot redact "
                   "in place, so the whole result is hidden.")
EVENTS = ("PreToolUse", "PostToolUse")


def _deny(reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                              "permissionDecisionReason": reason}}) + "\n"


def _as_claude(payload: dict) -> dict:
    """The same call in the shape stuntkey's check reads. Only `apply_patch` needs mapping."""
    out = dict(payload)
    if out.get("tool_name") == "apply_patch":
        ti = out.get("tool_input") if isinstance(out.get("tool_input"), dict) else {}
        out["tool_name"] = "Bash"
        out["tool_input"] = {"command": ti.get("command") if isinstance(ti.get("command"), str) else json.dumps(ti)}
    return out


def pre(payload: dict, check=None) -> tuple:
    """(exit status, stdout, stderr) for one PreToolUse call."""
    from . import hook
    check = check or hook.check
    status, out = check(json.dumps({**_as_claude(payload), "hook_event_name": "PreToolUse"}))
    if status != 0:
        return 2, "", REASON_FAILED
    return 0, out, ""


def post(payload: dict, mask=None) -> tuple:
    """(exit status, stdout, stderr) for one PostToolUse call. Withholds the whole result when it holds a protected key."""
    from . import scrub as scrub_mod
    from . import hook
    mask = mask or hook._mask_all
    resp = payload.get("tool_response")
    if resp is None:
        return 0, "", ""
    try:
        _new, hits = mask(resp, scrub_mod.load_fingerprints(), deadline=time.monotonic() + hook.POST_BUDGET,
                          secrets=scrub_mod.stored_secrets())
    except Exception:   # noqa: BLE001 - an output check that failed must not let the output through
        return 2, "", REASON_WITHHELD
    if hits:
        return 0, json.dumps({"decision": "block", "reason": REASON_WITHHELD,
                              "hookSpecificOutput": {"hookEventName": "PostToolUse"}}) + "\n", ""
    return 0, "", ""


def run(stdin_text: str, check=None, mask=None) -> tuple:
    """What `stuntkey hook codex` does: read Codex's JSON, answer in Codex's format. Never raises."""
    try:
        payload = json.loads(stdin_text)
        if not isinstance(payload, dict):
            raise ValueError("not an object")
    except Exception:   # noqa: BLE001
        return 2, "", REASON_FAILED
    event = payload.get("hook_event_name")
    try:
        if event == "PreToolUse":
            return pre(payload, check)
        if event == "PostToolUse":
            return post(payload, mask)
    except Exception:   # noqa: BLE001
        return 2, "", REASON_FAILED if event == "PreToolUse" else REASON_WITHHELD
    return 0, "", ""      # any other event: not ours, say nothing


def cmd_codex() -> int:
    status, out, err = run(sys.stdin.read(4_000_000))
    if out:
        sys.stdout.write(out)
    if err:
        sys.stderr.write(err + "\n")
    return status


# ---- config: ~/.codex/hooks.json (Windows: %USERPROFILE%\.codex\hooks.json)
def hooks_path(home: str | None = None) -> str:
    base = os.environ.get("CODEX_HOME") or os.path.join(home or os.path.expanduser("~"), ".codex")
    return os.path.join(base, "hooks.json")


def command_line(sub: str = "codex") -> str:
    exe = sys.executable or "python"
    q = (lambda s: '"' + s + '"') if " " in exe else (lambda s: s)
    flag = "-P" if sys.version_info >= (3, 11) else "-I"
    return f"{q(exe)} {flag} -m stuntkey hook {sub}"


def _entry(event: str) -> dict:
    return {"matcher": "Bash|apply_patch|mcp__.*" if event == "PreToolUse" else "Bash|apply_patch|mcp__.*",
            "hooks": [{"type": "command", "command": command_line(),
                       "statusMessage": "stuntkey: checking" if event == "PreToolUse" else "stuntkey: checking output",
                       "timeout": 20}]}


def _is_ours(group: dict) -> bool:
    return any("stuntkey" in str(h.get("command", "")) and " hook codex" in str(h.get("command", ""))
               for h in (group.get("hooks") or []) if isinstance(h, dict))


def merge_install(data: dict) -> tuple:
    """(new data, changed). Adds our PreToolUse and PostToolUse entries; keeps every other hook; idempotent."""
    out = json.loads(json.dumps(data if isinstance(data, dict) else {}))
    hooks = out.setdefault("hooks", {})
    changed = False
    for ev in EVENTS:
        groups = hooks.setdefault(ev, [])
        if not any(_is_ours(g) for g in groups if isinstance(g, dict)):
            groups.append(_entry(ev))
            changed = True
    return out, changed


def remove_install(data: dict) -> tuple:
    out = json.loads(json.dumps(data if isinstance(data, dict) else {}))
    changed = False
    for ev in EVENTS:
        groups = (out.get("hooks") or {}).get(ev)
        if isinstance(groups, list):
            keep = [g for g in groups if not (isinstance(g, dict) and _is_ours(g))]
            if len(keep) != len(groups):
                changed = True
                out["hooks"][ev] = keep
                if not keep:
                    del out["hooks"][ev]
    return out, changed


def _load(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    if not isinstance(d, dict):
        raise ValueError("the hooks file is not a JSON object")
    return d


def _save(path: str, data: dict) -> str | None:
    """Write atomically; keep one backup of the old file beside it. Returns the backup path."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    backup = None
    if os.path.exists(path):
        backup = path + ".stuntkey-backup-" + time.strftime("%Y%m%d-%H%M%S")
        shutil.copy2(path, backup)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)
    return backup


def cmd_install(write: bool, undo: bool = False, path: str | None = None, out=None) -> int:
    out = out or sys.stdout
    path = path or hooks_path()
    try:
        data = _load(path)
    except (OSError, ValueError) as e:
        out.write(f"  I cannot read {path} ({e}). I changed nothing; fix or move that file first.\n")
        return 1
    new, changed = (remove_install if undo else merge_install)(data)
    if not write:
        out.write(f"  This is what stuntkey would {'remove from' if undo else 'put in'} {path} (nothing was changed; add --write to do it):\n\n")
        out.write(json.dumps(new, indent=2) + "\n")
        return 0
    if not changed:
        out.write(f"  Nothing to {'remove' if undo else 'add'}: {path} is already {'without' if undo else 'set up with'} the stuntkey hook.\n")
        return 0
    backup = _save(path, new)
    out.write(f"  {'Removed' if undo else 'Added'} the stuntkey hook {'from' if undo else 'to'} {path}.\n")
    if backup:
        out.write(f"  Your old file is kept as {backup}.\n")
    if not undo:
        out.write("  One step is yours: Codex will not run a new hook until you trust it. Open Codex, type /hooks, and approve the "
                  "two stuntkey entries.\n"
                  "  Limits: Codex hooks are 'a useful guardrail, not a complete enforcement boundary' (its own docs). "
                  "Hosted tools like WebSearch do not run hooks. If a command's output holds a protected key, the whole result "
                  "is hidden (Codex cannot redact in place). Built from Codex's documentation; not yet run inside the real app.\n")
    return 0


def cmd_status(path: str | None = None, out=None) -> int:
    out = out or sys.stdout
    path = path or hooks_path()
    try:
        data = _load(path)
    except (OSError, ValueError) as e:
        out.write(f"  Cannot read {path}: {e}\n")
        return 1
    have = [ev for ev in EVENTS if any(_is_ours(g) for g in (data.get("hooks") or {}).get(ev, []) if isinstance(g, dict))]
    if len(have) == len(EVENTS):
        out.write(f"  Installed in {path} (PreToolUse and PostToolUse). Codex must also be told to trust it: open Codex and type /hooks.\n")
        return 0
    out.write(f"  Not (fully) installed in {path}: has {', '.join(have) or 'neither event'}. Run `stuntkey hook codex-install --write`.\n")
    return 1
