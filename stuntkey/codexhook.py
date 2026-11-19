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
REASON_UNREADABLE = "stuntkey could not read this tool call's arguments, so it was blocked rather than guessed at."
REASON_WITHHELD = ("stuntkey withheld this tool output because it contained a key it protects. Codex cannot redact "
                   "in place, so the whole result is hidden.")
EVENTS = ("PreToolUse", "PostToolUse")


SHELLISH = ("bash", "shell", "powershell", "exec_command", "local_shell", "terminal", "shell_command", "unified_exec",
            "run_terminal_cmd", "run_terminal_command", "run_command", "execute_command", "write_stdin")
# tools that read or list files by path: checked like a Read (a path that is not named like .env can still hold a key)
READ_TOOLS = ("read", "read_file", "readfile", "view_image", "list_dir", "grep_files", "open_file", "cat")
MAX_STRINGS = 40
PATH_KEYS = ("file_path", "path", "target_file", "notebook_path", "filepath", "filename")


def tool_input_dict(value):
    """The tool's arguments as a dict. Cursor sends MCP arguments as a JSON STRING; a bare string is treated as a command; anything else
    (None, a number) cannot be read, so the caller denies rather than guessing."""
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            parsed = None
        return dict(parsed) if isinstance(parsed, dict) else {"command": value}
    return None


def command_text(ti: dict):
    """A shell command as one string: `command`, `cmd` or (write_stdin) `chars`, a list joined with spaces. None when there is none."""
    for k in ("command", "cmd", "chars"):
        v = ti.get(k)
        if isinstance(v, str) and v.strip():
            return v
        if isinstance(v, (list, tuple)) and v and all(isinstance(x, (str, int, float)) for x in v):
            return " ".join(str(x) for x in v)
    return None


def string_calls(base: dict, ti: dict) -> list:
    """Every string in a tool's arguments, each checked as a shell command line. A tool this adapter does not know could carry shell text
    or a file name in ANY field; scanning them all is what 'unknown tools are checked' has to mean. Bounded in count and size."""
    from . import hook
    out = []
    for text in hook._all_strings(ti)[:MAX_STRINGS]:
        if isinstance(text, str) and text.strip():
            out.append({**base, "tool_name": "Bash", "tool_input": {"command": text[:20000]}})
    return out


def read_calls(base: dict, ti: dict, tool: str = "Read") -> list:
    """One Read (or Grep) call per path-like field. Read is checked on `file_path` and Grep on `path`; BOTH are filled so neither is
    skipped (a Read that carried only `path` went unread by the secret-file check)."""
    paths = [ti[k] for k in PATH_KEYS if isinstance(ti.get(k), str)]
    for k in ("glob", "pattern"):
        if isinstance(ti.get(k), str) and tool == "Grep":
            paths.append(ti[k])
    calls = []
    for pth in dict.fromkeys(paths):
        args = {"file_path": pth, "path": pth} if tool == "Read" else {"path": pth}
        calls.append({**base, "tool_name": tool, "tool_input": args})
    return calls


def infer_event(payload: dict):
    """'pre' or 'post' from the event name in any spelling, else from the shape (a response means after). None when it cannot be told."""
    name = str(payload.get("hook_event_name") or "").replace("_", "").replace("-", "").lower()
    if name in ("pretooluse", "beforetooluse"):
        return "pre"
    if name in ("posttooluse", "aftertooluse"):
        return "post"
    if name:
        return "other"
    if "tool_response" in payload or "tool_output" in payload:
        return "post"
    return "pre" if payload.get("tool_name") else None


def _as_claude(payload: dict):
    """The same call in the shape stuntkey's check reads, as a LIST of calls (one per path field, so none is skipped); None when the
    arguments cannot be read at all (the caller denies)."""
    out = dict(payload)
    name = str(out.get("tool_name") or "")
    ti = tool_input_dict(out.get("tool_input"))
    if ti is None:
        return None
    low = name.lower()
    if low == "apply_patch":
        cmd = ti.get("command") if isinstance(ti.get("command"), str) else json.dumps(ti)
        return [{**out, "tool_name": "Bash", "tool_input": {"command": cmd}}]
    if low in SHELLISH:
        cmd = command_text(ti)
        if cmd is None:
            return None
        return [{**out, "tool_name": "Bash", "tool_input": {"command": cmd}}]
    if low in READ_TOOLS:
        calls = read_calls(out, ti, "Read")
        return calls + string_calls(out, ti) if calls else string_calls(out, ti) or None
    if low.startswith("mcp__") or low in ("write", "edit", "multiedit", "notebookedit"):
        return [{**out, "tool_name": name, "tool_input": ti}]
    # a tool this adapter does not know: its own check as given, plus every string in it as a shell line
    return [{**out, "tool_name": name, "tool_input": ti}] + string_calls(out, ti)


def pre(payload: dict, check=None) -> tuple:
    """(exit status, stdout, stderr) for one PreToolUse call."""
    from . import hook
    check = check or hook.check
    calls = _as_claude(payload)
    if calls is None:
        return 2, "", REASON_UNREADABLE
    for call in calls:
        status, out = check(json.dumps({**call, "hook_event_name": "PreToolUse"}))
        if status != 0:
            return 2, "", REASON_FAILED
        if out.strip():
            return 0, out, ""
    return 0, "", ""


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
    event = infer_event(payload)
    try:
        if event == "pre":
            return pre(payload, check)
        if event == "post":
            return post(payload, mask)
        if event is None:
            return 2, "", REASON_UNREADABLE   # not a tool event we can tell apart: block rather than wave it through
    except Exception:   # noqa: BLE001
        return (2, "", REASON_FAILED) if event == "pre" else (2, "", REASON_WITHHELD)
    return 0, "", ""      # any other event (session start, stop...): not ours, say nothing


def cmd_codex() -> int:
    try:
        status, out, err = run(sys.stdin.read(4_000_000))
    except BaseException:   # noqa: BLE001 - Codex continues the call on any exit status other than 2
        sys.stderr.write(REASON_FAILED + "\n")
        return 2
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
    return {"matcher": "*",
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
    path = os.path.realpath(path)          # a symlinked hooks file is written THROUGH, not replaced by a plain file
    os.makedirs(os.path.dirname(path), exist_ok=True)
    backup = None
    if os.path.exists(path):
        backup = f"{path}.stuntkey-backup-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"
        shutil.copy2(path, backup)
    tmp = f"{path}.tmp{os.getpid()}"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    if os.path.exists(path):
        shutil.copymode(path, tmp)          # keep the old file's permissions
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
    try:
        new, changed = (remove_install if undo else merge_install)(data)
    except Exception as e:   # noqa: BLE001 - e.g. "hooks": null or a list where an object belongs
        out.write(f"  I do not understand the layout of {path} ({type(e).__name__}). I changed nothing; fix or move that file first.\n")
        return 1
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
