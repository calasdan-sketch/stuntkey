"""stuntkey for Cursor hooks.

BUILT FROM CURSOR'S PUBLISHED HOOK DOCUMENTATION (cursor.com/docs/hooks, read 2026-11-19). Cursor is not installed where this was
written, so it has been tested only against the JSON that page documents, NOT inside the real app.

How Cursor differs from Claude Code, and what this does about it:
  - Tool names differ: Shell, Read, Write, Grep, Delete, Task and MCP:<name>. They are mapped to the names stuntkey's own check reads
    (Shell -> Bash, MCP:x -> mcp__cursor__x). The file-path field of Read/Write/Grep calls is not specified on that page, so
    `file_path`, `path` and `target_file` are all accepted.
  - The deny answer is `{"permission": "deny", "user_message", "agent_message"}`; stuntkey's deny is converted.
  - Cursor hooks FAIL OPEN by default. The install sets `failClosed: true`, and any failure here also answers exit 2 (block).
  - THE BIG LIMIT: after a tool runs, Cursor lets a hook replace the output of MCP tools only (`updated_mcp_tool_output`). The output of a
    shell command, a file read or a search CANNOT be hidden or redacted by a hook. So on Cursor stuntkey protects only BEFORE the call:
    it refuses commands and reads that would show a key; it cannot clean up afterwards. Keys in an MCP tool's output are withheld.
  - Hooks are a guardrail, not an enforcement boundary; Tab completions and some paths have separate hooks that are not covered."""
import json
import os
import shutil
import sys
import time

from . import codexhook as _shared

REASON_FAILED = "stuntkey could not check this call, so it was blocked (Cursor hooks fail open unless told otherwise)."
REASON_WITHHELD = "stuntkey withheld this MCP tool output because it contained a key it protects."
NAME_MAP = {"Shell": "Bash", "Read": "Read", "Write": "Write", "Grep": "Grep", "Task": "Task"}
PATH_FIELDS = ("file_path", "path", "target_file")
PRE_MATCHER = "Shell|Read|Write|Grep|Delete|Task|MCP:.*"
POST_MATCHER = "MCP:.*"


def _deny_for_cursor(check_stdout: str) -> str:
    try:
        spec = json.loads(check_stdout)["hookSpecificOutput"]
        if spec.get("permissionDecision") != "deny":
            return ""
        why = str(spec.get("permissionDecisionReason") or "blocked by stuntkey")
    except Exception:   # noqa: BLE001
        return json.dumps({"permission": "deny", "user_message": REASON_FAILED, "agent_message": REASON_FAILED}) + "\n"
    return json.dumps({"permission": "deny", "user_message": why, "agent_message": why}) + "\n"


def as_claude(payload: dict) -> dict:
    """The same call in the shape stuntkey's check reads."""
    out = dict(payload)
    name = str(out.get("tool_name") or "")
    ti = dict(out.get("tool_input")) if isinstance(out.get("tool_input"), dict) else {}
    if name.startswith("MCP:"):
        out["tool_name"] = "mcp__cursor__" + name[4:]
    elif name == "Delete":
        out["tool_name"] = "Write"
        ti.setdefault("content", "")
    elif name in NAME_MAP:
        out["tool_name"] = NAME_MAP[name]
    if "file_path" not in ti:
        for f in PATH_FIELDS:
            if isinstance(ti.get(f), str):
                ti["file_path"] = ti[f]
                break
    if name == "Write" and "content" not in ti and isinstance(ti.get("contents"), str):
        ti["content"] = ti["contents"]
    out["tool_input"] = ti
    return out


def pre(payload: dict, check=None) -> tuple:
    from . import hook
    check = check or hook.check
    status, out = check(json.dumps({**as_claude(payload), "hook_event_name": "PreToolUse"}))
    if status != 0:
        return 2, "", REASON_FAILED
    if not out.strip():
        return 0, json.dumps({"permission": "allow"}) + "\n", ""
    return 0, _deny_for_cursor(out), ""


def post(payload: dict, mask=None) -> tuple:
    """Only MCP tool output can be replaced in Cursor. Any other tool: nothing can be done after the call, so say nothing."""
    name = str(payload.get("tool_name") or "")
    if not name.startswith("MCP:"):
        return 0, "", ""
    from . import hook
    from . import scrub as scrub_mod
    mask = mask or hook._mask_all
    try:
        raw = payload.get("tool_output")
        value = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:   # noqa: BLE001
        value = payload.get("tool_output")
    try:
        _new, hits = mask(value, scrub_mod.load_fingerprints(), deadline=time.monotonic() + hook.POST_BUDGET,
                          secrets=scrub_mod.stored_secrets())
    except Exception:   # noqa: BLE001
        hits = 1
    if hits:
        return 0, json.dumps({"updated_mcp_tool_output": {"withheld": REASON_WITHHELD}}) + "\n", ""
    return 0, "", ""


def run(stdin_text: str, check=None, mask=None) -> tuple:
    try:
        payload = json.loads(stdin_text)
        if not isinstance(payload, dict):
            raise ValueError("not an object")
    except Exception:   # noqa: BLE001
        return 2, "", REASON_FAILED
    event = payload.get("hook_event_name")
    try:
        if event == "preToolUse":
            return pre(payload, check)
        if event == "postToolUse":
            return post(payload, mask)
    except Exception:   # noqa: BLE001
        return (2, "", REASON_FAILED) if event == "preToolUse" else (0, "", "")
    return 0, "", ""


def cmd_cursor() -> int:
    status, out, err = run(sys.stdin.read(4_000_000))
    if out:
        sys.stdout.write(out)
    if err:
        sys.stderr.write(err + "\n")
    return status


# ---- config: ~/.cursor/hooks.json
def hooks_path(home: str | None = None) -> str:
    return os.path.join(home or os.path.expanduser("~"), ".cursor", "hooks.json")


def _entry(event: str) -> dict:
    return {"command": _shared.command_line("cursor"), "matcher": PRE_MATCHER if event == "preToolUse" else POST_MATCHER,
            "timeout": 20, "failClosed": True}


def _is_ours(e) -> bool:
    return isinstance(e, dict) and "stuntkey" in str(e.get("command", "")) and " hook cursor" in str(e.get("command", ""))


EVENTS = ("preToolUse", "postToolUse")


def merge_install(data: dict) -> tuple:
    out = json.loads(json.dumps(data if isinstance(data, dict) else {}))
    out.setdefault("version", 1)
    hooks = out.setdefault("hooks", {})
    changed = False
    for ev in EVENTS:
        lst = hooks.setdefault(ev, [])
        if not any(_is_ours(e) for e in lst):
            lst.append(_entry(ev))
            changed = True
    return out, changed


def remove_install(data: dict) -> tuple:
    out = json.loads(json.dumps(data if isinstance(data, dict) else {}))
    changed = False
    for ev in EVENTS:
        lst = (out.get("hooks") or {}).get(ev)
        if isinstance(lst, list):
            keep = [e for e in lst if not _is_ours(e)]
            if len(keep) != len(lst):
                changed = True
                out["hooks"][ev] = keep
                if not keep:
                    del out["hooks"][ev]
    return out, changed


def cmd_install(write: bool, undo: bool = False, path: str | None = None, out=None) -> int:
    out = out or sys.stdout
    path = path or hooks_path()
    try:
        data = _shared._load(path)
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
    backup = _shared._save(path, new)
    out.write(f"  {'Removed' if undo else 'Added'} the stuntkey hook {'from' if undo else 'to'} {path}.\n")
    if backup:
        out.write(f"  Your old file is kept as {backup}.\n")
    if not undo:
        out.write("  Limits, plainly: Cursor cannot hide or clean up the output of a shell command, a file read or a search, so stuntkey can "
                  "only refuse those BEFORE they run. It can withhold a key from an MCP tool's output. The hook is set to block when it "
                  "fails (Cursor lets calls through by default). Built from Cursor's documentation; not yet run inside the real app. "
                  "Restart Cursor so it loads the hook.\n")
    return 0


def cmd_status(path: str | None = None, out=None) -> int:
    out = out or sys.stdout
    path = path or hooks_path()
    try:
        data = _shared._load(path)
    except (OSError, ValueError) as e:
        out.write(f"  Cannot read {path}: {e}\n")
        return 1
    have = [ev for ev in EVENTS if any(_is_ours(e) for e in (data.get("hooks") or {}).get(ev, []))]
    if len(have) == len(EVENTS):
        out.write(f"  Installed in {path} (preToolUse and postToolUse).\n")
        return 0
    out.write(f"  Not (fully) installed in {path}: has {', '.join(have) or 'neither event'}. Run `stuntkey hook cursor-install --write`.\n")
    return 1
