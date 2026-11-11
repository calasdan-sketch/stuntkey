"""`stuntkey setup` (everything in one go) and `stuntkey test` (one-line check).

setup = look for loose keys + move them into the keychain + switch on the
protection (Claude Code's safety check, Claude Desktop / Cursor, Claude Code
for all folders) + test, after ONE yes at the start. Every step is undoable
(`stuntkey undo`). It ends with "You're set up" or "Not safe yet: do X".

test = a pretend AI call goes through the real broker to a tiny local pretend
server; ONE line comes out: PASS or FAIL, and the one next step.

Nothing here prints a key. The pretend key is made up.
"""
from __future__ import annotations

import os
import sys

FAKE_KEY = "sk-FAKE-stuntkey-check-0000-not-a-real-key"


def _p(x) -> str:
    from . import recipes as recipes_mod
    return recipes_mod.printable(str(x))


# ------------------------------------------------------------------ test

class Result:
    def __init__(self, ok: bool, line: str, steps: list | None = None):
        self.ok, self.line, self.details = ok, line, steps or []


def _fake_round_trip() -> tuple:
    """(ok, plain sentence). A pretend AI call through the real broker to a
    local pretend server. The server echoes the pretend key back; the broker
    must hide it."""
    import http.client
    import http.server
    import tempfile
    import threading
    import urllib.parse
    from . import broker
    from . import recipes as recipes_mod

    class Fake(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            size = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(min(size, 100_000))
            auth = self.headers.get("Authorization", "")
            if auth != "Bearer " + FAKE_KEY:
                self.send_response(401)
                self.end_headers()
                return
            import json
            body = json.dumps({"id": "msg_check", "type": "message",
                               "content": [{"type": "text", "text": "pong"}],
                               "you_sent": auth}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Fake)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    work = tempfile.mkdtemp(prefix="skcheck")
    try:
        recipe = recipes_mod.validate_recipe({
            "service": "stuntkey-check", "display": "Pretend AI service",
            "key_url": "https://check.example.com/keys", "env_var": "CHECK_API_KEY",
            "steps": ["none: this is a pretend service"],
            "validate": {"method": "GET", "url": "https://api.check.example.com/v1/models",
                         "auth": {"type": "bearer"}, "expect": [200]},
            "untested": True})

        def send(req, _ip, _timeout):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                conn.request(req.get_method(), urllib.parse.urlsplit(req.full_url).path,
                             body=req.data, headers=dict(req.header_items()))
                r = conn.getresponse()
                return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
            finally:
                conn.close()

        policy = broker.Policy(allow_write=True, home=work, project_dir=work)
        try:
            out = broker.call(recipe, {"CHECK_API_KEY": FAKE_KEY}, "POST", "/v1/messages",
                              None, {"model": "pretend", "messages": [{"role": "user",
                                                                       "content": "ping"}]},
                              policy=policy, audit=None, send=send,
                              resolver=lambda host, port, **k: [(2, 1, 6, "", ("140.82.112.5", port))])
        except broker.BrokerError as e:
            return False, f"the pretend call was refused: {_p(e)[:120]}"
        if out.get("status") != 200 or "pong" not in out.get("body", ""):
            return False, "the pretend server did not answer as expected"
        if FAKE_KEY in out.get("body", "") or FAKE_KEY in str(out.get("headers", "")):
            return False, "the pretend key showed up in the answer (it must be hidden)"
        return True, "a pretend AI call went through and the key stayed hidden"
    finally:
        server.shutdown()
        server.server_close()
        import shutil
        shutil.rmtree(work, ignore_errors=True)


def run_check(catalog: dict | None = None) -> Result:
    from . import clients, claudecode, fixcmd, hook
    problems = []

    kc = fixcmd._keychain_item()
    if kc.level == fixcmd.RED:
        problems.append((kc.text, kc.step))
    for it in fixcmd._hook_items(hook.user_settings_path(), "user", required=True):
        if it.level == fixcmd.RED:
            problems.append((it.text, it.step or "Run `stuntkey fix`."))
    plugged = bool(clients.plugged()) or claudecode.state() == "ok"
    if not plugged:
        if claudecode.detected() and claudecode.cli_path() is None:
            step = ("Type this one command, then close and reopen Claude: "
                    + claudecode.one_command())
        elif any(os.path.exists(p) for n, (p, _k) in clients.targets().items()
                 if n in ("claude-desktop", "cursor")) or claudecode.detected():
            step = "Run `stuntkey fix`, then close and reopen Claude"
        else:
            step = ("Install Claude Desktop or Claude Code first, then run "
                    "`stuntkey setup`")
        problems.append(("stuntkey is not plugged into any AI app yet", step))
    try:
        ok, why = _fake_round_trip()
    except Exception as e:      # noqa: BLE001 - a check must answer, not crash
        ok, why = False, f"the pretend call could not run ({type(e).__name__})"
    if not ok:
        problems.append((why, "Run `stuntkey doctor` and read the first red line; "
                              "if it says nothing useful, run `pipx reinstall stuntkey`."))
    if problems:
        text, step = problems[0]
        return Result(False, f"FAIL: {text.rstrip('.')}. Next: {step.rstrip('.')}.",
                      [f"{t} Next: {s}" for t, s in problems])
    return Result(True, "PASS: a pretend AI call went through, the key stayed hidden, "
                        "and your AI app is plugged in.")


def cmd_test(args=None, catalog=None, out=None) -> int:
    out = out or sys.stdout
    res = run_check(catalog)
    out.write(_p(res.line) + "\n")
    if getattr(args, "verbose", False) and len(res.details) > 1:
        for d in res.details[1:]:
            out.write(f"  also: {_p(d)}\n")
    return 0 if res.ok else 1


# ------------------------------------------------------------------ setup

def _scan_env(root: str, catalog: dict, with_values: bool = False) -> dict:
    """What is in the project's .env files: new = keys I can save, have =
    already saved (left alone), skipped = right name, wrong-looking value,
    unknown = names with no service. Values only when asked."""
    from . import connect_import, findkeys, keychain
    from . import scan as scan_mod
    root = os.path.abspath(root)
    root_real = os.path.realpath(root)
    new, have, skipped, unknown, files = [], [], [], [], []
    try:
        backend = keychain.detect_backend()
    except Exception:           # noqa: BLE001
        backend = None
    for path in findkeys.env_files(root):
        text, _why = scan_mod.read_text_safely(path, root_real)
        if text is None:
            continue
        try:
            pairs = connect_import.parse_env(text)
        except Exception:       # noqa: BLE001
            continue
        text = None
        rel = os.path.relpath(path, root).replace("\\", "/")
        matched, unk, info = connect_import.match_services_ex(pairs, catalog)
        pairs = None
        if matched or unk:
            files.append(rel)
        unknown += [n for n in unk if n not in unknown]
        for recipe, var, value in matched:
            why = connect_import.shape_problem(recipe, var, value,
                                               strict_name=var not in info["by_title"])
            if not why and scan_mod.is_placeholder((value or "").strip()):
                # the same call `scan` makes: an example is never moved or counted
                why = "looks like an example"
            if why:
                skipped.append((var, why))
                continue
            try:
                had = bool(backend and keychain.read(recipe["service"], var, backend))
            except Exception:   # noqa: BLE001
                had = False
            if had:
                have.append((recipe["service"], var))
            else:
                new.append((rel, recipe, var, value if with_values else None))
    return {"new": new, "have": have, "skipped": skipped, "unknown": unknown,
            "files": files, "backend": backend}


def _plan_text(env: dict, examples: list, fixable: list, claude_note: str) -> str:
    lines = ["", "  stuntkey setup: one go, one yes.", ""]
    lines.append("  What I found:")
    if env["new"]:
        names = ", ".join(sorted({v for _f, _r, v, _x in env["new"]}))
        lines.append(f"    - {len(env['new'])} key(s) in {', '.join(env['files'])} that I can "
                     f"move into your keychain: {_p(names)}")
    else:
        lines.append("    - no loose keys that I can move")
    for service, var in env["have"]:
        lines.append(f"    - {_p(var)} is already in your keychain (left alone)")
    for var, why in env["skipped"]:
        lines.append(f"    - {_p(var)} {_p(why)} (skipped)")
    said = {var for var, _why in env["skipped"]}
    for rel, name in [e for e in examples if e[1] not in said][:6]:
        lines.append(f"    - {_p(name)} in {_p(rel)} looks like an example, skipped")
    if fixable:
        lines.append("    - things to switch on:")
        for i in fixable:
            lines.append(f"        * {_p(i.fix_text or i.text)}")
    else:
        lines.append("    - nothing else to switch on")
    if claude_note:
        lines.append(f"    - {claude_note}")
    lines += ["", "  Then I will test that it all works.",
              "  Every change keeps a backup, and `stuntkey undo` puts it back.",
              "  Your .env file is not deleted. Your keys are never shown.", ""]
    return "\n".join(lines)


def _import_keys(root: str, catalog: dict, out, change) -> int:
    """Save the keys; returns how many were saved. Never shows a value."""
    from . import keychain
    env = _scan_env(root, catalog, with_values=True)
    saved = 0
    backend = env["backend"]
    if backend is None:
        out.write("  Keys: this computer has no keychain I can use, so I moved nothing.\n")
        return 0
    for rel, recipe, var, value in env["new"]:
        try:
            keychain.store(recipe["service"], var, value, backend)
            change.note_key(recipe["service"], [var])
            saved += 1
            out.write(f"  Saved {_p(var)} in your keychain.\n")
        except Exception as e:      # noqa: BLE001 - never a value, never a traceback
            out.write(f"  Could not save {_p(var)}: {_p(getattr(e, 'strerror', None) or e)[:100]}\n")
    env = None
    return saved


def _final(out, ok_steps: list, problem: tuple | None, changed: bool) -> int:
    if problem is None:
        out.write("\n  You're set up.\n")
        for s in ok_steps:
            out.write(f"    - {_p(s)}\n")
    else:
        out.write(f"\n  Not safe yet: {_p(problem[0]).rstrip('.')}.\n"
                  f"  Do this: {_p(problem[1])}\n")
        for s in ok_steps:
            out.write(f"    - done: {_p(s)}\n")
    if changed:
        out.write("\n  Now close Claude (Claude Code and Claude Desktop, every window) "
                  "and open it again.\n"
                  "  Then ask it: \"Which keys can you use?\"\n")
    out.write("  Changed your mind? `stuntkey undo` puts it back.\n")
    return 0 if problem is None else 1


def cmd_setup_all(args, catalog: dict, out=None, ask=None, interactive=None,
                  root: str | None = None) -> int:
    from . import claudecode, fixcmd, findkeys, safeprompt, undo
    out = out or sys.stdout
    root = root or os.getcwd()
    env = _scan_env(root, catalog)
    examples = findkeys.examples_skipped(root, catalog)
    items = fixcmd.collect(catalog)
    fixable = []
    seen = []
    for i in items:
        if i.fixer and not any(i.fixer is s for s in seen):
            seen.append(i.fixer)
            fixable.append(i)
    claude_note = ""
    if claudecode.detected() and claudecode.cli_path() is None and claudecode.state() != "ok":
        claude_note = ("I cannot find the `claude` program, so for Claude Code in every "
                       "folder you will type one command at the end.")
    out.write(_plan_text(env, examples, fixable, claude_note))
    if getattr(args, "dry_run", False):
        out.write("  (--dry-run: nothing was changed.)\n")
        return 0
    if not getattr(args, "yes", False):
        if interactive is None:
            try:
                interactive = bool(sys.stdin and sys.stdin.isatty())
            except (OSError, ValueError):
                interactive = False
        if not interactive and ask is None:
            out.write("  Run it again in a terminal to answer, or add --yes.\n")
            return 2
        answer = safeprompt.ask("  Go ahead with all of it? [y/N] ", out,
                                enter_means=False, reader=ask)
        if answer is not True:
            out.write("  Nothing was changed.\n")
            return 1
    change = undo.begin("setup")
    done_steps = []
    try:
        fixcmd.snapshot_files(change)
        saved = _import_keys(root, catalog, out, change) if env["new"] else 0
        if saved:
            done_steps.append(f"{saved} key(s) moved into your keychain")
        failed = fixcmd.apply_fixes(fixable, out) if fixable else 0
        for i in fixable:
            done_steps.append(i.fix_text or i.key)
    finally:
        change.commit()
    # the same checks again, then the pretend call
    after = fixcmd.collect(catalog)
    problem = None
    red = [i for i in after if i.level == fixcmd.RED]
    if red:
        problem = (red[0].text, red[0].step or "Run `stuntkey fix`.")
    leftover = _scan_env(root, catalog)
    if problem is None and (leftover["have"] or leftover["new"]):
        names = sorted({v for _s, v in leftover["have"]}
                       | {v for _f, _r, v, _x in leftover["new"]})
        where = ", ".join(leftover["files"]) or ".env"
        problem = (f"{where} still holds {len(names)} key(s) in plain text "
                   f"({', '.join(names)[:80]})",
                   f"Open {where} in Notepad and delete those lines (or delete the "
                   "file if nothing else is in it). The keys are safe in your keychain now.")
    res = run_check(catalog)
    if problem is None and not res.ok:
        text, _, step = res.line[len("FAIL: "):].partition(" Next: ")
        problem = (text, step)
    out.write("\n  Test: " + _p(res.line) + "\n")
    return _final(out, done_steps, problem, bool(done_steps))
