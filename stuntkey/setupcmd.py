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
    def __init__(self, ok: bool, line: str, steps: list | None = None,
                 fault: bool = False):
        self.ok, self.line, self.details = ok, line, steps or []
        self.fault = fault          # True: the pretend call itself failed


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
    # The same checks `status` shows: if any AI app entry is not fully in place
    # (for example Claude Code for ALL folders), this test cannot say "plugged in".
    app_items = []
    if plugged:
        try:
            app_items = [i for i in fixcmd._client_items() if i.level != fixcmd.GREEN]
        except Exception:       # noqa: BLE001 - the checks must answer, not crash
            app_items = []
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
    for it in app_items:
        problems.append((it.text, it.step or "Run `stuntkey fix`."))
    ok, why = False, ""
    for _try in range(2):       # a busy computer can fail the first try: once more
        try:
            ok, why = _fake_round_trip()
        except Exception as e:  # noqa: BLE001 - a check must answer, not crash
            ok, why = False, f"the pretend call could not run ({type(e).__name__})"
        if ok:
            break
    if not ok:
        problems.append((why, "Run `stuntkey doctor` and read the first red line."))
    if problems:
        text, step = problems[0]
        return Result(False, f"FAIL: {text.rstrip('.')}. Next: {step.rstrip('.')}.",
                      [f"{t} Next: {s}" for t, s in problems], fault=not ok)
    return Result(True, "PASS: a pretend AI call went through, the key stayed hidden, "
                        "and your AI app is plugged in.")


def cmd_test(args=None, catalog=None, out=None) -> int:
    out = out or sys.stdout
    res = run_check(catalog)
    if getattr(args, 'json', False):
        import json
        out.write(json.dumps({"schema": 1, "ok": bool(res.ok), "fault": bool(res.fault),
                              "summary": _p(res.line), "details": [_p(d) for d in res.details]}) + "\n")
        return 0 if res.ok else 1
    out.write(_p(res.line) + "\n")
    if not res.ok:
        n = max(1, len(res.details))
        if res.fault:
            out.write("  Summary: the built-in check itself did not work. That is a real "
                      "fault: run `stuntkey doctor` and read the first red line.\n")
        else:
            out.write(f"  Summary: {n} thing{'' if n == 1 else 's'} still to switch on. "
                      "On a new computer this is normal; nothing is damaged. Do the "
                      "Next step above, then run `stuntkey test` again.\n")
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
            try:                # the date a key was added, for `stuntkey age` (never the key)
                from . import ledger
                ledger.record(root, recipe["service"], "keychain")
            except Exception:   # noqa: BLE001 - the record is a convenience
                pass
            saved += 1
            out.write(f"  Saved {_p(var)} in your keychain.\n")
        except Exception as e:      # noqa: BLE001 - never a value, never a traceback
            out.write(f"  Could not save {_p(var)}: {_p(getattr(e, 'strerror', None) or e)[:100]}\n")
    env = None
    return saved


def copy_text(text: str) -> bool:
    """Put `text` on the clipboard, best effort; True when it worked. Only the
    system's own copy program is used (looked for in system folders). A practice
    or test run (the in-memory keychain is on) never touches the real clipboard.
    Used only for the one command a person has to type; never for a key."""
    import subprocess
    if os.environ.get("STUNTKEY_KEYCHAIN"):
        return False
    try:
        if os.name == "nt":
            exe = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows",
                               "System32", "clip.exe")
            if not os.path.isfile(exe):
                return False
            argv = [exe]
        elif sys.platform == "darwin":
            argv = ["/usr/bin/pbcopy"]
            if not os.path.isfile(argv[0]):
                return False
        else:
            from . import safeexec
            exe = safeexec.find("wl-copy") or safeexec.find("xclip")
            if not exe:
                return False
            argv = [exe] if exe.endswith("wl-copy") else [exe, "-selection", "clipboard"]
        done = subprocess.run(argv, input=text.encode("ascii", "replace"), timeout=5,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return done.returncode == 0
    except Exception:           # noqa: BLE001 - the clipboard is a convenience
        return False


def claude_by_hand(out, copy=None) -> None:
    """The one command a person types when the `claude` program cannot be
    found, copied to the clipboard when possible, and the Claude Desktop route
    in plain words."""
    from . import claudecode
    cmd = claudecode.one_command()
    copied = (copy or copy_text)(cmd)
    out.write("\n  One step is left for Claude Code. Open any terminal window, paste this "
              "one line and press Enter:\n"
              f"      {_p(cmd)}\n")
    if copied:
        out.write("  (I copied that line for you: press Ctrl+V to paste it.)\n")
    out.write("  Using Claude Desktop instead? Nothing to type: stuntkey already added "
              "itself to its settings. Close Claude Desktop completely (also from the "
              "tray) and open it again.\n")


# ------------------------------------------------------- plaintext copies in .env

CLEAN_NOTE = "# stuntkey: {name} moved to your keychain and removed from this file"


def _is_single_line_value(line: str) -> bool:
    """False for a value that opens a quote and does not close it on this line
    (a multi-line value): such a line is never touched."""
    _head, _eq, rest = line.partition("=")
    rest = rest.strip()
    if not rest or rest[0] not in "\"'":
        return True
    q = rest[0]
    return len(rest) >= 2 and rest.endswith(q) and not rest.endswith("\\" + q)


def plan_clean(root: str, catalog: dict) -> dict:
    """What `clean-env` would do, without changing anything:
    {"files": [{"path", "rel", "names": [..], "lines": n}], "left": [(rel, name, why)]}.
    A line is only chosen when the keychain holds the SAME key: a different
    value in the file is left alone (it may be the only copy of another key)."""
    import hmac
    import re
    from . import connect_import, findkeys, keychain
    from . import scan as scan_mod
    root = os.path.abspath(root)
    root_real = os.path.realpath(root)
    files, left = [], []
    try:
        backend = keychain.detect_backend()
    except Exception:           # noqa: BLE001
        backend = None
    if backend is None:
        return {"files": [], "left": [], "backend": None}
    line_re = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=")
    for path in findkeys.env_files(root):
        text, _why = scan_mod.read_text_safely(path, root_real)
        if not text:
            continue
        rel = os.path.relpath(path, root).replace("\\", "/")
        try:
            pairs = connect_import.parse_env(text)
            matched, _unk, _info = connect_import.match_services_ex(pairs, catalog)
        except Exception:       # noqa: BLE001
            continue
        pairs = None
        names = {}
        for recipe, var, value in matched:
            if scan_mod.is_placeholder((value or "").strip()):
                continue
            try:
                saved = keychain.read(recipe["service"], var, backend)
            except Exception:   # noqa: BLE001
                saved = None
            if not saved:
                left.append((rel, var, "is not saved in your keychain"))
            elif not hmac.compare_digest(str(saved).encode(), str(value).encode()):
                left.append((rel, var, "differs from the keychain copy"))
            else:
                names[var] = recipe["service"]
        value = None
        if not names:
            continue
        count, hit = 0, set()
        for line in text.splitlines():
            m = line_re.match(line)
            if m and m.group(1) in names:
                if _is_single_line_value(line):
                    count += 1
                    hit.add(m.group(1))
                else:
                    left.append((rel, m.group(1), "spans several lines"))
        text = None
        if hit:
            files.append({"path": path, "rel": rel, "names": sorted(hit), "lines": count})
    return {"files": files, "left": left, "backend": backend}


def apply_clean(plan: dict, change=None) -> list:
    """Comment out the planned lines. Each file is snapshotted into the undo
    store first (private, in ~/.stuntkey/undo), so `stuntkey undo` puts it
    back. Returns [(rel, "ok" | plain reason)]."""
    import re
    import tempfile
    results = []
    line_re = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=")
    for f in plan["files"]:
        path = f["path"]
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                results.append((f["rel"], "it is not plain UTF-8 text, so I left it alone"))
                continue
            bom = text.startswith("\ufeff")
            if bom:
                text = text[1:]
            names = set(f["names"])
            out_lines = []
            for line in text.splitlines(keepends=True):
                m = line_re.match(line)
                body = line.rstrip("\r\n")
                if m and m.group(1) in names and _is_single_line_value(body):
                    out_lines.append(CLEAN_NOTE.format(name=m.group(1)) + line[len(body):])
                else:
                    out_lines.append(line)
            new = ("\ufeff" if bom else "") + "".join(out_lines)
            if change is not None:
                change.snapshot_file(path)
            fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as dst:
                    dst.write(new.encode("utf-8"))
                try:
                    os.chmod(tmp, os.stat(path).st_mode & 0o777)
                except OSError:
                    pass
                os.replace(tmp, path)
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
            results.append((f["rel"], "ok"))
        except OSError as e:
            results.append((f["rel"], (e.strerror or "could not be written")))
    return results


def clean_env_command(root: str | None = None) -> str:
    return "stuntkey clean-env --yes"


def cmd_clean_env(args, catalog: dict, out=None, ask=None, interactive=None,
                  root: str | None = None) -> int:
    """`stuntkey clean-env`: for keys that are safely in the keychain, comment
    out the plaintext copy in the project's .env files. Asks first; `undo`
    puts the files back."""
    from . import safeprompt, undo
    out = out or sys.stdout
    root = root or os.getcwd()
    plan = plan_clean(root, catalog)
    if plan.get("backend") is None:
        out.write("  This computer has no keychain I can use, so I will not remove any "
                  "key from a file.\n")
        return 1
    for rel, name, why in plan["left"]:
        out.write(f"  Left alone: {_p(name)} in {_p(rel)} {_p(why)}.\n")
    if not plan["files"]:
        out.write("  No plaintext copy of a saved key was found in the .env files here. "
                  "Nothing to do.\n")
        return 0
    out.write("\n  These lines hold a key that is ALREADY safe in your keychain:\n")
    for f in plan["files"]:
        out.write(f"    {_p(f['rel'])}: {_p(', '.join(f['names']))}\n")
    out.write("  I will comment those lines out (the rest of the file stays). A copy of each "
              "file as it was is kept privately in your stuntkey folder (not next to your "
              "project, where an AI could read it), and `stuntkey undo` puts it back.\n")
    if getattr(args, "dry_run", False):
        out.write("  (--dry-run: nothing was changed.)\n")
        return 0
    if not getattr(args, "yes", False):
        if interactive is None:
            interactive = safeprompt.stdin_is_terminal()
        if not interactive and ask is None:
            out.write("  Run it again in a terminal to answer, or type this exact line: "
                      f"{clean_env_command()}\n")
            return 2
        if safeprompt.ask("  Go ahead? [y/N] ", out, enter_means=False, reader=ask) is not True:
            out.write("  Nothing was changed.\n")
            return 1
    change = undo.begin("clean-env")
    try:
        results = apply_clean(plan, change)
    finally:
        change.commit()
    bad = 0
    for rel, res in results:
        if res == "ok":
            out.write(f"  Cleaned {_p(rel)}.\n")
        else:
            bad += 1
            out.write(f"  Could not clean {_p(rel)}: {_p(res)}\n")
    out.write("  Done. Your keys are still in your keychain. "
              "Changed your mind? `stuntkey undo`.\n" if not bad else
              "  Some files could not be cleaned; see above.\n")
    return 1 if bad else 0


# ------------------------------------------------------------------ setup

def _final(out, ok_steps: list, problems, changed: bool, extra=None) -> int:
    """ONE clear state: "All done" or "Almost done: N step(s) left". The
    "close Claude and open it again" words come only with "All done", that is,
    only once the plug-in step is confirmed (the final check passed); they are
    never printed beside a failed check."""
    if isinstance(problems, tuple):                 # one problem, the old way of calling
        problems = [problems]
    problems = list(problems or [])
    if not problems:
        out.write("\n  All done. You're set up.\n")
        for s in ok_steps:
            out.write(f"    - {_p(s)}\n")
        if changed:
            out.write("\n  Now close Claude (Claude Code and Claude Desktop, every window) "
                      "and open it again.\n"
                      "  Then ask it: \"Which keys can you use?\"\n")
    else:
        n = len(problems)
        out.write(f"\n  Almost done: {n} step{'' if n == 1 else 's'} left.\n")
        for text, step in problems:
            out.write(f"    - {_p(text).rstrip('.')}.\n      Do this: {_p(step)}\n")
        # the steps that worked were already printed as Done: while they ran; not repeated here
        if extra:
            extra()
        out.write("  When those are done, run `stuntkey setup` again (it only finishes "
                  "what is left).\n")
    out.write("  Changed your mind? `stuntkey undo` puts it back.\n")
    return 0 if not problems else 1


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
    if interactive is None:
        interactive = safeprompt.stdin_is_terminal()
    if not getattr(args, "yes", False):
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
    failed_items = []
    try:
        fixcmd.snapshot_files(change)
        saved = _import_keys(root, catalog, out, change) if env["new"] else 0
        if saved:
            done_steps.append(f"{saved} key(s) moved into your keychain")
        worked = []
        fixcmd.apply_fixes(fixable, out, worked) if fixable else 0
        for i in fixable:
            if any(i is w for w in worked):
                done_steps.append(i.fix_text or i.key)
            else:
                failed_items.append(i)      # never "done" for a step that failed
    finally:
        change.commit()
    # the same checks again, then the pretend call
    after = fixcmd.collect(catalog)
    problems = []
    for i in failed_items:
        problems.append((f"Could not {i.fix_text or i.key}", i.step or "Run `stuntkey fix`."))
    for i in [i for i in after if i.level == fixcmd.RED]:
        if not any(i.text == t for t, _s in problems):
            problems.append((i.text, i.step or "Run `stuntkey fix`."))
    leftover = _scan_env(root, catalog)
    if leftover["have"] or leftover["new"]:
        if (not problems and not leftover["new"] and leftover["have"]
                and not getattr(args, "yes", False) and (interactive or ask is not None)):
            # the keys are safe; offer, once, to take the plaintext copy out
            plan = plan_clean(root, catalog)
            if plan["files"]:
                out.write("\n  Your keys are safe in the keychain, but a plaintext copy is "
                          "still in: " + _p(", ".join(f["rel"] for f in plan["files"])) + "\n")
                a = safeprompt.ask("  Comment those lines out now? A private backup is kept "
                                   "and `stuntkey undo` puts them back. [y/N] ", out,
                                   enter_means=False, reader=ask)
                if a is True:
                    ch = undo.begin("clean-env")
                    try:
                        for rel, res in apply_clean(plan, ch):
                            out.write(f"  {'Cleaned ' + _p(rel) + '.' if res == 'ok' else 'Could not clean ' + _p(rel) + ': ' + _p(res)}\n")
                    finally:
                        ch.commit()
                    done_steps.append("plaintext copies of your keys commented out")
                    leftover = _scan_env(root, catalog)
        if leftover["have"] or leftover["new"]:
            names = sorted({v for _s, v in leftover["have"]}
                           | {v for _f, _r, v, _x in leftover["new"]})
            where = ", ".join(leftover["files"]) or ".env"
            if leftover["new"]:
                step = (f"Open {where} in Notepad and delete those lines (or delete the "
                        "file if nothing else is in it).")
            else:
                step = (f"Type this one line: {clean_env_command()}   (it comments out those "
                        f"lines in {where}, keeps a private backup, and `stuntkey undo` "
                        "puts them back). Or delete the lines yourself in Notepad.")
            if not problems or not any(where in t for t, _s in problems):
                problems.append((f"{where} still holds {len(names)} key(s) in plain text "
                                 f"({', '.join(names)[:80]})", step))
    res = run_check(catalog)
    if res.ok:
        out.write("\n  Test: " + _p(res.line) + "\n")
    elif not problems:
        for d in (res.details or [res.line[len("FAIL: "):]]):
            text, _, step = d.partition(" Next: ")
            problems.append((text, step or "Run `stuntkey fix`."))
    elif res.details:
        # the test found more than the checks above: say those too, once each
        for d in res.details:
            text, _, step = d.partition(" Next: ")
            if not any(text.rstrip(".") == t.rstrip(".") for t, _s in problems):
                problems.append((text, step or "Run `stuntkey fix`."))
    # the one command is promised in the plan AND shown at the end whenever it is still needed
    by_hand = any("claude mcp add" in s for _t, s in problems)
    return _final(out, done_steps, problems, bool(done_steps),
                  extra=(lambda: claude_by_hand(out)) if by_hand else None)
