"""Round 4, builder B: first-use polish and four new commands.

DX: status after setup, the plaintext .env copy (`clean-env`), setup never says
"done" for a failed step, the one command at the end, ONE state for overview /
status / doctor / test, call and resume ask in the open, plainer words.
NEW: `verify`, `explain`, `scan --agent-configs`, `age`.

Every test runs in a throwaway home with the in-memory keychain and only
made-up keys; nothing can open a real window, browser or clipboard.
"""
import argparse
import contextlib
import datetime
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import _isolation  # noqa: F401
import test_r14_ux as r14
from stuntkey import (age, agentscan, claudecode, cli, clients, cmds, explain, extras, fixcmd,
                      hook, keychain, ledger, proxy, recipes, scan, setupcmd, undo, verify)

REPO = _isolation.REPO
KEY = r14.FAKE_ANTHROPIC
OTHER = "sk-ant-api03-Mm4Qz9LkR2wXd7NfTb5HcY8pJe3Us6GaVv1Wo0RiQx"


def _read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


class Base(r14.Home):
    def env_path(self):
        return os.path.join(self.cwd, ".env")

    def save_key_in_keychain(self, value=KEY):
        keychain.store("anthropic", "ANTHROPIC_API_KEY", value, keychain.detect_backend())


# ============================================================ 1. status after setup

class StatusAfterSetup(Base):
    def test_status_does_not_ask_for_setup_once_setup_is_done(self):
        self.use_claude_code()
        code, out, _ = self.run_cli("setup", "--yes")
        self.assertEqual(code, 0, out)
        code, out, _ = self.run_cli("status")
        self.assertNotIn("no stuntkey setup", out)
        self.assertNotIn("Run `stuntkey setup`", out)
        self.assertIn("whole computer", out)

    def test_status_json_after_setup_says_set_up_and_gives_the_state(self):
        self.use_claude_code()
        self.run_cli("setup", "--yes")
        _code, out, _ = self.run_cli("status", "--json")
        data = json.loads(out)
        self.assertTrue(data["setup"])
        self.assertIn(data["state"], ("ready", "almost"))

    def test_an_untouched_computer_is_still_told_to_run_setup(self):
        _code, out, _ = self.run_cli("status")
        self.assertIn("Run `stuntkey setup`", out)


# ============================================================ 2. the plaintext .env copy

class CleanEnv(Base):
    def _env_with_key(self, extra=""):
        with open(self.env_path(), "w", encoding="utf-8") as f:
            f.write(f"# my app\nANTHROPIC_API_KEY={KEY}\nPORT=3000\n{extra}")

    def test_status_hint_for_a_keychain_key_with_a_plaintext_copy_is_to_remove_it(self):
        self.save_key_in_keychain()
        self._env_with_key()
        item = fixcmd._keys_item(recipes.load_recipes())
        self.assertIn("clean-env", item.step)
        self.assertNotIn("stuntkey setup", item.step)

    def test_a_key_only_in_env_still_says_setup(self):
        self._env_with_key()
        item = fixcmd._keys_item(recipes.load_recipes())
        self.assertIn("stuntkey setup", item.step)

    def test_clean_env_comments_out_the_line_and_keeps_the_rest(self):
        self.save_key_in_keychain()
        self._env_with_key()
        code, out, _ = self.run_cli("clean-env", "--yes")
        self.assertEqual(code, 0, out)
        text = open(self.env_path(), encoding="utf-8").read()
        self.assertNotIn(KEY, text)
        self.assertIn("PORT=3000", text)
        self.assertIn("# my app", text)
        self.assertIn("ANTHROPIC_API_KEY moved to your keychain", text)
        self.assertNotIn(KEY, out)
        self.assertEqual(keychain.read("anthropic", "ANTHROPIC_API_KEY", keychain.detect_backend()), KEY)

    def test_undo_puts_the_plaintext_back(self):
        self.save_key_in_keychain()
        self._env_with_key()
        before = open(self.env_path(), encoding="utf-8").read()
        self.run_cli("clean-env", "--yes")
        code, out, _ = self.run_cli("undo", "--yes")
        self.assertEqual(code, 0, out)
        self.assertEqual(open(self.env_path(), encoding="utf-8").read(), before)
        # the key is still in the keychain: undo of clean-env only restores the file
        self.assertEqual(keychain.read("anthropic", "ANTHROPIC_API_KEY", keychain.detect_backend()), KEY)

    def test_a_different_value_in_the_file_is_never_removed(self):
        self.save_key_in_keychain(OTHER)
        self._env_with_key()
        before = open(self.env_path(), encoding="utf-8").read()
        _code, out, _ = self.run_cli("clean-env", "--yes")
        self.assertEqual(open(self.env_path(), encoding="utf-8").read(), before)
        self.assertIn("differs from the keychain copy", out)

    def test_a_key_not_saved_in_the_keychain_is_never_removed(self):
        self._env_with_key()
        before = open(self.env_path(), encoding="utf-8").read()
        self.run_cli("clean-env", "--yes")
        self.assertEqual(open(self.env_path(), encoding="utf-8").read(), before)

    def test_without_a_terminal_and_without_yes_it_prints_the_exact_line(self):
        self.save_key_in_keychain()
        self._env_with_key()
        code, out, _ = self.run_cli("clean-env")
        self.assertEqual(code, 2)
        self.assertIn("stuntkey clean-env --yes", out)
        self.assertIn(KEY, open(self.env_path(), encoding="utf-8").read())

    def test_dry_run_changes_nothing(self):
        self.save_key_in_keychain()
        self._env_with_key()
        before = open(self.env_path(), encoding="utf-8").read()
        code, out, _ = self.run_cli("clean-env", "--dry-run")
        self.assertEqual(code, 0)
        self.assertEqual(open(self.env_path(), encoding="utf-8").read(), before)

    def test_a_value_spread_over_lines_is_left_alone(self):
        self.save_key_in_keychain()
        with open(self.env_path(), "w", encoding="utf-8") as f:
            f.write(f'ANTHROPIC_API_KEY="{KEY}\nsecond line"\n')
        before = open(self.env_path(), encoding="utf-8").read()
        self.run_cli("clean-env", "--yes")
        self.assertEqual(open(self.env_path(), encoding="utf-8").read(), before)

    def test_setup_offers_once_to_clean_and_does_it_on_yes(self):
        self.use_claude_code()
        self._env_with_key()
        asked = []

        def reader(prompt):
            asked.append(prompt)
            return "y"
        out = io.StringIO()
        code = setupcmd.cmd_setup_all(mock.Mock(yes=False, dry_run=False), recipes.load_recipes(),
                                      out=out, ask=reader, root=self.cwd)
        self.assertEqual(len(asked), 2, out.getvalue())       # the one yes, and the .env offer
        self.assertNotIn(KEY, open(self.env_path(), encoding="utf-8").read())
        self.assertEqual(code, 0, out.getvalue())
        self.assertNotIn(KEY, out.getvalue())

    def test_setup_with_yes_never_edits_env_but_prints_the_exact_line(self):
        self.use_claude_code()
        self._env_with_key()
        code, out, _ = self.run_cli("setup", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("stuntkey clean-env --yes", out)
        self.assertIn(KEY, open(self.env_path(), encoding="utf-8").read())

    def test_setup_records_the_date_a_key_was_added(self):
        self.use_claude_code()
        self._env_with_key()
        self.run_cli("setup", "--yes")
        self.assertIsNotNone(ledger.get(self.cwd, "anthropic"))


# ============================================================ 3. a failed step is never "done"

class FailedStepNeverDone(Base):
    def test_the_self_test_is_tried_twice_before_failing(self):
        answers = iter([False, True])
        with mock.patch.object(hook, "self_test", lambda handler, run=None: next(answers)):
            fixcmd.fix_hook(hook.user_settings_path())           # must not raise
        self.assertTrue(os.path.exists(hook.user_settings_path()))

    def test_the_first_failure_message_has_no_reinstall_advice(self):
        with mock.patch.object(hook, "self_test", lambda handler, run=None: False):
            with self.assertRaises(RuntimeError) as cm:
                fixcmd.fix_hook(hook.user_settings_path())
        self.assertNotIn("pipx reinstall", str(cm.exception))
        self.assertIn("stuntkey doctor", str(cm.exception))

    def test_setup_never_prints_could_not_and_done_for_the_same_step(self):
        self.use_claude_code()
        with mock.patch.object(hook, "self_test", lambda handler, run=None: False):
            _code, out, _ = self.run_cli("setup", "--yes")
        self.assertIn("Could not do this one (switch on the Claude Code safety check", out)
        self.assertNotIn("done: switch on the Claude Code safety check", out)
        self.assertNotIn("pipx reinstall", out)

    def test_apply_fixes_reports_only_the_steps_that_worked(self):
        good = fixcmd.Item("a", fixcmd.YELLOW, "x", fixer=lambda: None, fix_text="good one")

        def boom():
            raise RuntimeError("no")
        bad = fixcmd.Item("b", fixcmd.YELLOW, "y", fixer=boom, fix_text="bad one")
        worked = []
        failed = fixcmd.apply_fixes([good, bad], io.StringIO(), worked)
        self.assertEqual(failed, 1)
        self.assertEqual([i.key for i in worked], ["a"])


# ============================================================ 4. the one command at the end

class OneCommandAtTheEnd(Base):
    def test_the_command_is_printed_copied_and_the_desktop_route_is_said(self):
        self.use_claude_code(with_cli=False)
        copied = []
        with mock.patch.object(setupcmd, "copy_text", lambda t: copied.append(t) or True):
            code, out, _ = self.run_cli("setup", "--yes")
        self.assertEqual(code, 1)
        cmd = claudecode.one_command()
        self.assertEqual(copied, [cmd])
        self.assertGreater(out.rfind(cmd), out.find("Almost done"))
        self.assertIn("I copied that line", out)
        self.assertIn("Claude Desktop", out)

    def test_nothing_is_said_about_a_copy_when_the_clipboard_is_not_available(self):
        self.use_claude_code(with_cli=False)
        with mock.patch.object(setupcmd, "copy_text", lambda t: False):
            _code, out, _ = self.run_cli("setup", "--yes")
        self.assertNotIn("I copied that line", out)
        self.assertIn(claudecode.one_command(), out)

    def test_the_test_run_never_touches_the_real_clipboard(self):
        self.assertFalse(setupcmd.copy_text("hello"))     # STUNTKEY_KEYCHAIN is set here

    def test_a_computer_with_only_desktop_plugged_does_not_get_all_done(self):
        self.use_claude_code(with_cli=False)
        fixcmd.fix_clients(["claude-desktop"])
        out = io.StringIO()
        with mock.patch.object(setupcmd, "copy_text", lambda t: False):
            code = setupcmd.cmd_setup_all(mock.Mock(yes=True, dry_run=False),
                                          recipes.load_recipes(), out=out, root=self.cwd)
        self.assertEqual(code, 1)
        self.assertNotIn("All done", out.getvalue())
        self.assertIn(claudecode.one_command(), out.getvalue())


# ============================================================ 5. ONE state

class OneState(Base):
    def _desktop_only(self):
        self.use_claude_code(with_cli=False)
        fixcmd.fix_clients(["claude-desktop"])
        fixcmd.fix_hook(hook.user_settings_path())

    def test_state_function_names(self):
        items = [fixcmd.Item("a", fixcmd.GREEN, "ok")]
        self.assertEqual(fixcmd.state(items)[0], "ready")
        self.assertEqual(fixcmd.state(items + [fixcmd.Item("b", fixcmd.YELLOW, "y")])[0], "almost")
        self.assertEqual(fixcmd.state(items + [fixcmd.Item("c", fixcmd.RED, "r")])[0], "attention")

    def test_test_does_not_say_plugged_in_when_claude_code_is_not(self):
        self._desktop_only()
        self.assertTrue(any(i.key == "claude-code:user" and i.level != fixcmd.GREEN
                            for i in fixcmd.collect()))
        res = setupcmd.run_check()
        self.assertFalse(res.ok, res.line)
        self.assertNotIn("is plugged in", res.line)
        self.assertIn("Claude Code", res.line)

    def test_overview_status_doctor_and_test_agree(self):
        self._desktop_only()
        _c, status_out, _ = self.run_cli("status", "--json")
        _c, over_out, _ = self.run_cli("overview", "--json")
        status_state = json.loads(status_out)["state"]
        self.assertEqual(json.loads(over_out)["state"], status_state)
        self.assertEqual(status_state, "almost")
        with mock.patch.object(extras, "_ensure_log_key", lambda: None):
            from stuntkey import gitscan
            with mock.patch.object(gitscan, "doctor", lambda: {"ok": True, "checks": []}):
                _c, doc_out, _ = self.run_cli("doctor", "--json")
        self.assertEqual(json.loads(doc_out)["overall"]["state"], status_state)
        # and `test` fails, because status is not green for Claude Code
        self.assertFalse(setupcmd.run_check().ok)

    def test_overview_ready_only_when_status_is_ready(self):
        self.use_claude_code()
        self.save_key_in_keychain()
        self.run_cli("setup", "--yes")
        _c, over_out, _ = self.run_cli("overview", "--json")
        self.assertEqual(json.loads(over_out)["state"], "ready")
        _c, text, _ = self.run_cli("overview")
        self.assertIn("stuntkey is ready.", text)

    def test_overview_is_not_ready_when_the_safety_check_is_off(self):
        self.save_key_in_keychain()
        _c, text, _ = self.run_cli("overview")
        self.assertNotIn("stuntkey is ready.", text)
        self.assertIn("Not ready yet", text)


# ============================================================ 6. call and resume

class CallAndResume(Base):
    def test_the_notice_comes_first_and_no_answer_in_time_means_no(self):
        said, order = [], []

        def slow(summary):
            order.append("asked")
            time.sleep(1.0)
            return True
        answer = cmds.ask_with_notice("allow?", ask=slow,
                                      say=lambda t: (said.append(t), order.append("said")),
                                      wait=0, grace=0)
        self.assertFalse(answer)
        self.assertEqual(order[0], "said")
        self.assertEqual(said[0], cmds.WINDOW_NOTICE)
        self.assertIn("No answer", said[-1])

    def test_a_yes_in_time_is_a_yes(self):
        self.assertTrue(cmds.ask_with_notice("allow?", ask=lambda s: True, say=lambda t: None, wait=5))

    def test_the_wait_is_the_approval_timeout_setting(self):
        seen = []
        with mock.patch.dict(os.environ, {"STUNTKEY_APPROVE_TIMEOUT": "33"}):
            with mock.patch("threading.Thread.join", lambda self, timeout=None: seen.append(timeout)):
                cmds.ask_with_notice("x", ask=lambda s: True, say=lambda t: None)
        self.assertEqual(seen, [33 + 5])

    def test_call_says_a_window_opened_before_asking(self):
        recipe = recipes.load_recipes()["github"]
        args = argparse.Namespace(method="GET", path="/user", query=None, data=None,
                                  env_file=".env", json=False)
        from stuntkey import broker, remote
        asked = []

        def fake_call(*a, **k):
            asked.append(k["policy"].approve("allow GET /user?"))
            return {"status": 200, "headers": {}, "body": "{}"}
        err = io.StringIO()
        with mock.patch.object(remote, "collect_values", lambda *a, **k: {"X": "v"}), \
                mock.patch.object(broker, "call", fake_call), \
                mock.patch("stuntkey.approve.ask_person", lambda s: True), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            cmds.cmd_call(recipe, args)
        self.assertEqual(asked, [True])
        self.assertIn("A permission window has opened", err.getvalue())

    def test_resume_asks_in_the_open_and_accepts_yes_without_crashing(self):
        from stuntkey import caps, remote
        home = remote.home_dir()
        os.makedirs(home, exist_ok=True)
        with open(caps.stop_path(home), "w", encoding="utf-8") as f:
            f.write("stopped\n")
        with mock.patch("stuntkey.approve.ask_person", lambda s: True):
            code, out, err = self.run_cli("resume", "--yes")
        self.assertEqual(code, 0, out + err)
        self.assertFalse(os.path.lexists(caps.stop_path(home)))
        self.assertIn("A permission window has opened", err)       # no terminal here: a window decides
        self.assertIn("only works when you type", err)

    def test_resume_yes_in_a_real_terminal_skips_the_question(self):
        from stuntkey import caps, remote
        home = remote.home_dir()
        os.makedirs(home, exist_ok=True)
        with open(caps.stop_path(home), "w", encoding="utf-8") as f:
            f.write("stopped\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cmds.cmd_resume(argparse.Namespace(yes=True), home=home, interactive=True)
        self.assertEqual(code, 0)
        self.assertFalse(os.path.lexists(caps.stop_path(home)))

    def test_status_fix_is_accepted_and_repairs(self):
        self.use_claude_code()
        code, out, err = self.run_cli("status", "--fix", "--yes")
        self.assertNotIn("unrecognized", err)
        self.assertTrue(os.path.exists(hook.user_settings_path()), out + err)


# ============================================================ 7. plain words

class PlainWords(Base):
    def test_no_signature_key_wording(self):
        self.assertNotIn("create the activity log's signature key", _read("stuntkey", "fixcmd.py"))
        for it in fixcmd.collect():
            self.assertNotIn("signature key", it.fix_text)

    def test_scan_names_the_folder_it_could_not_open(self):
        d = tempfile.mkdtemp(prefix="r4bscan")
        self.addCleanup(_isolation.rmtree, d)
        real = os.scandir

        def denied(path="."):
            if os.path.abspath(path) == os.path.abspath(d):
                raise PermissionError(13, "Access is denied")
            return real(path)
        with mock.patch("os.scandir", denied):
            result = scan.scan_path(d, recipes.load_recipes(recipes.RECIPES_DIR))
        text = scan.render_text(result)
        self.assertIn(d, text)
        self.assertIn("could not be opened", text)

    def test_the_port_note_is_not_part_of_the_default_checks(self):
        with mock.patch.object(fixcmd, "_port_item", side_effect=AssertionError("port looked at")):
            fixcmd.collect()                                      # must not raise
            with self.assertRaises(AssertionError):
                fixcmd.collect(include_port=True)

    def test_a_stale_stuntkey_on_path_is_warned_about(self):
        line = fixcmd.stale_program_warning(which=lambda n: r"C:\old\stuntkey.exe",
                                            run=lambda exe: "stuntkey 0.9.3", version="0.9.4",
                                            practice=False)
        self.assertIn("0.9.3", line)
        self.assertIn("0.9.4", line)
        self.assertIn("pipx upgrade", line)
        same = fixcmd.stale_program_warning(which=lambda n: r"C:\old\stuntkey.exe",
                                            run=lambda exe: "stuntkey 0.9.4", version="0.9.4",
                                            practice=False)
        self.assertEqual(same, "")
        self.assertEqual(fixcmd.stale_program_warning(which=lambda n: None, run=lambda e: "",
                                                      version="0.9.4", practice=False), "")
        self.assertEqual(fixcmd.stale_program_warning(which=lambda n: "x", run=lambda e: "garbage",
                                                      version="0.9.4", practice=False), "")

    def test_the_warning_shows_in_about_status_and_overview(self):
        with mock.patch.object(fixcmd, "stale_program_warning", lambda *a, **k: "STALE-PATH-LINE"):
            _c, about, _ = self.run_cli("about")
            _c, status, _ = self.run_cli("status")
            _c, over, _ = self.run_cli("overview")
        self.assertIn("STALE-PATH-LINE", about)
        self.assertIn("STALE-PATH-LINE", status)
        self.assertIn("STALE-PATH-LINE", over)

    def test_a_test_run_never_starts_the_real_program_on_path(self):
        with mock.patch("subprocess.run", side_effect=AssertionError("started a program")):
            self.assertEqual(fixcmd.stale_program_warning(), "")


# ============================================================ 8. verify

class Verify(Base):
    def test_all_three_checks_pass(self):
        results = verify.run_checks()
        self.assertEqual(len(results), 3, results)
        self.assertTrue(all(r["ok"] for r in results), results)

    def test_the_command_exits_zero_and_json_is_valid(self):
        code, out, _ = self.run_cli("verify")
        self.assertEqual(code, 0, out)
        self.assertEqual(out.count("PASS"), 3)
        code, out, _ = self.run_cli("verify", "--json")
        self.assertTrue(json.loads(out)["ok"])

    def test_a_key_in_the_programs_environment_fails_the_check(self):
        real = proxy.child_env

        def leaky(catalog, base, tokens, **k):
            env = real(catalog, base, tokens, **k)
            env["OOPS"] = _LEAK[0]
            return env
        _LEAK = [""]
        orig_run_checks = verify.run_checks

        def with_known_key():
            import secrets
            _LEAK[0] = "sk-verify-" + "0" * 32
            with mock.patch.object(secrets, "token_hex", lambda n: "0" * 32), \
                    mock.patch.object(proxy, "child_env", leaky):
                return orig_run_checks()
        results = with_known_key()
        self.assertFalse(next(r for r in results if r["name"] == "hides the key")["ok"], results)
        code = 0 if all(r["ok"] for r in results) else 1
        self.assertEqual(code, 1)

    def test_nothing_is_written_to_the_real_home(self):
        before = set(os.listdir(os.path.expanduser("~"))) if os.path.isdir(os.path.expanduser("~")) else set()
        verify.run_checks()
        after = set(os.listdir(os.path.expanduser("~")))
        self.assertEqual(before, after)

    def test_the_home_variables_are_put_back(self):
        saved = {n: os.environ.get(n) for n in ("USERPROFILE", "HOME", "APPDATA")}
        verify.run_checks()
        self.assertEqual({n: os.environ.get(n) for n in saved}, saved)


# ============================================================ 9. explain

def _line(**kw):
    base = {"service": "github", "method": "GET", "host": "api.github.com", "path": "/user",
            "status": 200, "bytes": 5, "result": "ok", "ms": 3}
    base.update(kw)
    return json.dumps(base)


class Explain(Base):
    NOW = 1_800_000_000.0

    def _home_with_log(self, lines):
        home = _isolation.mktemp()
        with open(os.path.join(home, "audit.log"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        return home

    def test_an_empty_log_is_said_in_words(self):
        home = _isolation.mktemp()
        data = explain.explain(home, 7 * 86400, now=self.NOW, saved=[])
        self.assertIn("Nothing has gone through", data["sentences"][0])

    def test_calls_blocked_and_unused_keys(self):
        n = self.NOW
        lines = [_line(ts=n - 100), _line(ts=n - 200),
                 _line(service="openai", ts=n - 300),
                 _line(result="refused", ts=n - 400),
                 _line(result="denied", ts=n - 500),
                 "this line is not json",
                 _line(service="stripe", ts=n - 40 * 86400)]
        home = self._home_with_log(lines)
        data = explain.explain(home, 7 * 86400, now=n, saved=["github", "openai", "stripe", "resend"])
        text = " ".join(data["sentences"])
        self.assertIn("5 calls went through", text)
        self.assertIn("github: 4", text)
        self.assertIn("2 calls were blocked", text)
        self.assertIn("turned down in the permission window", text)
        self.assertIn("stripe", text)
        self.assertIn("resend", text)
        self.assertIn("not used through stuntkey for 30 days", text)
        self.assertIn("damaged", text)                   # the malformed line is said, not a crash
        self.assertLessEqual(len(data["sentences"]), 10)

    def test_a_panic_is_mentioned(self):
        ledger.event(self.cwd, "github", "panic: revoke", "done")
        home = self._home_with_log([_line(ts=time.time() - 10)])
        data = explain.explain(home, 7 * 86400, saved=["github"])
        self.assertIn("panic", " ".join(data["sentences"]))
        self.assertIn("github", " ".join(s for s in data["sentences"] if "panic" in s))

    def test_a_key_saved_today_is_not_called_unused_for_30_days(self):
        ledger.record(self.cwd, "openai", "keychain")      # saved just now, never used yet
        home = _isolation.mktemp()
        data = explain.explain(home, 7 * 86400, saved=["openai"])
        text = " ".join(data["sentences"])
        self.assertNotIn("not used through stuntkey", text)
        self.assertIn("No saved key has sat unused", text)

    def test_a_stopped_stuntkey_is_said(self):
        from stuntkey import caps
        home = _isolation.mktemp()
        with open(caps.stop_path(home), "w", encoding="utf-8") as f:
            f.write("x")
        data = explain.explain(home, 86400, now=self.NOW, saved=[])
        self.assertIn("STOPPED", " ".join(data["sentences"]))

    def test_no_key_value_can_appear(self):
        home = self._home_with_log([_line(ts=self.NOW - 5, path="/user/" + "[path withheld]")])
        text = json.dumps(explain.explain(home, 86400, now=self.NOW, saved=["github"]))
        self.assertNotIn(KEY, text)

    def test_parse_since(self):
        self.assertEqual(explain.parse_since("7d"), 7 * 86400)
        self.assertEqual(explain.parse_since("24h"), 86400)
        self.assertEqual(explain.parse_since("2w"), 14 * 86400)
        self.assertEqual(explain.parse_since(None), 7 * 86400)
        with self.assertRaises(ValueError):
            explain.parse_since("soon")

    def test_the_command(self):
        code, out, _ = self.run_cli("explain", "--since", "7d")
        self.assertEqual(code, 0)
        self.assertTrue(out.strip())
        code, out, _ = self.run_cli("explain", "--json")
        self.assertIn("sentences", json.loads(out))
        code, _out, err = self.run_cli("explain", "--since", "soon")
        self.assertEqual(code, 2)
        self.assertIn("--since", err)


# ============================================================ 10. scan --agent-configs

class AgentConfigs(Base):
    def _write(self, base, rel, text):
        path = os.path.join(base, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_it_finds_keys_in_project_and_home_agent_files_and_masks_them(self):
        self._write(self.cwd, ".claude/settings.local.json",
                    json.dumps({"env": {"ANTHROPIC_API_KEY": KEY}}))
        self._write(self.cwd, ".mcp.json",
                    json.dumps({"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": r14.FAKE_GITHUB}}}}))
        self._write(self.home, ".cursor/mcp.json", json.dumps({"k": OTHER}))
        code, out, _ = self.run_cli("scan", "--agent-configs")
        self.assertEqual(code, 1, out)
        for needle in ("settings.local.json", ".mcp.json", ".cursor/mcp.json"):
            self.assertIn(needle, out)
        for secret in (KEY, r14.FAKE_GITHUB, OTHER):
            self.assertNotIn(secret, out)
        self.assertIn("agent-configs", out)
        self.assertIn("stuntkey get", out)

    def test_clean_files_are_clean(self):
        self._write(self.cwd, ".claude/settings.local.json", json.dumps({"permissions": {"allow": ["Bash(ls)"]}}))
        code, out, _ = self.run_cli("scan", "--agent-configs")
        self.assertEqual(code, 0, out)
        self.assertIn("No key-shaped text found", out)

    def test_huge_and_binary_files_are_skipped_and_said(self):
        self._write(self.cwd, ".claude/big.json", '{"a": "' + "x" * (agentscan.MAX_BYTES + 10) + '"}')
        with open(os.path.join(self.cwd, ".claude", "blob.json"), "wb") as f:
            f.write(b"\x00\x01\x02" * 100)
        res = agentscan.scan_agent_configs(recipes.load_recipes(recipes.RECIPES_DIR), self.cwd, self.home)
        self.assertEqual(res["findings"], [])
        text = " ".join(res["skipped"])
        self.assertIn("big.json", text)
        self.assertIn("blob.json", text)

    def test_json_prints_only_the_agent_result_and_never_the_key(self):
        self._write(self.cwd, ".mcp.json", json.dumps({"x": KEY}))
        code, out, _ = self.run_cli("scan", "--agent-configs", "--json")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(len(data["agent_configs"]["findings"]), 1)
        self.assertNotIn(KEY, out)

    def test_the_chat_history_folders_of_home_are_not_read(self):
        self._write(self.home, ".claude/projects/p/chat.json", json.dumps({"x": KEY}))
        res = agentscan.scan_agent_configs(recipes.load_recipes(recipes.RECIPES_DIR), self.cwd, self.home)
        self.assertEqual(res["findings"], [])


# ============================================================ 11. age

class Age(Base):
    def _record(self, service, days_ago):
        when = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days_ago)
        ledger.record(self.cwd, service, "keychain", now=when)

    def test_old_new_and_unknown(self):
        be = keychain.detect_backend()
        keychain.store("github", "GITHUB_TOKEN", r14.FAKE_GITHUB, be)
        keychain.store("anthropic", "ANTHROPIC_API_KEY", KEY, be)
        keychain.store("openai", "OPENAI_API_KEY", "sk-proj-Zq8Lm2VtR7wKd4NfXb9HcY5pJe3Us6GaTv1Wo0Ri", be)
        self._record("github", 120)
        self._record("anthropic", 5)
        data = age.collect(recipes.load_recipes(), 90)
        by = {k["service"]: k for k in data["keys"]}
        self.assertTrue(by["github"]["old"])
        self.assertEqual(by["github"]["age_days"], 120)
        self.assertFalse(by["anthropic"]["old"])
        self.assertIsNone(by["openai"]["age_days"])
        self.assertEqual(data["old"], ["github"])
        text = age.render(data)
        self.assertIn("unknown age", text)
        self.assertIn("older than the limit", text)
        for secret in (r14.FAKE_GITHUB, KEY):
            self.assertNotIn(secret, text)

    def test_the_status_line(self):
        keychain.store("github", "GITHUB_TOKEN", r14.FAKE_GITHUB, keychain.detect_backend())
        self._record("github", 200)
        self.assertIn("1 key older than 90 days", age.status_line(recipes.load_recipes()))
        self.use_claude_code()
        self.run_cli("fix", "--yes")
        _c, out, _ = self.run_cli("status")
        self.assertIn("1 key older than 90 days", out)

    def test_the_threshold_comes_from_the_flag_or_the_environment(self):
        self.assertEqual(age.warn_days(None, {}), 90)
        self.assertEqual(age.warn_days(None, {"STUNTKEY_AGE_WARN": "30"}), 30)
        self.assertEqual(age.warn_days(45, {"STUNTKEY_AGE_WARN": "30"}), 45)
        self.assertEqual(age.warn_days(None, {"STUNTKEY_AGE_WARN": "abc"}), 90)
        self.assertEqual(age.warn_days(0, {}), 90)

    def test_the_command_and_its_flag(self):
        keychain.store("github", "GITHUB_TOKEN", r14.FAKE_GITHUB, keychain.detect_backend())
        self._record("github", 40)
        code, out, _ = self.run_cli("age", "--warn", "30")
        self.assertEqual(code, 0)
        self.assertIn("40 days", out)
        self.assertIn("older than the limit", out)
        _c, out, _ = self.run_cli("age", "--json")
        self.assertEqual(json.loads(out)["warn_days"], 90)

    def test_a_key_with_no_record_is_not_called_old(self):
        keychain.store("github", "GITHUB_TOKEN", r14.FAKE_GITHUB, keychain.detect_backend())
        self.assertEqual(age.collect(recipes.load_recipes(), 1)["old"], [])
        self.assertEqual(age.status_line(recipes.load_recipes(), 1), "")


# ============================================================ 12. docs, help, completion

NEW = ("verify", "explain", "age", "clean-env")


class DocsAndLists(Base):
    def test_help_all_lists_the_new_commands_and_counts_them(self):
        parser = cli._build_parser()
        text = fixcmd.render_help(parser)
        for name in NEW:
            self.assertIn(f"stuntkey {name}", text)
        n = len(fixcmd._help_texts(parser))
        self.assertIn(f"That is {n} commands in all", text)

    def test_completion_lists_the_new_commands(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(cli.main(["completion", "bash"]), 0)
        for name in NEW:
            self.assertIn(name, out.getvalue())

    def test_the_readme_and_guide_describe_the_new_commands(self):
        for doc in (("README.md",), ("docs", "guide.md")):
            text = _read(*doc)
            for name in NEW:
                self.assertIn(f"stuntkey {name}", text, (doc, name))
            self.assertIn("--agent-configs", text, doc)

    def test_the_changelog_names_them(self):
        text = _read("CHANGELOG.md")
        for name in NEW:
            self.assertIn(f"`stuntkey {name}", text)

    def test_the_new_flags_exist(self):
        p = cli._build_parser()
        self.assertTrue(p.parse_args(["scan", "--agent-configs"]).agent_configs)
        self.assertTrue(p.parse_args(["resume", "--yes"]).yes)
        self.assertTrue(p.parse_args(["status", "--fix"]).fix)
        self.assertEqual(p.parse_args(["age", "--warn", "30"]).warn, 30)
        self.assertEqual(p.parse_args(["explain", "--since", "2w"]).since, "2w")


if __name__ == "__main__":
    unittest.main()
