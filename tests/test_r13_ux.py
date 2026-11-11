"""Round 13, usability: `fix`, the health screen, `help`, `update-check`, `limits`,
`completion`, `uninstall` as a true undo, plain wording, and the local page.

Every test runs with HOME, USERPROFILE, APPDATA and LOCALAPPDATA pointing at a
fresh temp folder, the keychain swapped for the in-memory test one and only
made-up keys. The real safety-check self-test (which starts a program) is
stubbed, and nothing here can open a permission window."""
import contextlib
import io
import json
import os
import re
import socket
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from stuntkey import cli, clients, extras, fixcmd, hook  # noqa: E402


def _no_real_dialog(*a, **k):
    raise AssertionError("a real permission window was asked for")


class Home(unittest.TestCase):
    """A fresh fake home for each test."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.home = os.path.realpath(self._tmp.name)
        self.cwd = os.path.join(self.home, "proj")
        os.makedirs(self.cwd)
        env = {"HOME": self.home, "USERPROFILE": self.home,
               "APPDATA": os.path.join(self.home, "AppData", "Roaming"),
               "LOCALAPPDATA": os.path.join(self.home, "AppData", "Local"),
               "STUNTKEY_KEYCHAIN": "memory"}
        self._env = mock.patch.dict(os.environ, env)
        self._env.start()
        for k in [k for k in os.environ if k.startswith("STUNTKEY_") and k != "STUNTKEY_KEYCHAIN"]:
            del os.environ[k]
        self._old_cwd = os.getcwd()
        os.chdir(self.cwd)
        self._st = mock.patch.object(hook, "self_test", lambda handler, run=None: True)
        self._st.start()
        # nothing in these tests may open a real window
        from stuntkey import approve
        self._ap = mock.patch.object(approve, "ask_person", _no_real_dialog)
        self._ap.start()
        self.settings = hook.user_settings_path()

    def tearDown(self):
        self._ap.stop()
        self._st.stop()
        os.chdir(self._old_cwd)
        self._env.stop()
        self._tmp.cleanup()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(list(argv))
            except SystemExit as e:
                code = int(e.code or 0)
        return code, out.getvalue(), err.getvalue()

    def write_json(self, path, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def read_json(self, path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)


class TestSandbox(Home):
    def test_home_is_the_fake_one(self):
        self.assertTrue(hook.user_settings_path().startswith(self.home))
        self.assertTrue(os.path.expanduser("~").startswith(self.home))


class TestFix(Home):
    def test_clean_machine_gets_the_hook_and_second_run_changes_nothing(self):
        code, out, _ = self.run_cli("fix", "--yes")
        self.assertIn("Done: switch on the Claude Code safety check", out)
        data = self.read_json(self.settings)
        self.assertTrue(list(hook._our_handlers(data["hooks"]["PreToolUse"])))
        before = open(self.settings, "rb").read()
        code, out, _ = self.run_cli("fix", "--yes")
        self.assertNotIn("Done:", out)
        self.assertEqual(before, open(self.settings, "rb").read())

    def test_other_hooks_and_settings_survive_a_fix(self):
        mine = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}
        self.write_json(self.settings, {"theme": "dark", "hooks": {"PreToolUse": [mine]}})
        self.run_cli("fix", "--yes")
        data = self.read_json(self.settings)
        self.assertEqual(data["theme"], "dark")
        self.assertIn(mine, data["hooks"]["PreToolUse"])

    def test_program_moved_after_an_upgrade_is_red_and_repaired(self):
        self.run_cli("fix", "--yes")
        data = self.read_json(self.settings)
        for ev in ("PreToolUse", "PostToolUse"):
            for _g, h in hook._our_handlers(data["hooks"][ev]):
                h["command"] = os.path.join(self.home, "gone", "stuntkey.exe")
        self.write_json(self.settings, data)
        items = fixcmd.collect()
        bad = [i for i in items if i.key == "hook:user"]
        self.assertEqual(bad[0].level, fixcmd.RED)
        self.assertIn("gone", bad[0].text)
        self.assertIn("stuntkey fix", bad[0].step)
        code, out, _ = self.run_cli("fix", "--yes")
        again = [i for i in fixcmd.collect() if i.key == "hook:user"]
        self.assertEqual(again[0].level, fixcmd.GREEN)
        fixed = self.read_json(self.settings)
        for _g, h in hook._our_handlers(fixed["hooks"]["PreToolUse"]):
            self.assertTrue(os.path.isfile(h["command"]))

    def test_old_fail_open_hook_is_made_to_block(self):
        self.run_cli("fix", "--yes")
        data = self.read_json(self.settings)
        for _g, h in hook._our_handlers(data["hooks"]["PreToolUse"]):
            h.pop("onFailure", None)
        self.write_json(self.settings, data)
        item = [i for i in fixcmd.collect() if i.key == "hook:user"][0]
        self.assertEqual(item.level, fixcmd.YELLOW)
        self.run_cli("fix", "--yes")
        for _g, h in hook._our_handlers(self.read_json(self.settings)["hooks"]["PreToolUse"]):
            self.assertEqual(h.get("onFailure"), "block")

    def test_unreadable_settings_file_is_left_alone(self):
        os.makedirs(os.path.dirname(self.settings), exist_ok=True)
        with open(self.settings, "w") as f:
            f.write("{ this is not json")
        code, out, _ = self.run_cli("fix", "--yes")
        self.assertEqual(open(self.settings).read(), "{ this is not json")
        self.assertNotEqual(code, 0)
        self.assertIn("cannot be read", out)

    def test_fix_without_yes_and_without_a_terminal_changes_nothing(self):
        with mock.patch("sys.stdin", io.StringIO("")):
            code, out, _ = self.run_cli("fix")
        self.assertFalse(os.path.exists(self.settings))
        self.assertIn("--yes", out)

    def test_fix_json_lists_without_changing(self):
        code, out, _ = self.run_cli("fix", "--json")
        self.assertFalse(os.path.exists(self.settings))
        self.assertTrue(json.loads(out)["fixable"])

    def test_doctor_fix_flag_exists(self):
        code, out, err = self.run_cli("doctor", "--fix", "--yes")
        self.assertNotIn("unrecognized", err)
        self.assertTrue(os.path.exists(self.settings))

    def test_stale_claude_desktop_entry_is_repaired_and_others_kept(self):
        path, key = clients.targets()["claude-desktop"]
        self.write_json(path, {key: {"stuntkey": {"command": os.path.join(self.home, "gone", "python.exe"),
                                                  "args": ["-m", "stuntkey", "mcp"]},
                                     "other": {"command": "x", "args": []}}})
        item = [i for i in fixcmd.collect() if i.key == "client:broken"][0]
        self.assertEqual(item.level, fixcmd.RED)
        self.run_cli("fix", "--yes")
        data = self.read_json(path)
        self.assertEqual(data[key]["other"], {"command": "x", "args": []})
        self.assertTrue(os.path.isfile(data[key]["stuntkey"]["command"]))
        self.assertFalse([i for i in fixcmd.collect() if i.key.startswith("client:") and i.level == fixcmd.RED])

    def test_fix_plugs_into_apps_that_are_found(self):
        path, key = clients.targets()["cursor"]
        self.write_json(path, {key: {}})
        self.run_cli("fix", "--yes")
        self.assertIn("stuntkey", self.read_json(path)[key])


class TestUninstallIsAnUndo(Home):
    def test_uninstall_puts_settings_back_exactly(self):
        original = {"theme": "dark", "hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo hi"}]}]}}
        self.write_json(self.settings, original)
        cpath, ckey = clients.targets()["cursor"]
        cursor_original = {ckey: {"other": {"command": "x"}}}
        self.write_json(cpath, cursor_original)
        self.run_cli("fix", "--yes")
        self.assertNotEqual(self.read_json(self.settings), original)
        self.assertIn("stuntkey", self.read_json(cpath)[ckey])
        code, out, _ = self.run_cli("uninstall", "--yes")
        self.assertEqual(code, 0)
        self.assertEqual(self.read_json(self.settings), original)
        self.assertEqual(self.read_json(cpath), cursor_original)

    def test_uninstall_from_nothing_is_quiet_and_safe(self):
        code, out, _ = self.run_cli("uninstall", "--yes")
        self.assertEqual(code, 0)
        self.assertFalse(os.path.exists(self.settings))

    def test_keep_hook_leaves_the_safety_check(self):
        self.run_cli("fix", "--yes")
        self.run_cli("uninstall", "--yes", "--keep-hook")
        self.assertTrue(list(hook._our_handlers(self.read_json(self.settings)["hooks"]["PreToolUse"])))

    def test_uninstall_leaves_saved_keys(self):
        from stuntkey import keychain
        backend = keychain.detect_backend()
        keychain.store("github", "GITHUB_TOKEN", "ghp_" + "A" * 36, backend)
        self.run_cli("fix", "--yes")
        self.run_cli("uninstall", "--yes")
        self.assertEqual(keychain.read("github", "GITHUB_TOKEN", backend), "ghp_" + "A" * 36)

    def test_declining_the_hook_removal_keeps_it(self):
        self.run_cli("fix", "--yes")
        with mock.patch("builtins.input", return_value="n"):
            self.run_cli("uninstall")
        self.assertTrue(list(hook._our_handlers(self.read_json(self.settings)["hooks"]["PreToolUse"])))

    def test_install_says_one_more_step_when_the_hook_is_off(self):
        code, out, _ = self.run_cli("install", "--yes", "cursor")
        self.assertIn("stuntkey fix", out)


class TestHealthScreen(Home):
    def test_status_screen_has_levels_and_one_next_step_each(self):
        code, out, _ = self.run_cli("status")
        self.assertIn("[x]", out)
        self.assertRegex(out, r"Next: Run `stuntkey fix`")
        for item in fixcmd.collect():
            if item.level != fixcmd.GREEN and item.step:
                self.assertEqual(item.step.count("`") % 2, 0)

    def test_everything_green_after_fix_except_the_to_do_notes(self):
        self.run_cli("fix", "--yes")
        levels = {i.key: i.level for i in fixcmd.collect()}
        self.assertEqual(levels["hook:user"], fixcmd.GREEN)
        self.assertNotIn(fixcmd.RED, levels.values())

    def test_port_busy_is_yellow_with_one_step(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        try:
            item = fixcmd._port_item(s.getsockname()[1])
        finally:
            s.close()
        self.assertEqual(item.level, fixcmd.YELLOW)
        self.assertIn("stuntkey serve --port", item.step)

    def test_locked_keychain_is_red_with_a_next_step(self):
        from stuntkey import keychain
        with mock.patch.object(keychain, "read", side_effect=keychain.KeychainError("locked")):
            item = fixcmd._keychain_item()
        self.assertEqual(item.level, fixcmd.RED)
        self.assertIn("locked or busy", item.text)
        self.assertTrue(item.step)

    def test_no_keychain_at_all_is_red(self):
        from stuntkey import keychain
        with mock.patch.object(keychain, "detect_backend", return_value=None):
            item = fixcmd._keychain_item()
        self.assertEqual(item.level, fixcmd.RED)

    def test_json_mode(self):
        code, out, _ = self.run_cli("status", "--json")
        json.loads(out)       # no manifest: the existing short answer, still valid JSON

    def test_health_json_shape(self):
        out = io.StringIO()
        fixcmd.cmd_health(mock.Mock(json=True), out=out)
        data = json.loads(out.getvalue())
        self.assertIn(data["overall"], ("green", "yellow", "red"))
        self.assertTrue(all("next_step" in c for c in data["checks"]))


class TestHelpAndCompletion(Home):
    def test_every_command_is_in_the_grouped_help(self):
        code, out, _ = self.run_cli("help")
        parser = cli._build_parser()
        for name in fixcmd._help_texts(parser):
            self.assertIn(f"stuntkey {name} ", out + " ", name)
        for title, _names in fixcmd.GROUPS:
            self.assertIn(title, out)

    def test_help_lines_are_not_cut_mid_word(self):
        code, out, _ = self.run_cli("help")
        for line in out.splitlines():
            self.assertLessEqual(len(line), 110, line)
        self.assertNotRegex(out, r"\w\.\.\.\s*$")

    def test_help_about_one_command(self):
        code, out, _ = self.run_cli("help", "fix")
        self.assertEqual(code, 0)
        self.assertIn("usage: stuntkey fix", out)

    def test_unknown_command_points_at_help(self):
        code, out, err = self.run_cli("fixx")
        self.assertEqual(code, 2)
        self.assertIn("stuntkey fix", err)
        self.assertIn("stuntkey help", err)

    def test_no_arguments_shows_three_steps_with_fix(self):
        code, out, _ = self.run_cli()
        self.assertIn("stuntkey fix", out)
        self.assertIn("stuntkey help", out)

    def test_completion_scripts_list_commands(self):
        for shell, marker in (("powershell", "Register-ArgumentCompleter"), ("bash", "complete -F")):
            code, out, _ = self.run_cli("completion", shell)
            self.assertEqual(code, 0)
            self.assertIn(marker, out)
            for name in ("fix", "status", "uninstall", "limits"):
                self.assertIn(name, out)


class TestUpdateCheckNeverPhonesHome(Home):
    def test_default_makes_no_network_call(self):
        import urllib.request
        with mock.patch.object(urllib.request, "urlopen",
                               side_effect=AssertionError("went online")), \
                mock.patch.object(socket, "create_connection",
                                  side_effect=AssertionError("went online")):
            code, out, _ = self.run_cli("update-check")
        self.assertEqual(code, 0)
        self.assertIn("never contacts anyone unless you ask", out)

    def test_online_and_offline_failure_is_calm(self):
        import urllib.request
        with mock.patch.object(urllib.request, "urlopen", side_effect=OSError("no net")):
            code, out, _ = self.run_cli("update-check", "--online")
        self.assertEqual(code, 0)
        self.assertIn("could not reach", out)
        self.assertNotIn("Traceback", out)

    def test_online_newer_and_current(self):
        a = io.StringIO()
        fixcmd.cmd_update_check(mock.Mock(online=True), out=a,
                                fetch=lambda url: json.dumps({"info": {"version": "99.0.0"}}))
        self.assertIn("newer version", a.getvalue())
        from stuntkey import __version__
        b = io.StringIO()
        fixcmd.cmd_update_check(mock.Mock(online=True), out=b,
                                fetch=lambda url: json.dumps({"info": {"version": __version__}}))
        self.assertIn("newest version", b.getvalue())

    def test_garbage_answer_is_calm(self):
        a = io.StringIO()
        fixcmd.cmd_update_check(mock.Mock(online=True), out=a, fetch=lambda url: b"<html>")
        self.assertIn("could not reach", a.getvalue())

    def test_nothing_else_in_my_files_goes_online_on_its_own(self):
        for name in ("cli.py", "cmds.py", "extras.py", "projectcmds.py", "fixcmd.py", "clients.py"):
            text = open(os.path.join(ROOT, "stuntkey", name), encoding="utf-8").read()
            if name == "fixcmd.py":
                self.assertEqual(text.count("urlopen"), 1)
            else:
                self.assertNotIn("urlopen", text, name)


class TestLimitsPage(Home):
    def test_command_lists_every_limit(self):
        code, out, _ = self.run_cli("limits")
        self.assertEqual(code, 0)
        for head, _body in fixcmd.LIMITS:
            self.assertIn(head[:40], out)

    def test_site_page_matches_the_command_text(self):
        page = open(os.path.join(ROOT, "docs", "site", "what-it-does-not-protect.html"),
                    encoding="utf-8").read()
        for head, _b in fixcmd.LIMITS:
            self.assertIn(head.replace("`", "").split("`")[0][:30].replace("'", "'"), page.replace("<code>", "").replace("</code>", ""))
        self.assertIn("lowers the risk", page)

    def test_is_honest_about_the_known_gaps(self):
        text = " ".join(h + b for h, b in fixcmd.LIMITS).lower()
        for must in ("virus", "cursor", "clipboard", "independent security", "separate windows account"):
            self.assertIn(must, text)


class TestPlainWords(Home):
    BAD = re.compile(r"\b(hmac|nonce|reparse|ledger|fingerprints?|argv|payload|daemon|loopback|CONNECT)\b")

    def test_help_and_screens_have_no_jargon(self):
        texts = [fixcmd.render_help(cli._build_parser()), fixcmd.render_limits(),
                 fixcmd.render(fixcmd.collect()), cli.NEXT_STEPS]
        for t in texts:
            self.assertIsNone(self.BAD.search(t), self.BAD.search(t))

    def test_every_argparse_help_text_is_jargon_free(self):
        import argparse
        found = []

        def walk(p, path):
            for a in p._actions:
                for t in (a.help, getattr(a, "description", None)):
                    if t and self.BAD.search(str(t)):
                        found.append((path, str(t)[:60]))
                if isinstance(a, argparse._SubParsersAction):
                    for n, sp in a.choices.items():
                        if sp.description and self.BAD.search(sp.description):
                            found.append((n, sp.description[:60]))
                        walk(sp, path + " " + n)
        walk(cli._build_parser(), "stuntkey")
        self.assertEqual(found, [])

    def test_fix_and_health_texts_say_what_to_do(self):
        for item in fixcmd.collect():
            if item.level == fixcmd.RED:
                self.assertTrue(item.step, item.key)


class TestLocalPage(unittest.TestCase):
    def setUp(self):
        self.html = open(os.path.join(ROOT, "stuntkey", "web", "index.html"),
                         encoding="utf-8").read()

    def test_language_viewport_skip_link_and_main(self):
        for needle in ('lang="en-CA"', 'name="viewport"', 'class="skip"', '<main id="main">',
                       "<noscript>"):
            self.assertIn(needle, self.html)

    def test_every_button_has_a_distinct_name(self):
        names = re.findall(r'<button[^>]*aria-label="([^"]+)"', self.html)
        self.assertEqual(len(names), len(re.findall(r"<button", self.html)))
        self.assertEqual(len(set(names)), len(names))

    def test_every_input_has_a_label(self):
        for m in re.finditer(r'<input[^>]*id="([^"]+)"', self.html):
            self.assertIn(f'for="{m.group(1)}"', self.html)

    def test_no_external_requests(self):
        self.assertNotRegex(self.html, r'(src|href)="https?://(?!calasautomations)')
        self.assertNotRegex(self.html, r"https://fonts\.")

    def test_text_colours_pass_aa_contrast(self):
        def lum(h):
            h = h.lstrip("#")
            if len(h) == 3:
                h = "".join(c * 2 for c in h)
            r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
            f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
            return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)

        def ratio(a, b):
            la, lb = sorted((lum(a), lum(b)), reverse=True)
            return (la + 0.05) / (lb + 0.05)
        css = open(os.path.join(ROOT, "docs", "site", "styles.css"), encoding="utf-8").read()
        light = dict(re.findall(r"--([a-z0-9-]+):(#[0-9A-Fa-f]{3,6})\b", css.split("@media")[0]))
        pairs = [("ink", "paper"), ("ink-2", "paper"), ("ink-2", "sunk"), ("gold-text", "paper"),
                 ("btn-ink", "btn-bg"), ("accent", "paper")]
        for fg, bg in pairs:
            self.assertGreaterEqual(ratio(light[fg], light[bg]), 4.5, (fg, bg))

    def test_mentions_fix_and_status(self):
        self.assertIn("stuntkey fix", self.html)
        self.assertIn("stuntkey status", self.html)


class TestFixIsCareful(Home):
    def test_a_safety_check_that_cannot_run_is_not_switched_on(self):
        # it would be set to block on failure and stop every Claude Code action
        with mock.patch.object(hook, "self_test", lambda handler, run=None: False):
            code, out, _ = self.run_cli("fix", "--yes")
        self.assertFalse(os.path.exists(self.settings))
        self.assertIn("did not switch it on", out.replace("so I did not switch it on", "did not switch it on"))
        self.assertNotEqual(code, 0)

    def test_failed_repair_leaves_an_existing_file_byte_for_byte(self):
        self.write_json(self.settings, {"hooks": {"PreToolUse": []}, "x": 1})
        before = open(self.settings, "rb").read()
        with mock.patch.object(hook, "self_test", lambda handler, run=None: False):
            self.run_cli("fix", "--yes")
        self.assertEqual(before, open(self.settings, "rb").read())

    def test_shell_form_hook_stays_in_shell_form(self):
        data = {}
        handler = hook.hook_handler(shell_form=True)
        hook.merge_install(data, handler)
        self.write_json(self.settings, data)
        handler_in = list(hook._our_handlers(data["hooks"]["PreToolUse"]))[0][1]
        self.assertNotIn("args", handler_in)
        fixcmd.fix_hook(self.settings)
        after = list(hook._our_handlers(self.read_json(self.settings)["hooks"]["PreToolUse"]))[0][1]
        self.assertNotIn("args", after)

    def test_stale_project_hook_is_found_too(self):
        proj = hook.project_settings_path()
        data = {}
        hook.merge_install(data, hook.hook_handler())
        for ev in data["hooks"]:
            for _g, h in hook._our_handlers(data["hooks"][ev]):
                h["command"] = os.path.join(self.home, "gone", "stuntkey.exe")
        self.write_json(proj, data)
        keys = {i.key: i.level for i in fixcmd.collect()}
        self.assertEqual(keys["hook:project"], fixcmd.RED)

    def test_start_and_status_point_at_fix_not_install(self):
        from stuntkey import cmds
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cmds.cmd_start({}, ".env")
        self.assertIn("stuntkey fix", out.getvalue())

    def test_dark_theme_text_passes_contrast_too(self):
        css = open(os.path.join(ROOT, "docs", "site", "styles.css"), encoding="utf-8").read()
        m = re.search(r':root\[data-theme="dark"\]\{(.*?)\}', css, re.S)
        self.assertIsNotNone(m, "the dark theme block is missing")
        dark = dict(re.findall(r"--([a-z0-9-]+):(#[0-9A-Fa-f]{6})", m.group(1)))

        def lum(h):
            r, g, b = (int(h.lstrip("#")[i:i + 2], 16) / 255 for i in (0, 2, 4))
            f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
            return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
        for fg, bg in (("ink", "paper"), ("ink-2", "paper"), ("btn-ink", "btn-bg")):
            la, lb = sorted((lum(dark[fg]), lum(dark[bg])), reverse=True)
            self.assertGreaterEqual((la + 0.05) / (lb + 0.05), 4.5, (fg, bg))


class TestUndoOfEverySetupStep(Home):
    def test_every_setup_command_has_an_undo_in_help(self):
        code, out, _ = self.run_cli("help")
        self.assertIn("Undo, stop, or recover", out)
        for undo in ("uninstall", "forget", "stop", "resume", "panic"):
            self.assertIn(f"stuntkey {undo} ", out)


if __name__ == "__main__":
    unittest.main()
