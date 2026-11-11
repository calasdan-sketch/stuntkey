"""Round 14, first-use speed: `setup` in one go, `test`, `undo`, `get` with no
name, the short `help`, a quieter `status`, `scan`/`start` agreeing, Claude Code
for all folders, lazy start-up, and the wiring of `recipe`.

Every test runs with HOME, USERPROFILE, APPDATA and LOCALAPPDATA pointing at a
fresh temp folder, the keychain swapped for the in-memory test one, only
made-up keys, the clipboard and Claude's own program stubbed, and nothing that
can open a real window or browser."""
import contextlib
import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from stuntkey import (claudecode, cli, clients, extras, findkeys, fixcmd, getmenu,  # noqa: E402,F401
                      hook, keychain, recipes, setupcmd, undo)

# A made-up key that is not an obvious example (no "xxx", "abc", "example"...).
FAKE_ANTHROPIC = "sk-ant-api03-Zq8Lm2VtR7wKd4NfXb9HcY5pJe3Us6GaTv1Wo0RiQ"
FAKE_GITHUB = "ghp_" + "Zq8Lm2VtR7wKd4NfXb9HcY5pJe3Us6GaTv1W"


def _no_real_dialog(*a, **k):
    raise AssertionError("a real permission window was asked for")


class FakeClaude:
    """Stands in for the `claude` program: `mcp add/remove --scope user`
    edit a fake ~/.claude.json, as the real one would."""

    def __init__(self, home):
        self.home, self.calls = home, []

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        path = claudecode.config_path(self.home)
        data = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        words = argv[1:]
        if words[:2] == ["mcp", "add"]:
            i = words.index("stuntkey")
            data.setdefault("mcpServers", {})["stuntkey"] = {
                "command": words[i + 2], "args": words[i + 3:]}
        elif words[:2] == ["mcp", "remove"]:
            data.get("mcpServers", {}).pop("stuntkey", None)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return subprocess.CompletedProcess(argv, 0, b"", b"")


class Home(unittest.TestCase):
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
        self._patches = [
            mock.patch.object(hook, "self_test", lambda handler, run=None: True),
            mock.patch("stuntkey.approve.ask_person", _no_real_dialog),
            mock.patch("webbrowser.open", lambda *a, **k: False),
        ]
        for p in self._patches:
            p.start()
        keychain._memory.clear()

    def tearDown(self):
        for p in self._patches:
            p.stop()
        keychain._memory.clear()
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

    def use_claude_code(self, with_cli=True):
        """Make this home look like it has Claude Code (and a stub program)."""
        os.makedirs(os.path.join(self.home, ".claude"), exist_ok=True)
        self.fake = FakeClaude(self.home)
        self._c1 = mock.patch.object(claudecode, "RUN", self.fake)
        self._c2 = mock.patch.object(claudecode, "cli_path",
                                     lambda which=None: "claude" if with_cli else None)
        self._c1.start()
        self._c2.start()
        self.addCleanup(self._c1.stop)
        self.addCleanup(self._c2.stop)

    def write_env(self, text):
        with open(os.path.join(self.cwd, ".env"), "w", encoding="utf-8") as f:
            f.write(text)


class TestSetup(Home):
    def test_setup_is_one_command_and_ends_set_up(self):
        self.use_claude_code()
        code, out, _ = self.run_cli("setup", "--yes")
        self.assertEqual(code, 0, out)
        self.assertIn("You're set up", out)
        self.assertIn("close Claude", out)
        self.assertIn("PASS", out)
        # the safety check and Claude Code for all folders are on
        self.assertEqual(claudecode.state(self.home), "ok")
        self.assertTrue(any(i.key == "hook:user" and i.level == fixcmd.GREEN
                            for i in fixcmd.collect()))

    def test_setup_moves_keys_and_says_what_is_left(self):
        self.use_claude_code()
        self.write_env(f"ANTHROPIC_API_KEY={FAKE_ANTHROPIC}\nSOMETHING_ELSE=hello\n")
        code, out, _ = self.run_cli("setup", "--yes")
        self.assertNotIn(FAKE_ANTHROPIC, out)
        self.assertIn("Saved ANTHROPIC_API_KEY", out)
        be = keychain.detect_backend()
        self.assertEqual(keychain.read("anthropic", "ANTHROPIC_API_KEY", be), FAKE_ANTHROPIC)
        # the file still holds the key, so it is NOT safe yet, and the step is plain
        self.assertEqual(code, 1)
        self.assertIn("Not safe yet", out)
        self.assertIn(".env", out)
        self.assertTrue(os.path.exists(os.path.join(self.cwd, ".env")))   # never deleted for them

    def test_plan_is_listed_before_anything_changes_and_dry_run_changes_nothing(self):
        self.use_claude_code()
        self.write_env(f"ANTHROPIC_API_KEY={FAKE_ANTHROPIC}\n")
        code, out, _ = self.run_cli("setup", "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("one go, one yes", out)
        self.assertIn("ANTHROPIC_API_KEY", out)
        self.assertNotIn(FAKE_ANTHROPIC, out)
        self.assertFalse(os.path.exists(hook.user_settings_path()))
        self.assertEqual(self.fake.calls, [])
        self.assertIsNone(keychain.read("anthropic", "ANTHROPIC_API_KEY",
                                        keychain.detect_backend()))

    def test_without_yes_and_no_terminal_it_asks_for_yes_and_changes_nothing(self):
        self.use_claude_code()
        code, out, _ = self.run_cli("setup")
        self.assertEqual(code, 2)
        self.assertIn("--yes", out)
        self.assertFalse(os.path.exists(hook.user_settings_path()))

    def test_one_yes_at_the_start_is_the_only_question(self):
        self.use_claude_code()
        asked = []
        out = io.StringIO()

        def reader(prompt):
            asked.append(prompt)
            return "y"
        code = setupcmd.cmd_setup_all(mock.Mock(yes=False, dry_run=False),
                                      recipes.load_recipes(), out=out, ask=reader)
        self.assertEqual(len(asked), 1)
        self.assertEqual(code, 0, out.getvalue())

    def test_a_no_changes_nothing(self):
        self.use_claude_code()
        out = io.StringIO()
        code = setupcmd.cmd_setup_all(mock.Mock(yes=False, dry_run=False),
                                      recipes.load_recipes(), out=out, ask=lambda p: "n")
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(hook.user_settings_path()))
        self.assertEqual(self.fake.calls, [])

    def test_example_values_are_named_never_silent_and_never_moved(self):
        self.use_claude_code()
        self.write_env("OPENAI_API_KEY=sk-your-key-here-0000000000\n")
        code, out, _ = self.run_cli("setup", "--yes")
        self.assertIn("looks like an example", out)
        self.assertIsNone(keychain.read("openai", "OPENAI_API_KEY", keychain.detect_backend()))

    def test_not_safe_yet_names_the_one_next_step_when_claude_cannot_be_reached(self):
        self.use_claude_code(with_cli=False)
        code, out, _ = self.run_cli("setup", "--yes")
        self.assertEqual(code, 1)
        self.assertIn("Not safe yet", out)
        self.assertIn("claude mcp add --scope user", out)

    def test_old_project_setup_still_there(self):
        code, out, _ = self.run_cli("setup", "--project")
        self.assertEqual(code, 1)
        self.assertIn("stuntkey init", out)


class TestUndo(Home):
    def test_undo_puts_back_the_files_and_the_keys(self):
        self.use_claude_code()
        os.makedirs(os.path.dirname(hook.user_settings_path()), exist_ok=True)
        original = json.dumps({"theme": "dark"})
        with open(hook.user_settings_path(), "w", encoding="utf-8") as f:
            f.write(original)
        self.write_env(f"ANTHROPIC_API_KEY={FAKE_ANTHROPIC}\n")
        self.run_cli("setup", "--yes")
        self.assertNotEqual(open(hook.user_settings_path(), encoding="utf-8").read(), original)
        code, out, _ = self.run_cli("undo", "--yes")
        self.assertEqual(code, 0, out)
        self.assertIn("back the way it was", out)
        self.assertEqual(open(hook.user_settings_path(), encoding="utf-8").read(), original)
        self.assertIsNone(keychain.read("anthropic", "ANTHROPIC_API_KEY",
                                        keychain.detect_backend()))
        self.assertEqual(claudecode.state(self.home), "missing")
        self.assertIn("remove", self.fake.calls[-1])

    def test_undo_with_nothing_to_undo_says_so(self):
        code, out, _ = self.run_cli("undo", "--yes")
        self.assertEqual(code, 0)
        self.assertIn("Nothing to undo", out)

    def test_undo_asks_first_and_a_no_changes_nothing(self):
        self.run_cli("fix", "--yes")
        out = io.StringIO()
        code = undo.cmd_undo(mock.Mock(yes=False), out=out, ask=lambda p: "n")
        self.assertEqual(code, 1)
        self.assertTrue(os.path.exists(hook.user_settings_path()))

    def test_undo_is_one_step_at_a_time(self):
        self.run_cli("fix", "--yes")
        first = undo.last()
        self.assertIsNotNone(first)
        self.run_cli("undo", "--yes")
        self.assertIsNone(undo.last())

    def test_fix_is_undoable(self):
        self.run_cli("fix", "--yes")
        self.assertTrue(os.path.exists(hook.user_settings_path()))
        self.run_cli("undo", "--yes")
        self.assertFalse(os.path.exists(hook.user_settings_path()))

    def test_get_is_undoable(self):
        recipe = recipes.load_recipes()["github"]
        be = keychain.detect_backend()
        keychain.store("github", "GITHUB_TOKEN", FAKE_GITHUB, be)
        cli._note_for_undo(recipe)          # what `get` writes after a first save
        code, out, _ = self.run_cli("undo", "--yes")
        self.assertEqual(code, 0)
        self.assertIsNone(keychain.read("github", "GITHUB_TOKEN", be))

    def test_an_unchanged_run_leaves_no_second_undo_step(self):
        self.run_cli("fix", "--yes")
        self.run_cli("fix", "--yes")        # nothing to change the second time
        self.assertEqual(len(undo._load()), 1)


class TestTest(Home):
    def test_fails_before_setup_with_one_line_and_one_step(self):
        code, out, _ = self.run_cli("test")
        self.assertEqual(code, 1)
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertTrue(out.startswith("FAIL"))
        self.assertIn("Next:", out)

    def test_passes_after_setup_on_one_line(self):
        self.use_claude_code()
        self.run_cli("setup", "--yes")
        code, out, _ = self.run_cli("test")
        self.assertEqual(code, 0, out)
        self.assertEqual(len(out.strip().splitlines()), 1)
        self.assertTrue(out.startswith("PASS"))

    def test_the_other_names_work(self):
        self.use_claude_code()
        self.run_cli("setup", "--yes")
        for name in ("check", "try-it"):
            code, out, _ = self.run_cli(name)
            self.assertEqual(code, 0, (name, out))
            self.assertTrue(out.startswith("PASS"))

    def test_the_pretend_call_really_goes_through_the_broker_and_hides_the_key(self):
        ok, why = setupcmd._fake_round_trip()
        self.assertTrue(ok, why)

    def test_a_broker_that_leaks_the_pretend_key_fails(self):
        from stuntkey import broker
        real = broker.call

        def leaky(*a, **k):
            r = real(*a, **k)
            r["body"] += " " + setupcmd.FAKE_KEY
            return r
        with mock.patch.object(broker, "call", leaky):
            ok, why = setupcmd._fake_round_trip()
        self.assertFalse(ok)
        self.assertIn("hidden", why)

    def test_a_broken_round_trip_is_a_fail_line_with_a_next_step(self):
        self.use_claude_code()
        self.run_cli("setup", "--yes")
        with mock.patch.object(setupcmd, "_fake_round_trip", lambda: (False, "it broke")):
            code, out, _ = self.run_cli("test")
        self.assertEqual(code, 1)
        self.assertIn("FAIL: it broke", out)
        self.assertIn("Next:", out)

    def test_never_prints_a_key(self):
        self.use_claude_code()
        _, out, _ = self.run_cli("test")
        self.assertNotIn(setupcmd.FAKE_KEY, out)


class TestHelp(Home):
    EVERYDAY = ("setup", "get", "test", "status", "fix", "undo", "run", "scan")

    def test_plain_help_shows_about_eight_commands(self):
        code, out, _ = self.run_cli("help")
        rows = re.findall(r"^\s+stuntkey (\S+)\s", out, re.M)
        self.assertEqual(tuple(rows), self.EVERYDAY)
        self.assertNotIn("stuntkey wrap", out)
        self.assertIn("help --all", out)

    def test_help_all_lists_the_rest(self):
        code, out, _ = self.run_cli("help", "--all")
        for name in ("wrap", "panic", "undo", "test", "recipe", "revoke", "sessions", "setup"):
            self.assertIn(f"stuntkey {name} ", out + " ", name)

    def test_help_for_one_command_still_works(self):
        code, out, _ = self.run_cli("help", "undo")
        self.assertEqual(code, 0)
        self.assertIn("usage: stuntkey undo", out)

    def test_short_help_is_plain_words_and_fits(self):
        _, out, _ = self.run_cli("help")
        for line in out.splitlines():
            self.assertLessEqual(len(line), 100, line)
        self.assertIsNone(re.search(r"\b(hmac|nonce|argv|payload|daemon|loopback)\b", out))

    def test_no_arguments_page_points_at_setup(self):
        _, out, _ = self.run_cli()
        self.assertIn("stuntkey setup", out)


class TestStatusPort(Home):
    def test_free_port_says_nothing(self):
        items = fixcmd.collect(port=0)
        self.assertFalse(any(i.key == "port" for i in items))

    def test_busy_port_is_a_calm_note_only_about_the_web_page(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        try:
            item = fixcmd._port_item(s.getsockname()[1])
        finally:
            s.close()
        self.assertEqual(item.level, fixcmd.GREEN)
        self.assertIn("only matters if you use the stuntkey web page", item.text)
        self.assertEqual(fixcmd.verdict([item])[0], fixcmd.GREEN)


class TestScanAndStartAgree(Home):
    PLACEHOLDER = "OPENAI_API_KEY=sk-your-key-here-0000000000\n"

    def test_example_in_env_is_reported_by_scan_and_start_not_silent(self):
        self.write_env(self.PLACEHOLDER)
        cat = recipes.load_recipes()
        found = findkeys.examples_skipped(self.cwd, cat)
        self.assertEqual([n for _f, n in found], ["OPENAI_API_KEY"])
        code, out, _ = self.run_cli("scan")
        self.assertEqual(code, 0)                  # an example is not a leaked key
        self.assertIn("ooks like an example, skipped", out)
        self.assertIn("OPENAI_API_KEY", out)

    def test_start_counts_what_scan_counts(self):
        from stuntkey import cmds, gitscan
        self.write_env(f"{self.PLACEHOLDER}ANTHROPIC_API_KEY={FAKE_ANTHROPIC}\n")
        cat = recipes.load_recipes()
        scan_count = len(findkeys.find_loose(self.cwd, cat)["findings"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out), \
                mock.patch.object(gitscan, "doctor", lambda: {"ok": True, "checks": []}), \
                mock.patch.object(gitscan, "format_doctor", lambda d: ""):
            cmds.cmd_start(cat, ".env")
        text = out.getvalue()
        self.assertIn(f"{scan_count} place(s)", text)
        self.assertIn("ooks like an example, skipped", text)
        self.assertNotIn(FAKE_ANTHROPIC, text)

    def test_json_scan_output_is_untouched(self):
        self.write_env(self.PLACEHOLDER)
        code, out, _ = self.run_cli("scan", "--json")
        json.loads(out)


class TestGetMenu(Home):
    def setUp(self):
        super().setUp()
        self.cat = recipes.load_recipes()

    def test_spoken_names_find_the_service(self):
        for text, slug in (("open ai", "openai"), ("OpenAI", "openai"), ("git hub", "github"),
                           ("stripe", "stripe"), ("chatgpt", "openai"), ("claude", "anthropic"),
                           ("gemini", "google-gemini")):
            self.assertEqual(getmenu.best(text, self.cat), slug, text)

    def test_unsure_is_none_not_a_guess(self):
        self.assertIsNone(getmenu.best("open", self.cat))        # openai, openrouter, ...
        self.assertIsNone(getmenu.best("zzzz", self.cat))
        self.assertIsNone(getmenu.best("", self.cat))

    def test_a_key_is_recognised_by_its_shape_and_the_service_named(self):
        self.assertEqual(getmenu.service_for_key(FAKE_ANTHROPIC, self.cat)[0], "anthropic")
        self.assertEqual(getmenu.service_for_key(FAKE_GITHUB, self.cat)[0], "github")
        self.assertEqual(getmenu.service_for_key("hello world", self.cat), [])

    def _clip(self, value):
        cleared = []
        return (lambda: value, lambda: cleared.append(1) or True), cleared

    def test_clipboard_key_is_named_and_used_after_a_yes_without_being_shown(self):
        clip, _ = self._clip(FAKE_ANTHROPIC)
        out = io.StringIO()
        got = getmenu.choose(self.cat, out=out, clip=clip, reader=lambda p: "")
        self.assertEqual(got[:3], ("key", "anthropic", FAKE_ANTHROPIC))
        self.assertIn("Anthropic", out.getvalue())
        self.assertNotIn(FAKE_ANTHROPIC, out.getvalue())

    def test_a_no_falls_back_to_the_menu(self):
        clip, _ = self._clip(FAKE_ANTHROPIC)
        out = io.StringIO()
        got = getmenu.choose(self.cat, out=out, clip=clip, reader=lambda p: "n",
                             ask=lambda p: "stripe")
        self.assertEqual(got, ("service", "stripe"))
        self.assertIn("Which service", out.getvalue())

    def test_typed_number_and_name_and_site(self):
        clip, _ = self._clip("")
        self.assertEqual(getmenu.choose(self.cat, out=io.StringIO(), clip=clip,
                                        ask=lambda p: "1"), ("service", "openai"))
        self.assertEqual(getmenu.choose(self.cat, out=io.StringIO(), clip=clip,
                                        ask=lambda p: "open ai"), ("service", "openai"))
        self.assertEqual(getmenu.choose(self.cat, out=io.StringIO(), clip=clip,
                                        ask=lambda p: "mailchimp.com"),
                         ("service", "mailchimp.com"))

    def test_a_key_typed_into_the_menu_is_refused_not_saved(self):
        clip, _ = self._clip("")
        out = io.StringIO()
        got = getmenu.choose(self.cat, out=out, clip=clip, ask=lambda p: FAKE_ANTHROPIC)
        self.assertIsNone(got)
        self.assertIn("Do not type keys here", out.getvalue())
        self.assertNotIn(FAKE_ANTHROPIC, out.getvalue())

    def test_no_clipboard_at_all_still_gives_the_menu(self):
        from stuntkey import clipboard
        with mock.patch.object(clipboard, "backend", side_effect=clipboard.Unavailable("none")):
            got = getmenu.choose(self.cat, out=io.StringIO(), ask=lambda p: "github")
        self.assertEqual(got, ("service", "github"))

    def test_cli_get_with_no_name_saves_the_copied_key_and_empties_the_clipboard(self):
        clip, cleared = self._clip(FAKE_ANTHROPIC)
        seen = {}

        def fake_connect(recipe, **kw):
            seen["service"], seen["lines"] = recipe["service"], kw.get("key_lines")
            return 0
        with mock.patch("stuntkey.clipboard.backend", return_value=clip), \
                mock.patch("stuntkey.safeprompt.read_quiet", lambda prompt: ""), \
                mock.patch("stuntkey.clipboard.clear_verified", lambda g, c: c() is not False), \
                mock.patch.object(cli, "connect_service", fake_connect):
            code, out, _ = self.run_cli("get")
        self.assertEqual(code, 0, out)
        self.assertEqual(seen, {"service": "anthropic", "lines": [FAKE_ANTHROPIC]})
        self.assertEqual(cleared, [1])
        self.assertNotIn(FAKE_ANTHROPIC, out)

    def test_cli_get_with_a_spoken_name(self):
        seen = {}

        def fake_connect(recipe, **kw):
            seen["service"] = recipe["service"]
            return 0
        with mock.patch.object(cli, "connect_service", fake_connect):
            code, out, err = self.run_cli("get", "open ai")
        self.assertEqual(seen.get("service"), "openai")
        self.assertIn("OpenAI", err)             # "I took 'open ai' to mean OpenAI"


class TestClaudeCodeAllFolders(Home):
    def test_not_detected_without_its_folder(self):
        self.assertEqual(fixcmd._claude_code_items(), [])

    def test_detected_and_not_plugged_is_a_fixable_yellow(self):
        self.use_claude_code()
        items = fixcmd._claude_code_items()
        self.assertEqual(items[0].level, fixcmd.YELLOW)
        self.assertIsNotNone(items[0].fixer)

    def test_fix_plugs_in_for_all_folders_with_claude_own_command(self):
        self.use_claude_code()
        code, out, _ = self.run_cli("fix", "--yes")
        self.assertEqual(code, 0, out)
        words = self.fake.calls[0]
        self.assertEqual(words[1:6], ["mcp", "add", "--scope", "user", "stuntkey"])
        self.assertEqual(claudecode.state(self.home), "ok")

    def test_when_the_program_is_missing_the_one_command_is_given(self):
        self.use_claude_code(with_cli=False)
        item = fixcmd._claude_code_items()[0]
        self.assertIsNone(item.fixer)
        self.assertIn("claude mcp add --scope user stuntkey", item.step)

    def test_an_out_of_date_entry_is_replaced(self):
        self.use_claude_code()
        with open(claudecode.config_path(self.home), "w", encoding="utf-8") as f:
            json.dump({"mcpServers": {"stuntkey": {"command": "old", "args": []}}}, f)
        self.assertEqual(claudecode.state(self.home), "outdated")
        ok, _ = claudecode.add_user_scope(self.home)
        self.assertTrue(ok)
        self.assertEqual(claudecode.state(self.home), "ok")

    def test_an_unreadable_file_is_left_alone(self):
        self.use_claude_code()
        with open(claudecode.config_path(self.home), "w", encoding="utf-8") as f:
            f.write("{not json")
        ok, why = claudecode.add_user_scope(self.home)
        self.assertFalse(ok)
        self.assertEqual(self.fake.calls, [])
        self.assertIn("claude mcp add", why)


class TestLazyStartup(unittest.TestCase):
    def _modules(self, code):
        env = dict(os.environ)
        tmp = tempfile.mkdtemp()
        env.update(HOME=tmp, USERPROFILE=tmp, APPDATA=tmp, LOCALAPPDATA=tmp,
                   STUNTKEY_KEYCHAIN="memory", PYTHONPATH=ROOT)
        done = subprocess.run([sys.executable, "-c", code], env=env, cwd=tmp,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def test_importing_the_cli_does_not_load_the_heavy_modules(self):
        out = self._modules(
            "import sys, stuntkey.cli\n"
            "print(sorted(m for m in sys.modules if m.startswith('stuntkey.')))")
        for heavy in ("connect", "mcp", "hook", "scan", "store", "keychain", "doctor", "agent"):
            self.assertNotIn(f"'stuntkey.{heavy}'", out, heavy)

    def test_help_does_not_load_them_either(self):
        out = self._modules(
            "import sys, io, contextlib, stuntkey.cli as c\n"
            "with contextlib.redirect_stdout(io.StringIO()):\n"
            "    c.main(['help'])\n"
            "print(sorted(m for m in sys.modules if m.startswith('stuntkey.')))")
        for heavy in ("connect", "mcp", "hook", "scan", "agent", "doctor"):
            self.assertNotIn(f"'stuntkey.{heavy}'", out, heavy)

    def test_a_command_still_loads_what_it_needs(self):
        out = self._modules(
            "import sys, io, contextlib, stuntkey.cli as c\n"
            "with contextlib.redirect_stdout(io.StringIO()):\n"
            "    c.main(['list'])\n"
            "print('ok')")
        self.assertIn("ok", out)

    def test_lazy_module_reads_sets_and_patches_the_real_module(self):
        from stuntkey import keychain as real
        with mock.patch.object(cli.keychain_mod, "detect_backend", lambda: "x"):
            self.assertEqual(real.detect_backend(), "x")
        self.assertNotEqual(real.detect_backend(), "x")


class TestRecipeAndProxyWiring(Home):
    def test_recipe_approve_calls_the_trust_layer(self):
        from stuntkey import remote
        calls = []
        with mock.patch.object(remote, "recipe_approve",
                               lambda s, **kw: calls.append(("approve", s)) or 0), \
                mock.patch.object(remote, "recipe_revoke",
                                  lambda s, **kw: calls.append(("revoke", s)) or 0):
            code1, _, _ = self.run_cli("recipe", "approve", "mine")
            code2, _, _ = self.run_cli("recipe", "revoke", "mine")
        self.assertEqual((code1, code2), (0, 0))
        self.assertEqual(calls, [("approve", "mine"), ("revoke", "mine")])

    def test_recipe_list_runs_with_no_recipes(self):
        code, out, _ = self.run_cli("recipe", "list")
        self.assertEqual(code, 0)

    def test_revoke_sessions_and_proxy_limits_are_wired(self):
        parser = cli._build_parser()
        a = parser.parse_args(["revoke", "--all"])
        self.assertTrue(a.all)
        b = parser.parse_args(["revoke", "github"])
        self.assertEqual(b.service, "github")
        parser.parse_args(["sessions"])
        c = parser.parse_args(["proxy", "--ttl", "30m", "--max-calls", "5", "echo", "hi"])
        self.assertEqual((c.ttl, c.max_calls), ("30m", 5))

    def test_sessions_command_runs(self):
        code, out, _ = self.run_cli("sessions")
        self.assertEqual(code, 0)


class TestCompareSite(unittest.TestCase):
    SITE = os.path.join(ROOT, "docs", "site")

    def _page(self):
        with open(os.path.join(self.SITE, "compare.html"), encoding="utf-8") as f:
            return f.read()

    def test_compare_page_exists_with_the_verified_facts_and_the_honest_part(self):
        page = self._page()
        for must in ("1Password", "Doppler", "Infisical", "dotenvx",
                     "https://www.1password.dev/environments/claude-plugin",
                     "https://infisical.com/blog/agent-vault-the-open-source-credential-proxy-and-vault-for-agents",
                     "https://www.doppler.com/agents", "check their site",
                     "Mac and Linux", "2.1.273"):
            self.assertIn(must, page, must)
        self.assertRegex(page, r"(?i)where they are better")
        self.assertNotRegex(page, r"(?i)better than (1password|doppler|infisical|dotenvx)")


if __name__ == "__main__":
    unittest.main()
