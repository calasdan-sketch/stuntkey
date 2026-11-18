"""Beginner-experience fixes found by running every command on a real Windows PC.

1 one "Start here" path, said the same everywhere   2 closed input never hangs
3 clipboard wait in a window that cannot redraw     4 only keychain keys count as saved
5 scan and scan-git agree about examples            6 install --dry-run
7 plainer status lines and a test summary           8 call example, completion help,
                                                      selftest progress line and cache

Everything is synthetic: fake keys, a throwaway HOME, the in-memory keychain.
"""
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import cli, clients, clipboard as clip_mod, cmds, connect as connect_mod
from stuntkey import fixcmd, gitscan, keychain, recipes as recipes_mod, safeprompt
from stuntkey import selftest, setupcmd

REPO = _isolation.REPO
REAL_LOOKING = "zq9Xr4Lm2Vt8Kp3Wn7Yb5Qd6Hs1JfAbCdEfGhIj"        # no known format, not an example
EXAMPLE = "sk-FAKE-stuntkey-check-0000-not-a-real-key"


def _memory_keychain(case):
    os.environ["STUNTKEY_KEYCHAIN"] = "memory"
    keychain._memory.clear()
    case.addCleanup(keychain._memory.clear)
    case.addCleanup(lambda: os.environ.pop("STUNTKEY_KEYCHAIN", None))


def _catalog():
    return recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)


def _env_dir(case, text):
    d = tempfile.mkdtemp(prefix="dx3")
    case.addCleanup(_isolation.rmtree, d)
    with open(os.path.join(d, ".env"), "w", encoding="utf-8") as f:
        f.write(text)
    return d


def _read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
        return f.read()


# ============================================================ 1. one way in

class OneStartHerePath(unittest.TestCase):
    def setUp(self):
        self.steps = [f"stuntkey setup", "stuntkey get github"]

    def test_the_block_names_setup_then_get(self):
        block = fixcmd.render_start_here()
        self.assertLess(block.index("stuntkey setup"), block.index("stuntkey get github"))
        self.assertIn("stuntkey try", block)             # practice is optional, said once

    def test_every_screen_carries_the_same_block(self):
        block = fixcmd.render_start_here().rstrip("\n")
        parser = cli._build_parser()
        for name, text in (("no arguments", cli.NEXT_STEPS),
                           ("help", fixcmd.render_everyday()),
                           ("help --all", fixcmd.render_help(parser)),
                           ("--help", parser.format_help())):
            with self.subTest(screen=name):
                self.assertIn(block, text)

    def test_dash_dash_help_shows_start_here_above_the_long_list(self):
        text = cli._build_parser().format_help()
        self.assertLess(text.index("Start here"), text.index("positional arguments"))
        self.assertNotIn("stuntkey connect <service>", text)

    def test_start_says_it_too(self):
        out = io.StringIO()
        with mock.patch.object(gitscan, "doctor", lambda: {"ok": True, "checks": []}), \
                mock.patch.object(gitscan, "format_doctor", lambda d: ""), \
                contextlib.redirect_stdout(out):
            _memory_keychain(self)
            d = tempfile.mkdtemp(prefix="dx3")
            self.addCleanup(_isolation.rmtree, d)
            old = os.getcwd()
            os.chdir(d)
            try:
                cmds.cmd_start(_catalog(), ".env")
            finally:
                os.chdir(old)
        self.assertIn(fixcmd.render_start_here().rstrip("\n"), out.getvalue())
        self.assertNotIn("Then run `stuntkey fix` to switch everything on", out.getvalue())

    def test_readme_and_guide_say_the_same_order(self):
        for rel in (("README.md",), ("docs", "guide.md")):
            text = _read(*rel)
            with self.subTest(file=rel[-1]):
                self.assertIn("stuntkey setup", text)
                i = text.index("## Start here") if "## Start here" in text else 0
                section = text[i:i + 3500]
                self.assertLess(section.index("stuntkey setup"), section.index("stuntkey get github"))

    def test_the_command_count_is_true(self):
        parser = cli._build_parser()
        texts = fixcmd._help_texts(parser)
        self.assertGreater(len(texts), 50)
        self.assertIn(f"{len(texts)} commands in all", fixcmd.render_help(parser))
        everyday = fixcmd.render_everyday()
        self.assertNotIn("about 50", everyday)
        self.assertIn("more than 50", everyday)
        for rel in (("README.md",), ("docs", "guide.md")):
            self.assertNotIn("about 50", _read(*rel))


# ============================================================ 2. closed input never hangs

class ClosedInput(unittest.TestCase):
    def test_the_null_device_is_not_a_terminal(self):
        # Python says NUL is a terminal on Windows; getpass / getwch would then wait forever
        with open(os.devnull, "r") as nul, mock.patch.object(sys, "stdin", nul):
            self.assertFalse(safeprompt.stdin_is_terminal())
            with mock.patch.object(safeprompt.getpass, "getpass") as gp:
                with self.assertRaises(safeprompt.NoTerminal):
                    safeprompt.read_hidden("x: ")
                gp.assert_not_called()

    def test_read_quiet_on_closed_input_ends_instead_of_waiting(self):
        with open(os.devnull, "r") as nul, mock.patch.object(sys, "stdin", nul), \
                mock.patch.object(safeprompt.getpass, "getpass") as gp, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(EOFError):
                safeprompt.read_quiet("y/n: ")
            gp.assert_not_called()

    def test_get_with_closed_input_ends_in_seconds(self):
        # the exact command that sat silent for 40 s+: real process, closed input, a time limit
        home = tempfile.mkdtemp(prefix="dx3h")
        self.addCleanup(_isolation.rmtree, home)
        env = dict(os.environ, USERPROFILE=home, HOME=home, APPDATA=home, LOCALAPPDATA=home,
                   STUNTKEY_KEYCHAIN="file:" + os.path.join(home, "kc.json"),
                   PYTHONPATH=REPO, PYTHONIOENCODING="utf-8")
        proc = subprocess.run([sys.executable, "-m", "stuntkey", "get", "github",
                               "--no-clipboard", "--no-browser"], stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=60, env=env, cwd=home,
                              encoding="utf-8", errors="replace")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("normal terminal window", proc.stdout)
        self.assertNotIn("Traceback", proc.stdout + proc.stderr)


# ============================================================ 3. clipboard wait, no terminal

FIELD = {"label": "API key", "name": "key", "env_var": "X"}


class WaitWithoutATerminal(unittest.TestCase):
    def _run(self, buf, ticks):
        def fake_wait(*a, on_tick=None, **k):
            for left in ticks:
                on_tick(left)
            return REAL_LOOKING
        with mock.patch.object(clip_mod, "wait_for_key", fake_wait):
            connect_mod._ask_one(FIELD, True, lambda _t: "", buf, (lambda: "", lambda: True), set())
        return buf.getvalue()

    def test_says_up_front_it_cannot_count_down_and_prints_a_line_a_minute(self):
        text = self._run(io.StringIO(), [180, 179, 120, 119, 60, 59, 1])
        self.assertIn("cannot show a live countdown", text)
        self.assertIn("Still waiting for your copy... 2 minutes left (round 1 of 3)", text)
        self.assertIn("1 minute left (round 1 of 3)", text)
        self.assertEqual(text.count("Still waiting"), 2)       # not at the start, not every second
        self.assertNotIn("\r", text)
        self.assertNotIn(REAL_LOOKING, text)

    def test_a_real_terminal_still_gets_the_live_countdown(self):
        class Tty(io.StringIO):
            def isatty(self):
                return True
        text = self._run(Tty(), [125])
        self.assertIn("2:05 left (round 1 of 3)", text)
        self.assertNotIn("cannot show a live countdown", text)

    def test_wiping_the_countdown_uses_the_real_window_width(self):
        for width in (40, 120):
            buf = io.StringIO()
            with mock.patch.object(connect_mod.shutil, "get_terminal_size",
                                   lambda *a, w=width: os.terminal_size((w, 30))):
                connect_mod._wipe_line(buf)
            self.assertEqual(buf.getvalue(), "\r" + " " * (width - 1) + "\r")


# ============================================================ 4. only keychain keys count

class OnlyKeychainKeysCount(unittest.TestCase):
    def setUp(self):
        _memory_keychain(self)
        self.catalog = _catalog()

    def test_an_example_in_dot_env_counts_for_nothing(self):
        d = _env_dir(self, f"OPENAI_API_KEY={EXAMPLE}\n")
        safe, loose = fixcmd.key_places(self.catalog, os.path.join(d, ".env"))
        self.assertEqual((safe, loose), ([], []))

    def test_a_real_looking_key_only_in_dot_env_is_loose_not_saved(self):
        d = _env_dir(self, f"OPENAI_API_KEY={REAL_LOOKING}\n")
        safe, loose = fixcmd.key_places(self.catalog, os.path.join(d, ".env"))
        self.assertEqual(safe, [])
        self.assertEqual(loose, ["openai"])

    def test_a_keychain_key_counts(self):
        d = _env_dir(self, "")
        backend = keychain.detect_backend()
        keychain.store("openai", "OPENAI_API_KEY", REAL_LOOKING, backend)
        safe, loose = fixcmd.key_places(self.catalog, os.path.join(d, ".env"))
        self.assertEqual((safe, loose), (["openai"], []))

    def _status(self, d, as_json=False):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cmds.cmd_status(self.catalog, os.path.join(d, ".env"), as_json)
        return out.getvalue()

    def test_overview_does_not_count_an_example(self):
        d = _env_dir(self, f"OPENAI_API_KEY={EXAMPLE}\n")
        text = self._status(d)
        self.assertIn("with a key stored in the keychain: 0", text)
        self.assertIn("Not ready yet", text)
        data = json.loads(self._status(d, as_json=True))
        self.assertEqual((data["with_keys"], data["connected"], data["env_file_only"]), (0, [], []))

    def test_overview_says_a_dot_env_key_is_not_protected(self):
        d = _env_dir(self, f"OPENAI_API_KEY={REAL_LOOKING}\n")
        text = self._status(d)
        self.assertIn("with a key stored in the keychain: 0", text)
        self.assertIn("found only in a .env file, not protected: openai", text)
        self.assertNotIn(REAL_LOOKING, text)

    def test_start_does_not_say_connected_for_an_example(self):
        d = _env_dir(self, f"OPENAI_API_KEY={EXAMPLE}\n")
        out = io.StringIO()
        old = os.getcwd()
        os.chdir(d)
        try:
            with mock.patch.object(gitscan, "doctor", lambda: {"ok": True, "checks": []}), \
                    mock.patch.object(gitscan, "format_doctor", lambda x: ""), \
                    contextlib.redirect_stdout(out):
                cmds.cmd_start(self.catalog, ".env")
        finally:
            os.chdir(old)
        self.assertNotIn("Connected already", out.getvalue())

    def test_the_status_screen_does_not_say_saved_for_an_example(self):
        d = _env_dir(self, f"OPENAI_API_KEY={EXAMPLE}\n")
        old = os.getcwd()
        os.chdir(d)
        try:
            item = fixcmd._keys_item(self.catalog)
        finally:
            os.chdir(old)
        self.assertNotIn("saved in your keychain", item.text)
        self.assertEqual(item.level, fixcmd.YELLOW)

    def test_the_status_screen_calls_a_dot_env_key_not_protected(self):
        d = _env_dir(self, f"OPENAI_API_KEY={REAL_LOOKING}\n")
        old = os.getcwd()
        os.chdir(d)
        try:
            item = fixcmd._keys_item(self.catalog)
        finally:
            os.chdir(old)
        self.assertIn("not protected", item.text)
        self.assertIn("No key is in your keychain", item.text)


# ============================================================ 5. scan and scan-git agree

def _git(repo, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return subprocess.run(["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com",
                           "-c", "commit.gpgsign=false", *args], capture_output=True, env=env)


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class ScanGitAgreesWithScan(unittest.TestCase):
    def _repo(self, text):
        d = tempfile.mkdtemp(prefix="dx3g")
        self.addCleanup(_isolation.rmtree, d)
        _git(d, "init", "-q")
        with open(os.path.join(d, "a.env"), "w", encoding="utf-8") as f:
            f.write(text)
        _git(d, "add", ".")
        _git(d, "commit", "-q", "-m", "x")
        return d

    def test_an_example_is_skipped_and_said_in_one_line(self):
        d = self._repo(f"OPENAI_API_KEY={EXAMPLE}\n")
        res = gitscan.scan_git(d)
        self.assertEqual(res["findings"], [])
        self.assertGreaterEqual(res["examples"], 1)
        text = gitscan.format_git(res)
        self.assertIn("no keys found", text)
        self.assertIn("example", text)
        self.assertIn("`stuntkey scan`", text)

    def test_a_real_looking_key_is_still_found(self):
        key = "sk-ant-" + "Zq9Xr4Lm2Vt8Kp3Wn7Yb5Qd6Hs1JfAbCd"
        d = self._repo(f"ANTHROPIC_API_KEY={key}\n")
        res = gitscan.scan_git(d)
        self.assertGreaterEqual(len(res["findings"]), 1)       # (a sk-ant key matches two shapes)
        self.assertNotIn(key, json.dumps(res))

    def test_a_folder_that_is_not_a_repository_says_so_in_words(self):
        d = tempfile.mkdtemp(prefix="dx3n")
        self.addCleanup(_isolation.rmtree, d)
        res = gitscan.scan_git(d)
        self.assertIn("not a git repository", res["error"])
        self.assertNotIn("128", res["error"])


class SameRuleForFiles(unittest.TestCase):
    def test_the_line_matcher_skips_examples_like_scan_does(self):
        self.assertEqual(gitscan._pattern_hits(f"X={EXAMPLE}"), [])
        self.assertGreaterEqual(len(gitscan._pattern_hits("X=sk-ant-" + "Zq9Xr4Lm2Vt8Kp3Wn7Yb5Qd6Hs1JfAbCd")), 1)


# ============================================================ 6. install --dry-run

class InstallDryRun(unittest.TestCase):
    def test_the_flag_exists(self):
        args = cli._build_parser().parse_args(["install", "--dry-run"])
        self.assertTrue(args.dry_run)

    def test_it_lists_the_files_and_changes_nothing(self):
        home = tempfile.mkdtemp(prefix="dx3i")
        self.addCleanup(_isolation.rmtree, home)
        cwd = tempfile.mkdtemp(prefix="dx3c")
        self.addCleanup(_isolation.rmtree, cwd)
        lines = []
        tg = clients.targets(home=home, cwd=cwd)
        path = tg["cursor"][0]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write('{"mcpServers": {"other": {"command": "x"}}}')
        before = open(path, "rb").read()
        code = clients.run(["cursor"], False, ask=lambda _t: 1 / 0, out=lines.append,
                           dry_run=True, home=home, cwd=cwd)
        text = "\n".join(lines)
        self.assertEqual(code, 0)
        self.assertEqual(open(path, "rb").read(), before)
        self.assertEqual([n for n in os.listdir(os.path.dirname(path)) if ".bak" in n], [])
        self.assertIn("would change", text)
        self.assertIn(os.path.abspath(path), text)
        self.assertIn("(--dry-run: nothing was changed.)", text)
        self.assertNotIn("go ahead?", text)        # no question: nothing is changed

    def test_the_same_words_as_setup(self):
        out = io.StringIO()
        args = types_ns(dry_run=True, yes=False)
        with mock.patch.object(setupcmd, "_scan_env", lambda *a, **k: {"new": [], "have": [], "skipped": [],
                                                                         "unknown": [], "files": [], "backend": None}), \
                mock.patch.object(fixcmd, "collect", lambda c=None: []), \
                mock.patch("stuntkey.findkeys.examples_skipped", lambda *a: []):
            setupcmd.cmd_setup_all(args, {}, out=out, root=tempfile.gettempdir())
        self.assertIn("(--dry-run: nothing was changed.)", out.getvalue())


def types_ns(**kw):
    import types
    return types.SimpleNamespace(**kw)


# ============================================================ 7. plainer status lines

class PlainStatusLines(unittest.TestCase):
    def test_a_busy_port_is_a_note_not_a_problem(self):
        import socket
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        self.addCleanup(s.close)
        item = fixcmd._port_item(s.getsockname()[1])
        self.assertEqual(item.level, fixcmd.GREEN)
        self.assertIn("not a problem", item.text)
        self.assertNotIn("in use by something else", item.text)

    def test_the_repair_count_matches_the_headline(self):
        fix = lambda: None   # noqa: E731
        items = [fixcmd.Item("a", fixcmd.RED, "one", "s", fixer=fix, fix_text="f"),
                 fixcmd.Item("b", fixcmd.YELLOW, "two", "s", fixer=fix, fix_text="g"),
                 fixcmd.Item("c", fixcmd.YELLOW, "three", "s"),
                 fixcmd.Item("d", fixcmd.GREEN, "four", "", fixer=fix, fix_text="h")]
        text = fixcmd.render(items)
        self.assertIn("1 problem, 2 to look at", text)
        self.assertIn("I can repair 2 of the 3 items marked above", text)

    def test_a_fresh_machine_fails_with_a_friendly_summary(self):
        res = setupcmd.Result(False, "FAIL: x is not set up. Next: run `stuntkey setup`.",
                              ["x Next: a", "y Next: b"])
        out = io.StringIO()
        with mock.patch.object(setupcmd, "run_check", lambda c=None: res):
            code = setupcmd.cmd_test(None, None, out=out)
        text = out.getvalue()
        self.assertEqual(code, 1)
        self.assertTrue(text.startswith("FAIL:"))
        self.assertIn("Summary: 2 things still to switch on", text)
        self.assertIn("normal", text)

    def test_a_real_fault_is_not_called_normal(self):
        res = setupcmd.Result(False, "FAIL: the pretend call was refused. Next: doctor.", ["a"], fault=True)
        out = io.StringIO()
        with mock.patch.object(setupcmd, "run_check", lambda c=None: res):
            setupcmd.cmd_test(None, None, out=out)
        self.assertIn("real fault", out.getvalue())
        self.assertNotIn("normal on a new computer", out.getvalue())

    def test_a_pass_has_no_summary(self):
        res = setupcmd.Result(True, "PASS: all good.")
        out = io.StringIO()
        with mock.patch.object(setupcmd, "run_check", lambda c=None: res):
            self.assertEqual(setupcmd.cmd_test(None, None, out=out), 0)
        self.assertNotIn("Summary", out.getvalue())


# ============================================================ 8. call, completion, selftest

class CallExampleAndCompletion(unittest.TestCase):
    def test_call_without_enough_words_shows_a_working_example(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            cli._build_parser().parse_args(["call", "github"])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("Example: stuntkey call github GET /user", err.getvalue())

    def test_call_help_has_the_example_too(self):
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit):
            cli._build_parser().parse_args(["call", "--help"])
        self.assertIn("stuntkey call github GET /user", out.getvalue())

    def test_completion_says_where_to_paste_it(self):
        for shell, place in (("powershell", "$PROFILE"), ("bash", ".bashrc")):
            out = io.StringIO()
            fixcmd.cmd_completion(types_ns(shell=shell), cli._build_parser(), out=out)
            with self.subTest(shell=shell):
                self.assertIn("Where to paste this", out.getvalue())
                self.assertIn(place, out.getvalue())


class SelftestProgressAndCache(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def fake_run_all():
            self.calls.append(1)
            return [{"pass": True}] * 3
        # looks like the real function to the cache (a replaced one never is cached)
        fake_run_all.__module__ = selftest.__name__
        patcher = mock.patch.object(selftest, "run_all", fake_run_all)
        patcher.start()
        self.addCleanup(patcher.stop)
        p2 = mock.patch.object(selftest, "attacks", lambda: [0] * 77)
        p2.start()
        self.addCleanup(p2.stop)
        self.addCleanup(self._rm)
        self._rm()

    def _rm(self):
        try:
            os.unlink(selftest._cache_path())
        except OSError:
            pass

    def test_says_one_line_with_the_count_before_it_runs(self):
        said = []
        selftest.checked(say=said.append)
        self.assertEqual(said, ["Checking 77 attack tests (about 6 seconds)..."])

    def test_a_clean_result_is_reused_for_a_few_minutes(self):
        said, clock = [], [1000.0]
        self.assertEqual(selftest.checked(say=said.append, now=lambda: clock[0]), (3, 3, False))
        clock[0] += 120
        self.assertEqual(selftest.checked(say=said.append, now=lambda: clock[0]), (3, 3, True))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(said), 1)                  # no message when nothing runs
        clock[0] += selftest.CACHE_SECONDS + 1
        self.assertEqual(selftest.checked(now=lambda: clock[0])[2], False)
        self.assertEqual(len(self.calls), 2)

    def test_a_failure_is_never_kept(self):
        self.calls.clear()
        with mock.patch.object(selftest, "run_all", self._failing()):
            self.assertEqual(selftest.checked()[:2], (2, 3))
            self.assertEqual(selftest.checked()[:2], (2, 3))
        self.assertEqual(len(self.calls), 2)

    def _failing(self):
        def run():
            self.calls.append(1)
            return [{"pass": True}, {"pass": True}, {"pass": False}]
        run.__module__ = selftest.__name__
        return run

    def test_a_changed_stuntkey_file_throws_the_old_result_away(self):
        selftest.checked()
        with mock.patch.object(selftest, "_code_stamp", lambda: "other"):
            self.assertFalse(selftest.checked()[2])
        self.assertEqual(len(self.calls), 2)

    def test_the_selftest_command_itself_never_uses_the_cache(self):
        selftest.checked()
        with contextlib.redirect_stdout(io.StringIO()):
            selftest.cmd_selftest(True, False)
        self.assertEqual(len(self.calls), 2)

    def test_a_replaced_run_all_is_never_cached(self):
        calls = []
        with mock.patch.object(selftest, "run_all", lambda: calls.append(1) or [{"pass": True}]):
            selftest.checked()
            selftest.checked()
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
