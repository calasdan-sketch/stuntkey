"""`stuntkey get` connect flow: countdown, auto-restart, no tracebacks when
there is no keyboard, optional ssh and OS-specific hints in doctor. No real
waiting: the clock, the clipboard and the prompts are all fake."""
import io
import sys
import unittest
import warnings
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import cli, clients, clipboard as clip_mod, connect as connect_mod
from stuntkey import gitscan, safeprompt

KEY = "sk-FAKE-TEST-0000-abcdefghijklmnop"
FIELD = {"label": "API key", "name": "key", "env_var": "X"}


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += max(s, 0.5)


class TtyBuffer(io.StringIO):
    def isatty(self):
        return True


class Countdown(unittest.TestCase):
    def test_wait_reports_seconds_left_without_real_sleep(self):
        clock, seen = FakeClock(), []
        got = clip_mod.wait_for_key(None, set(), lambda: "", lambda: True, wait=5, poll=1,
                                    now=clock.now, sleep=clock.sleep, on_tick=seen.append)
        self.assertIsNone(got)
        self.assertEqual(seen[0], 5)
        self.assertEqual(seen, sorted(seen, reverse=True))
        self.assertLessEqual(seen[-1], 1)

    def test_a_broken_display_does_not_stop_the_wait(self):
        clock = FakeClock()
        feed = iter(["", "", KEY])

        def boom(_left):
            raise RuntimeError("screen gone")
        got = clip_mod.wait_for_key(None, set(), lambda: next(feed, KEY), lambda: True,
                                    wait=10, poll=1, now=clock.now, sleep=clock.sleep,
                                    on_tick=boom)
        self.assertEqual(got, KEY)

    def test_tick_never_receives_clipboard_text(self):
        clock, seen = FakeClock(), []
        clip_mod.wait_for_key(None, set(), lambda: "", lambda: True, wait=3, poll=1,
                              now=clock.now, sleep=clock.sleep, on_tick=seen.append)
        self.assertTrue(all(isinstance(x, int) for x in seen))


class AutoRestart(unittest.TestCase):
    def run_ask(self, waits, out=None, prompt=lambda _t: "pasted"):
        out = out or io.StringIO()
        results = iter(waits)
        cleared = []

        def fake_wait(*a, **k):
            r = next(results)
            if isinstance(r, BaseException):
                raise r
            return r
        with mock.patch.object(clip_mod, "wait_for_key", fake_wait):
            value = connect_mod._ask_one(FIELD, True, prompt, out,
                                         (lambda: "", lambda: cleared.append(1) or True), set())
        return value, out.getvalue(), cleared

    def test_lapse_says_round_and_restarts_by_itself(self):
        value, text, _ = self.run_ask([None, None, KEY])
        self.assertEqual(value, KEY)
        self.assertIn("round 1 of 3", text)
        self.assertIn("round 2 of 3", text)
        self.assertIn("do not need to run the command again", text)
        self.assertNotIn(KEY, text)

    def test_stops_after_the_cap_and_says_what_to_do(self):
        called = []

        def refuse(_t):
            called.append(1)
            raise KeyboardInterrupt
        value, text, cleared = self.run_ask([None, None, None], prompt=refuse)
        self.assertIsNone(value)
        self.assertIn("Nothing was copied in 9 minutes", text)
        self.assertIn("run `stuntkey get` again", text)
        self.assertTrue(cleared)                     # clipboard emptied on this path too

    def test_ctrl_c_during_the_wait_exits_cleanly_and_empties_clipboard(self):
        value, text, cleared = self.run_ask([KeyboardInterrupt()])
        self.assertIsNone(value)
        self.assertIn("cancelled", text)
        self.assertTrue(cleared)

    def test_closed_keyboard_after_timeout_gives_a_plain_message(self):
        def eof(_t):
            raise EOFError
        value, text, cleared = self.run_ask([None, None, None], prompt=eof)
        self.assertIsNone(value)
        self.assertIn("normal terminal window", text)
        self.assertTrue(cleared)
        self.assertNotIn("Traceback", text)

    def test_countdown_line_only_on_a_real_terminal(self):
        seen_ticks = []

        def fake_wait(*a, on_tick=None, **k):
            seen_ticks.append(on_tick)
            if on_tick:
                on_tick(125)
            return KEY
        for buf, expect_tick in ((TtyBuffer(), True), (io.StringIO(), False)):
            seen_ticks.clear()
            with mock.patch.object(clip_mod, "wait_for_key", fake_wait):
                connect_mod._ask_one(FIELD, True, lambda _t: "", buf,
                                     (lambda: "", lambda: True), set())
            # a real terminal gets the live countdown; anywhere else gets the
            # once-a-minute line (see test_dx_round3), never a redrawn line
            self.assertIsNotNone(seen_ticks[0])
            if expect_tick:
                self.assertIn("2:05 left (round 1 of 3)", buf.getvalue())
            else:
                self.assertNotIn("\r", buf.getvalue())
            self.assertNotIn(KEY, buf.getvalue())


class NoKeyboard(unittest.TestCase):
    def test_hidden_prompt_without_a_terminal_stops_up_front(self):
        # round 2: no real terminal -> stop before asking (never hang, never
        # fall back to a prompt that could show the typing)
        with mock.patch.object(sys, "stdin", io.StringIO("")), \
                mock.patch.object(safeprompt.getpass, "getpass") as gp:
            with self.assertRaises(safeprompt.NoTerminal):
                safeprompt.read_hidden("x: ")
        self.assertFalse(gp.called)

    def test_install_without_a_keyboard_says_so_plainly(self):
        # drive the helpers directly: no real config files are touched
        with self.assertRaises(clients._NoTerminal):
            clients._go_ahead(mock.Mock(side_effect=EOFError), "go ahead? ")
        out = []
        with mock.patch.object(clients, "_run", side_effect=clients._NoTerminal):
            self.assertEqual(clients.run(None, False, out=out.append), 1)
        self.assertEqual(out, [clients.NO_TERMINAL])
        self.assertIn("normal terminal window", clients.NO_TERMINAL)
        self.assertIn("--yes", clients.NO_TERMINAL)

    def test_stray_eof_in_main_is_a_line_not_a_traceback(self):
        err = io.StringIO()
        with mock.patch.object(cli, "_main", side_effect=EOFError), \
                mock.patch.object(sys, "stderr", err):
            code = cli.main(["get", "github"])
        self.assertEqual(code, 1)
        self.assertIn("normal terminal window", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


class Doctor(unittest.TestCase):
    def checks(self, which):
        res = gitscan.doctor(env={}, which=which)
        return {c["check"]: c for c in res["checks"] if c["check"] != "keychain"
                or not c.get("info")}, res

    def test_missing_ssh_is_optional_not_a_fix(self):
        by, res = self.checks(lambda name: None if name == "ssh" else "/bin/" + name)
        self.assertTrue(by["ssh"]["info"])
        self.assertTrue(by["ssh"]["ok"])
        self.assertIn("optional", by["ssh"]["detail"])
        self.assertNotIn("[FIX] ssh", gitscan.format_doctor(res))
        self.assertIn("[info] ssh", gitscan.format_doctor(res))

    def test_missing_git_is_still_a_fix(self):
        by, _ = self.checks(lambda name: None if name == "git" else "/bin/" + name)
        self.assertFalse(by["git"]["ok"])

    def test_keychain_hint_is_for_this_os(self):
        linux = gitscan.keychain_fix_hint("linux")
        self.assertIn("libsecret-tools", linux)
        self.assertNotIn("Credential Manager", linux)
        self.assertIn("Credential Manager", gitscan.keychain_fix_hint("win32"))
        self.assertNotIn("libsecret", gitscan.keychain_fix_hint("win32"))
        self.assertIn("security", gitscan.keychain_fix_hint("darwin"))

    def test_clipboard_hint_names_the_linux_tools(self):
        hint = gitscan.clipboard_fix_hint("linux")
        for tool in ("xclip", "xsel", "wl-clipboard"):
            self.assertIn(tool, hint)

    def test_missing_clipboard_tool_is_info_with_a_hint(self):
        with mock.patch.object(clip_mod, "backend",
                               side_effect=clip_mod.Unavailable("none")):
            res = gitscan.doctor(env={}, which=lambda n: "/bin/" + n)
        item = [c for c in res["checks"] if c["check"] == "clipboard"][0]
        self.assertTrue(item["info"])
        self.assertTrue(item["fix"])


if __name__ == "__main__":
    unittest.main()
