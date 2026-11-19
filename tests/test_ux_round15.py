"""Round 15 usability fixes from the hands-on audit: say the limits up front, no 65-name blob, honest suggestions."""
import contextlib
import io
import unittest

from stuntkey import cli, fixcmd


class FirstScreens(unittest.TestCase):
    def test_every_front_screen_states_the_limits_and_points_to_them(self):
        parser = cli._build_parser()
        for name, text in (("no arguments", cli.NEXT_STEPS), ("help", fixcmd.render_everyday()), ("--help", parser.format_help())):
            with self.subTest(screen=name):
                self.assertIn("not independently reviewed", text)
                self.assertIn("stuntkey limits", text)

    def test_no_absolute_never_logged_claim(self):
        # limits 7 and 9 say a program you start can print the key, so the front screen must not say "never" without a subject
        text = cli._build_parser().format_help()
        self.assertNotIn("The key is never shown or written to a log", text)
        self.assertIn("stuntkey itself never prints the key", text)

    def test_usage_line_is_not_the_command_dump(self):
        usage = cli._build_parser().format_usage()
        self.assertIn("<command>", usage)
        self.assertNotIn("{scan,wrap", usage)


class UnknownCommand(unittest.TestCase):
    def _say(self, word):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            cli._build_parser().parse_args([word])
        self.assertEqual(cm.exception.code, 2)
        return err.getvalue()

    def test_a_close_typo_gets_a_suggestion(self):
        self.assertIn("Did you mean: stuntkey status?", self._say("stauts"))

    def test_a_far_miss_gets_no_wrong_suggestion(self):
        out = self._say("bogus")
        self.assertNotIn("Did you mean", out)
        self.assertIn("stuntkey help", out)


class FixPreview(unittest.TestCase):
    def test_the_switch_on_preview_says_what_happens_if_the_hook_breaks(self):
        src = open(fixcmd.__file__, encoding="utf-8").read()
        self.assertIn("tool calls are blocked until `stuntkey hook uninstall`", src)


if __name__ == "__main__":
    unittest.main()


class ExitCodesAndJson(unittest.TestCase):
    """README: exit 0 fine, 1 problem. status and test must agree, and --json must carry a schema field."""

    def test_test_json_has_schema_and_matches_the_exit_code(self):
        import io
        import json
        from stuntkey import setupcmd
        out = io.StringIO()
        from unittest import mock
        res = setupcmd.Result(False, "FAIL: x Next: y")
        with mock.patch.object(setupcmd, "run_check", return_value=res):
            rc = setupcmd.cmd_test(type("A", (), {"json": True, "verbose": False})(), {}, out)
        doc = json.loads(out.getvalue())
        self.assertEqual((rc, doc["schema"], doc["ok"]), (1, 1, False))
        ok = setupcmd.Result(True, "PASS: fine")
        out = io.StringIO()
        with mock.patch.object(setupcmd, "run_check", return_value=ok):
            rc = setupcmd.cmd_test(type("A", (), {"json": True, "verbose": False})(), {}, out)
        self.assertEqual((rc, json.loads(out.getvalue())["ok"]), (0, True))

    def test_doctor_row_does_not_claim_a_bare_absolute(self):
        src = open(__import__("stuntkey.gitscan", fromlist=["x"]).__file__, encoding="utf-8").read()
        self.assertIn("simulated attacks on stuntkey's own rules", src)
        self.assertNotIn("stuntkey help leakbench", src)


class StatusExitCode(unittest.TestCase):
    def _run(self, level, set_up):
        import contextlib
        import io
        import json
        from unittest import mock
        args = type("A", (), {"json": True, "fix": False})()
        items = [fixcmd.Item("x", level, "something")]
        buf = io.StringIO()
        with mock.patch.object(fixcmd, "collect", return_value=items), mock.patch.object(cli, "_computer_is_set_up", return_value=set_up),                 contextlib.redirect_stdout(buf):
            rc = cli._status_without_project(args)
        return rc, json.loads(buf.getvalue())

    def test_a_set_up_computer_that_needs_attention_exits_1(self):
        rc, doc = self._run(fixcmd.RED, True)
        self.assertEqual((rc, doc["state"], doc["schema"]), (1, "attention", 1))

    def test_a_never_set_up_computer_is_told_to_run_setup_and_exits_0(self):
        rc, doc = self._run(fixcmd.RED, False)
        self.assertEqual((rc, doc["setup"]), (0, False))

    def test_ready_and_almost_exit_0(self):
        self.assertEqual(self._run(fixcmd.GREEN, True)[0], 0)
        self.assertEqual(self._run(fixcmd.YELLOW, True)[0], 0)
