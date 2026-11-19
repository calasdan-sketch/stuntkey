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
