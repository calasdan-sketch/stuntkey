"""0.6.3: the question after a key was taken is read without echo, and a key
pasted AT that question is refused, never echoed, never used.

Found on Windows: after "took 93 characters ... clipboard emptied" the tool
asked "Is that the key? Press Enter for yes, or type n:"; the person pasted
the key there, the terminal echoed all of it, and the tool accepted it.
"""

import io
import os
import sys
import types
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import cli as cli_mod
from stuntkey import clipboard as clip_mod
from stuntkey import connect as connect_mod
from stuntkey import keychain as keychain_mod
from stuntkey import safeprompt

# a key-looking value built from pieces (no real-looking literal in the source)
COPIED = "tok" + "_" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1Ll2Mm3"
PASTED = "tok" + "_" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp9Oo8Nn7"


def recipe():
    return {"service": "acme", "display": "Acme",
            "key_url": "https://acme.test/keys", "env_var": "ACME_API_KEY",
            "steps": ["Click 'New key'"], "scopes": ["read"],
            "validate": {"method": "GET", "url": "https://acme.test/me",
                         "auth": {"type": "bearer"}, "expect": [200]}}


class Replies:
    """A confirm reader that gives the answers in turn and remembers the prompts."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.prompts = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)


def no_paste(_prompt):
    raise EOFError              # the hidden paste prompt: the person gives up


def run_connect(confirm, stored):
    out = io.StringIO()
    with mock.patch.object(clip_mod, "wait_for_key", lambda *a, **k: COPIED):
        code = connect_mod.connect(
            recipe(), browser_open=lambda u: None, out=out,
            prompt=no_paste,
            validate_fn=lambda spec, key: True,
            clipboard=(lambda: "", lambda: None), confirm_in=confirm,
            store_fn=lambda var, key: stored.setdefault(var, key) and "saved")
    return code, out.getvalue()


class TestConnectConfirm(unittest.TestCase):
    """2026-11-08 (Dan): the "Press Enter to save it" step after a clipboard
    capture confused people, so it is gone. The key is taken, said in plain
    words, checked with the vendor and saved - no question in between."""

    def test_a_copied_key_is_saved_without_any_question(self):
        stored = {}
        replies = Replies()
        code, text = run_connect(replies, stored)
        self.assertEqual(code, 0)
        self.assertEqual(stored, {"ACME_API_KEY": COPIED})
        self.assertEqual(replies.prompts, [])
        self.assertIn("Got your", text)
        self.assertIn("has been added", text)
        self.assertNotIn(COPIED, text)

    def test_nothing_is_saved_when_the_vendor_rejects_a_wrong_copy(self):
        stored = {}
        out = io.StringIO()
        with mock.patch.object(clip_mod, "wait_for_key", lambda *a, **k: COPIED):
            connect_mod.connect(
                recipe(), browser_open=lambda u: None, out=out, prompt=no_paste,
                validate_fn=lambda spec, key: False,
                clipboard=(lambda: "", lambda: None), confirm_in=Replies(),
                store_fn=lambda var, key: stored.setdefault(var, key) and "saved")
        self.assertEqual(stored, {})
        self.assertNotIn("has been added", out.getvalue())
        self.assertNotIn(COPIED, out.getvalue())


class TestMaskedPaste(unittest.TestCase):
    """The hidden paste prompt shows a * per character and takes a paste
    without Enter; typing by hand still ends with Enter."""

    def _run(self, chars, gaps):
        """chars arrive with `gaps[i]` True when the next one is already waiting."""
        feed = list(chars)
        state = {"i": 0}

        def read_char():
            ch = feed[state["i"]]
            state["i"] += 1
            return ch

        def waiting(timeout):
            i = state["i"]
            return i < len(feed) and gaps[i - 1]
        out = io.StringIO()
        with mock.patch.object(safeprompt, "SETTLE", 0):
            value = safeprompt._masked_loop(read_char, waiting, out)
        return value, out.getvalue()

    def test_a_paste_is_taken_without_enter_and_shown_as_stars(self):
        value, shown = self._run(COPIED, [True] * (len(COPIED) - 1) + [False])
        self.assertEqual(value, COPIED)
        self.assertEqual(shown.strip(), "*" * len(COPIED))
        self.assertNotIn(COPIED, shown)

    def test_typing_by_hand_waits_for_enter(self):
        typed = "abc123def456ghi789xyz"
        value, shown = self._run(typed + "\r", [False] * (len(typed) + 1))
        self.assertEqual(value, typed)
        self.assertEqual(shown.strip(), "*" * len(typed))

    def test_backspace_removes_a_star(self):
        value, shown = self._run("ab\x08c\r", [False] * 5)
        self.assertEqual(value, "ac")

    def test_ctrl_c_cancels(self):
        with self.assertRaises(KeyboardInterrupt):
            self._run("ab\x03", [False] * 3)


class TestDefaultReader(unittest.TestCase):
    def test_without_a_reader_given_the_quiet_one_is_used(self):
        # the real default (no injected confirm_in): read_quiet, not input()
        stored = {}
        seen = []

        def quiet(prompt):
            seen.append(prompt)
            return PASTED if len(seen) == 1 else ""
        out = io.StringIO()
        with mock.patch.object(safeprompt, "read_quiet", quiet), \
                mock.patch("builtins.input", side_effect=AssertionError("echoing input()")), \
                mock.patch.object(clip_mod, "wait_for_key", lambda *a, **k: COPIED):
            code = connect_mod.connect(
                recipe(), browser_open=lambda u: None, out=out,
                validate_fn=lambda s, k: True, clipboard=(lambda: "", lambda: None),
                store_fn=lambda v, k: stored.setdefault(v, k) and "saved")
        self.assertEqual((code, stored), (0, {"ACME_API_KEY": COPIED}))
        self.assertNotIn(PASTED, out.getvalue())


class TestQuietReader(unittest.TestCase):
    def test_without_a_terminal_it_reads_a_line_and_shows_nothing_on_stdout(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO(PASTED + "\n")), \
                mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            line = safeprompt.read_quiet("  q: ")
        self.assertEqual(line, PASTED)
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn(PASTED, err.getvalue())

    def test_end_of_input_is_eof(self):
        with mock.patch.object(sys, "stdin", io.StringIO("")), \
                mock.patch.object(sys, "stderr", io.StringIO()):
            with self.assertRaises(EOFError):
                safeprompt.read_quiet("  q: ")

    def test_with_a_terminal_it_goes_through_getpass_and_drains_the_rest(self):
        tty = types.SimpleNamespace(isatty=lambda: True)
        drained = []
        with mock.patch.object(sys, "stdin", tty), \
                mock.patch.object(safeprompt.getpass, "getpass", lambda p: "n"), \
                mock.patch.object(safeprompt, "_drain_input", lambda: drained.append(1)):
            self.assertEqual(safeprompt.read_quiet("  q: "), "n")
        self.assertEqual(drained, [1])

    def test_the_hidden_paste_prompt_also_drains(self):
        drained = []
        with mock.patch.object(safeprompt.getpass, "getpass", lambda p: "x"), \
                mock.patch.object(safeprompt, "_drain_input", lambda: drained.append(1)):
            self.assertEqual(safeprompt.read_hidden("p: "), "x")
        self.assertEqual(drained, [1])


class TestClassify(unittest.TestCase):
    def test_answers(self):
        c = safeprompt.classify
        self.assertEqual([c(x) for x in ("", "  ", "y", "YES", "n", "No")],
                         ["enter", "enter", "yes", "yes", "no", "no"])
        self.assertEqual(c(PASTED), "key")
        self.assertEqual(c("maybe-later-ok"), "key")
        self.assertEqual(c("x1"), "other")
        self.assertEqual(c("abc", secret_pattern="abc"), "key")
        self.assertEqual(c("a\nb"), "key")

    def test_bracketed_paste_markers_alone_are_just_enter(self):
        self.assertEqual(safeprompt.classify("\x1b[200~\x1b[201~"), "enter")
        self.assertEqual(safeprompt.classify("\x1b[200~n\x1b[201~"), "no")

    def test_ctrl_c_cancels(self):
        def boom(_p):
            raise KeyboardInterrupt
        self.assertIsNone(safeprompt.ask("q", io.StringIO(), enter_means=True, reader=boom))


class TestOtherQuestionsAfterAKey(unittest.TestCase):
    def test_keychain_fallback_never_takes_a_pasted_key_for_yes(self):
        tmp = _isolation.mktemp()
        env = os.path.join(tmp, ".env")
        out = io.StringIO()
        fn = cli_mod.keychain_store(
            recipe(), env, out=out, backend=None,
            keychain=types.SimpleNamespace(
                detect_backend=lambda: None, KeychainError=keychain_mod.KeychainError,
                store=None, label=keychain_mod.label),
            ask=Replies(PASTED, "n"), interactive=lambda: True)
        with self.assertRaises(connect_mod.SaveDeclined):
            fn("ACME_API_KEY", COPIED)
        self.assertFalse(os.path.exists(env))
        self.assertIn("That looked like a key", out.getvalue())
        self.assertNotIn(PASTED, out.getvalue())

    def test_a_yes_no_question_enter_means_no(self):
        out = io.StringIO()
        self.assertFalse(safeprompt.ask("q", out, enter_means=False, reader=lambda p: ""))
        self.assertTrue(safeprompt.ask("q", out, enter_means=False, reader=lambda p: "y"))


if __name__ == "__main__":
    unittest.main()
