"""0.6.1: copy-and-go hardening."""
import io
import unittest

import _isolation  # noqa: F401
from stuntkey import clipboard as clip_mod
from stuntkey import connect as connect_mod

KEY = "Zk3pQ9vL2mXw8RtY5uBn7HcD"


class Fake:
    def __init__(self, script):
        self.script = list(script)       # successive reads
        self.value = self.script[0] if self.script else ""
        self.cleared = 0
        self.reads = 0

    def get(self):
        self.reads += 1
        if self.script:
            self.value = self.script.pop(0)
        return self.value

    def clear(self):
        self.cleared += 1
        self.value = ""


class Shape(unittest.TestCase):
    def test_not_keys(self):
        for v in ("localhost:3000", "http://x.example/a", "me@example.com", "/home/dan/project/file",
                  "C:\\Users\\dan\\x.txt", "my-project-name-here", "short", "a" * 15):
            self.assertFalse(clip_mod.looks_like(v, None), v)

    def test_keys(self):
        for v in (KEY, "sk-proj-abcdEFGH1234_-xyz", "a" * 40, "0123456789abcdef0123456789abcdef01234567"):
            self.assertTrue(clip_mod.looks_like(v, None), v)

    def test_describe_has_no_characters(self):
        d = clip_mod.describe(KEY)
        self.assertIn("24 characters", d)
        self.assertNotIn(KEY[:3], d)


class Waiting(unittest.TestCase):
    def test_second_identical_copy_is_noticed(self):
        # the key was on the clipboard BEFORE the command; the person copies it again
        c = Fake([KEY, KEY, "", "", KEY])
        got = clip_mod.wait_for_key(None, set(), c.get, c.clear, wait=10, poll=0, sleep=lambda s: None,
                                    now=iter(range(0, 1000)).__next__)
        self.assertEqual(got, KEY)
        self.assertGreaterEqual(c.cleared, 2)      # stale one emptied, then the taken one

    def test_stale_key_does_not_stay_on_clipboard_when_nothing_new(self):
        c = Fake([KEY])
        n = iter(range(0, 1000))
        got = clip_mod.wait_for_key(None, set(), c.get, c.clear, wait=5, poll=0,
                                    sleep=lambda s: None, now=lambda: next(n))
        self.assertIsNone(got)
        self.assertEqual(c.value, "")


class Ask(unittest.TestCase):
    field = {"name": "key", "label": "API key", "env_var": "X_KEY"}

    def test_ctrl_c_cancels_without_prompt(self):
        c = Fake([""])
        orig = clip_mod.wait_for_key
        clip_mod.wait_for_key = lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt())
        try:
            r = connect_mod._ask_one(self.field, True, lambda t: self.fail("prompted"),
                                     io.StringIO(), (c.get, c.clear), set())
        finally:
            clip_mod.wait_for_key = orig
        self.assertIsNone(r)
        self.assertEqual(c.cleared, 1)

    def test_prompt_fallback_empties_clipboard(self):
        c = Fake([KEY])
        c.value = KEY
        orig = clip_mod.wait_for_key
        clip_mod.wait_for_key = lambda *a, **k: None
        try:
            r = connect_mod._ask_one(self.field, True, lambda t: "typed-by-hand-123456", io.StringIO(),
                                     (c.get, c.clear), set())
        finally:
            clip_mod.wait_for_key = orig
        self.assertEqual(r, "typed-by-hand-123456")
        self.assertEqual(c.value, "")

    def test_generic_value_is_taken_without_a_question(self):
        c = Fake([""])
        orig = clip_mod.wait_for_key
        clip_mod.wait_for_key = lambda *a, **k: KEY
        out = io.StringIO()
        try:
            got = connect_mod._ask_one(self.field, True, lambda t: "", out, (c.get, c.clear), set(),
                                       confirm=lambda t: (_ for _ in ()).throw(AssertionError("asked")))
        finally:
            clip_mod.wait_for_key = orig
        self.assertEqual(got, KEY)
        self.assertNotIn(KEY, out.getvalue())

    def test_no_stale_clipboard_claim(self):
        with open(connect_mod.__file__) as f:
            src = f.read()
        self.assertNotIn("still has it on the clipboard", src)
