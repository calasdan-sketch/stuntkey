"""0.10.0 (panel review): fixes to the first draft of 0.10.0's content and prompt checks."""

import json
import os
import time
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import hook as hook_mod
from stuntkey import scrub

# built at run time so this file never holds a key-shaped string
STORED = "zq" + "9Xr4" + "Lm2Vt8Kp3Wn7Yb5Qe"
GITHUB = "ghp_" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zA7bC"


def raw_check(obj):
    status, out = hook_mod.check(json.dumps(obj))
    return status, (json.loads(out) if out.strip() else None)


def pre(tool, **inp):
    status, ans = raw_check({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": inp})
    assert status == 0, status
    return ans["hookSpecificOutput"]["permissionDecisionReason"] if ans else None


def write(path, content):
    return pre("Write", file_path=path, content=content)


class Base(unittest.TestCase):
    def setUp(self):
        self.path = scrub.fingerprint_path()
        scrub.remember_key("svc/API_KEY", STORED, self.path)
        self.addCleanup(scrub.forget_key, "svc/API_KEY", self.path)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(hook_mod.ALLOW_WRITE_VAR, None)
        os.environ.pop(hook_mod.ALLOW_PROMPT_VAR, None)


class F1BigWritesFailClosed(Base):
    def test_a_key_in_the_middle_of_a_big_write_is_never_let_through(self):
        for n in (350_000, 700_000):
            with self.subTest(n=n):
                body = "#" * n + f'API_KEY="{STORED}"' + "#" * n
                self.assertIsNotNone(write("/p/a.py", body))
        self.assertIsNotNone(write("/p/a.py", "#" * 700_000 + "print(os.environ)" + "#" * 700_000))

    def test_content_over_the_limit_is_refused_and_says_why(self):
        reason = write("/p/a.txt", "a" * (hook_mod.WRITE_SCAN + 1))
        self.assertIn("more than", reason)
        self.assertIsNone(write("/p/a.txt", "a" * hook_mod.WRITE_SCAN))

    def test_a_key_at_the_very_end_of_the_limit_is_found(self):
        body = "a " * ((hook_mod.WRITE_SCAN - 40) // 2) + STORED
        self.assertLessEqual(len(body), hook_mod.WRITE_SCAN)
        self.assertIsNotNone(write("/p/a.txt", body))

    def test_a_cut_payload_that_no_longer_parses_is_refused(self):
        payload = {"hook_event_name": "PreToolUse", "tool_name": "mcp__x__y",
                   "tool_input": {"a": "x" * 700_000, "b": ["y"] * 200_000}}
        status, ans = raw_check(payload)
        self.assertEqual(status, 0)
        self.assertEqual(ans["hookSpecificOutput"]["permissionDecision"], "deny")


class F2KeyPlacements(Base):
    def test_a_key_inside_urls_and_glued_words_is_found(self):
        for text in (f"https://api.telegram.org/bot{STORED}/sendMessage",
                     f"https://h/v1/{STORED}/chat", f"https://user:{STORED}@host/x",
                     f"{STORED}#frag", f"{STORED}-prod", f"x?key={STORED}&y=1",
                     STORED.upper(), STORED.lower(), STORED.encode().hex(),
                     STORED.encode().hex().upper()):
            with self.subTest(text=text[:30]):
                self.assertIsNotNone(write("/p/a.py", f"URL = '{text}'"))

    def test_a_key_that_itself_holds_dashes_is_still_found_when_glued(self):
        key = "sk-" + "proj-" + "Zx8Qw2Er4Ty6Ui8Op0As"
        scrub.remember_key("svc2/K", key, self.path)
        self.addCleanup(scrub.forget_key, "svc2/K", self.path)
        self.assertIsNotNone(write("/p/a.py", f"x = 'https://h/{key}-prod/x'"))

    def test_separator_runs_cost_few_fingerprints(self):
        self.assertLessEqual(sum(1 for _ in scrub._word_candidates("=" * 512)), 1)
        self.assertLessEqual(sum(1 for _ in scrub._word_candidates("a=" * 256)),
                             scrub.MAX_CANDIDATES)


class F3PromptSpeed(Base):
    def test_padded_prompts_check_in_under_two_seconds(self):
        for unit in ("=", "a=", "-", "a:", "A"):
            with self.subTest(unit=unit):
                text = unit * (8_000_000 // len(unit))
                start = time.monotonic()
                raw_check({"hook_event_name": "UserPromptSubmit", "prompt": text})
                self.assertLess(time.monotonic() - start, 2.0)


class F4FieldOrder(Base):
    def test_prompt_blocked_whatever_the_field_order(self):
        pr = "a" * 1_500_000 + " " + GITHUB + " " + "a" * 1_500_000
        for obj in ({"session_id": "x", "hook_event_name": "UserPromptSubmit", "prompt": pr},
                    {"session_id": "x", "prompt": pr, "hook_event_name": "UserPromptSubmit"}):
            with self.subTest(first=list(obj)[1]):
                status, ans = raw_check(obj)
                self.assertEqual((status, ans and ans["decision"]), (0, "block"))

    def test_the_event_name_inside_a_string_does_not_count(self):
        self.assertIsNone(hook_mod._PROMPT_EVENT_RE.search(
            json.dumps({"tool_input": {"c": '"hook_event_name": "UserPromptSubmit"'}})))


class F5FalsePositives(Base):
    ALLOWED = [
        ("/p/x.sh", "[ -f .env ] || cp .env.example .env; cat <<EOF\nhi\nEOF"),
        ("/p/x.sh", "cp .env.example .env && cat README"),
        ("/p/x.js", "dotenv.config({path:'.env', type:'file'}); fs.readFileSync('a.json')"),
        ("/p/x.js", "console.error('Missing key in .env file'); fs.readFileSync(p)"),
        ("/p/x.py", "print('see .env'); open('x').read()"),
        ("/p/x.py", "print(Path('.env').exists())"),
        ("/p/README.md", "print(os.environ)\n`cat .env`"),
        ("/p/x.py", "print(*os.environ)"),
    ]
    REFUSED = [
        ("/p/x.py", "print(open('.env').read())"),
        ("/p/x.py", "print(Path('.env.local').read_text())"),
        ("/p/x.js", "console.log(fs.readFileSync('.env', 'utf8'))"),
        ("/p/x.sh", "cat .env"),
        ("/p/x.sh", "set -e; cat -A config/.env"),
        ("/p/notes.txt", "print(open('.env').read())"),
    ]

    def test_allowed(self):
        for path, body in self.ALLOWED:
            with self.subTest(body=body):
                self.assertIsNone(write(path, body))

    def test_refused(self):
        for path, body in self.REFUSED:
            with self.subTest(body=body):
                self.assertIsNotNone(write(path, body))

    def test_vendor_example_keys_in_a_prompt_go_through(self):
        for text in ("the docs example AKIAIOSFODNN7EXAMPLE is fake",
                     "aws secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"):
            with self.subTest(text=text):
                self.assertIsNone(raw_check({"hook_event_name": "UserPromptSubmit",
                                             "prompt": text})[1])
        self.assertIsNotNone(raw_check({"hook_event_name": "UserPromptSubmit",
                                        "prompt": "AKIA" + "Q3ZK7WN2PL5XR8TB"})[1])


class F6EasyRewrites(Base):
    def test_easy_rewrites_of_an_env_dump_are_refused(self):
        for path, body in (
                ("/p/x.py", 'print(f"{os.environ}")'),
                ("/p/x.py", "e = os.environ\nprint(e)"),
                ("/p/x.py", "e=os.environ; print(e)"),
                ("/p/x.py", "from os import environ\nprint(environ)"),
                ("/p/x.py", "from os import path, environ as E\nprint(dict(E))"),
                ("/p/x.py", "for k, v in os.environ.items():\n    print(k, v)"),
                ("/p/x.py", "for k in os.environ:\n    print(k, os.environ[k])"),
                ("/p/x.py", "print(*os.environ.items())"),
                ("/p/x.js", "console.log(process['env'])"),
                ("/p/x.js", "const e = process.env; console.log(e)"),
                ("/p/x.js", "console.log(`${JSON.stringify(process.env)}`)"),
                ("/p/x.js", "for (const [k, v] of Object.entries(process.env)) console.log(k, v)")):
            with self.subTest(body=body):
                self.assertIsNotNone(write(path, body))

    def test_names_only_and_one_value_still_pass(self):
        for body in ("e = os.environ\nprint(e['HOME'])", "for k in os.environ:\n    print(k)",
                     "for k, v in os.environ.items():\n    print(k)",
                     "const e = process.env; console.log(e.NODE_ENV)"):
            with self.subTest(body=body):
                self.assertIsNone(write("/p/x.py", body))


if __name__ == "__main__":
    unittest.main()
