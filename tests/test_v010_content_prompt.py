"""0.10: the hook judges what an Edit / Write puts in a file (a stored key, a
program that prints the environment or a .env file), and blocks a prompt with
a pasted key (UserPromptSubmit)."""

import json
import os
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import hook as hook_mod
from stuntkey import scrub

# built at run time so this file never holds a key-shaped string
STORED = "zq" + "9Xr4" + "Lm2Vt8Kp3Wn7Yb5Qe"          # no known format: only a fingerprint finds it
GITHUB = "ghp_" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4zA7bC"
PEM_BODY = ("-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx" + "Q" * 60
            + "\n-----END " + "RSA PRIVATE KEY-----")


def pre(tool, **inp):
    status, out = hook_mod.check(json.dumps(
        {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": inp}))
    assert status == 0
    return json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"] if out else None


def prompt(text):
    status, out = hook_mod.check(json.dumps(
        {"hook_event_name": "UserPromptSubmit", "prompt": text}))
    assert status == 0
    return json.loads(out) if out else None


class WithStoredKey(unittest.TestCase):
    def setUp(self):
        self.path = scrub.fingerprint_path()
        scrub.remember_key("svc/API_KEY", STORED, self.path)
        self.addCleanup(scrub.forget_key, "svc/API_KEY", self.path)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(hook_mod.ALLOW_WRITE_VAR, None)
        os.environ.pop(hook_mod.ALLOW_PROMPT_VAR, None)


class StoredKeyInWrites(WithStoredKey):
    def test_each_write_tool_with_a_stored_key_is_refused(self):
        cases = [
            ("Write", {"file_path": "/p/tests/test_api.py", "content": f"KEY = '{STORED}'\n"}),
            ("Edit", {"file_path": "/p/.env.example", "old_string": "K=", "new_string": f"K={STORED}"}),
            ("MultiEdit", {"file_path": "/p/c.py",
                           "edits": [{"old_string": "a", "new_string": "b"},
                                     {"old_string": "c", "new_string": f"x = '{STORED}'"}]}),
            ("NotebookEdit", {"notebook_path": "/p/n.ipynb", "new_source": f"k = '{STORED}'"}),
            # a field name this version does not know about is still read
            ("Write", {"file_path": "/p/a.txt", "text_v2": {"body": [STORED]}}),
        ]
        for tool, inp in cases:
            with self.subTest(tool=tool, inp=inp):
                reason = pre(tool, **inp)
                self.assertIsNotNone(reason)
                self.assertIn("stored keys", reason)
                self.assertNotIn(STORED, reason)

    def test_taking_a_key_out_of_a_file_is_allowed(self):
        self.assertIsNone(pre("Edit", file_path="/p/a.py", old_string=f"KEY = '{STORED}'",
                              new_string="KEY = os.environ['KEY']"))

    def test_a_key_the_person_never_stored_is_not_a_false_alarm(self):
        # format-only matches (test fixtures, docs) are left alone in writes
        self.assertIsNone(pre("Write", file_path="/p/fixture.py", content=f"FAKE = '{GITHUB}'"))

    def test_a_key_late_in_a_long_file_is_found(self):
        body = ("x = 1\n" * 50_000) + f"KEY = '{STORED}'\n"
        self.assertIsNotNone(pre("Write", file_path="/p/big.py", content=body))

    def test_allow_write_turns_the_content_checks_off(self):
        os.environ[hook_mod.ALLOW_WRITE_VAR] = "1"
        self.assertIsNone(pre("Write", file_path="/p/a.py", content=f"K='{STORED}'"))
        self.assertIsNone(pre("Write", file_path="/p/leak.py", content="print(os.environ)"))


class EnvDumpingPrograms(WithStoredKey):
    REFUSED = [
        ("leak.py", "import os\nprint(dict(os.environ))\n"),
        ("leak.py", "import os\nprint(os.environ)"),
        ("leak.py", "print('env:', os.environ)"),
        ("leak.py", "import json, os\nprint(json.dumps(dict(os.environ), indent=2))"),
        ("leak.py", "from pprint import pprint\npprint(os.environ.copy())"),
        ("leak.py", "logging.info(os.environ)"),
        ("leak.js", "console.log(process.env)\n"),
        ("leak.js", "console.log({ ...process.env })"),
        ("leak.ts", "console.log(JSON.stringify(process.env, null, 2))"),
        ("leak.rb", "puts ENV\n"),
        ("leak.go", "fmt.Println(os.Environ())"),
        ("Leak.java", "System.out.println(System.getenv());"),
        ("leak.php", "print_r($_ENV);"),
        ("reader.py", "print(open('.env').read())\n"),
        ("reader.py", "print(open('config/.env.local').read())"),
        ("reader.js", "console.log(fs.readFileSync('.env', 'utf8'))"),
        ("run.sh", "#!/bin/sh\nset -e\nenv\n"),
        ("run.sh", "#!/bin/sh\nprintenv | sort\n"),
        ("run.sh", "#!/bin/sh\ncat .env\n"),
        ("C:\\work\\dump.ps1", "Get-ChildItem env:\n"),
    ]
    ALLOWED = [
        ("ok.py", "from dotenv import load_dotenv\nload_dotenv('.env')\nprint(os.environ['HOME'])\n"),
        ("ok.py", "print(sorted(os.environ))\nprint(os.environ.get('X'))\n"),
        ("ok.py", "print(len(os.environ))"),
        ("ok.js", "require('dotenv').config()\nconsole.log(process.env.NODE_ENV)\n"),
        ("ok.js", "console.log(Object.keys(process.env))"),
        ("ok.rb", "puts ENV['HOME']\n"),
        ("run.sh", "#!/bin/sh\nset -euo pipefail\nsource .env\nexport FOO=1\nprintenv PATH\n"),
        ("README.md", "Run `env` to list variables. `cat .env` shows the file."),
        ("notes.py", "# see .env.example for the variable names\nprint('loaded')"),
        ("copy.py", "print(open('.env.example').read())"),
    ]

    def test_refused(self):
        for name, content in self.REFUSED:
            with self.subTest(name=name, content=content):
                reason = pre("Write", file_path=name if "\\" in name else f"/p/{name}",
                             content=content)
                self.assertIsNotNone(reason)
                self.assertIn("Print only the names", reason)

    def test_allowed(self):
        for name, content in self.ALLOWED:
            with self.subTest(name=name, content=content):
                self.assertIsNone(pre("Write", file_path=f"/p/{name}", content=content))

    def test_edit_and_notebook_content_is_judged_too(self):
        self.assertIsNotNone(pre("Edit", file_path="/p/a.py", old_string="pass",
                                 new_string="print(os.environ)"))
        self.assertIsNotNone(pre("NotebookEdit", notebook_path="/p/n.ipynb",
                                 new_source="import os\nprint(os.environ)"))

    def test_old_string_is_not_judged(self):
        self.assertIsNone(pre("Edit", file_path="/p/a.py", old_string="print(os.environ)",
                              new_string="print(sorted(os.environ))"))

    def test_prose_skips_only_the_env_line_rule(self):
        self.assertIsNone(pre("Write", file_path="/p/README.md", content="`cat .env` shows it"))
        # `python notes.txt` runs it just as well: the whole-env rules still apply
        self.assertIsNotNone(pre("Write", file_path="/p/notes.txt", content="print(os.environ)"))
        self.assertIsNotNone(pre("Write", file_path="/p/notes.md",
                                 content=f"token: {STORED}"))

    def test_windows_stream_and_trailing_dot_names_are_still_scripts(self):
        for name in ("C:\\w\\run.sh::$DATA", "C:\\w\\run.SH.", "/p/run.ps1 "):
            with self.subTest(name=name):
                self.assertIsNotNone(pre("Write", file_path=name, content="env\n"))

    def test_shell_rules_apply_to_scripts_only(self):
        # a bare `env` line in a Python file is just a word
        self.assertIsNone(pre("Write", file_path="/p/a.txt", content="set\nenv\n"))
        self.assertIsNotNone(pre("Write", file_path="/p/a.bash", content="env\n"))

    def test_huge_lines_do_not_slow_it_down(self):
        import time
        start = time.monotonic()
        pre("Write", file_path="/p/a.py", content=("print(x) .env open( " * 60_000))
        pre("Write", file_path="/p/a.js", content=("console.log(" * 100_000))
        self.assertLess(time.monotonic() - start, 5)


class PastedKeyInPrompt(WithStoredKey):
    def test_stored_key_vendor_key_and_private_key_are_blocked(self):
        for text in (f"use this key: {STORED}", f"my token is {GITHUB} pls fix", PEM_BODY,
                     f"<pasted_content id=\"1\">\nTOKEN={GITHUB}\n</pasted_content id=\"1\">"):
            with self.subTest(text=text[:30]):
                answer = prompt(text)
                self.assertIsNotNone(answer)
                self.assertEqual(answer["decision"], "block")
                self.assertTrue(answer["hookSpecificOutput"]["suppressOriginalPrompt"])
                self.assertEqual(answer["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit")
                self.assertNotIn(STORED, json.dumps(answer))
                self.assertNotIn(GITHUB, json.dumps(answer))

    def test_talking_about_keys_goes_through(self):
        for text in ("hello", "why does my API key fail with 401?",
                     "API_KEY=your-key-here in .env.example",
                     "what does -----BEGIN " + "RSA PRIVATE KEY----- mean?",
                     "password = hunter2 is a bad password", ""):
            with self.subTest(text=text):
                self.assertIsNone(prompt(text))

    def test_allow_prompt_turns_it_off(self):
        os.environ[hook_mod.ALLOW_PROMPT_VAR] = "1"
        self.assertIsNone(prompt(f"use {STORED}"))

    def test_a_key_at_the_end_of_a_huge_prompt_is_found(self):
        self.assertIsNotNone(prompt("x " * 700_000 + GITHUB))
        self.assertIsNotNone(prompt("y " * 300_000 + GITHUB + " z" * 300_000))

    def test_prompt_is_not_judged_as_a_tool_call(self):
        # a prompt that mentions .env is not a PreToolUse deny
        self.assertIsNone(prompt("please add a .env.example and explain `cat .env`"))


class ScanWindows(unittest.TestCase):
    def test_text_exactly_the_budget_is_checked_to_its_end(self):
        text = "a" * hook_mod.SCAN_BUDGET
        pieces = list(hook_mod._pieces(text, [hook_mod.SCAN_BUDGET]))
        self.assertTrue(pieces[-1].endswith("a") and
                        sum(len(p) for p in pieces) >= len(text))
        covered = (len(pieces) - 1) * (hook_mod.CHUNK - hook_mod.OVERLAP) + len(pieces[-1])
        self.assertGreaterEqual(covered, len(text))


class PaddedCommandsStayFast(unittest.TestCase):
    """Before 0.10 a Bash command of 5,000 newlines took ~20 s to check (the
    hook's limit is 10 s): fail-closed, the call was blocked; --fail-open, a
    padded `cat .env` would have gone through. Whitespace runs are now
    collapsed before the rules run."""

    def test_padded_commands_are_checked_quickly_and_still_refused(self):
        import time
        for unit in ("\n", " \n", "\r\n", '"\n', "'\n", "\\\n", "$x\n", " ", "(\n"):
            with self.subTest(unit=unit):
                cmd = unit * (90_000 // len(unit)) + "cat .env"
                start = time.monotonic()
                reason = pre("Bash", command=cmd)
                self.assertLess(time.monotonic() - start, 4)
                self.assertIsNotNone(reason)

    def test_collapsing_keeps_newline_boundaries(self):
        self.assertEqual(hook_mod._collapse_ws("a \n\t b  c"), "a\nb c")
        self.assertIsNotNone(pre("Bash", command="true\n\n\n   \n  env"))
        self.assertIsNone(pre("Bash", command="env   FOO=1   python app.py"))


class InstallThePromptHook(unittest.TestCase):
    def test_install_adds_a_prompt_group_without_matcher_or_on_failure(self):
        data = {}
        self.assertEqual(hook_mod.merge_install(data, hook_mod.hook_handler()), "added")
        groups = data["hooks"]["UserPromptSubmit"]
        self.assertEqual(len(groups), 1)
        self.assertNotIn("matcher", groups[0])
        self.assertNotIn("onFailure", groups[0]["hooks"][0])
        self.assertEqual(groups[0]["hooks"][0]["statusMessage"], hook_mod.MARKER)
        self.assertEqual(hook_mod.merge_install(data, hook_mod.hook_handler()), "unchanged")

    def test_an_older_install_is_upgraded_and_others_hooks_are_kept(self):
        data = {}
        hook_mod.merge_install(data, hook_mod.hook_handler())
        del data["hooks"]["UserPromptSubmit"]           # what 0.9 wrote
        theirs = {"hooks": [{"type": "command", "command": "their-prompt-check"}]}
        data["hooks"]["UserPromptSubmit"] = [theirs]
        self.assertEqual(hook_mod.merge_install(data, hook_mod.hook_handler()), "updated")
        self.assertIn(theirs, data["hooks"]["UserPromptSubmit"])
        self.assertEqual(len(data["hooks"]["UserPromptSubmit"]), 2)
        self.assertEqual(hook_mod.merge_uninstall(data), 3)
        self.assertEqual(data["hooks"]["UserPromptSubmit"], [theirs])

    def test_a_bad_prompt_section_leaves_the_file_alone(self):
        data = {"hooks": {"UserPromptSubmit": {"not": "a list"}}}
        with self.assertRaises(hook_mod.SettingsError):
            hook_mod.merge_install(data, hook_mod.hook_handler())
        self.assertEqual(data, {"hooks": {"UserPromptSubmit": {"not": "a list"}}})


if __name__ == "__main__":
    unittest.main()
