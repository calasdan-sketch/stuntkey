"""0.9.x hook wave 1: one scrubber for scrub.py and redact.py, PreToolUse
blocks for commands that dump the environment or a credentials file, the
PostToolUse output mask (fingerprints + key formats), and the agent rules
block with its undo."""

import argparse
import io
import sys
import json
import os
import time
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import cli as cli_mod
from stuntkey import hook as hook_mod
from stuntkey import redact, scrub

# built at run time so this file never holds a key-shaped string
STORED = "zq" + "9Xr4" + "Lm2Vt8Kp3Wn7Yb5"            # no known format: only a fingerprint finds it
OPENAI = "sk-" + "proj-" + "Ab3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gH3jK5mN7p"
PEM = "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END " + "PRIVATE KEY-----"


def bash(cmd):
    return {"tool_name": "Bash", "tool_input": {"command": cmd}}


def blocked(cmd):
    return bool(hook_mod.decide_steal(bash(cmd)) or hook_mod.decide(bash(cmd)))


def post(stdout, stderr="", tool="Bash"):
    return {"hook_event_name": "PostToolUse", "tool_name": tool,
            "tool_input": {"command": "x"},
            "tool_response": {"stdout": stdout, "stderr": stderr,
                              "interrupted": False, "isImage": False}}


class OneScrubber(unittest.TestCase):
    def test_redact_names_are_the_scrub_implementation(self):
        self.assertIs(redact.Redactor, scrub.Scrubber)
        self.assertEqual(redact.MIN_LENGTH, scrub.MIN_LEN)
        self.assertEqual(redact.MARK, scrub.REDACTED)
        self.assertEqual(redact.variants(STORED), set(scrub.forms(STORED)))

    def test_the_union_of_both_old_form_lists(self):
        out = scrub.scrub_text(" ".join([STORED[::-1], STORED.upper(), STORED.lower()]), [STORED])
        self.assertEqual(out, "[REDACTED] [REDACTED] [REDACTED]")
        r = scrub.Scrubber([STORED])
        self.assertEqual(r.feed(STORED.encode("utf-16-le")) + r.flush(), b"[REDACTED]")
        self.assertEqual(r.hits, 1)


class DumpCommands(unittest.TestCase):
    BAD = ("env", "env | grep KEY", "printenv", "cd x && env", "set", "cmd /c set",
           "Get-ChildItem env:", "gci Env:", "dir env:", "Get-Item env:OPENAI*",
           "[Environment]::GetEnvironmentVariables()", "docker compose config",
           "docker-compose -f a.yml config", "docker inspect web",
           "docker inspect -f '{{.Config.Env}}' web", "cat server.pem",
           "type C:\\keys\\id_rsa", "Get-Content ~/.aws/credentials", "less ~/.netrc",
           "grep token ~/.npmrc", "sed -n 1p a.key", "export -p", "export", "declare -x",
           "cat /proc/self/environ", "git show HEAD:.env", "git log -p -- .env.production",
           "cat .env*", "echo $OPENAI_API_KEY", "printenv STRIPE_SECRET_KEY",
           "Write-Output $env:GITHUB_TOKEN", "python -c \"import os;print(os.environ)\"",
           "node -e 'console.log(process.env)'", "docker exec web env",
           "kubectl exec pod -- printenv", "bash -c env", "sh -c 'env'")
    GOOD = ("env FOO=1 python app.py", "python -m venv env", "source env/bin/activate",
            "set -e", "set -euo pipefail", "export FOO=bar", "printenv PATH", "echo $HOME",
            "for key in a b; do echo $key; done", "docker compose up -d",
            "docker inspect -f '{{.State.Running}}' web", "cat id_rsa.pub", "cat README.md",
            "grep -r password src/", "git log -p -- src/app.py", "pytest tests/test_env.py",
            "Get-Item env:PATH", "echo env", "conda activate myenv", "head -5 keyboard.py",
            "openssl x509 -in cert.pem -noout", "git status")

    def test_dumps_are_blocked(self):
        for cmd in self.BAD:
            self.assertTrue(blocked(cmd), cmd)

    def test_normal_dev_commands_pass(self):
        for cmd in self.GOOD:
            self.assertFalse(blocked(cmd), cmd)

    def test_only_shell_tools_get_the_dump_rules(self):
        call = {"tool_name": "mcp__notes__save", "tool_input": {"title": "env", "body": "set"}}
        self.assertIsNone(hook_mod.decide_steal(call))
        status, out = hook_mod.check(json.dumps(dict(bash("env"), hook_event_name="PreToolUse")))
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")


class Fingerprints(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(_isolation.mktemp(), "fp.json")

    def test_remember_holds_no_key_and_forget_drops_it(self):
        scrub.remember_key("svc/KEY", STORED, self.path)
        with open(self.path, encoding="utf-8") as f:
            self.assertNotIn(STORED, f.read())
        salt, prints = scrub.load_fingerprints(self.path)
        self.assertEqual(len(salt), 32)
        self.assertEqual(scrub.mask_secrets(f"K={STORED}.", (salt, prints)), ("K=[REDACTED].", 1))
        self.assertTrue(scrub.forget_key("svc/KEY", self.path))
        self.assertFalse(scrub.forget_key("svc/KEY", self.path))
        self.assertEqual(scrub.load_fingerprints(self.path)[1], frozenset())

    def test_rotation_replaces_the_old_fingerprint(self):
        scrub.remember_key("svc/KEY", STORED, self.path)
        scrub.remember_key("svc/KEY", STORED[::-1], self.path)
        prints = scrub.load_fingerprints(self.path)
        self.assertEqual(scrub.mask_secrets(STORED, prints)[1], 0)
        self.assertEqual(scrub.mask_secrets(STORED[::-1], prints)[1], 1)

    def test_known_formats_are_masked_without_a_fingerprint(self):
        empty = (b"", frozenset())
        for text in (f"key: {OPENAI}", PEM, "Authorization: Bearer " + STORED + "x9",
                     "postgres://app:" + "Pz8w" + "Lq2x@db/x", "API_TOKEN=" + STORED):
            out, n = scrub.mask_secrets(text, empty)
            self.assertGreater(n, 0, text)
            self.assertIn("[REDACTED]", out)
        self.assertEqual(scrub.mask_secrets("all 12 tests passed in 0.3s", empty), ("all 12 tests passed in 0.3s", 0))


class PostToolUse(unittest.TestCase):
    def setUp(self):
        scrub.remember_key("svc/KEY", STORED)
        self.addCleanup(scrub.forget_key, "svc/KEY")

    def answer(self, payload):
        status, out = hook_mod.check(json.dumps(payload))
        self.assertEqual(status, 0)
        return json.loads(out) if out else None

    def test_bash_output_is_replaced_in_the_documented_shape(self):
        got = self.answer(post(f"KEY={STORED}\nok\n", f"warn {OPENAI}"))
        spec = got["hookSpecificOutput"]
        self.assertEqual(spec["hookEventName"], "PostToolUse")
        self.assertEqual(spec["updatedToolOutput"], {
            "stdout": "KEY=[REDACTED]\nok\n", "stderr": "warn [REDACTED]",
            "interrupted": False, "isImage": False})
        self.assertIn("2 secret", spec["additionalContext"])

    def test_clean_output_and_other_tools_say_nothing(self):
        self.assertIsNone(self.answer(post("all good\n")))
        self.assertIsNone(self.answer(post(STORED, tool="Read")))
        self.assertIsNone(self.answer(post(STORED, tool="Grep")))

    def test_an_internal_error_fails_open_and_says_so_on_stderr(self):
        err = io.StringIO()
        with mock.patch.object(scrub, "load_fingerprints", side_effect=ValueError(STORED)):
            self.assertEqual(hook_mod.post_check(post(STORED), err=err), "")
        self.assertIn("shown unmasked", err.getvalue())
        self.assertNotIn(STORED, err.getvalue())

    def test_typical_output_is_fast(self):
        text = "\n".join(f"tests/test_mod{i}.py::test_case_{i} PASSED [{i}%]" for i in range(400))
        hook_mod.post_check(post(text))                 # first call loads the patterns
        start = time.perf_counter()
        hook_mod.post_check(post(text + STORED))
        self.assertLess(time.perf_counter() - start, 0.05)


class InstallBothEvents(unittest.TestCase):
    def setUp(self):
        self.dir = _isolation.mktemp()
        self.path = os.path.join(self.dir, "settings.json")
        p = mock.patch.object(hook_mod, "hook_argv", lambda: ["/opt/bin/stuntkey", "hook", "check"])
        p.start()
        self.addCleanup(p.stop)

    def test_install_adds_a_post_group_without_on_failure_and_uninstall_removes_both(self):
        data = {}
        self.assertEqual(hook_mod.merge_install(data, hook_mod.hook_handler()), "added")
        group = data["hooks"]["PostToolUse"][0]
        self.assertEqual(group["matcher"], "^(Bash|mcp__.*)$")
        self.assertNotIn("onFailure", group["hooks"][0])
        self.assertEqual(hook_mod.merge_install(data, hook_mod.hook_handler()), "unchanged")
        self.assertEqual(hook_mod.merge_uninstall(data), 2)
        self.assertEqual(data, {})

    def test_an_old_install_gets_the_post_group(self):
        data = {"hooks": {"PreToolUse": [hook_mod.hook_entry()]}}
        self.assertEqual(hook_mod.merge_install(data, hook_mod.hook_handler()), "updated")
        self.assertIn("PostToolUse", data["hooks"])


class AgentRules(unittest.TestCase):
    def setUp(self):
        self.dir = _isolation.mktemp()

    def test_add_to_existing_files_and_undo_restores_them(self):
        for name, text in (("AGENTS.md", "# Team\r\nbe nice\r\n"), (".cursorrules", "x\n")):
            with open(os.path.join(self.dir, name), "w", encoding="utf-8", newline="") as f:
                f.write(text)
        done = hook_mod.add_agent_rules(self.dir)
        self.assertEqual(sorted(os.path.basename(p) for p in done), [".cursorrules", "AGENTS.md"])
        self.assertFalse(os.path.exists(os.path.join(self.dir, "CLAUDE.md")))
        with open(os.path.join(self.dir, "AGENTS.md"), encoding="utf-8", newline="") as f:
            body = f.read()
        self.assertIn("Never read .env files", body)
        self.assertNotIn("\n", body.replace("\r\n", ""))           # kept CRLF
        self.assertEqual(hook_mod.add_agent_rules(self.dir), [])  # twice: no second block
        hook_mod.remove_agent_rules(self.dir)
        with open(os.path.join(self.dir, "AGENTS.md"), encoding="utf-8", newline="") as f:
            self.assertEqual(f.read(), "# Team\r\nbe nice\r\n")
        with open(os.path.join(self.dir, ".cursorrules"), encoding="utf-8", newline="") as f:
            self.assertEqual(f.read(), "x\n")

    def test_new_claude_md_when_none_and_undo_deletes_it(self):
        hook_mod.add_agent_rules(self.dir)
        path = os.path.join(self.dir, "CLAUDE.md")
        self.assertTrue(os.path.exists(path))
        self.assertEqual(hook_mod.remove_agent_rules(self.dir), [path])
        self.assertFalse(os.path.exists(path))

    def test_install_asks_only_with_project_and_respects_no(self):
        old = os.getcwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, old)
        parse = cli_mod._build_parser().parse_args
        out = io.StringIO()
        self.assertEqual(hook_mod._offer_agent_rules(parse(["hook", "install"]), out), "")
        self.assertEqual(hook_mod._offer_agent_rules(
            parse(["hook", "install", "--project"]), out, ask=lambda _: "n"), "")
        self.assertFalse(os.path.exists("CLAUDE.md"))
        with mock.patch.object(sys, "stdin", io.StringIO()):     # not a terminal: no prompt
            self.assertIn("Tip", hook_mod._offer_agent_rules(
                parse(["hook", "install", "--project"]), out))
        self.assertFalse(os.path.exists("CLAUDE.md"))
        self.assertEqual(hook_mod._offer_agent_rules(
            argparse.Namespace(project=True, agent_rules=False), out, ask=lambda _: "y"), "")
        said = hook_mod._offer_agent_rules(parse(["hook", "install", "--project"]), out,
                                           ask=lambda _: "y")
        self.assertIn("Added", said)
        self.assertTrue(os.path.exists("CLAUDE.md"))


if __name__ == "__main__":
    unittest.main()
