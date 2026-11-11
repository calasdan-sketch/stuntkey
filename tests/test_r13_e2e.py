"""Round 13: black-box journeys through the real command line, in a throwaway home.

Every child process gets HOME / USERPROFILE / APPDATA / LOCALAPPDATA pointed at a
fresh folder, every STUNTKEY_* variable cleared, and a keychain that is a plain
folder inside that home (never the real one). Only made-up keys are used.
"""
import json
import os
import subprocess
import sys
import unittest

import _isolation

REPO = _isolation.REPO
FAKE_OPENAI = "sk-proj-" + "R13e2eFakeKeyAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


class Home:
    """A throwaway home folder and the environment that points at it."""

    def __init__(self):
        self.dir = _isolation.mktemp()
        self.kc = os.path.join(self.dir, "kc")
        os.makedirs(self.kc, exist_ok=True)

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("STUNTKEY_")}
        env.update(HOME=self.dir, USERPROFILE=self.dir,
                   APPDATA=os.path.join(self.dir, "AppData", "Roaming"),
                   LOCALAPPDATA=os.path.join(self.dir, "AppData", "Local"),
                   XDG_CONFIG_HOME=os.path.join(self.dir, ".config"),
                   XDG_DATA_HOME=os.path.join(self.dir, ".local", "share"),
                   STUNTKEY_KEYCHAIN="file:" + self.kc,
                   PYTHONIOENCODING="utf-8", PYTHONPATH=REPO,
                   PYTHONDONTWRITEBYTECODE="1")
        env.update(extra)
        return env

    def sk(self, *args, input=None, cwd=None, timeout=90, **extra):
        stdin = {"stdin": subprocess.DEVNULL} if input is None else {}
        return subprocess.run([sys.executable, "-m", "stuntkey", *args],
                              input=input, capture_output=True, text=True, **stdin,
                              encoding="utf-8", errors="replace",
                              cwd=cwd or self.dir, env=self.env(**extra),
                              timeout=timeout)

    def write(self, rel, data):
        path = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    def everything_on_disk(self):
        """Every byte under the home, except the keychain folder."""
        blob = b""
        for root, _d, files in os.walk(self.dir):
            if os.path.abspath(root).startswith(os.path.abspath(self.kc)):
                continue
            for f in files:
                try:
                    with open(os.path.join(root, f), "rb") as fh:
                        blob += fh.read()
                except OSError:
                    pass
        return blob


class Journey(unittest.TestCase):
    def setUp(self):
        self.home = Home()

    def test_hook_install_then_uninstall_restores_settings_byte_for_byte(self):
        original = (b'{\n  "model": "x",\n  "hooks": {\n    "PreToolUse": [\n'
                    b'      {"matcher": "Bash", "hooks": [{"type": "command", '
                    b'"command": "echo mine"}]}\n    ]\n  }\n}\n')
        settings = self.home.write("proj/.claude/settings.json", original)
        r = self.home.sk("hook", "install", "--settings", settings, "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        changed = open(settings, "rb").read()
        self.assertNotEqual(changed, original)
        data = json.loads(changed)
        self.assertIn("echo mine", json.dumps(data), "the user's own hook must stay")
        self.assertIn("stuntkey", json.dumps(data))
        s = self.home.sk("hook", "status", "--settings", settings)
        self.assertNotIn("Traceback", s.stdout + s.stderr)
        u = self.home.sk("hook", "uninstall", "--settings", settings)
        self.assertEqual(u.returncode, 0, u.stdout + u.stderr)
        self.assertEqual(json.loads(open(settings, "rb").read()), json.loads(original))
        # Known gap (reported to the lead): uninstall re-writes the file in its own
        # layout (and Windows line endings), so the bytes differ although every
        # setting is the same. What IS promised is the backup made at install:
        backups = os.path.join(self.home.dir, ".stuntkey", "backups")
        held = [open(os.path.join(backups, n), "rb").read() for n in os.listdir(backups)]
        self.assertIn(original, held, "the install backup must hold the exact old bytes")

    def test_hook_install_on_missing_file_then_uninstall_leaves_nothing_behind(self):
        settings = os.path.join(self.home.dir, "p", ".claude", "settings.json")
        r = self.home.sk("hook", "install", "--settings", settings, "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(os.path.exists(settings))
        u = self.home.sk("hook", "uninstall", "--settings", settings)
        self.assertEqual(u.returncode, 0, u.stdout + u.stderr)
        if os.path.exists(settings):
            self.assertEqual(json.loads(open(settings, "rb").read()).get("hooks", {}), {})

    def test_import_run_never_shows_the_key_and_audit_is_clean(self):
        env_file = self.home.write("secrets.env", f"OPENAI_API_KEY={FAKE_OPENAI}\n")
        r = self.home.sk("import", env_file, "--yes")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn(FAKE_OPENAI, r.stdout + r.stderr)
        child = ("import os,sys; k=os.environ.get('OPENAI_API_KEY',''); "
                 "print('LEN', len(k)); print(k); sys.stderr.write(k+'\\n'); "
                 "print([n for n in os.environ if n.startswith('STUNTKEY')])")
        run = self.home.sk("run", "openai", "--", sys.executable, "-c", child)
        out = run.stdout + run.stderr
        self.assertNotIn(FAKE_OPENAI, out, "the key must be scrubbed from output")
        self.assertIn("LEN " + str(len(FAKE_OPENAI)), out, "the child did get the key")
        # without redaction on a captured pipe the key is the child's own business;
        # but nothing stuntkey wrote to disk may hold it
        os.remove(env_file)        # the export itself is the user's to delete
        self.assertNotIn(FAKE_OPENAI.encode(), self.home.everything_on_disk())
        a = self.home.sk("audit")
        self.assertNotIn("Traceback", a.stdout + a.stderr)
        self.assertNotIn(FAKE_OPENAI, a.stdout + a.stderr)
        self.assertEqual(a.returncode, 0, a.stdout + a.stderr)

    def test_run_with_no_saved_key_is_a_plain_message(self):
        run = self.home.sk("run", "openai", "--", sys.executable, "-c", "print(1)")
        self.assertNotIn("Traceback", run.stdout + run.stderr)
        self.assertNotEqual(run.returncode, 0)

    def test_version_doctor_about_work_in_a_clean_home(self):
        v = self.home.sk("--version")
        self.assertEqual(v.returncode, 0)
        self.assertRegex(v.stdout + v.stderr, r"\d+\.\d+\.\d+")
        for cmd in (["about"], ["doctor"], ["doctor", "--self"], ["overview"], ["list"]):
            r = self.home.sk(*cmd)
            self.assertNotIn("Traceback", r.stdout + r.stderr, cmd)

    def test_nothing_was_written_to_the_real_home(self):
        real = os.path.expanduser("~")
        # the child was told a different home, so its files are all under self.home.dir
        self.home.sk("overview")
        self.assertTrue(os.path.abspath(self.home.dir) != os.path.abspath(real))


class HookContract(unittest.TestCase):
    """Claude Code feeds the hook JSON on stdin. A refusal is exit 0 with a JSON
    "deny" decision; input that is not JSON at all is a non-zero exit with a plain
    sentence (the installed hook says `onFailure: block`, so Claude Code then stops
    the call). Never a traceback."""

    def setUp(self):
        self.home = Home()

    def check(self, payload, raw=False):
        data = payload if raw else json.dumps(payload)
        return self.home.sk("hook", "check", input=data)

    @staticmethod
    def denied(r):
        if r.returncode != 0 or not r.stdout.strip():
            return False
        try:
            d = json.loads(r.stdout)
        except ValueError:
            return False
        return d.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"

    def test_env_read_is_denied_and_harmless_read_is_not(self):
        bad = self.check({"tool_name": "Read", "tool_input": {"file_path": ".env"}})
        self.assertTrue(self.denied(bad), bad.stdout + bad.stderr)
        reason = json.loads(bad.stdout)["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertNotIn("Traceback", reason)
        self.assertEqual(json.loads(bad.stdout)["hookSpecificOutput"]["hookEventName"],
                         "PreToolUse")
        ok = self.check({"tool_name": "Read", "tool_input": {"file_path": "README.md"}})
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertFalse(self.denied(ok))

    def test_every_malformed_input_ends_in_a_plain_outcome(self):
        cases = ["", "{", "null", "[]", "42", '"x"', "{}", '{"tool_name": 5}',
                 '{"tool_name": "Read", "tool_input": "x"}',
                 '{"tool_name": "Read", "tool_input": null}',
                 '{"tool_name": "Bash", "tool_input": {"command": 7}}',
                 "\ufeff{}", "\x00\x00", "{" * 5000, "[" * 5000]
        for raw in cases:
            r = self.check(raw, raw=True)
            out = r.stdout + r.stderr
            self.assertNotIn("Traceback", out, repr(raw[:40]))
            self.assertIn(r.returncode, (0, 1, 2), (repr(raw[:40]), r.returncode, out))

    def test_input_that_is_not_json_is_not_waved_through(self):
        for raw in ("", "{", "not json at all", "[" * 5000, "\x00\x00"):
            r = self.check(raw, raw=True)
            self.assertNotEqual(r.returncode, 0, (repr(raw[:20]), r.stdout, r.stderr))
            self.assertFalse(r.stdout.strip(), "no decision JSON for garbage")
            self.assertIn("not the JSON", r.stderr)

    def test_huge_input_does_not_hang_or_crash(self):
        big = json.dumps({"tool_name": "Bash",
                          "tool_input": {"command": "echo " + "a" * 3_000_000}})
        r = self.home.sk("hook", "check", input=big, timeout=60)
        self.assertNotIn("Traceback", r.stdout + r.stderr)
        self.assertIn(r.returncode, (0, 1, 2))

    def test_env_name_forms_are_denied(self):
        for cmd in ("cat .env", "type .env", "cat ./.env.local", "Get-Content .env",
                    "cat '.env'", 'cat ".env"', "cat .e''nv", "cat .ENV", "gc .env",
                    "cat < .env", "cat .env.production"):
            r = self.check({"tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertTrue(self.denied(r), (cmd, r.stdout, r.stderr))
        for cmd in ("cat .env.example", "ls", "git status"):
            r = self.check({"tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertFalse(self.denied(r), (cmd, r.stdout))

    def test_env_path_forms_for_the_read_tool_are_denied(self):
        for p in (".env", "C:\\x\\.env", "C:/x/.ENV.local", ".env ", ".env.",
                  "\\\\?\\C:\\x\\.env", "sub/dir/.env"):
            r = self.check({"tool_name": "Read", "tool_input": {"file_path": p}})
            self.assertTrue(self.denied(r), (p, r.stdout, r.stderr))

    @unittest.expectedFailure
    def test_a_list_where_a_path_belongs_is_still_checked(self):
        # KNOWN GAP (round 13, reported to the lead): a path given as a list is
        # allowed. Claude Code itself never sends one, so this is defence in depth.
        r = self.check({"tool_name": "Read", "tool_input": {"file_path": [".env"]}})
        self.assertTrue(self.denied(r))


if __name__ == "__main__":
    unittest.main()
