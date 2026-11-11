"""0.5.1: the review panel's findings on 0.5.0 - scan that cannot be made to
hang or to lie by omission, a hook that never runs a command read from a file,
and the false negatives. Every key below is made up (built from pieces)."""

import contextlib
import io
import json
import os
import signal
import stat
import subprocess
import sys
import time
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import cli as cli_mod
from stuntkey import hook as hook_mod
from stuntkey import recipes as recipes_mod
from stuntkey import scan as scan_mod
from stuntkey import validate as validate_mod

from test_scan import (ANTHROPIC, CATALOG, GENERIC, OPENAI, FakeValidate, NoNetwork,
                       args_for, run_cli, scan_text, write)
from test_hook import call, ok_run, Settings

M = 1024 * 1024


def timed(fn, *a, **k):
    t = time.monotonic()
    result = fn(*a, **k)
    return result, time.monotonic() - t


# ------------------------------------------------------------------ 1. ReDoS

class TestNoPatternCanHangTheScan(unittest.TestCase):
    def test_twenty_thousand_As_on_one_line_is_fast(self):
        # was 9-26 seconds (ASSIGN_RE was quadratic); 1 MB took ten minutes
        _, took = timed(scan_text, "A" * 20000 + "\n")
        self.assertLess(took, 1.0)

    def test_a_megabyte_of_the_worst_lines_is_fast(self):
        for text in ("sk-" * 350000, "a.-" * 350000 + "=", "KEY=" + "A1" * 500000,
                     "token:" * 170000, "-----BEGIN " * 90000, "a " * 500000,
                     "x://u:" * 170000, "Bearer " * 150000):
            _, took = timed(scan_text, text)
            self.assertLess(took, 2.0, text[:12])

    def test_every_pattern_survives_adversarial_lines(self):
        rules = scan_mod.build_rules(CATALOG)
        literals = sorted({r.literal for r in rules if r.literal} | {"sk-", "AKIA", "eyJ"})
        bodies = ("A", "A1", "a-", "A.", "1_", "=:", " ", "A@")
        slowest = 0.0
        for lit in literals:
            for body in bodies:
                text = (lit + body * 64000)[:256 * 1024]
                _, took = timed(scan_mod.scan_text, text, "x", rules, CATALOG)
                slowest = max(slowest, took)
                self.assertLess(took, 1.0, (lit, body))

    def test_a_pattern_that_is_a_trap_is_stopped_not_waited_for(self):
        if not scan_mod.user_patterns_usable():
            self.skipTest("no timer signal on this system")
        evil = {"service": "evil", "display": "Evil", "key_url": "https://evil.test/k",
                "env_var": "EVIL_KEY", "steps": ["x"],
                "fields": [{"name": "key", "env_var": "EVIL_KEY", "pattern": "(a+)+b"}],
                "validate": {"method": "GET", "url": "https://evil.test/me",
                             "auth": {"type": "bearer"}, "expect": [200]}}
        with self.assertRaises(recipes_mod.RecipeError):      # 0.6.1: refused up front ...
            recipes_mod.validate_recipe(evil)
        evil["_builtin"] = False
        catalog = dict(CATALOG, evil=evil)
        rules = scan_mod.build_rules(catalog)
        self.assertFalse([r for r in rules if r.provider == "evil" and r.trusted])
        budget = scan_mod.Budget(30)
        _, took = timed(scan_mod.scan_text, "a" * 60 + "!\n", "x", rules, catalog, None, budget)
        self.assertLess(took, 3.0)
        self.assertTrue(any("took too long" in n for n in budget.notes))

    def test_a_file_that_runs_out_of_time_is_reported_incomplete(self):
        root = _isolation.mktemp()
        write(root, ".env", f"OPENAI_API_KEY={OPENAI}\n" * 3)
        with mock.patch.object(scan_mod, "FILE_SECONDS", -1.0):
            result = scan_mod.scan_path(root, CATALOG)
        self.assertTrue(result.incomplete)
        self.assertIn("stopped after", result.skipped[0].reason)


# ------------------------------------------------------- 5. truncated scans lie

class TestAnIncompleteScanSaysSo(NoNetwork):
    def test_an_env_file_behind_fifty_thousand_empty_files_is_found(self):
        root = _isolation.mktemp()
        for i in range(50010):
            open(os.path.join(root, f".a{i:06d}"), "w").close()
        write(root, ".env", f"OPENAI_API_KEY={OPENAI}\n")
        code, out, err = run_cli("scan", root)
        self.assertEqual(code, 1)
        self.assertIn("OpenAI", out)

    def test_hitting_the_file_cap_is_loud_and_exit_2(self):
        root = _isolation.mktemp()
        for i in range(10):
            write(root, f".env.n{i}", "A=1\n")
        with mock.patch.object(scan_mod, "MAX_CANDIDATES", 3):
            code, out, err = run_cli("scan", root)
        self.assertEqual(code, 2)
        self.assertIn("INCOMPLETE", out)
        self.assertNotIn("No keys found in files an AI agent can read", out)
        self.assertIn("INCOMPLETE", err)

    def test_fail_on_live_is_never_a_clean_zero_when_incomplete(self):
        root = _isolation.mktemp()
        write(root, ".env", f"OPENAI_API_KEY={OPENAI}\n")
        for i in range(5):
            write(root, f".env.n{i}", "A=1\n")
        with mock.patch.object(scan_mod, "MAX_CANDIDATES", 2):
            code, out, err = run_cli("scan", root, "--fail-on", "live")
        self.assertEqual(code, 2)

    def test_too_deep_is_incomplete(self):
        root = _isolation.mktemp()
        deep = os.path.join(root, *["d"] * (scan_mod.MAX_DEPTH + 2))
        os.makedirs(deep)
        write(deep, ".env", f"K_TOKEN={GENERIC}\n")
        code, out, _ = run_cli("scan", root)
        self.assertEqual(code, 2)
        self.assertIn("too many folders deep", out)

    def test_a_folder_that_cannot_be_opened_is_incomplete(self):
        root = _isolation.mktemp()
        os.makedirs(os.path.join(root, "locked"))
        real = os.scandir

        def scandir(path):
            if str(path).endswith("locked"):
                raise PermissionError(13, "Permission denied")
            return real(path)
        with mock.patch.object(os, "scandir", scandir):
            code, out, _ = run_cli("scan", root)
        self.assertEqual(code, 2)
        self.assertIn("could not be opened", out)

    def test_a_big_env_file_is_a_gap_but_a_big_log_is_not(self):
        root = _isolation.mktemp()
        write(root, ".env", "A=" + "x" * (M + 10))
        write(root, "big.log", "x" * (M + 10))
        result = scan_mod.scan_path(root, CATALOG, everything=True)
        flags = {s.path: s.incomplete for s in result.skipped}
        self.assertEqual(flags, {".env": True, "big.log": False})

    def test_build_folders_are_pruned_and_that_is_not_incomplete(self):
        root = _isolation.mktemp()
        for d in ("target", "build", "dist", ".next"):
            write(root, f"{d}/.env", f"K_TOKEN={GENERIC}\n")
        code, out, _ = run_cli("scan", root)
        self.assertEqual(code, 0)
        self.assertNotIn("INCOMPLETE", out)

    def test_json_and_sarif_carry_the_gap(self):
        root = _isolation.mktemp()
        write(root, ".env.a", "A=1\n")
        write(root, ".env.b", "A=1\n")
        with mock.patch.object(scan_mod, "MAX_CANDIDATES", 1):
            data = json.loads(run_cli("scan", root, "--json")[1])
            sarif = json.loads(run_cli("scan", root, "--sarif")[1])
        self.assertTrue(data["incomplete"])
        self.assertTrue(data["skipped"][0]["incomplete"])
        inv = sarif["runs"][0]["invocations"][0]
        self.assertFalse(inv["executionSuccessful"])

    def test_the_skipped_line_gives_the_real_reasons(self):
        root = _isolation.mktemp()
        write(root, ".env", "A=" + "x" * (M + 10))
        write(root, ".env.bin", "\0\0\0abc")
        write(root, "CLAUDE.md", "")
        out = run_cli("scan", root)[1]
        self.assertIn("bigger than 1 MB", out)
        self.assertIn("a binary file", out)
        self.assertNotIn("a pipe, or a link", out)

    def test_the_same_file_reached_through_a_link_is_named_by_its_real_path(self):
        root = _isolation.mktemp()
        write(root, "real/.env", f"OPENAI_API_KEY={OPENAI}\n")
        try:
            os.symlink(os.path.join(root, "real", ".env"), os.path.join(root, ".env.link"))
        except (OSError, NotImplementedError):
            self.skipTest("no symbolic links here")
        result = scan_mod.scan_path(root, CATALOG)
        self.assertEqual([f.file for f in result.findings], ["real/.env"])


# --------------------------------------------- 6. wrong provider, 401 vs 403

class TestNameBasedGuessesAreNotSent(NoNetwork):
    def go(self, env_text, *argv, fake=None, **kw):
        root = _isolation.mktemp()
        write(root, ".env", env_text)
        out, err = io.StringIO(), io.StringIO()
        fake = fake or FakeValidate()
        code = scan_mod.cmd_scan(args_for(root, *argv), CATALOG, out=out, err=err,
                                 validate_fn=fake, ask=lambda p: "y",
                                 interactive=lambda: False)
        return code, out.getvalue(), err.getvalue(), fake

    def test_a_value_that_is_not_an_openai_key_is_never_sent_to_openai(self):
        code, out, err, fake = self.go(f"OPENAI_API_KEY={GENERIC}\n", "--validate", "--yes")
        self.assertEqual(fake.calls, [])
        self.assertIn("could not be checked", out)
        self.assertNotIn("no longer works", out)
        self.assertNotIn("Delete", out)

    def test_a_loose_word_in_the_name_gives_no_vendor_at_all(self):
        f = scan_text(f"MYOPENAI_THING_TOKEN={GENERIC}\n")[0]
        self.assertIsNone(f.provider)

    def test_public_and_webhook_names_are_never_mapped_to_a_vendor(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9." + "eyJyb2xlIjoiYW5vbiJ9Xk39dLq82mZpR71" + ".Zq8vK2mXp9LrTg5H"
        for name in ("SUPABASE_ANON_KEY", "STRIPE_WEBHOOK_SECRET", "GOOGLE_MAPS_API_KEY",
                     "NEXT_PUBLIC_SUPABASE_KEY", "OPENAI_WEBHOOK_TOKEN"):
            for f in scan_text(f"{name}={jwt}\n"):
                self.assertIsNone(f.provider, name)

    def test_only_401_means_rejected(self):
        seen = []

        def fake(spec, key, timeout=10.0):
            seen.append(spec)
            return validate_mod._verdict(404, spec)
        code, out, err, _ = self.go(f"OPENAI_API_KEY={OPENAI}\n", "--validate", "--yes",
                                    fake=fake)
        self.assertEqual(seen[0]["reject"], [401])
        self.assertIn("could not be checked", out)
        self.assertIn("HTTP 404", out)
        self.assertNotIn("rejected by the service", out)

    def test_a_401_is_worded_without_telling_you_to_delete(self):
        code, out, err, _ = self.go(f"OPENAI_API_KEY={OPENAI}\n", "--validate", "--yes",
                                    fake=FakeValidate({OPENAI: False}))
        self.assertIn("rejected", out)
        self.assertIn("may not be", out)
        self.assertIn("Rotate it if you are unsure", out)
        self.assertNotIn("Delete", out)


# ------------------------------------------- 7. user recipes are not trusted

class TestYourOwnRecipesAreOptIn(NoNetwork):
    def setUp(self):
        super().setUp()
        # (Windows: recipes of your own are not run there - see _isolation)
        stack = contextlib.ExitStack()
        stack.enter_context(_isolation.custom_patterns_allowed())
        self.addCleanup(stack.close)

    def put_recipe(self):
        folder = recipes_mod.user_recipes_dir()
        os.makedirs(folder, exist_ok=True)
        r = {"service": "acme", "display": "Acme", "key_url": "https://acme.test/keys",
             "env_var": "ACME_KEY", "steps": ["Click"],
             "fields": [{"name": "key", "env_var": "ACME_KEY",
                         "pattern": "acme_[A-Za-z0-9]{20,}"}],
             "validate": {"method": "GET", "url": "https://evil.example/me",
                          "auth": {"type": "bearer"}, "expect": [200]}}
        path = os.path.join(folder, "acme.json")
        with open(path, "w") as f:
            json.dump(r, f)
        self.addCleanup(os.unlink, path)

    def test_scan_ignores_your_recipes_unless_asked(self):
        self.put_recipe()
        root = _isolation.mktemp()
        write(root, ".env", "ACME_KEY=acme_Qw3Er5Ty7Ui9Op1As3Df5Gh\n")
        self.assertNotIn("Acme", run_cli("scan", root)[1])
        code, out, _ = run_cli("scan", root, "--my-recipes")
        self.assertIn("Acme", out)

    def test_a_user_recipe_cannot_replace_a_builtin_for_scan(self):
        folder = recipes_mod.user_recipes_dir()
        os.makedirs(folder, exist_ok=True)
        r = dict(CATALOG["openai"])
        r = {k: v for k, v in r.items() if not k.startswith("_")}
        r["validate"] = dict(r["validate"], url="https://evil.example/steal")
        path = os.path.join(folder, "openai.json")
        with open(path, "w") as f:
            json.dump(r, f)
        self.addCleanup(os.unlink, path)
        root = _isolation.mktemp()
        write(root, ".env", f"OPENAI_API_KEY={OPENAI}\n")
        sent = []

        def fake_send(req, *a, **k):
            sent.append(req.full_url)
            return 200, b""
        with mock.patch.object(validate_mod, "_send", fake_send):
            code, out, err = run_cli("scan", root, "--validate", "--yes")
        self.assertEqual(len(sent), 1, err)
        self.assertIn("api.openai.com", sent[0])
        self.assertNotIn("evil.example", sent[0])
        self.assertNotIn("evil.example", err)

    def test_yes_never_covers_your_own_recipes(self):
        self.put_recipe()
        root = _isolation.mktemp()
        write(root, ".env", "ACME_KEY=acme_Qw3Er5Ty7Ui9Op1As3Df5Gh\n")
        catalog = recipes_mod.load_recipes()
        sent = []
        fake = lambda spec, key, timeout=10.0: sent.append(spec["url"]) or True
        for answer, interactive, expect in (("y", False, 0), ("n", True, 0), ("yes", True, 1)):
            del sent[:]
            out, err = io.StringIO(), io.StringIO()
            scan_mod.cmd_scan(args_for(root, "--validate", "--yes", "--my-recipes"), catalog,
                              out=out, err=err, validate_fn=fake,
                              ask=lambda p: answer, interactive=lambda: interactive)
            self.assertEqual(len(sent), expect, (answer, interactive))
        self.assertIn("[from YOUR recipe]", err.getvalue())


# ------------------------------------------------------------------ 11. misses

PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"


class TestFalseNegativesAreClosed(NoNetwork):
    def test_a_private_key_on_one_line_inside_json(self):
        text = json.dumps({"private_key": f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY}\n-----END PRIVATE KEY-----\n"})
        self.assertIn("private-key-block", [f.rule for f in scan_text(text)])

    def test_a_header_with_nothing_after_it_is_still_not_a_key(self):
        self.assertEqual(scan_text("echo '-----BEGIN PRIVATE KEY-----' is the header\n"), [])

    def test_a_password_in_a_connection_url(self):
        found = scan_text("DATABASE_URL=postgres://app:Zq8vK2mXp9Lr@db.example.com:5432/app\n")
        self.assertEqual([f.rule for f in found], ["url-password"])
        self.assertNotIn("Zq8vK2mXp9Lr", repr(found[0].redacted))
        for harmless in ("postgres://postgres:postgres@localhost/db",
                         "postgres://user:${DB_PASS}@host/db", "redis://:@host",
                         "https://user:password@example.com", "mysql://app:<password>@h/d",
                         "postgres://app@db.example.com/app"):
            self.assertEqual(scan_text(f"U={harmless}\n"), [], harmless)

    def test_password_names(self):
        for text in ("DB_PASSWORD=Zq8vK2mXp9Lr", 'password: "Zq8vK2mXp9Lr"',
                     "ADMIN_PASSWD = Zq8vK2mXp9Lr", "dbPassword=Zq8vK2mXp9Lr"):
            self.assertEqual(len(scan_text(text + "\n")), 1, text)
        for text in ("DB_PASSWORD=changeme", "DB_PASSWORD=password", "PASSWORD=${DB_PASSWORD}",
                     "DB_PASSWORD=get_password_from_env", "PASSWORD_FILE=/run/secrets/db",
                     "password: str", "PASSWORD_RESET_URL=https://example.com/reset",
                     "DB_PASSWORD=DB_PASSWORD_FROM_VAULT", "passwd = _splitpasswd(url)",
                     "password = Optional[str]", "self.password = HTTPPasswordMgr"):
            self.assertEqual(scan_text(text + "\n"), [], text)

    def test_a_password_finding_says_change_the_password_not_rotate_a_key(self):
        for text in ("DATABASE_URL=postgres://app:Zq8vK2mXp9Lr@db.example.com/app", "DB_PASSWORD=Zq8vK2mXp9Lr"):
            step = scan_text(text + "\n")[0].next_step
            self.assertIn("Change this password", step)
            self.assertNotIn("--validate", step)

    def test_a_name_only_guess_is_worded_as_a_guess(self):
        f = scan_text("AWS_SECRET_ACCESS_KEY=Xk39dLq82mZpR71vBn04TgYw5HcJe6UaS+/Zq\n")[0]
        self.assertTrue(f.provider_name.startswith("Possibly "), f.provider_name)
        self.assertFalse(f.can_validate)

    def test_a_bearer_token_with_no_name(self):
        found = scan_text(f'curl -H "Authorization: Bearer {GENERIC}" https://x.test\n')
        self.assertEqual([f.rule for f in found], ["bearer-token"])
        self.assertEqual(scan_text("Authorization: Bearer ${TOKEN}\n"), [])
        self.assertEqual(scan_text("the bearer of this letter\n"), [])

    def test_slack_webhooks_and_signing_secrets(self):
        hook = "https://hooks.slack." + "com/services/T01234ABCDE/B01234ABCDE/" + "Xk39dLq82mZpR71vBn04TgYw"
        self.assertEqual([f.provider_name for f in scan_text(f"URL={hook}\n")],
                         ["Slack webhook URL"])
        whsec = "whsec" + "_Xk39dLq82mZpR71vBn04TgYw5HcJe6UaS"
        self.assertEqual([f.provider_name for f in scan_text(f"S={whsec}\n")],
                         ["Stripe webhook signing secret"])

    def test_utf16_env_files_are_read(self):
        root = _isolation.mktemp()
        text = f"OPENAI_API_KEY={OPENAI}\r\n"
        write(root, ".env", b"\xff\xfe" + text.encode("utf-16-le"), mode="wb")
        write(root, ".env.local", text.encode("utf-16-le"), mode="wb")        # no byte-order mark
        write(root, ".env.be", text.encode("utf-16-be"), mode="wb")
        result = scan_mod.scan_path(root, CATALOG)
        self.assertEqual(sorted(f.file for f in result.findings), [".env", ".env.be", ".env.local"])
        self.assertEqual(result.files_scanned, 3)

    def test_a_real_binary_is_still_skipped(self):
        root = _isolation.mktemp()
        write(root, ".env.bin", bytes(range(256)) * 8, mode="wb")
        self.assertEqual(scan_mod.scan_path(root, CATALOG).files_scanned, 0)

    def test_a_key_after_a_very_long_minified_line_is_found_exactly_once(self):
        for offset in (0, 7000, 8191, 8192, 9000, 19990, 20000, 20001, 33333, 200000):
            text = "x," * (offset // 2) + f' "k": "{OPENAI}"' + ", y" * 2000
            found = scan_text(text)
            self.assertEqual([f.provider for f in found], ["openai"], offset)
            self.assertEqual(found[0].redacted, scan_mod.redact(OPENAI))

    def test_a_named_value_far_along_a_long_line_is_found(self):
        text = "{" + ", ".join(f'"a{i}": {i}' for i in range(3000)) + f', "api_token": "{GENERIC}"' + "}"
        self.assertGreater(len(text), 40000)
        self.assertEqual([f.rule for f in scan_text(text)], ["named-assignment"])

    def test_a_placeholder_is_a_word_not_a_stretch_of_letters(self):
        real = [f"sk-proj-Qw3Er5abc123Ty7Ui9Op1As3Df5Gh", "sk-proj-Qw3Er5123456Ty7Ui9Op1As3Df5Gh",
                "sk-proj-Qw3Er5fakeTy7Ui9Op1As3Df5GhK9", "sk-proj-Qw3Er5Ty7YourUi9Op1As3Df5GhK9"]
        for key in real:
            self.assertEqual(len(scan_text(f"K={key}\n")), 1, key)
        for fake in ("sk-proj-your-key-here-1234567890", "sk-proj-xxxxxxxxxxxxxxxxxxxx",
                     "sk-proj-yourkeyhere12345678", "sk-proj-example1234567890abcdef",
                     "sk-proj-<paste-your-key-here>", "sk-proj-REPLACE_ME_1234567890"):
            self.assertEqual(scan_text(f"K={fake}\n"), [], fake)
        self.assertTrue(scan_mod.is_placeholder("your_key_here"))
        self.assertTrue(scan_mod.is_placeholder("changeme"))
        self.assertFalse(scan_mod.is_placeholder("Zq8vabc123K2mXp9Lr"))


# ------------------------------------------------------ 12. trailing marks

class TestTrailingPunctuation(NoNetwork):
    def test_a_sentence_ending_in_a_key_does_not_swallow_the_full_stop(self):
        for tail in (".", "-", "_", "..", ")."):
            f = scan_text(f"the key is {OPENAI}{tail}\n")[0]
            self.assertEqual(f.redacted, scan_mod.redact(OPENAI), tail)
            self.assertEqual(f._value, OPENAI)

    def test_the_trimmed_value_is_what_is_validated(self):
        root = _isolation.mktemp()
        write(root, "CLAUDE.md", f"use {OPENAI}.\n")
        fake = FakeValidate()
        scan_mod.cmd_scan(args_for(root, "--validate", "--yes"), CATALOG, out=io.StringIO(),
                          err=io.StringIO(), validate_fn=fake, interactive=lambda: False)
        self.assertEqual([c[1] for c in fake.calls], [OPENAI])


# ------------------------------------------------------------ hook: 2, 3, 8

class TestHookNeverRunsWhatItReads(Settings):
    def test_status_does_not_execute_the_command_in_a_cloned_settings_file(self):
        marker = os.path.join(self.dir, "pwned")
        evil = f"touch {marker}; stuntkey hook check"
        self.put({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": evil}]}]}})
        args = cli_mod._build_parser().parse_args(["hook", "status", "--settings", self.path])
        out = io.StringIO()
        hook_mod.cmd_hook(args, out=out, err=io.StringIO())     # the real subprocess.run
        self.assertFalse(os.path.exists(marker), "a command from the file was run")
        # not ours, so: not installed
        self.assertIn("not installed", out.getvalue())

    @unittest.skipIf(os.name == "nt", "the POSIX shell form")
    def test_even_a_marked_handler_is_never_run_by_status(self):
        marker = os.path.join(self.dir, "pwned2")
        self.put({"hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [
            {"type": "command", "command": f"touch {marker}", "statusMessage": hook_mod.MARKER}]}]}})
        ran = []
        args = cli_mod._build_parser().parse_args(["hook", "status", "--settings", self.path])
        out = io.StringIO()
        hook_mod.cmd_hook(args, out=out, err=io.StringIO(),
                          run=lambda argv, **kw: ran.append(argv) or ok_run(argv))
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(ran, [["/bin/sh", "-c", "/opt/bin/stuntkey hook check"]])
        self.assertIn("not the one this installation would write", out.getvalue())

    def test_self_test_never_uses_a_shell_string_for_a_file_command(self):
        seen = {}

        def run(argv, **kw):
            seen.update(kw, argv=argv)
            return ok_run(argv)
        hook_mod.self_test(hook_mod.hook_handler(), run)
        self.assertIs(seen["shell"], False)
        self.assertIsInstance(seen["argv"], list)

    def test_ours_means_exactly_ours(self):
        ours = ("/opt/bin/stuntkey hook check", "'/opt/my tools/stuntkey' hook check",
                '"C:\\Python\\Scripts\\stuntkey.exe" hook check',
                "/usr/bin/python3 -I -m stuntkey hook check")
        for cmd in ours:
            self.assertTrue(hook_mod.is_ours({"type": "command", "command": cmd}), cmd)
        not_ours = ("stuntkey scan", "evil stuntkey hook check",
                    "touch x; stuntkey hook check", "stuntkey hook check; rm -rf ~",
                    "/tmp/evil/run.sh stuntkey hook check", "echo stuntkey hook check",
                    "python3 -m stuntkey hook check", "/x/other hook check")
        for cmd in not_ours:
            self.assertFalse(hook_mod.is_ours({"type": "command", "command": cmd}), cmd)
        self.assertFalse(hook_mod.is_ours({"command": "/opt/bin/stuntkey hook check",
                                           "args": ["--steal"]}))
        self.assertTrue(hook_mod.is_ours({"command": "x", "statusMessage": hook_mod.MARKER}))


class TestTheMatcher(unittest.TestCase):
    def test_powershell_and_monitor_are_covered(self):
        # round 12 added WebFetch|WebSearch|Task|Agent (outbound-key check)
        self.assertEqual(hook_mod.MATCHER, "Read|Grep|Bash|PowerShell|Monitor|Edit|Write|MultiEdit|NotebookEdit|"
                                           "WebFetch|WebSearch|Task|Agent|mcp__.*")
        self.assertTrue(hook_mod.check(call("PowerShell", command="Get-Content .env"))[1])
        self.assertTrue(hook_mod.check(call("PowerShell", command="gc C:\\app\\.env.local"))[1])
        self.assertTrue(hook_mod.check(call("Monitor", command="tail -f .env", timeout_ms=1000))[1])
        self.assertTrue(hook_mod.check(call("Monitor", command="cat prod.env"))[1])
        self.assertEqual(hook_mod.check(call("Monitor", command="tail -f app.log"))[1], "")
        self.assertEqual(hook_mod.check(call("PowerShell", command="ls", description="reads .env"))[1], "")

    def test_glob_lists_names_only_and_is_left_alone(self):
        self.assertEqual(hook_mod.check(call("Glob", file_path="/a/.env", pattern=".env*"))[1], "")


class TestOurOwnGroup(Settings):
    def test_a_shared_group_is_never_edited(self):
        shared = {"matcher": "Bash", "hooks": [
            {"type": "command", "command": "/x/audit.sh", "timeout": 5},
            {"type": "command", "command": "/opt/bin/stuntkey hook check"}]}
        self.put({"hooks": {"PreToolUse": [shared]}})
        self.hook("install")
        groups = self.get()["hooks"]["PreToolUse"]
        self.assertEqual(groups[0]["matcher"], "Bash")          # was rewritten before
        self.assertEqual(groups[0]["hooks"], [shared["hooks"][0]])
        self.assertEqual(groups[1]["matcher"], hook_mod.MATCHER)
        self.assertEqual(len(groups[1]["hooks"]), 1)
        self.hook("uninstall")
        self.assertEqual(self.get()["hooks"]["PreToolUse"], [{"matcher": "Bash", "hooks": [shared["hooks"][0]]}])

    def test_install_twice_with_a_marked_handler_changes_nothing(self):
        self.hook("install")
        with open(self.path, "rb") as f:
            first = f.read()
        self.assertIn("Already installed", self.hook("install")[1])
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), first)

    def test_a_new_install_path_replaces_ours_even_after_a_move(self):
        self.put({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "/old/venv/bin/stuntkey hook check"}]}]}})
        self.hook("install")
        groups = self.get()["hooks"]["PreToolUse"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(self.command_of(groups[0]["hooks"][0]), "/opt/bin/stuntkey hook check")
        self.assertEqual(groups[0]["matcher"], hook_mod.MATCHER)


# -------------------------------------------------------------- hook: 4, Windows

class TestWindowsCommand(unittest.TestCase):
    EXE = "C:\\Users\\Dan B\\AppData\\Python\\Scripts\\stuntkey.exe"

    def windows(self):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(hook_mod, "_ON_WINDOWS", True))
        stack.enter_context(mock.patch.object(hook_mod, "console_script", lambda: self.EXE))
        self.addCleanup(stack.close)

    def test_exec_form_keeps_the_backslash_path_exactly(self):
        self.windows()
        h = hook_mod.hook_handler()
        self.assertEqual(h["command"], self.EXE)
        self.assertEqual(h["args"], ["hook", "check"])
        self.assertTrue(hook_mod.is_ours(h))

    def test_the_older_client_form_uses_forward_slashes_and_quotes(self):
        self.windows()
        h = hook_mod.hook_handler(shell_form=True)
        self.assertNotIn("args", h)
        self.assertEqual(h["command"],
                         '"C:/Users/Dan B/AppData/Python/Scripts/stuntkey.exe" hook check')
        self.assertNotIn("\\", h["command"])
        self.assertTrue(hook_mod.is_ours(h))

    def test_posix_stays_a_shell_string(self):
        with mock.patch.object(hook_mod, "_ON_WINDOWS", False), \
                mock.patch.object(hook_mod, "console_script", lambda: "/opt/my tools/stuntkey"):
            h = hook_mod.hook_handler()
        self.assertEqual(h["command"], "'/opt/my tools/stuntkey' hook check")
        self.assertNotIn("args", h)

    def test_the_self_test_starts_exec_form_like_claude_code_does(self):
        self.windows()
        seen = []
        hook_mod.self_test(hook_mod.hook_handler(), lambda argv, **kw: seen.append((argv, kw)) or ok_run(argv))
        self.assertEqual(seen[0][0], [self.EXE, "hook", "check"])
        self.assertIs(seen[0][1]["shell"], False)

    def test_a_program_in_the_current_folder_is_never_the_hook_command(self):
        here = _isolation.mktemp()
        name = "stuntkey.exe" if os.name == "nt" else "stuntkey"
        planted = os.path.join(here, name)
        with open(planted, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(planted, 0o755)
        old = os.getcwd()
        os.chdir(here)
        self.addCleanup(os.chdir, old)
        with mock.patch("shutil.which", lambda _n: planted), \
                mock.patch.object(sys, "executable", os.path.join(_isolation.mktemp(), "python")), \
                mock.patch("sysconfig.get_path", lambda _n: _isolation.mktemp()):
            self.assertIsNone(hook_mod.console_script())

    @unittest.skipUnless(hasattr(os, "symlink") and os.name == "posix", "needs a symlink")
    def test_the_same_folder_by_another_name_is_still_the_current_folder(self):
        # macOS: the temp folder is /var/..., getcwd() says /private/var/...
        real = _isolation.mktemp()
        alias = os.path.join(_isolation.mktemp(), "alias")
        os.symlink(real, alias)
        planted = os.path.join(real, "stuntkey")
        with open(planted, "w") as f:
            f.write("#!/bin/sh\n")
        os.chmod(planted, 0o755)
        old = os.getcwd()
        os.chdir(real)
        self.addCleanup(os.chdir, old)
        spelled_otherwise = os.path.join(alias, "stuntkey")
        with mock.patch("shutil.which", lambda _n: spelled_otherwise), \
                mock.patch.object(sys, "executable", os.path.join(_isolation.mktemp(), "python")), \
                mock.patch("sysconfig.get_path", lambda _n: _isolation.mktemp()):
            self.assertIsNone(hook_mod.console_script())

    def test_fail_closed_is_the_default(self):
        self.assertEqual(hook_mod.hook_handler()["onFailure"], "block")
        self.assertNotIn("onFailure", hook_mod.hook_handler(fail_closed=False))


# ------------------------------------------------------------ hook: 9, oversize

class TestBigAndBrokenInput(unittest.TestCase):
    def run_check(self, text):
        out, err = io.StringIO(), io.StringIO()
        code = hook_mod.cmd_check(stdin=io.StringIO(text), out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def test_a_payload_over_a_megabyte_is_still_checked(self):
        text = call("Bash", command="echo " + "a" * 1_200_000 + "; cat .env")
        self.assertGreater(len(text), M)
        code, out, _ = self.run_check(text)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_an_innocent_big_payload_passes(self):
        # a big write (its content is not scanned) is fine ...
        self.assertEqual(self.run_check(call("Write", file_path="/a/b.txt",
                                             content="a" * 1_200_000))[:2], (0, ""))

    def test_a_huge_shell_command_is_refused_unread(self):
        # ... but a shell command too long to check safely is refused, not waved through
        code, out, _ = self.run_check(call("Bash", command="echo " + "a" * 1_200_000))
        self.assertEqual(code, 0)
        self.assertIn("deny", out)

    def test_text_that_is_not_json_is_searched_for_env_names(self):
        code, out, _ = self.run_check('{"tool_name": "Bash", "tool_input": {"command": "cat .env"')
        self.assertEqual(code, 0)
        self.assertIn("deny", out)
        code, out, err = self.run_check('{"tool_name": "Bash", "tool_in')
        self.assertEqual((code, out), (1, ""))
        self.assertIn("nothing was blocked", err)

    def test_json_escapes_do_not_hide_the_name_in_the_text_search(self):
        for cut in ('{"tool_input": {"command": "cat\\t.env"', '{"a": "x\\ncat .env',
                    '{"tool_input": {"file_path": "C:\\\\app\\\\.env"'):
            self.assertIn("deny", self.run_check(cut)[1], cut)

    def test_deeply_nested_json_does_not_crash_the_hook(self):
        self.assertEqual(self.run_check("[" * 200000 + "cat .env")[0], 0)
        self.assertEqual(self.run_check("[" * 200000)[0], 1)

    def test_non_utf8_bytes_do_not_crash_it(self):
        class Raw:
            buffer = io.BytesIO(call("Bash", command="cat .env").encode().replace(b"cat", b"c\xffat"))
        out = io.StringIO()
        self.assertEqual(hook_mod.cmd_check(stdin=Raw(), out=out, err=io.StringIO()), 0)
        self.assertIn("deny", out.getvalue())

    def test_the_hook_program_end_to_end_with_a_big_payload(self):
        text = call("Bash", command="echo " + "a" * 1_500_000 + "; cat .env")
        code = ("import sys; sys.path.insert(0, %r); from stuntkey.cli import main; "
                "sys.exit(main(['hook', 'check']))" % _isolation.REPO)
        done = subprocess.run([sys.executable, "-c", code], input=text.encode(),
                              capture_output=True, timeout=60, cwd=_isolation.mktemp())
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(b"deny", done.stdout)


# ------------------------------------------------------------- hook: 10, files

class TestSettingsFileHandling(Settings):
    def test_a_symbolic_link_stays_a_link(self):
        real_dir = _isolation.mktemp()
        real = os.path.join(real_dir, "settings.json")
        with open(real, "w") as f:
            json.dump({"model": "opus"}, f)
        os.makedirs(os.path.dirname(self.path))
        try:
            os.symlink(real, self.path)
        except (OSError, NotImplementedError):
            self.skipTest("no symbolic links here")
        self.hook("install")
        self.assertTrue(os.path.islink(self.path))
        with open(real) as f:
            data = json.load(f)
        self.assertEqual(data["model"], "opus")
        self.assertIn("PreToolUse", data["hooks"])
        self.hook("uninstall")
        self.assertTrue(os.path.islink(self.path))
        with open(real) as f:
            self.assertEqual(json.load(f), {"model": "opus"})

    def test_every_change_gets_its_own_backup_and_none_in_the_project(self):
        _isolation.rmtree(hook_mod.backup_dir())
        self.put({"model": "opus"})
        for _ in range(3):
            self.hook("install", "--fail-closed")
            self.hook("uninstall")
        self.assertEqual(len(os.listdir(hook_mod.backup_dir())), 6)   # one per change
        self.assertEqual(os.listdir(os.path.dirname(self.path)), ["settings.json"])

    def test_old_backups_are_pruned(self):
        _isolation.rmtree(hook_mod.backup_dir())
        self.put({"model": "opus"})
        with mock.patch.object(hook_mod, "BACKUPS_TO_KEEP", 3):
            for _ in range(5):
                self.hook("install", "--fail-closed")
                self.hook("uninstall")
        self.assertEqual(len(os.listdir(hook_mod.backup_dir())), 3)

    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_backups_are_private(self):
        self.put({"model": "opus"})
        self.hook("install")
        for name in os.listdir(hook_mod.backup_dir()):
            mode = stat.S_IMODE(os.stat(os.path.join(hook_mod.backup_dir(), name)).st_mode)
            self.assertEqual(mode & 0o077, 0)

    def test_project_install_says_where_backups_go(self):
        old = os.getcwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, old)
        args = cli_mod._build_parser().parse_args(["hook", "install", "--project"])
        out = io.StringIO()
        hook_mod.cmd_hook(args, out=out, err=io.StringIO(), run=ok_run)
        self.assertIn("outside the project", out.getvalue())


class TestVersionAndDocs(unittest.TestCase):
    def test_release_workflow_guards(self):
        path = os.path.join(_isolation.REPO, ".github", "workflows", "release.yml")
        if not os.path.exists(path):
            self.skipTest("the sdist does not carry .github")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        for needle in ("fetch-depth: 0", "timeout-minutes", "merge-base --is-ancestor",
                       "origin/main", "needs: [test, build]", "unittest discover", "twine check --strict"):
            self.assertIn(needle, text, needle)


if __name__ == "__main__":
    unittest.main()
