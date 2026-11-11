"""0.5.0: `stuntkey scan` - keys that leaked into files an AI agent reads.

Every key below is made up (built from pieces so the test file itself holds
no key-shaped text). No test touches the network: a guard makes any socket
connection fail the test.
"""

import contextlib
import io
import json
import os
import socket
import stat
import sys
import threading
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import __version__
from stuntkey import cli as cli_mod
from stuntkey import recipes as recipes_mod
from stuntkey import scan as scan_mod
from stuntkey import validate as validate_mod

CATALOG = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)

OPENAI = "sk-" + "proj-Ab3dEf9Gh2Jk5Lm8Np1Qr4St7Uv0Wx"
ANTHROPIC = "sk-ant-" + "api03-Zx9Cv8Bn7Mq6Wl5Ke4Jr3Ht2Gf1"
OPENROUTER = "sk-or-" + "v1-9f8e7d6c5b4a39281706f5e4d3c2b1a0"
STRIPE = "sk_" + "live_51Hq8Zk2LmNp4Rt6Vw9Yb3Dc"
GITHUB = "gh" + "p_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"[:36]
AWS = "AK" + "IA" + "Q7WXV3TLPM2N4BHD"
SLACK = "xo" + "xb-8301947265-QmZkWvTnRb41"
GOOGLE = "AI" + "za" + "SyB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z"
SHOPIFY = "shp" + "at_" + "a1b2c3d4e5f60718293a4b5c6d7e8f90"
NOTION = "nt" + "n_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
GENERIC = "Xk39dLq82mZpR71vBn04TgYw5HcJe6UaS"
ALL_KEYS = (OPENAI, ANTHROPIC, OPENROUTER, STRIPE, GITHUB, AWS, SLACK, GOOGLE,
            SHOPIFY, NOTION, GENERIC)


def write(root, rel, text="", mode="w"):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as f:
        f.write(text)
    return path


def scan_text(text, name="x.md", catalog=CATALOG):
    return scan_mod.scan_text(text, name, scan_mod.build_rules(catalog), catalog)


def run_cli(*argv, **kw):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli_mod.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


def args_for(*argv):
    return cli_mod._build_parser().parse_args(["scan", *argv])


class NoNetwork(unittest.TestCase):
    """Any attempt to open a connection fails the test."""

    def setUp(self):
        def boom(*a, **k):
            raise AssertionError("network used in a test")
        for target in ("connect", "connect_ex"):
            p = mock.patch.object(socket.socket, target, boom)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(socket, "getaddrinfo", boom)
        p.start()
        self.addCleanup(p.stop)
        self.root = _isolation.mktemp()


class TestDetection(NoNetwork):
    def one(self, text, **kw):
        found = scan_text(text, **kw)
        self.assertEqual(len(found), 1, found)
        return found[0]

    def test_openai_key(self):
        f = self.one(f"OPENAI_API_KEY={OPENAI}\n")
        self.assertEqual((f.provider, f.line), ("openai", 1))

    def test_anthropic_is_not_mistaken_for_openai(self):
        self.assertEqual(self.one(f"key {ANTHROPIC}").provider, "anthropic")

    def test_openrouter_is_not_mistaken_for_openai(self):
        self.assertEqual(self.one(f"key {OPENROUTER}").provider, "openrouter")

    def test_stripe_github_aws(self):
        self.assertEqual(self.one(f"x={STRIPE}").provider, "stripe")
        self.assertEqual(self.one(f"x={GITHUB}").provider, "github")
        self.assertEqual(self.one(f"x={AWS}").provider, "aws")

    def test_well_known_prefixes_without_a_recipe(self):
        for key, name in ((SLACK, "Slack"), (SHOPIFY, "Shopify")):
            f = self.one(f"token: {key}")
            self.assertIsNone(f.provider)
            self.assertIn(name, f.provider_name)
            self.assertEqual(f.confidence, "known")

    def test_google_key_is_found_but_cannot_be_proven(self):
        f = self.one(f"k={GOOGLE}")
        self.assertFalse(f.can_validate)

    def test_a_guessed_format_says_so(self):
        f = self.one(f"NOTION={NOTION}")
        self.assertEqual(f.confidence, "guess")
        self.assertIn("guess", scan_mod.render_text(scan_mod.ScanResult(
            "/r", 1, [f], [])))

    def test_private_key_block(self):
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
        f = self.one(f"-----BEGIN PRIVATE KEY-----\n{body}\n")
        self.assertEqual(f.rule, "private-key-block")
        self.assertEqual(f.redacted, "(private key)")
        self.assertEqual(scan_text("-----BEGIN PRIVATE KEY-----\n"), [])

    def test_name_ending_in_token_with_a_random_value(self):
        f = self.one(f"MY_SERVICE_TOKEN={GENERIC}")
        self.assertIsNone(f.provider)
        self.assertEqual(f.rule, "named-assignment")

    def test_name_decides_the_provider(self):
        f = self.one(f"TWILIO_AUTH_TOKEN={GENERIC}")
        self.assertEqual(f.provider, "twilio")
        f = self.one(f"AWS_SECRET_ACCESS_KEY={GENERIC}")
        self.assertEqual(f.provider, "aws")

    def test_json_and_yaml_assignments(self):
        self.assertEqual(len(scan_text(f'{{"clientSecret": "{GENERIC}"}}')), 1)
        self.assertEqual(len(scan_text(f"api_key: {GENERIC}")), 1)
        self.assertEqual(len(scan_text(f"export APP_SECRET='{GENERIC}'")), 1)

    def test_placeholders_are_ignored(self):
        for value in ("your_key_here_please_replace", "xxxxxxxxxxxxxxxxxxxxxxxx",
                      "<your-api-token-goes-here>", "sk-example-1234567890abcdef",
                      "changeme_changeme_changeme", "${OPENAI_API_KEY}_value_0",
                      "000000000000000000000000", "REPLACE_WITH_REAL_TOKEN_9",
                      "sk-" + "x" * 30, "sk-...", "dummy-token-for-tests-12345"):
            self.assertEqual(scan_text(f"API_KEY={value}\nsee {value}\n"), [], value)

    def test_a_key_printed_in_the_vendors_docs_is_ignored(self):
        self.assertEqual(scan_text("STRIPE_SECRET_KEY=sk_" "test_4eC39HqLyjWDarjtT1zdp7dc"), [])

    def test_public_keys_and_ordinary_values_are_ignored(self):
        for text in (f"NEXT_PUBLIC_API_KEY={GENERIC}", f"STRIPE_PUBLISHABLE_KEY={GENERIC}",
                     "SORT_KEY=created_at_descending_order", "API_KEY=short",
                     "TOKEN_URL=https://auth.example.org/oauth/token_endpoint",
                     "CONFIG_KEY=/etc/some/long/path/to/a/file.json",
                     "SECRET_HOST=db-primary.internal.example.org",
                     "KEY=aaaaaaaabbbbbbbbccccccccdddddddd"):
            self.assertEqual(scan_text(text), [], text)

    def test_a_reference_to_a_key_is_not_a_key(self):
        for text in ("clientSecret: process.env.AUTH0_CLIENT_SECRET,",
                     "client_secret = var.client_secret_value_here",
                     "API_TOKEN=AUTH0_CLIENT_SECRET_VALUE_NAME",
                     "const fileKey = 'kL9xQ2mP7vR4tY8wZ3nB6cD1'",
                     "FILE_KEY=kL9xQ2mP7vR4tY8wZ3nB6cD1"):
            self.assertEqual(scan_text(text), [], text)

    def test_package_files_are_not_keys(self):
        self.assertEqual(scan_text('{ name = "hf_xet-1.2.0-cp37-abi3-manylinux.whl" }'), [])

    def test_a_token_in_a_jwt_shape_is_still_found(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.Zm9vYmFyYmF6cXV4MTIz"
        self.assertEqual(len(scan_text(f"AUTH_TOKEN={jwt}")), 1)

    def test_sk_words_in_prose_are_not_keys(self):
        self.assertEqual(scan_text("use sk-learn-extension-pipeline for it"), [])
        self.assertEqual(scan_text("the task-manager-extension-name-here"), [])

    def test_line_and_column(self):
        f = self.one(f"first\nsecond\nAPI={OPENAI}\n")
        self.assertEqual((f.line, f.column), (3, 5))

    def test_two_keys_on_one_line(self):
        self.assertEqual(len(scan_text(f"{OPENAI} {ANTHROPIC}")), 2)

    def test_a_very_long_line_is_scanned_in_pieces_not_hung_or_dropped(self):
        found = scan_text("a" * 500000 + f" {OPENAI}")
        self.assertEqual([f.provider for f in found], ["openai"])


class TestRedaction(NoNetwork):
    def test_first_four_and_last_two(self):
        self.assertEqual(scan_mod.redact(OPENAI), OPENAI[:4] + "..." + OPENAI[-2:])

    def test_short_values_show_less(self):
        self.assertEqual(scan_mod.redact("abcdefgh"), "ab...")

    def test_no_output_ever_holds_a_whole_key(self):
        write(self.root, ".env", "\n".join(
            f"K{i}_TOKEN={k}" for i, k in enumerate(ALL_KEYS)) + "\n")
        for flag in ([], ["--json"], ["--sarif"]):
            code, out, err = run_cli("scan", self.root, *flag)
            self.assertEqual(code, 1)
            for key in ALL_KEYS:
                self.assertNotIn(key, out + err)
                self.assertNotIn(key[4:-2], out + err)
        result = scan_mod.scan_path(self.root, CATALOG)
        for f in result.findings:
            for key in ALL_KEYS:
                self.assertNotIn(key, repr(f))
                self.assertNotIn(key, f.next_step)

    def test_json_never_lists_the_value_field(self):
        write(self.root, ".env", f"OPENAI_API_KEY={OPENAI}\n")
        data = json.loads(run_cli("scan", self.root, "--json")[1])
        self.assertNotIn("_value", json.dumps(data))


# made up, and in pieces so this file holds no key-shaped text of its own
BARE_HEX = "a3f9c1d2e4b5a697" + "8f0e1d2c3b4a5968" + "7766554433221100" + "ffeeddccbbaa9988"


class TestBareToken(NoNetwork):
    """A credential alone on a line, matching no vendor format and with no
    NAME= beside it. Found silently passed over in 0.9.0: a live 64-character
    bearer token in a file named `.token` gave `findings: 0` and the human
    report said "No keys found in files an AI agent can read."."""

    def test_a_dot_token_file_of_64_hex_characters_is_found(self):
        write(self.root, ".token", BARE_HEX)
        result = scan_mod.scan_path(self.root, CATALOG)
        self.assertEqual([(f.file, f.rule) for f in result.findings],
                         [(".token", "bare-token")])
        self.assertEqual(scan_mod.exit_code(result, "any"), 1)

    def test_the_value_is_still_never_printed(self):
        write(self.root, ".token", BARE_HEX)
        for flag in ([], ["--json"], ["--sarif"]):
            code, out, err = run_cli("scan", self.root, *flag)
            self.assertEqual(code, 1)
            self.assertNotIn(BARE_HEX, out + err)
            self.assertNotIn(BARE_HEX[4:-2], out + err)

    def test_the_format_is_reported_as_a_guess_and_never_sent(self):
        f = scan_text(BARE_HEX + "\n")[0]
        self.assertEqual((f.confidence, f.provider, f.can_validate),
                         ("guess", None, False))
        self.assertTrue(f.skip_reason)

    def test_bare_jwt_and_base64_tokens_are_found(self):
        for value in ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.Zm9vYmFyYmF6cXV4MTIzNA",
                      "aGVsbG9fd29ybGRfdGhpc19pc19hX3NlY3JldDEyMzQ1Ng==",
                      '  "' + BARE_HEX + '",'):
            self.assertEqual(len(scan_text(value + "\n")), 1, value)

    def test_a_line_with_anything_else_on_it_is_not_a_bare_token(self):
        # the other rules own those lines; this one must not double-report
        self.assertEqual([f.rule for f in scan_text(f"API_KEY={GENERIC}\n")],
                         ["named-assignment"])
        self.assertEqual([f.rule for f in scan_text(f"{OPENAI}\n")],
                         ["recipe-pattern"])

    def test_ordinary_lone_lines_are_not_keys(self):
        for text in ("The quick brown fox jumps over the lazy dog, honestly.",
                     "your_key_here_please_replace_me_now", "x" * 30,
                     "db-primary.internal.example.org.uk",
                     "/etc/some/long/path/to/a/file.json",
                     "AUTH0_CLIENT_SECRET_VALUE_NAME_X",
                     "hf_xet-1.2.0-cp37-abi3-manylinux1",
                     "get_password_from_environment_now",
                     "d41d8cd98f00b204e9800998ecf8427ed41d8cd9  archive.tar.gz",
                     '    "integrity": "sha512-aGVsbG9fd29ybGRfdGhpc19pc19hX",'):
            self.assertEqual(scan_text(text + "\n"), [], text)

    def test_a_lone_file_name_is_not_a_key(self):
        # a list of files on a line each (SOURCES.txt, MANIFEST.in, .gitignore)
        # is long and mixed enough to pass for a credential; the extension
        # decides. A real key may hold "/", so "/" alone cannot decide.
        for path in ("tests/test_round10_fixes.py", "stuntkey.egg-info/SOURCES.txt",
                     "src/components/Button/index.module.scss",
                     "build/release/linux-x86_64/libfoo.so",
                     "assets/img/hero-banner-2x.png", "docs/THREAT_MODEL.md",
                     "a/very/long/path/to/some/file.yaml"):
            self.assertEqual(scan_text(path + "\n"), [], path)

    def test_a_key_containing_slashes_is_still_found(self):
        self.assertEqual(
            [f.rule for f in scan_text("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEYX\n")],
            ["bare-token"])

    def test_a_certificate_body_is_not_reported_line_by_line(self):
        body = "aGVsbG9fd29ybGRfdGhpc19pc19hX3NlY3JldDEyMzQ1Ng==\n" * 4
        text = "-----BEGIN CERTIFICATE-----\n" + body + "-----END CERTIFICATE-----\n"
        self.assertEqual(scan_text(text), [])


class TestHonestScope(NoNetwork):
    """A clean result must say what it did not look at."""

    def test_files_passed_over_by_default_are_counted_and_named(self):
        write(self.root, "README.md", "nothing here\n")
        write(self.root, "src/app.py", "print('hi')\n")
        result = scan_mod.scan_path(self.root, CATALOG)
        self.assertEqual(result.not_considered, 2)
        self.assertIn("were NOT looked at", scan_mod.render_text(result))
        self.assertIn("--all", scan_mod.render_text(result))
        self.assertEqual(scan_mod.to_json(result)["files_not_considered"], 2)

    def test_the_headline_count_survives_the_passed_over_note(self):
        # the note must not displace "Found N keys": they are separate lines
        write(self.root, ".token", BARE_HEX)
        write(self.root, "README.md", "nothing here\n")
        text = scan_mod.render_text(scan_mod.scan_path(self.root, CATALOG))
        self.assertIn("Found 1 key an AI agent can read", text)
        self.assertIn("NOT looked at", text)

    def test_with_all_nothing_is_passed_over(self):
        write(self.root, "README.md", "nothing here\n")
        result = scan_mod.scan_path(self.root, CATALOG, everything=True)
        self.assertEqual(result.not_considered, 0)
        self.assertNotIn("were NOT looked at", scan_mod.render_text(result))

    def test_credential_filenames_are_scanned_without_all(self):
        for rel in (".token", ".secret", ".npmrc", ".netrc", ".pypirc",
                    "sub/app.token", ".git-credentials"):
            write(self.root, rel, f"X_API_KEY={GENERIC}\n")
        result = scan_mod.scan_path(self.root, CATALOG)
        self.assertEqual(len(result.findings), 7, result.findings)


class TestWhichFiles(NoNetwork):
    def test_agent_files_are_scanned_and_others_not(self):
        key = f"X_API_KEY={GENERIC}\n"
        for rel in (".env", ".env.local", "pkg/.env.production", "CLAUDE.md",
                    "sub/AGENTS.md", "GEMINI.md", ".cursorrules",
                    ".claude/settings.json", ".claude/commands/deploy.md",
                    ".claude/memory/notes.md", "prod.env"):
            write(self.root, rel, key)
        for rel in ("README.md", "src/app.py", "notes.txt"):
            write(self.root, rel, key)
        result = scan_mod.scan_path(self.root, CATALOG)
        self.assertEqual(
            sorted(f.file for f in result.findings),
            sorted([".env", ".env.local", "pkg/.env.production", "CLAUDE.md",
                    "sub/AGENTS.md", "GEMINI.md", ".cursorrules",
                    ".claude/settings.json", ".claude/commands/deploy.md",
                    ".claude/memory/notes.md", "prod.env"]))

    def test_all_flag_reads_every_text_file(self):
        write(self.root, "src/app.py", f"X_API_KEY={GENERIC}\n")
        self.assertEqual(scan_mod.scan_path(self.root, CATALOG).findings, [])
        self.assertEqual(len(scan_mod.scan_path(self.root, CATALOG, everything=True).findings), 1)

    def test_git_and_node_modules_are_skipped(self):
        write(self.root, ".git/CLAUDE.md", f"X_API_KEY={GENERIC}")
        write(self.root, "node_modules/p/.env", f"X_API_KEY={GENERIC}")
        self.assertEqual(scan_mod.scan_path(self.root, CATALOG, True).findings, [])

    def test_a_file_you_name_is_scanned_whatever_it_is_called(self):
        path = write(self.root, "notes.txt", f"X_API_KEY={GENERIC}\n")
        self.assertEqual(len(scan_mod.scan_path(path, CATALOG).findings), 1)

    def test_missing_path_is_a_usage_error(self):
        code, out, err = run_cli("scan", os.path.join(self.root, "nope"))
        self.assertEqual(code, 2)
        self.assertIn("does not exist", err)

    def test_huge_file_is_skipped_unread(self):
        path = write(self.root, ".env", f"X_API_KEY={GENERIC}\n")
        with open(path, "ab") as f:
            f.write(b"#" * scan_mod.MAX_FILE_BYTES)
        result = scan_mod.scan_path(self.root, CATALOG)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.files_scanned, 0)
        self.assertIn("bigger than 1 MB", result.skipped[0].reason)

    def test_binary_file_is_skipped(self):
        write(self.root, ".env", b"\x00\x01\x02" + GENERIC.encode(), mode="wb")
        result = scan_mod.scan_path(self.root, CATALOG)
        self.assertEqual((result.findings, result.skipped[0].reason), ([], "a binary file"))

    def test_bom_and_bad_bytes_do_not_crash(self):
        write(self.root, ".env", b"\xef\xbb\xbf\xff\xfeAPP_SECRET=" + GENERIC.encode() + b"\n", mode="wb")
        self.assertEqual(len(scan_mod.scan_path(self.root, CATALOG).findings), 1)

    @unittest.skipIf(os.name == "nt", "symbolic links need privileges on Windows")
    def test_link_leaving_the_folder_is_not_followed(self):
        outside = _isolation.mktemp()
        target = write(outside, "secret.txt", f"X_API_KEY={GENERIC}\n")
        os.symlink(target, os.path.join(self.root, ".env"))
        result = scan_mod.scan_path(self.root, CATALOG)
        self.assertEqual(result.findings, [])
        self.assertIn("outside the folder", result.skipped[0].reason)

    @unittest.skipIf(os.name == "nt", "symbolic links need privileges on Windows")
    def test_link_inside_the_folder_counts_once(self):
        real = write(self.root, "CLAUDE.md", f"X_API_KEY={GENERIC}\n")
        os.symlink(real, os.path.join(self.root, "AGENTS.md"))
        self.assertEqual(len(scan_mod.scan_path(self.root, CATALOG).findings), 1)

    @unittest.skipIf(os.name == "nt", "symbolic links need privileges on Windows")
    def test_link_loops_cannot_hang_a_scan(self):
        os.symlink("b.md", os.path.join(self.root, "CLAUDE.md"))
        os.symlink("CLAUDE.md", os.path.join(self.root, "b.md"))
        os.makedirs(os.path.join(self.root, ".claude"))
        os.symlink("..", os.path.join(self.root, ".claude", "loop"))
        result = scan_in_thread(self.root)
        self.assertEqual(result.findings, [])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
    def test_a_named_pipe_is_never_opened(self):
        os.mkfifo(os.path.join(self.root, ".env"))
        result = scan_in_thread(self.root)
        self.assertEqual(result.findings, [])
        self.assertIn("not a regular file", result.skipped[0].reason)

    @unittest.skipUnless(os.path.exists("/dev/zero"), "needs /dev/zero")
    def test_a_device_you_name_is_never_read(self):
        result = scan_in_thread("/dev/zero")
        self.assertEqual(result.findings, [])
        self.assertIn("not a regular file", result.skipped[0].reason)


def scan_in_thread(path, timeout=20):
    """Run a scan; fail (not hang) if it does not finish."""
    box = []
    t = threading.Thread(target=lambda: box.append(scan_mod.scan_path(path, CATALOG)),
                         daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise AssertionError("scan did not finish")
    return box[0]


class TestOutput(NoNetwork):
    def setUp(self):
        super().setUp()
        write(self.root, ".env", f"OPENAI_API_KEY={OPENAI}\nOTHER={SLACK}\n")

    def test_clean_folder_exits_0(self):
        clean = _isolation.mktemp()
        write(clean, ".env", "OPENAI_API_KEY=your_key_here\n")
        code, out, _ = run_cli("scan", clean)
        self.assertEqual(code, 0)
        self.assertIn("No keys found", out)

    def test_findings_exit_1_and_read_in_plain_words(self):
        code, out, _ = run_cli("scan", self.root)
        self.assertEqual(code, 1)
        self.assertIn(".env:1", out)
        self.assertIn("OpenAI", out)
        self.assertIn("not checked", out)
        self.assertIn("stuntkey connect openai", out)
        self.assertIn("https://platform.openai.com/api-keys", out)

    def test_json_fields(self):
        code, out, _ = run_cli("scan", self.root, "--json")
        data = json.loads(out)
        self.assertEqual((code, data["version"], len(data["findings"])), (1, __version__, 2))
        f = data["findings"][0]
        for field in ("file", "line", "provider", "redacted", "status", "next_step"):
            self.assertIn(field, f)
        self.assertEqual(f["status"], "unchecked")

    def test_sarif_has_the_required_fields(self):
        code, out, _ = run_cli("scan", self.root, "--sarif")
        s = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(s["version"], "2.1.0")
        self.assertTrue(s["$schema"].endswith("sarif-2.1.0.json"))
        run = s["runs"][0]
        driver = run["tool"]["driver"]
        self.assertEqual(driver["name"], "stuntkey")
        ids = [r["id"] for r in driver["rules"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(run["results"]), 2)
        for r in run["results"]:
            self.assertIn(r["level"], ("error", "warning", "note", "none"))
            self.assertEqual(driver["rules"][r["ruleIndex"]]["id"], r["ruleId"])
            self.assertTrue(r["message"]["text"])
            loc = r["locations"][0]["physicalLocation"]
            self.assertEqual(loc["artifactLocation"]["uri"], ".env")
            self.assertGreaterEqual(loc["region"]["startLine"], 1)
            self.assertGreaterEqual(loc["region"]["startColumn"], 1)

    def test_sarif_for_a_clean_folder_is_still_valid(self):
        clean = _isolation.mktemp()
        s = json.loads(run_cli("scan", clean, "--sarif")[1])
        self.assertEqual(s["runs"][0]["results"], [])

    def test_json_and_sarif_together_are_a_usage_error(self):
        self.assertEqual(run_cli("scan", self.root, "--json", "--sarif")[0], 2)

    def test_unknown_option_is_exit_2(self):
        self.assertEqual(run_cli("scan", "--nope")[0], 2)

    def test_hostile_file_name_cannot_drive_the_terminal(self):
        if os.name == "nt":
            self.skipTest("file names cannot hold escape characters on Windows")
        write(self.root, "CLAUDE.md\x1b[31m.md", "")
        write(self.root, "x/.claude/a\x1b]0;pwned\x07.md", f"X_API_KEY={GENERIC}\n")
        code, out, _ = run_cli("scan", self.root)
        self.assertNotIn("\x1b", out)

    def test_status_words(self):
        self.assertEqual(scan_mod.STATUS_WORDS["live"], "STILL WORKS")
        self.assertEqual(set(scan_mod.STATUSES), set(scan_mod.STATUS_WORDS))

    def test_next_step_when_dead_never_says_delete_it(self):
        f = scan_text(f"K={OPENAI}")[0]
        f.status = "dead"
        self.assertNotIn("Delete", f.next_step)
        self.assertIn("may not be a OpenAI key", f.next_step)
        self.assertIn("Rotate it", f.next_step)


class FakeValidate:
    """Stands in for validate_key: records what it was given."""

    def __init__(self, answers=None, raises=None, log=None):
        self.calls, self.answers, self.raises, self.log = [], answers or {}, raises, log

    def __call__(self, spec, key, timeout=10.0):
        if self.log is not None:
            self.calls.append((spec["url"], key, self.log.getvalue()))
        else:
            self.calls.append((spec["url"], key))
        if self.raises:
            raise self.raises
        return self.answers.get(key, True)


class TestValidate(NoNetwork):
    def setUp(self):
        super().setUp()
        # (Windows: recipes of your own are not run there - see _isolation)
        stack = contextlib.ExitStack()
        stack.enter_context(_isolation.custom_patterns_allowed())
        self.addCleanup(stack.close)
        write(self.root, ".env", f"OPENAI_API_KEY={OPENAI}\nANTHROPIC_API_KEY={ANTHROPIC}\n")

    def go(self, *argv, fake=None, answer="", interactive=False, catalog=CATALOG, root=None):
        out, err = io.StringIO(), io.StringIO()
        fake = fake or FakeValidate(log=err)
        code = scan_mod.cmd_scan(args_for(root or self.root, *argv), catalog, out=out, err=err,
                                 validate_fn=fake, ask=lambda prompt: answer,
                                 interactive=lambda: interactive)
        return code, out.getvalue(), err.getvalue(), fake

    def test_offline_by_default(self):
        fake = FakeValidate()
        out, err = io.StringIO(), io.StringIO()
        scan_mod.cmd_scan(args_for(self.root), CATALOG, out=out, err=err, validate_fn=fake)
        self.assertEqual(fake.calls, [])

    def test_no_terminal_and_no_yes_sends_nothing(self):
        code, out, err, fake = self.go("--validate")
        # the report is still printed (every key "not checked"); exit by findings
        self.assertEqual((code, fake.calls), (1, []))
        self.assertIn("--yes", err)
        self.assertEqual(out.count("not checked"), 2)

    def test_yes_sends_and_marks_live(self):
        code, out, err, fake = self.go("--validate", "--yes")
        self.assertEqual(code, 1)
        self.assertEqual(sorted(c[1] for c in fake.calls), sorted([OPENAI, ANTHROPIC]))
        self.assertEqual(out.count("STILL WORKS"), 2)

    def test_dead_key(self):
        code, out, _, _ = self.go("--validate", "--yes", "--json",
                                  fake=FakeValidate({OPENAI: False, ANTHROPIC: False}))
        self.assertEqual([f["status"] for f in json.loads(out)["findings"]], ["dead", "dead"])
        self.assertEqual(code, 1)
        text = self.go("--validate", "--yes", fake=FakeValidate({OPENAI: False}))[1]
        self.assertIn("rejected by the service", text)
        self.assertNotIn("no longer works", text)

    def test_the_host_is_printed_before_the_key_is_sent(self):
        code, out, err, fake = self.go("--validate", "--yes")
        for url, key, log_then in fake.calls:
            host = url.split("/")[2]
            self.assertIn(host, log_then)

    def test_interactive_yes(self):
        code, out, err, fake = self.go("--validate", answer="y", interactive=True)
        self.assertEqual(len(fake.calls), 2)

    def test_interactive_no_sends_nothing(self):
        code, out, err, fake = self.go("--validate", answer="", interactive=True)
        self.assertEqual(fake.calls, [])
        self.assertIn("Nothing was sent", err)
        self.assertIn("not checked", out)

    def test_fail_on_live(self):
        self.assertEqual(self.go("--validate", "--yes", "--fail-on", "live")[0], 1)
        dead = FakeValidate({OPENAI: False, ANTHROPIC: False})
        self.assertEqual(self.go("--validate", "--yes", "--fail-on", "live", fake=dead)[0], 0)

    def test_fail_on_live_without_validate_explains(self):
        code, out, err, _ = self.go("--fail-on", "live")
        self.assertEqual(code, 0)
        self.assertIn("--validate", err)

    def test_check_failure_is_unknown_and_quiet_about_the_key(self):
        fake = FakeValidate(raises=validate_mod.ValidationError("network error during validation: down"))
        code, out, err, _ = self.go("--validate", "--yes", fake=fake)
        self.assertIn("could not be checked", out)
        self.assertNotIn(OPENAI, out + err)

    def test_the_same_key_is_sent_once(self):
        write(self.root, "CLAUDE.md", f"OPENAI_API_KEY={OPENAI}\n")
        _, _, _, fake = self.go("--validate", "--yes")
        self.assertEqual([c[1] for c in fake.calls].count(OPENAI), 1)

    def test_two_value_services_are_never_sent(self):
        root = _isolation.mktemp()
        write(root, ".env", f"AWS_ACCESS_KEY_ID={AWS}\n")
        code, out, err, fake = self.go("--validate", "--yes", root=root)
        self.assertEqual(fake.calls, [])
        self.assertIn("second value", out)

    def test_ambiguous_format_is_never_sent(self):
        root = _isolation.mktemp()
        write(root, ".env", f"G={GOOGLE}\n")
        self.assertEqual(self.go("--validate", "--yes", root=root)[3].calls, [])

    def test_service_without_a_recipe_is_never_sent(self):
        root = _isolation.mktemp()
        write(root, ".env", f"S={SLACK}\n")
        self.assertEqual(self.go("--validate", "--yes", root=root)[3].calls, [])

    def _custom(self, key_url, validate_url):
        r = {"service": "acme", "display": "Acme", "key_url": key_url,
             "env_var": "ACME_KEY", "steps": ["Click"],
             "fields": [{"name": "key", "env_var": "ACME_KEY", "pattern": "acme_[A-Za-z0-9]{20,}"}],
             "validate": {"method": "GET", "url": validate_url,
                          "auth": {"type": "bearer"}, "expect": [200]}}
        recipes_mod.validate_recipe(r)
        r["_builtin"] = False
        root = _isolation.mktemp()
        write(root, ".env", "ACME_KEY=acme_Qw3Er5Ty7Ui9Op1As3Df5Gh\n")
        return {"acme": r}, root

    def test_a_check_on_another_domain_is_not_sent_without_a_typed_yes(self):
        catalog, root = self._custom("https://acme.test/keys", "https://collector.example.net/me")
        code, out, err, fake = self.go("--validate", "--yes", answer="y", interactive=True,
                                       catalog=catalog, root=root)
        self.assertEqual(fake.calls, [])
        self.assertIn("DIFFERENT domain", err)
        self.assertIn("could not be checked", out)

    def test_a_check_on_another_domain_can_be_typed_through(self):
        catalog, root = self._custom("https://acme.test/keys", "https://collector.example.net/me")
        code, out, err, fake = self.go("--validate", answer="yes", interactive=True,
                                       catalog=catalog, root=root)
        self.assertEqual(len(fake.calls), 1)

    def test_same_domain_custom_recipe_is_sent(self):
        catalog, root = self._custom("https://acme.test/keys", "https://api.acme.test/me")
        # a recipe of your own always needs a typed y: --yes alone sends nothing
        self.assertEqual(self.go("--validate", "--yes", catalog=catalog, root=root)[3].calls, [])
        self.assertEqual(len(self.go("--validate", "--yes", answer="y", interactive=True,
                                     catalog=catalog, root=root)[3].calls), 1)

    def test_a_non_https_check_is_refused(self):
        catalog, root = self._custom("https://acme.test/keys", "https://api.acme.test/me")
        catalog["acme"]["validate"]["url"] = "http://api.acme.test/me"
        fake = self.go("--validate", "--yes", catalog=catalog, root=root)[3]
        self.assertEqual(fake.calls, [])

    def test_json_mode_keeps_prompts_off_stdout(self):
        code, out, err, fake = self.go("--validate", "--yes", "--json")
        data = json.loads(out)
        self.assertEqual([f["status"] for f in data["findings"]], ["live", "live"])
        self.assertTrue(data["validated"])
        self.assertIn("will send keys", err)

    def test_no_key_found_means_nothing_to_ask(self):
        root = _isolation.mktemp()
        code, out, err, fake = self.go("--validate", root=root)
        self.assertEqual((code, fake.calls), (0, []))


class TestVersionAndHelp(unittest.TestCase):
    def test_version_is_0_7_5_everywhere(self):
        self.assertEqual(__version__, "0.9.4")
        self.assertIn(__version__, run_cli("--version")[1])

    def test_help_leads_with_scan(self):
        code, out, _ = run_cli("--help")
        self.assertIn("scan", out)
        self.assertLess(out.index("scan"), out.index("connect"))
        self.assertIn("hook", out)
