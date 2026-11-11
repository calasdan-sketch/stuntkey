import contextlib
import io
import json
import multiprocessing
import os
import tempfile
import unittest

import _isolation  # noqa: F401  (fake HOME for the whole run)
from stuntkey import cli, mcp, recipes, scrub
import leakbench.report

K = "Zq8vN3mX7pL2wR5tY9uB"          # a stored key in no known format (temp file only)


def _remember(args):
    path, worker = args
    for i in range(5):
        scrub.remember_key(f"svc/W{worker}_{i}", f"key-{worker}-{i}-" + "x" * 20, path)


class GluedStoredKey(unittest.TestCase):
    def setUp(self):
        self.fp = os.path.join(tempfile.mkdtemp(), "fingerprints.json")
        scrub.remember_key("svc/K", K, self.fp)
        self.prints = scrub.load_fingerprints(self.fp)

    def test_every_copy_masked(self):
        for text in (f"{K}=bot{K}/x", f"pre{K}={K}", f"x/{K}:{K}",
                     f"{K}:https://a/bot{K}/getMe", f"u=https://h/{K}/a?t={K}"):
            out, n = scrub.mask_secrets(text, self.prints)
            self.assertNotIn(K, out, text)
            self.assertGreaterEqual(n, 1)
        self.assertTrue(scrub.has_stored_key(f"x/{K}:{K}", self.prints))


class ConcurrentRemember(unittest.TestCase):
    def test_six_processes_lose_nothing(self):
        fp = os.path.join(tempfile.mkdtemp(), "fingerprints.json")
        with multiprocessing.Pool(6) as pool:
            pool.map(_remember, [(fp, w) for w in range(6)])
        names = scrub._read_fingerprints(fp)["keys"]
        self.assertEqual(len(names), 30)



def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = cli._main(list(argv))
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue(), err.getvalue()


class CliText(unittest.TestCase):
    def test_bare_command_prints_steps(self):
        rc, out, _ = run_cli()
        self.assertEqual(rc, 0)
        for word in ("stuntkey get", "stuntkey fix", "stuntkey status", "ask it",
                     "Close and reopen your AI app", "stuntkey help"):   # r13: three-step journey
            self.assertIn(word, out)

    def test_typo_gets_did_you_mean(self):
        rc, _, err = run_cli("instal")
        self.assertEqual(rc, 2)
        self.assertIn("Did you mean: stuntkey install", err)

    def test_install_help(self):
        rc, out, _ = run_cli("install", "--help")
        flat = " ".join(out.split())
        self.assertIn("Run this in your project folder. claude-code and vscode are set up for "
                      "this folder only (.mcp.json, .vscode/mcp.json)", flat)
        self.assertIn("Do not ask (for scripts)", flat)
        self.assertIn("Run it in your project folder.", " ".join(run_cli("start", "--help")[1].split()))

    def test_unknown_install_target_points_at_setup_agent(self):
        rc, out, _ = run_cli("install", "codex", "--yes")
        self.assertEqual(rc, 2)
        self.assertIn("stuntkey setup-agent codex", out)

    def test_get_store_help_names_the_real_default(self):
        flat = " ".join(run_cli("get", "--help")[1].split())
        self.assertIn("keychain (default for get)", flat)


class ToolListTexts(unittest.TestCase):
    def test_short_descriptions_back_and_under_cap(self):
        tools = mcp._tool_defs()
        self.assertLessEqual(len(json.dumps(tools)), 3_000)
        by = {t["name"]: t["inputSchema"]["properties"] for t in tools}
        self.assertIn("10-180", by["capture_key"]["timeout_seconds"]["description"])
        self.assertIn("max 45", by["capture_key"]["wait_seconds"]["description"])
        self.assertEqual(by["find_public_apis"]["auth"]["enum"], ["No", "apiKey", "OAuth"])
        self.assertIn("default current", by["needs_keys"]["project"]["description"])


class LeakbenchFooter(unittest.TestCase):
    def test_footer(self):
        self.assertIn("Bash output only; PowerShell and Monitor output is not masked",
                      leakbench.report.to_table([], "x"))


if __name__ == "__main__":
    unittest.main()
