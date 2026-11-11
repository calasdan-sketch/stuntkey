"""MCP configs in `stuntkey scan`, `stuntkey wrap`, and `stuntkey scan --bundle`.

Every config lives in a temp folder passed as home/root: the real ones are
never touched. Keys are made up and built from pieces. No network: a URL
check gets a fake resolver and a fake GET.
"""

import io
import json
import os
import sys
import types
import unittest

import _isolation  # noqa: F401
from stuntkey import bundle as bundle_mod
from stuntkey import keychain as keychain_mod
from stuntkey import mcpwrap
from stuntkey import recipes as recipes_mod
from stuntkey import scan as scan_mod

CATALOG = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
GITHUB = "gh" + "p_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"[:36]
OPENAI = "sk-" + "proj-Ab3dEf9Gh2Jk5Lm8Np1Qr4St7Uv0Wx"
GENERIC = "Xk39dLq82mZpR71vBn04TgYw5HcJe6UaS"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text)
    return path


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class FakeKeychain:
    KeychainError = keychain_mod.KeychainError

    def __init__(self):
        self.saved = {}

    def detect_backend(self):
        return "fake"

    def label(self, _b):
        return "fake keychain"

    def read(self, service, var, _b):
        return self.saved.get((service, var))

    def store(self, service, var, key, _b):
        self.saved[(service, var)] = key
        return "fake"


def args(**kw):
    base = dict(client=None, server=None, all=False, dry_run=False, undo=False, file=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


class McpScan(unittest.TestCase):
    def setUp(self):
        self.home = _isolation.mktemp()
        self.root = _isolation.mktemp()

    def test_finds_keys_in_every_place_and_never_prints_them(self):
        write(os.path.join(self.home, ".cursor", "mcp.json"), json.dumps({"mcpServers": {
            "github": {"command": "npx", "args": ["-y", "server-github"],
                       "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": GITHUB}},
            "remote": {"url": "https://x.example/mcp",
                       "headers": {"Authorization": "Bearer " + GENERIC}},
            "cli": {"command": "tool", "args": ["--api-key", OPENAI]}}}, indent=2))
        write(os.path.join(self.home, ".codex", "config.toml"),
              '[mcp_servers.brave]\ncommand = "npx"\nargs = ["brave"]\n\n'
              f'[mcp_servers.brave.env]\nBRAVE_API_KEY = "{GENERIC}"\n')
        write(os.path.join(self.home, ".config", "zed", "settings.json"),
              '{\n  // my settings\n  "context_servers": {"z": {"command": "z",'
              f' "env": {{"API_TOKEN": "{GENERIC}"}},}},}},\n}}\n')
        result = scan_mod.ScanResult(self.root, 0, [], [])
        mcpwrap.add_to_scan(result, CATALOG, self.root, home=self.home, env={},
                            platform="linux")
        where = sorted((f.file, f.line) for f in result.findings)
        files = {w[0] for w in where}
        self.assertIn("~/.cursor/mcp.json", files)
        if sys.version_info >= (3, 11):
            self.assertIn("~/.codex/config.toml", files)
        self.assertIn("~/.config/zed/settings.json", files)
        self.assertEqual(len([w for w in where if w[0] == "~/.cursor/mcp.json"]), 3)
        text = scan_mod.render_text(result) + json.dumps(scan_mod.to_json(result))
        for key in (GITHUB, OPENAI, GENERIC):
            self.assertNotIn(key, text)
        self.assertIn("stuntkey wrap cursor github", text)

    def test_cli_scan_reads_home_configs_and_no_mcp_skips_them(self):
        from stuntkey import cli as cli_mod
        import contextlib
        write(os.path.join(self.home, ".gemini", "settings.json"), json.dumps(
            {"mcpServers": {"g": {"command": "g", "env": {"OPENAI_API_KEY": OPENAI}}}}))
        old = {k: os.environ.get(k) for k in _isolation.ENV_VARS}
        for k in _isolation.ENV_VARS:
            os.environ[k] = self.home
        try:
            codes = []
            for extra in ([], ["--no-mcp"]):
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    codes.append(cli_mod.main(["scan", self.root, *extra]))
                self.assertNotIn(OPENAI, out.getvalue())
        finally:
            for k, v in old.items():
                os.environ[k] = v
        self.assertEqual(codes, [1, 0])


class Wrap(unittest.TestCase):
    def setUp(self):
        self.home = _isolation.mktemp()
        self.root = _isolation.mktemp()
        self.kc = FakeKeychain()

    def run_wrap(self, answer="y", **kw):
        out = io.StringIO()
        code = mcpwrap.cmd_wrap(args(**kw), recipes_mod.load_recipes(), out=out,
                                ask=lambda _p: answer, keychain=self.kc,
                                home=self.home, root=self.root)
        return code, out.getvalue()

    def test_json_wrap_moves_key_to_keychain_and_undo_restores(self):
        path = write(os.path.join(self.home, ".cursor", "mcp.json"), json.dumps({
            "mcpServers": {"gh": {"command": "npx", "args": ["-y", "server-github"],
                                  "env": {"GITHUB_TOKEN": GITHUB, "LOG": "debug"}},
                           "other": {"command": "x"}}}, indent=2))
        before = read(path)
        code, out = self.run_wrap(client="cursor", server="gh", dry_run=True)
        self.assertEqual(code, 0)
        self.assertEqual(read(path), before)            # dry run: unchanged
        self.assertNotIn(GITHUB, out)
        self.assertIn("GITHUB_TOKEN", out)
        code, out = self.run_wrap(client="cursor", server="gh")
        self.assertEqual(code, 0, out)
        self.assertNotIn(GITHUB, out)
        self.assertEqual(self.kc.saved[("github", "GITHUB_TOKEN")], GITHUB)
        entry = json.loads(read(path))["mcpServers"]["gh"]
        self.assertNotIn(GITHUB, read(path))
        self.assertEqual(entry["env"], {"LOG": "debug"})
        i = entry["args"].index("run")
        self.assertEqual(entry["args"][i - 2:i + 3], ["-m", "stuntkey", "run", "github", "--"])
        self.assertEqual(entry["args"][i + 3:], ["npx", "-y", "server-github"])
        self.assertEqual(json.loads(read(path))["mcpServers"]["other"], {"command": "x"})
        backups = os.listdir(mcpwrap.backup_dir())
        self.assertTrue(any(b.endswith(".bak") for b in backups))
        code, _ = self.run_wrap(client="cursor", server="gh")
        self.assertEqual(code, 1)                       # already wrapped
        code, out = self.run_wrap(client="cursor", undo=True)
        self.assertEqual(code, 0, out)
        self.assertNotIn(GITHUB, out)
        self.assertEqual(read(path), before)

    def test_unknown_service_gets_an_unverified_recipe_run_can_use(self):
        write(os.path.join(self.root, ".mcp.json"), json.dumps({"mcpServers": {
            "My Tool": {"command": "tool", "env": {"TOOL_API_KEY": GENERIC}}}}))
        # round 14: the person says yes at a terminal, so the new recipe is approved; this
        # test plays that person (no real terminal here)
        from unittest import mock
        with mock.patch("stuntkey.recipetrust._refusal", return_value=None):
            code, out = self.run_wrap(client="claude-code", server="My Tool")
        self.assertEqual(code, 0, out)
        catalog = recipes_mod.load_recipes()
        recipe = catalog["mcp-my-tool"]
        self.assertEqual(recipes_mod.env_vars(recipe), ["TOOL_API_KEY"])
        self.assertTrue(recipe["unverified"])
        self.assertTrue(recipe["validate"]["url"].endswith(".invalid/"))
        self.assertEqual(self.kc.saved[("mcp-my-tool", "TOOL_API_KEY")], GENERIC)
        got = keychain_mod.gather(recipe, "fake", lambda s, v, b: self.kc.saved.get((s, v)))
        self.assertEqual(got, {"TOOL_API_KEY": GENERIC})

    def test_no_answer_changes_nothing(self):
        path = write(os.path.join(self.home, ".cursor", "mcp.json"), json.dumps(
            {"mcpServers": {"gh": {"command": "npx", "env": {"GITHUB_TOKEN": GITHUB}}}}))
        before = read(path)
        code, _ = self.run_wrap(answer="n", client="cursor", server="gh")
        self.assertEqual((code, read(path), self.kc.saved), (1, before, {}))

    def test_jsonc_and_header_keys_are_not_rewritten(self):
        write(os.path.join(self.home, ".cursor", "mcp.json"), json.dumps(
            {"mcpServers": {"r": {"url": "https://x.example",
                                  "headers": {"Authorization": "Bearer " + GENERIC}}}}))
        code, out = self.run_wrap(client="cursor", server="r")
        self.assertEqual(code, 1)
        self.assertIn("no command", out)

    @unittest.skipIf(sys.version_info < (3, 11), "TOML needs tomllib")
    def test_toml_edit_touches_only_the_target_table(self):
        text = ('# my codex config\nmodel = "o3"\n\n'
                '[mcp_servers.brave]\ncommand = "npx"\nargs = [\n  "-y",\n  "brave",\n]\n'
                'startup_timeout_sec = 20\n\n'
                f'[mcp_servers.brave.env]\nBRAVE_API_KEY = "{GENERIC}"\nKEEP = "1"\n\n'
                f'[mcp_servers.other]\ncommand = "o"\nenv = {{ TOKEN = "{OPENAI}" }}\n')
        path = write(os.path.join(self.home, ".codex", "config.toml"), text)
        code, out = self.run_wrap(client="codex", server="brave")
        self.assertEqual(code, 0, out)
        new = read(path)
        import tomllib
        data = tomllib.loads(new)
        brave = data["mcp_servers"]["brave"]
        self.assertEqual(brave["env"], {"KEEP": "1"})
        self.assertEqual(brave["startup_timeout_sec"], 20)
        self.assertEqual(brave["args"][brave["args"].index("--") + 1:], ["npx", "-y", "brave"])
        self.assertEqual(self.kc.saved[("brave-search", "BRAVE_API_KEY")], GENERIC)
        # everything outside the brave table is byte-for-byte the same
        self.assertTrue(new.startswith('# my codex config\nmodel = "o3"\n\n[mcp_servers.brave]\n'))
        self.assertTrue(new.endswith(text[text.index("[mcp_servers.other]"):]))
        # inline env: the remaining value is kept
        code, out = self.run_wrap(client="codex", server="other")
        self.assertEqual(code, 0, out)
        other = tomllib.loads(read(path))["mcp_servers"]["other"]
        self.assertNotIn("env", other)
        self.assertNotIn(OPENAI, read(path))

    def test_all_dry_run_lists_every_server_and_changes_nothing(self):
        p1 = write(os.path.join(self.home, ".cursor", "mcp.json"), json.dumps(
            {"mcpServers": {"a": {"command": "a", "env": {"GITHUB_TOKEN": GITHUB}},
                            "b": {"command": "b", "env": {"X_API_KEY": GENERIC}}}}))
        p2 = write(os.path.join(self.home, ".gemini", "settings.json"), json.dumps(
            {"mcpServers": {"c": {"command": "c", "env": {"OPENAI_API_KEY": OPENAI}}}}))
        before = read(p1), read(p2)
        code, out = self.run_wrap(all=True, dry_run=True)
        self.assertEqual(code, 0)
        self.assertEqual((read(p1), read(p2)), before)
        for name in ("cursor 'a'", "cursor 'b'", "gemini 'c'"):
            self.assertIn(name, out)
        for key in (GITHUB, OPENAI, GENERIC):
            self.assertNotIn(key, out)

    def test_all_wraps_two_servers_in_one_file(self):
        p1 = write(os.path.join(self.home, ".cursor", "mcp.json"), json.dumps(
            {"mcpServers": {"a": {"command": "a", "env": {"GITHUB_TOKEN": GITHUB}},
                            "b": {"command": "b", "env": {"X_API_KEY": GENERIC}}}}))
        code, out = self.run_wrap(all=True)
        self.assertEqual(code, 0, out)
        data = read(p1)
        self.assertNotIn(GITHUB, data)
        self.assertNotIn(GENERIC, data)


class Bundle(unittest.TestCase):
    def test_folder_finds_browser_keys_and_skips_public_ones(self):
        root = _isolation.mktemp()
        write(os.path.join(root, "src", "app.js"), f'const k = "{OPENAI}"')   # source: not shipped
        write(os.path.join(root, "dist", "assets", "index-1.js"),
              f'var e={{VITE_OPENAI:"{GENERIC}",VITE_STRIPE_PUBLISHABLE_KEY:"pk_live_'
              f'{GENERIC}",VITE_API_URL:"https://api.example.com/v1/xyz"}};fetch(x,"{OPENAI}")')
        write(os.path.join(root, "dist", "index.js.map"), '{"sourcesContent":["x"]}')
        result = bundle_mod.scan_bundle(root, CATALOG)
        self.assertEqual(result.kind, "bundle")
        self.assertEqual(sorted(f._value for f in result.findings), sorted([GENERIC, OPENAI]))
        self.assertTrue(all(f.file.startswith("dist/assets/") for f in result.findings))
        text = scan_mod.render_text(result)
        self.assertIn("every visitor", text)
        self.assertNotIn(GENERIC, text)
        self.assertNotIn(OPENAI, text)

    def fake_site(self, pages):
        def get(url, ip, limit):
            self.assertEqual(ip, "93.184.216.34")
            got = pages.get(url)
            if got is None:
                return 404, "", b""
            if isinstance(got, tuple):
                return got
            return 200, "", got.encode()
        return get

    def test_url_fetches_same_site_scripts_only(self):
        pages = {
            "https://app.example.com/": (301, "/home", b""),
            "https://app.example.com/home": '<script src="/a.js"></script>'
                '<script src="https://cdn.other.com/b.js"></script>'
                '<link rel="modulepreload" href="c.js">',
            "https://app.example.com/a.js": f'x="{OPENAI}"',
            "https://app.example.com/c.js": f'NEXT_PUBLIC_SECRET:"{GENERIC}"',
            "https://cdn.other.com/b.js": f'y="{GITHUB}"',
        }
        result = bundle_mod.scan_url("https://app.example.com/", CATALOG,
                                     resolve=lambda h, p: "93.184.216.34",
                                     get=self.fake_site(pages))
        values = sorted(f._value for f in result.findings)
        self.assertEqual(values, sorted([OPENAI, GENERIC]))   # not the CDN one
        self.assertIn("rotate it", result.findings[0].next_step.lower())

    def test_url_refusals(self):
        def private(host, port):
            raise bundle_mod.broker_mod.BrokerError(f"{host} resolves to a private "
                                                    f"or internal address; refused", 5)
        for url, kw in (("http://app.example.com/", {}),
                        ("https://user:pw@app.example.com/", {}),
                        ("https://10.0.0.1/", {"resolve": private}),
                        ("https://intranet.local/", {"resolve": private})):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    bundle_mod.scan_url(url, CATALOG, get=lambda *a: (200, "", b""), **kw)
        # the real resolver refuses a private address too (no network needed)
        with self.assertRaises(ValueError):
            bundle_mod.scan_url("https://127.0.0.1/", CATALOG, get=lambda *a: (200, "", b""))
        pages = {"https://app.example.com/": (302, "https://evil.example.net/", b"")}
        with self.assertRaises(ValueError):
            bundle_mod.scan_url("https://app.example.com/", CATALOG,
                                resolve=lambda h, p: "93.184.216.34",
                                get=self.fake_site(pages))


if __name__ == "__main__":
    unittest.main()
