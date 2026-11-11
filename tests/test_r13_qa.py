"""Round 13 QA: the MCP server's wire behaviour, parsers fed random junk (fixed
seeds, standard library only), the recipe files, the AI-tool config writers."""
import json
import os
import random
import re
import subprocess
import sys
import unittest

import _isolation
from test_r13_e2e import Home, REPO

from stuntkey import connect_import as ci
from stuntkey import recipes as recipes_mod


# ---- MCP over stdio -------------------------------------------------------------

def talk(home, lines, timeout=60):
    """Send raw bytes lines to `stuntkey mcp`, close stdin, return (replies, rc, err)."""
    data = b"".join(l if isinstance(l, bytes) else l.encode("utf-8") for l in lines)
    p = subprocess.run([sys.executable, "-m", "stuntkey", "mcp"], input=data,
                       capture_output=True, cwd=home.dir, env=home.env(),
                       timeout=timeout)
    replies = []
    for raw in p.stdout.split(b"\n"):
        if raw.strip():
            replies.append(json.loads(raw.decode("utf-8")))
    return replies, p.returncode, p.stderr.decode("utf-8", "replace")


def rpc(i, method, params=None):
    msg = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg) + "\n"


class McpWire(unittest.TestCase):
    def setUp(self):
        self.home = Home()

    def test_handshake_list_ping_and_clean_exit_on_stdin_close(self):
        replies, rc, err = talk(self.home, [
            rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "qa", "version": "1"}}),
            '{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
            rpc(2, "tools/list"), rpc(3, "ping")])
        self.assertEqual(rc, 0, err)
        self.assertEqual([r["id"] for r in replies], [1, 2, 3], "a notification gets no reply")
        init = replies[0]["result"]
        self.assertIn("tools", init["capabilities"])
        self.assertTrue(init["serverInfo"]["name"])
        self.assertRegex(init["protocolVersion"], r"^\d{4}-\d\d-\d\d$")
        tools = replies[1]["result"]["tools"]
        self.assertTrue(tools)
        names = [t["name"] for t in tools]
        self.assertEqual(len(names), len(set(names)))
        for t in tools:
            self.assertRegex(t["name"], r"^[a-zA-Z0-9_-]{1,64}$")
            self.assertTrue(t["description"].strip())
            self.assertEqual(t["inputSchema"]["type"], "object")
        self.assertEqual(replies[2]["result"], {})
        for r in replies:
            self.assertEqual(r["jsonrpc"], "2.0")

    def test_server_info_carries_the_package_version(self):
        from stuntkey import __version__
        replies, _rc, _err = talk(self.home, [rpc(1, "initialize", {"protocolVersion": "1999-01-01"})])
        info = replies[0]["result"]
        self.assertEqual(info["serverInfo"].get("version"), __version__)
        self.assertEqual(info["protocolVersion"], "2024-11-05", "an unknown version gets one we speak")

    def test_errors_use_the_standard_codes_and_the_server_keeps_going(self):
        replies, rc, err = talk(self.home, [
            "this is not json\n",
            "[]\n", "42\n", '"hello"\n', "null\n",
            rpc(1, "no/such/method"),
            rpc(2, "tools/call", {"name": 5}),
            rpc(3, "tools/call", {"name": "no_such_tool", "arguments": {}}),
            rpc(4, "tools/call", {"name": "get_recipe", "arguments": []}),
            '{"jsonrpc":"2.0","id":5,"method":"tools/list","params":[1]}\n',
            b"\xff\xfe\x00 not utf8\n",
            rpc(6, "ping")])
        self.assertEqual(rc, 0, err)
        self.assertNotIn("Traceback", err)
        by_id = {r.get("id"): r for r in replies}
        self.assertEqual(by_id[1]["error"]["code"], -32601)
        self.assertEqual(by_id[2]["error"]["code"], -32602)
        self.assertEqual(by_id[3]["error"]["code"], -32602)
        self.assertEqual(by_id[4]["error"]["code"], -32602)
        self.assertEqual(by_id[5]["error"]["code"], -32602)
        self.assertEqual(by_id[6]["result"], {}, "still answering after all that junk")
        parse_errors = [r for r in replies if r.get("error", {}).get("code") == -32700]
        self.assertTrue(parse_errors)
        for r in parse_errors:
            self.assertIsNone(r["id"])

    def test_cancel_and_unknown_notifications_are_silent(self):
        replies, rc, _ = talk(self.home, [
            '{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9}}\n',
            '{"jsonrpc":"2.0","method":"notifications/roots/list_changed"}\n',
            '{"jsonrpc":"2.0","method":"whatever/else"}\n',
            rpc(1, "ping")])
        self.assertEqual(rc, 0)
        self.assertEqual([r["id"] for r in replies], [1])

    def test_string_ids_are_echoed_exactly(self):
        replies, _, _ = talk(self.home, [
            json.dumps({"jsonrpc": "2.0", "id": "abc-é", "method": "ping"}) + "\n",
            json.dumps({"jsonrpc": "2.0", "id": 2.5, "method": "ping"}) + "\n"])
        self.assertEqual(replies[0]["id"], "abc-é")
        self.assertEqual(replies[1]["id"], 2.5)

    def test_crlf_and_blank_lines_are_fine(self):
        replies, rc, _ = talk(self.home, ["\r\n", "\n", rpc(1, "ping").replace("\n", "\r\n"), "   \n"])
        self.assertEqual(rc, 0)
        self.assertEqual([r["id"] for r in replies], [1])

    def test_a_huge_message_is_an_error_not_a_crash(self):
        big = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "get_recipe",
                                     "arguments": {"service": "a" * 6_000_000}}}) + "\n"
        replies, rc, err = talk(self.home, [big, rpc(2, "ping")], timeout=90)
        self.assertEqual(rc, 0, err[-300:])
        self.assertNotIn("Traceback", err)
        self.assertEqual(replies[-1]["id"], 2)
        self.assertEqual(replies[-1]["result"], {})

    def test_deeply_nested_json_is_refused_politely(self):
        deep = "[" * 50000 + "]" * 50000 + "\n"
        replies, rc, err = talk(self.home, [deep, rpc(1, "ping")])
        self.assertEqual(rc, 0, err[-300:])
        self.assertEqual(replies[-1]["id"], 1)

    def test_a_message_without_a_final_newline_is_still_answered(self):
        replies, rc, _ = talk(self.home, [rpc(1, "ping").strip()])
        self.assertEqual(rc, 0)
        self.assertEqual([r["id"] for r in replies], [1])

    def test_tools_never_hand_back_a_saved_key(self):
        fake = "sk-proj-" + "R13mcpFakeKeyBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        envf = self.home.write("k.env", f"OPENAI_API_KEY={fake}\n")
        imp = self.home.sk("import", envf, "--yes")
        self.assertEqual(imp.returncode, 0, imp.stdout + imp.stderr)
        replies, rc, err = talk(self.home, [
            rpc(1, "tools/call", {"name": "list_services", "arguments": {"connected_only": True}}),
            rpc(2, "tools/call", {"name": "get_recipe", "arguments": {"service": "openai"}})])
        blob = json.dumps(replies) + err
        self.assertNotIn(fake, blob)
        self.assertIn("openai", blob)

    def test_second_stdin_closed_case_returns_a_message(self):
        p = subprocess.run([sys.executable, "-m", "stuntkey", "mcp"], stdin=subprocess.DEVNULL,
                           capture_output=True, cwd=self.home.dir, env=self.home.env(),
                           timeout=60)
        self.assertEqual(p.returncode, 0)
        self.assertNotIn(b"Traceback", p.stderr)


# ---- fuzz: parsers (fixed seeds) ------------------------------------------------

ALPHABET = ("abcXYZ019_-=#'\"\\ \t\r\n{}[],:;$`é中​﻿\x00.+/*")


def junk(rng, n):
    return "".join(rng.choice(ALPHABET) for _ in range(n))


class ParserFuzz(unittest.TestCase):
    def test_env_parser_never_crashes_and_never_invents_names(self):
        rng = random.Random(1301)
        for _ in range(1500):
            text = junk(rng, rng.randint(0, 200))
            try:
                pairs = ci.parse_text(text, "env")
            except ci.ImportProblem:
                continue
            for name, value in pairs:
                self.assertRegex(name, r"^[A-Za-z_][A-Za-z0-9_]*$")
                self.assertTrue(value)
                self.assertNotIn("\n", name)
            self.assertEqual(len({n for n, _ in pairs}), len(pairs), "names are unique")

    def test_env_parser_roundtrip_on_clean_lines(self):
        rng = random.Random(1302)
        for _ in range(300):
            want = {}
            for i in range(rng.randint(1, 6)):
                want[f"VAR_{i}"] = "".join(rng.choice("abcdefXYZ0123456789-_") for _ in range(rng.randint(1, 30)))
            text = "\n".join(f"{k}={v}" for k, v in want.items())
            self.assertEqual(dict(ci.parse_text(text, "env")), want)

    def test_env_parser_quote_and_comment_cases(self):
        cases = {'A="x y" # c': {"A": "x y"}, "A='x#y'": {"A": "x#y"},
                 "A=x # c": {"A": "x"}, "A=x#y": {"A": "x#y"},
                 "export A=1\nA=": {}, "# A=1": {}, "A=1\nA=2": {"A": "2"},
                 "A = spaced": {"A": "spaced"}, 'A="unclosed': {"A": '"unclosed'}}
        for text, want in cases.items():
            self.assertEqual(dict(ci.parse_text(text, "env")), want, text)

    def test_json_parser_on_random_structures(self):
        rng = random.Random(1303)

        def rand(depth=0):
            k = rng.randint(0, 6 if depth < 4 else 3)
            if k == 0: return None
            if k == 1: return rng.choice([True, False])
            if k == 2: return rng.randint(-5, 10**12)
            if k == 3: return junk(rng, rng.randint(0, 12))
            if k == 4: return rng.random()
            if k == 5: return [rand(depth + 1) for _ in range(rng.randint(0, 4))]
            return {junk(rng, rng.randint(0, 6)): rand(depth + 1) for _ in range(rng.randint(0, 4))}
        for _ in range(1000):
            text = json.dumps(rand())
            try:
                out = ci.parse_text(text, "json")
            except ci.ImportProblem:
                continue
            for name, value in out:
                self.assertIsInstance(name, str)
                self.assertIsInstance(value, str)

    def test_json_bool_is_not_turned_into_a_key(self):
        # a Doppler-style export with true/false flags must not offer "True" as a secret
        out = ci.parse_text('{"DEBUG": true, "OPENAI_API_KEY": "abc"}', "json")
        self.assertNotIn(("DEBUG", "True"), out)

    def test_doppler_secrets_json_with_computed_values_is_read(self):
        text = json.dumps({"OPENAI_API_KEY": {"computed": "abc123", "raw": "${X}"},
                           "EMPTY": {"computed": ""}, "FLAG": False, "N": None})
        self.assertEqual(ci.parse_text(text, "json"), [("OPENAI_API_KEY", "abc123")])

    def test_real_world_exports_are_read_end_to_end(self):
        catalog = recipes_mod.load_recipes()
        key = "sk-proj-" + "R13importFake" + "A1b2C3d4E5f6G7h8I9j0" * 2
        for kind, text in (
                ("csv", "Title,Url,Username,Password,Notes,Type\nOpenAI,,me,%s,,Login\n" % key),
                ("json", json.dumps({"items": [{"name": "OPENAI_API_KEY", "login": {"password": key}}]})),
                ("env", "export OPENAI_API_KEY='%s' # work\r\nDEBUG=1\r\n" % key)):
            pairs = ci.parse_text(text, kind)
            matched, unknown = ci.match_services(pairs, catalog)
            self.assertEqual([(r["service"], v) for r, _var, v in matched], [("openai", key)], kind)

    def test_csv_parser_on_junk(self):
        rng = random.Random(1304)
        for _ in range(800):
            text = junk(rng, rng.randint(0, 200))
            try:
                ci.parse_text(text, "csv")
            except ci.ImportProblem:
                pass

    def test_deep_and_huge_inputs_are_refused_politely(self):
        for text, kind in (("[" * 100000, "json"), ('{"a":' * 5000 + "1" + "}" * 5000, "json"),
                           ("a" * 3_000_000, "env"), ('"' * 200000, "csv"),
                           ("A=" + " " * 40000 + "\n", "env")):
            try:
                ci.parse_text(text, kind)
            except ci.ImportProblem:
                pass

    def test_decode_text_never_raises(self):
        rng = random.Random(1305)
        for _ in range(500):
            raw = bytes(rng.randrange(256) for _ in range(rng.randint(0, 60)))
            self.assertIsInstance(ci.decode_text(raw), str)
        self.assertEqual(ci.decode_text("A=1".encode("utf-16")), "A=1")
        self.assertEqual(ci.decode_text(b"\xef\xbb\xbfA=1"), "A=1")
        self.assertEqual(ci.decode_text("A=1\n".encode("utf-16-le")), "A=1\n")

    def test_match_services_never_crashes_on_random_names(self):
        rng = random.Random(1306)
        catalog = recipes_mod.load_recipes()
        for _ in range(300):
            pairs = [(junk(rng, rng.randint(1, 12)), junk(rng, rng.randint(1, 20)))
                     for _ in range(rng.randint(0, 6))]
            matched, unknown = ci.match_services(pairs, catalog)
            for recipe, var, _value in matched:
                self.assertIn(var, recipes_mod.env_vars(recipe))


# ---- the recipe files -----------------------------------------------------------

RECIPE_DIR = os.path.join(REPO, "stuntkey", "recipes")


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)


def _is_loopback(url):
    return bool(re.match(r"^http://(127\.0\.0\.1|localhost)(:\d+)?/", url))


class RecipeFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {}
        for name in sorted(os.listdir(RECIPE_DIR)):
            if name.endswith(".json"):
                with open(os.path.join(RECIPE_DIR, name), "rb") as f:
                    cls.files[name[:-5]] = f.read()
        # the packaged recipes only: a recipe another test saved in the user folder
        # must not decide whether the shipped ones are sound
        loaded = recipes_mod.load_recipes()
        cls.catalog = {k: v for k, v in loaded.items() if k in cls.files}

    def test_every_file_is_plain_utf8_json_named_after_its_service(self):
        self.assertGreaterEqual(len(self.files), 35)
        for stem, raw in self.files.items():
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), stem + " has a byte-order mark")
            data = json.loads(raw.decode("utf-8"))
            self.assertEqual(data["service"], stem)
            self.assertIn(stem, self.catalog)

    def test_every_web_address_is_https_unless_it_is_this_computer(self):
        for slug, rec in self.catalog.items():
            for text in _strings(rec):
                for url in re.findall(r"https?://[^\s\"')]+", text):
                    if url.startswith("http://"):
                        self.assertTrue(_is_loopback(url + "/"), (slug, url))
            v = rec.get("validate") or {}
            if "local" in rec:
                continue
            self.assertTrue(v.get("url", "").startswith("https://"), slug)
            self.assertTrue(rec["key_url"].startswith("https://"), slug)
            self.assertTrue(rec["docs"].startswith("https://"), slug)

    def test_validation_is_a_read_not_a_write(self):
        for slug, rec in self.catalog.items():
            v = rec.get("validate") or {}
            if not v:
                continue
            self.assertIn(v["method"], ("GET", "POST"), slug)
            if v["method"] == "POST":
                # only the signed AWS identity check is a POST that changes nothing
                self.assertEqual((v["auth"] or {}).get("type"), "aws_sigv4", slug)
            self.assertTrue(all(isinstance(c, int) and 100 <= c <= 599 for c in v["expect"]), slug)

    def test_a_key_is_never_asked_for_in_the_url_except_documented_query_keys(self):
        for slug, rec in self.catalog.items():
            url = (rec.get("validate") or {}).get("url", "")
            if (rec.get("validate") or {}).get("auth", {}).get("type") != "query":
                self.assertNotRegex(url, r"(?i)[?&](key|api_?key|token|appid|secret)=", slug)

    def test_patterns_compile_and_stay_fast_on_hostile_text(self):
        import time
        hostile = ["a" * 40000, "sk-" + "a-" * 20000, "A" * 40000 + "!", "_" * 40000,
                   "AKIA" + "A" * 40000, ("ab" * 20000) + "\n"]
        for slug, rec in self.catalog.items():
            for f in recipes_mod.fields(rec):
                for k in ("detect", "accept", "pattern", "capture_accept"):
                    pat = f.get(k)
                    if not pat:
                        continue
                    rx = re.compile(pat)
                    for text in hostile:
                        t0 = time.perf_counter()
                        rx.search(text)
                        self.assertLess(time.perf_counter() - t0, 0.5, (slug, k, pat))

    def test_an_example_key_of_each_documented_shape_is_recognised(self):
        examples = {
            "openai": "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0" * 3,
            "anthropic": "sk-ant-api03-" + "A1b2C3d4E5f6G7h8I9j0" * 3,
            "groq": "gsk_" + "A1b2C3d4E5f6G7h8I9j0" * 2,
            "stripe": "sk_live_" + "A1b2C3d4E5f6G7h8I9j0",
            "huggingface": "hf_" + "A1b2C3d4E5f6G7h8I9j0" * 2,
            "openrouter": "sk-or-v1-" + "0123456789abcdef" * 4,
            "replicate": "r8_" + "A" * 37,
        }
        for slug, key in examples.items():
            hit = False
            for f in recipes_mod.fields(self.catalog[slug]):
                pat = f.get("detect") or f.get("accept")
                hit = hit or bool(pat and re.search(pat, key))
            self.assertTrue(hit, slug)

    def test_the_same_variable_name_is_not_stored_by_two_services(self):
        owners = {}
        for slug, rec in self.catalog.items():
            for var in recipes_mod.env_vars(rec):
                owners.setdefault(var, []).append(slug)
        shared = {v: s for v, s in owners.items() if len(s) > 1}
        self.assertEqual(shared, {}, "one name, two services: `run` could hand over the wrong key")

    def test_steps_and_labels_are_plain_readable_text(self):
        for slug, rec in self.catalog.items():
            self.assertTrue(rec["steps"], slug)
            for s in _strings(rec):
                self.assertEqual(recipes_mod.printable(s), s, (slug, s[:40]))
                self.assertNotRegex(s, r"(?i)\b(todo|fixme|xxx|lorem)\b", slug)

    def test_the_basic_and_field_names_an_auth_block_uses_exist(self):
        for slug, rec in self.catalog.items():
            names = {f["name"] for f in recipes_mod.fields(rec)}
            auth = (rec.get("validate") or {}).get("auth") or {}
            for k in ("username_field", "password_field", "field", "client_id_field",
                      "client_secret_field", "access_key_field", "secret_key_field"):
                if auth.get(k):
                    self.assertIn(auth[k], names | {"access_key_id", "secret_access_key",
                                                    "client_id", "client_secret", "key"},
                                  (slug, k))


# ---- AI tool config files ---------------------------------------------------------

class InstallJourney(unittest.TestCase):
    """`stuntkey install` / `uninstall` in a throwaway home: every tool's file is
    valid JSON in that tool's own shape, other servers are kept, a second run
    changes nothing, and uninstall takes out only stuntkey."""

    def test_install_twice_then_uninstall_keeps_other_servers(self):
        home = Home()
        proj = os.path.join(home.dir, "proj")
        home.write("proj/.vscode/mcp.json", json.dumps(
            {"servers": {"other": {"type": "stdio", "command": "x"}}, "inputs": []}))
        home.write("proj/.mcp.json", json.dumps({"mcpServers": {"other": {"command": "y"}}}))
        home.write(".cursor/mcp.json", json.dumps({"mcpServers": {"other": {"url": "https://x"}}}))
        r = home.sk("install", "--yes", "claude-desktop", "cursor", "claude-code", "vscode", cwd=proj)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        files = {
            "proj/.vscode/mcp.json": "servers",
            "proj/.mcp.json": "mcpServers",
            ".cursor/mcp.json": "mcpServers",
            os.path.join("AppData", "Roaming", "Claude", "claude_desktop_config.json"): "mcpServers",
        }
        before = {}
        for rel, top in files.items():
            data = json.load(open(os.path.join(home.dir, rel), encoding="utf-8"))
            entry = data[top]["stuntkey"]
            self.assertTrue(os.path.isabs(entry["command"]), rel)
            self.assertTrue(all(isinstance(a, str) for a in entry["args"]), rel)
            self.assertIn("mcp", entry["args"], rel)
            if rel != os.path.join("AppData", "Roaming", "Claude", "claude_desktop_config.json"):
                self.assertIn("other", data[top], "the other server must stay: " + rel)
            before[rel] = open(os.path.join(home.dir, rel), "rb").read()
        self.assertEqual(json.load(open(os.path.join(proj, ".vscode", "mcp.json")))["inputs"], [])
        again = home.sk("install", "--yes", "cursor", "vscode", "claude-code", cwd=proj)
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        for rel in files:
            self.assertEqual(open(os.path.join(home.dir, rel), "rb").read(), before[rel],
                             "a second install must not change " + rel)
        gone = home.sk("uninstall", "--yes", "--keep-hook", "cursor", "vscode", "claude-code",
                       "claude-desktop", cwd=proj)
        self.assertEqual(gone.returncode, 0, gone.stdout + gone.stderr)
        for rel, top in files.items():
            data = json.load(open(os.path.join(home.dir, rel), encoding="utf-8"))
            self.assertNotIn("stuntkey", data.get(top, {}), rel)
        self.assertIn("other", json.load(open(os.path.join(proj, ".mcp.json")))["mcpServers"])

    def test_uninstall_in_a_script_without_yes_does_not_hang_or_remove(self):
        home = Home()
        proj = os.path.join(home.dir, "proj")
        os.makedirs(proj)
        self.assertEqual(home.sk("install", "--yes", "cursor", cwd=proj).returncode, 0)
        r = home.sk("uninstall", "--keep-hook", "cursor", cwd=proj, timeout=60)
        self.assertNotIn("Traceback", r.stdout + r.stderr)
        data = json.load(open(os.path.join(home.dir, ".cursor", "mcp.json")))
        self.assertIn("stuntkey", data["mcpServers"], "nothing may be removed without a yes")


try:
    import tomllib
except ImportError:              # Python 3.10
    tomllib = None


def _run_setup_agent(client, home, write=True):
    import io
    from types import SimpleNamespace
    from stuntkey import agentsetup
    out = io.StringIO()
    rc = agentsetup.cmd_setup_agent(SimpleNamespace(client=client, write=write), out=out,
                                    home=home, cwd=home, keychain_ok=True)
    return rc, out.getvalue()


@unittest.skipIf(tomllib is None, "needs tomllib (Python 3.11+)")
class CodexToml(unittest.TestCase):
    """Codex reads ~/.codex/config.toml. Whatever was there, what we leave must
    still be valid TOML with exactly one [mcp_servers.stuntkey] table."""

    def written(self, body):
        home = _isolation.mktemp()
        path = os.path.join(home, ".codex", "config.toml")
        os.makedirs(os.path.dirname(path))
        with open(path, "wb") as f:
            f.write(body.encode("utf-8"))
        rc, out = _run_setup_agent("codex", home)
        with open(path, "rb") as f:
            return rc, f.read().decode("utf-8"), home, path

    def test_valid_before_means_valid_after_and_idempotent(self):
        cases = ["", '[mcp_servers.other]\ncommand = "x"\n',
                 '# mine\r\nmodel = "o3"\r\n[mcp_servers.stuntkey]\r\ncommand = "old"\r\n\r\n[other]\r\nx = 1\r\n',
                 '[mcp_servers.stuntkey]\ncommand = "old"\nargs = [\n  "-m",\n]\n[tail]\nz = 1\n',
                 '[mcp_servers.stuntkey]\ncommand = "old"\n[mcp_servers.stuntkey.env]\nA = "1"\n',
                 'model = "o3"']
        for body in cases:
            rc, text, home, path = self.written(body)
            self.assertEqual(rc, 0)
            data = tomllib.loads(text)
            self.assertTrue(os.path.isabs(data["mcp_servers"]["stuntkey"]["command"]))
            _run_setup_agent("codex", home)
            self.assertEqual(open(path, "rb").read().decode("utf-8"), text, "second run changes nothing")
            if "[tail]" in body or "[other]" in body:
                self.assertIn("tail" if "[tail]" in body else "other", data)

    def test_a_command_with_quotes_backslashes_and_accents_is_valid_toml(self):
        from stuntkey import agentsetup
        for cmd in ('C:\\Users\\Dan "D" \u00c7alas\\py thon.exe', "/home/o'brien/\u4e2d/python", "a\tb"):
            text = agentsetup._toml({"command": cmd, "args": ["-m", "x", 'q"uote', "back\\slash"]})
            data = tomllib.loads(text)
            self.assertEqual(data["mcp_servers"]["stuntkey"]["command"], cmd)
            self.assertEqual(data["mcp_servers"]["stuntkey"]["args"][-2:], ['q"uote', "back\\slash"])

    def test_an_unusual_spelling_of_our_own_table_never_corrupts_the_file(self):
        # FIXED by the lead (round 13): agentsetup now checks the result parses as TOML
        # and refuses to write otherwise.
        # A hand-written `[mcp_servers."stuntkey"]` is still a valid table. The writer
        # must either replace it or leave the file alone: never add a second one.
        for body in ('[mcp_servers."stuntkey"]\ncommand = "old"\n',
                     '[ mcp_servers.stuntkey ]\ncommand = "old"\n',
                     'mcp_servers.stuntkey.command = "old"\n',
                     'mcp_servers = { stuntkey = { command = "old" } }\n'):
            rc, text, _home, _path = self.written(body)
            try:
                tomllib.loads(text)
            except tomllib.TOMLDecodeError as e:
                self.fail(f"config.toml is now invalid ({e}) after setup-agent codex --write "
                          f"on {body!r}")


class JsonClientFiles(unittest.TestCase):
    def test_writers_keep_bom_and_line_endings_and_refuse_what_they_cannot_read(self):
        for client, rel in (("gemini", os.path.join(".gemini", "settings.json")),
                            ("cursor", os.path.join(".cursor", "mcp.json"))):
            for body, expect_rc in (("", 0), ("\ufeff{}", 0),
                                    ('{\r\n  "mcpServers": {"x": {"command": "y"}}\r\n}', 0),
                                    ('{\n // a comment\n "mcpServers": {}\n}', 1),
                                    ("[]", 1), ('{"mcpServers": "no"}', 1), ('{"a":1,}', 1)):
                home = _isolation.mktemp()
                path = os.path.join(home, rel)
                os.makedirs(os.path.dirname(path))
                raw = body.encode("utf-8")
                open(path, "wb").write(raw)
                rc, _out = _run_setup_agent(client, home)
                after = open(path, "rb").read()
                self.assertEqual(rc, expect_rc, (client, body))
                if expect_rc:
                    self.assertEqual(after, raw, "an unreadable file is left byte-for-byte alone")
                else:
                    data = json.loads(after.decode("utf-8-sig"))
                    self.assertIn("stuntkey", data["mcpServers"])
                    if body.startswith("\ufeff"):
                        self.assertTrue(after.startswith(b"\xef\xbb\xbf"), "BOM kept")
                    if "\r\n" in body:
                        self.assertNotIn(b"\n", after.replace(b"\r\n", b""), "CRLF kept")
                        self.assertIn("x", data["mcpServers"], "the other server is kept")


# ---- leakbench ------------------------------------------------------------------

from leakbench import harness as lb_harness, loader as lb_loader, profiles as lb_profiles
from leakbench import runner as lb_runner, sandbox as lb_sandbox


class LeakbenchJudge(unittest.TestCase):
    def test_a_disguised_canary_is_a_leak_not_a_pass(self):
        import base64
        for style in lb_sandbox.CANARY_STYLES:
            c = lb_sandbox.new_canary(style)
            shown = {
                "plain": c, "hex": c.encode().hex(), "reversed": c[::-1],
                "spaced": " ".join(c), "wrapped": "\n".join(c[i:i + 4] for i in range(0, len(c), 4)),
            }
            for pad in range(3):
                shown[f"b64+{pad}"] = base64.b64encode(b"x" * pad + c.encode() + b"\ntail=1\n").decode()
            for name, text in shown.items():
                self.assertEqual(lb_runner._judge_output(text, c)[0], "leaked", (style, name))
            self.assertEqual(lb_runner._judge_output("API_KEY=***", c)[0], "masked")
            self.assertEqual(lb_runner._judge_output("nothing here", c)[0], "n/a")

    def test_canary_styles(self):
        a, b = lb_sandbox.new_canary("opaque"), lb_sandbox.new_canary("opaque")
        self.assertNotEqual(a, b)
        self.assertFalse(a.startswith("sk-"), "opaque has no recognisable prefix")
        self.assertTrue(lb_sandbox.new_canary().startswith("sk-canary-"))
        with self.assertRaises(ValueError):
            lb_sandbox.new_canary("nonsense")

    def test_the_sandbox_plants_the_canary_under_a_name_that_says_nothing(self):
        sbx = lb_sandbox.build("opaque")
        try:
            self.assertEqual(sbx.env["LB_PAYLOAD"], sbx.canary)
            self.assertFalse(sbx.canary.startswith("sk-"))
            self.assertNotEqual(os.path.abspath(sbx.home), os.path.abspath(os.path.expanduser("~")))
        finally:
            lb_sandbox.destroy(sbx)


class LeakbenchExtended(unittest.TestCase):
    def test_extended_probes_are_valid_unique_and_separate_from_the_core(self):
        core = lb_loader.load()
        both = lb_loader.load(extended=True)
        self.assertGreater(len(both), len(core))
        core_ids = {p.id for p in core}
        extra = [p for p in both if p.id not in core_ids]
        self.assertGreaterEqual(len(extra), 20)
        self.assertEqual(len({p.id for p in both}), len(both))
        for p in extra:
            self.assertIn(p.check, ("canary_in_output", "write_tamper", "no_guard"))
            self.assertTrue(p.attack.strip() and p.tool["tool_input"])
        self.assertGreaterEqual(len({p.category for p in extra}), 3)

    def test_the_default_run_is_still_the_published_core_set(self):
        self.assertEqual(len(lb_loader.load()), 64)

    def test_no_probe_command_can_touch_anything_outside_its_sandbox(self):
        for p in lb_loader.load(extended=True):
            cmd = json.dumps(p.run) + json.dumps(p.tool)
            for bad in ("rm -rf", "Remove-Item", "format ", "del /", "shutdown", "curl http",
                        "wget ", "Invoke-WebRequest", "~/.ssh", "%USERPROFILE%", "$HOME/"):
                self.assertNotIn(bad, cmd, p.id)

    def test_nothing_gets_blocked_by_the_none_profile_and_no_probe_hangs(self):
        results = lb_harness.run("none", extended=True)
        self.assertGreaterEqual(len(results), 84)
        self.assertEqual([r.probe_id for r in results if r.status == "blocked"], [])

    def test_the_hook_unregistered_profile_exists_and_is_listed(self):
        self.assertIn("stuntkey-hook-unregistered", lb_profiles.AVAILABLE)
        prof = lb_profiles.get("stuntkey-hook-unregistered")
        self.assertTrue(callable(prof))

    # What the hook still lets through, said plainly. These are PINNED so a new
    # leak fails the build; a closed one just shrinks the set (update the README).
    KNOWN_EXTENDED_GAPS_REGISTERED = {
        "runaway-loop-no-cap", "unbounded-retry",                      # the hook cannot count spend
        "disguise-spaced-env-var", "disguise-wrapped-env-var",         # key printed with spaces / cut into lines
    }
    KNOWN_GAPS_UNREGISTERED_OPAQUE = KNOWN_EXTENDED_GAPS_REGISTERED | {
        "disguise-base64-of-env-var", "disguise-hex-of-env-var", "disguise-exception-with-key",
        "disguise-key-as-argument", "echo-key-in-error", "git-log-patch",
        "malicious-mcp-asks-for-key", "read-source-map", "traceback-prints-key",
        "disguise-reversed-env-var",
    }

    def _leaks(self, profile, canary):
        return {r.probe_id for r in lb_harness.run(profile, canary=canary, extended=True)
                if r.status == "leaked"}

    def test_registered_key_leaks_are_only_the_known_ones(self):
        new = self._leaks("stuntkey-hook", "prefixed") - self.KNOWN_EXTENDED_GAPS_REGISTERED
        self.assertEqual(new, set(), f"new leak(s) with a key stuntkey knows: {sorted(new)}")

    def test_unknown_key_leaks_are_only_the_known_ones(self):
        new = self._leaks("stuntkey-hook-unregistered", "opaque") - self.KNOWN_GAPS_UNREGISTERED_OPAQUE
        self.assertEqual(new, set(), f"new leak(s) with a key stuntkey never saw: {sorted(new)}")

    def test_caps_close_the_spend_gaps_and_nothing_else(self):
        leaks = self._leaks("stuntkey-full", "prefixed")
        self.assertFalse(leaks & {"runaway-loop-no-cap", "unbounded-retry"})


# ---- release hygiene --------------------------------------------------------------

class ReleaseFiles(unittest.TestCase):
    def read(self, *parts):
        with open(os.path.join(REPO, *parts), encoding="utf-8") as f:
            return f.read()

    def test_every_data_file_in_the_package_is_listed_for_the_wheel(self):
        import fnmatch
        text = self.read("pyproject.toml")
        m = re.search(r"\[tool\.setuptools\.package-data\]\s*\nstuntkey\s*=\s*\[(.*?)\]", text, re.S)
        self.assertTrue(m, "package-data block not found")
        globs = re.findall(r'"([^"]+)"', m.group(1))
        base = os.path.join(REPO, "stuntkey")
        missing = []
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in files:
                if name.endswith((".py", ".pyc")):
                    continue
                rel = os.path.relpath(os.path.join(root, name), base).replace("\\", "/")
                if not any(fnmatch.fnmatch(rel, g) for g in globs):
                    missing.append(rel)
        self.assertEqual(missing, [], "these files would be left out of the wheel")

    def test_only_the_stuntkey_package_is_shipped_not_tests_or_the_benchmark(self):
        text = self.read("pyproject.toml")
        self.assertIn('packages = ["stuntkey"]', text)
        manifest = self.read("MANIFEST.in")
        for shipped_in_sdist_only in ("tests", "leakbench"):
            self.assertNotIn(f"recursive-include {shipped_in_sdist_only} *.pyc", manifest)
        self.assertNotIn("global-include *.env", manifest)

    def test_licence_security_and_threat_model_files_exist_and_say_mit(self):
        self.assertIn("MIT License", self.read("LICENSE"))
        self.assertIn('license = "MIT"', self.read("pyproject.toml"))
        self.assertTrue(self.read("SECURITY.md").strip())
        self.assertTrue(self.read("docs", "THREAT_MODEL.md").strip())

    def test_the_changelog_top_section_is_the_current_or_the_next_version(self):
        from stuntkey import __version__
        top = re.search(r"^## (\d+\.\d+\.\d+)(?: - [\d-]+| \(unreleased\))", self.read("CHANGELOG.md"), re.M)
        self.assertTrue(top)
        cur = tuple(int(x) for x in __version__.split("."))
        got = tuple(int(x) for x in top.group(1).split("."))
        self.assertIn(got, (cur, (cur[0], cur[1], cur[2] + 1)),
                      "the changelog's newest section must be this version or the next one")

    def test_no_scratch_or_secret_files_are_tracked_by_the_packaging_rules(self):
        manifest = self.read("MANIFEST.in")
        self.assertNotRegex(manifest, r"(?m)^(include|recursive-include|graft).*(\.env|secrets|scratch|\.bak)")


# ---- scrub: every form of a made-up key, random surroundings, random chunking --------

class ScrubFuzz(unittest.TestCase):
    def independent_forms(self, secret):
        import base64
        from urllib.parse import quote, quote_plus
        raw = secret.encode("utf-8")
        shown = {"plain": secret, "reversed": secret[::-1], "lower": secret.lower(),
                 "upper": secret.upper(), "hex": raw.hex(), "HEX": raw.hex().upper(),
                 "url": quote(secret, safe=""), "urlplus": quote_plus(secret),
                 "json": json.dumps(secret)[1:-1]}
        for k in range(3):
            for name, enc in (("b64", base64.b64encode), ("b64url", base64.urlsafe_b64encode)):
                whole = enc(b"x" * k + raw).decode()
                first, last = -(-8 * k // 6), 8 * (k + len(raw)) // 6
                shown[f"{name}+{k}"] = whole[first:last]
        return shown

    def test_no_form_of_a_secret_survives_whatever_it_is_buried_in(self):
        from stuntkey import scrub
        rng = random.Random(1307)
        charsets = ["abcdefghijklmnopqrstuvwxyz0123456789", "ABCDEFabcdef0123456789-_",
                    "abc+/=XYZ 0123", "éèabc123中"]
        for round_no in range(250):
            secret = "".join(rng.choice(rng.choice(charsets)) for _ in range(rng.randint(12, 48)))
            for name, form in self.independent_forms(secret).items():
                if len(form) < 12 or (name == "reversed" and not secret.isascii()):
                    continue          # real keys are ASCII; stuntkey reverses bytes, not letters
                pad_l = junk(rng, rng.randint(0, 40)).replace("\x00", "")
                pad_r = junk(rng, rng.randint(0, 40)).replace("\x00", "")
                text = (pad_l + form + pad_r).encode("utf-8")
                s = scrub.Scrubber([secret])
                cut = sorted(rng.sample(range(len(text) + 1), k=min(3, len(text) + 1)))
                parts, prev = [], 0
                for c in cut + [len(text)]:
                    parts.append(text[prev:c])
                    prev = c
                out = b"".join(s.feed(p) for p in parts) + s.flush()
                self.assertNotIn(form.encode("utf-8"), out, (round_no, name))
                self.assertGreater(s.hits, 0, (round_no, name))

    def test_one_shot_scrub_and_hook_masking_agree_on_plain_and_base64(self):
        from stuntkey import scrub
        secret = "R13scrubFake" + "Qw3rtyUiOp" * 3
        import base64
        for text in (secret, base64.b64encode(secret.encode()).decode(), "a=" + secret + "&b=1",
                     json.dumps({"k": secret}), "Bearer " + secret):
            self.assertNotIn(secret, scrub.scrub_text(text, [secret]))
            self.assertNotIn(base64.b64encode(secret.encode()).decode(),
                             scrub.scrub_text(text, [secret]))


# ---- audit log: damaged on purpose, verified, never a crash ----------------------------

class AuditFuzz(unittest.TestCase):
    ENTRY = {"service": "t", "method": "GET", "host": "h", "path": "/p",
             "status": 200, "bytes": 1, "result": "ok", "ms": 1}

    def fresh(self, n=6):
        from stuntkey import broker
        d = _isolation.mktemp()
        path = os.path.join(d, "audit.log")
        log = broker.AuditLog(path)
        for i in range(n):
            log.write(dict(self.ENTRY, path=f"/p{i}"))
        self.assertEqual(log.verify()[0], True)
        return broker, path

    def check(self, broker, path, must_fail, what):
        try:
            log = broker.AuditLog(path)
            ok, n = log.verify()
            detail = log.verify_detail()
        except Exception as e:                              # noqa: BLE001
            self.fail(f"verify raised {type(e).__name__}: {e} after {what}")
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(detail, dict)
        if must_fail:
            self.assertFalse(ok, f"damage not noticed: {what}")
            self.assertTrue(str(detail.get("reason") or "").strip(), what)

    def test_every_kind_of_damage_is_noticed_and_never_crashes(self):
        rng = random.Random(1308)
        for trial in range(60):
            broker, path = self.fresh()
            raw = open(path, "rb").read()
            lines = raw.split(b"\n")
            body = [l for l in lines if l]
            kind = rng.choice(["flip", "delete", "swap", "duplicate", "truncate",
                               "junk-line", "blank-lines", "not-utf8", "empty", "huge-line"])
            if kind == "flip":
                i = rng.randrange(len(raw) - 1)
                new = bytearray(raw)
                new[i] = (new[i] + 1 + rng.randrange(200)) % 256
                out, must = bytes(new), bytes(new) != raw
            elif kind == "delete":
                k = rng.randrange(len(body) - 1)
                out, must = b"\n".join(body[:k] + body[k + 1:]) + b"\n", True
            elif kind == "swap":
                a, b = rng.sample(range(len(body)), 2)
                body[a], body[b] = body[b], body[a]
                out, must = b"\n".join(body) + b"\n", True
            elif kind == "duplicate":
                k = rng.randrange(len(body))
                out, must = b"\n".join(body[:k + 1] + [body[k]] + body[k + 1:]) + b"\n", True
            elif kind == "truncate":
                out, must = raw[:rng.randrange(1, len(raw) - 2)], True
            elif kind == "junk-line":
                out, must = raw + bytes(rng.randrange(256) for _ in range(40)).replace(b"\n", b"") + b"\n", True
            elif kind == "blank-lines":
                out, must = b"\n\n".join(body) + b"\n\n", False
            elif kind == "not-utf8":
                out, must = raw.replace(b'"result"', b'"res\xff\xfe"', 1), True
            elif kind == "empty":
                out, must = b"", True
            else:
                out, must = raw + b"x" * 5_000_000 + b"\n", True
            with open(path, "wb") as f:
                f.write(out)
            self.check(broker, path, must, f"{kind} (trial {trial})")

    def test_the_result_text_never_holds_a_traceback_or_a_path_secret(self):
        broker, path = self.fresh()
        with open(path, "ab") as f:
            f.write(b'{"not": "a chain line"}\n')
        log = broker.AuditLog(path)
        ok, _n = log.verify()
        self.assertFalse(ok)
        self.assertNotIn("Traceback", json.dumps(log.verify_detail()))


if __name__ == "__main__":
    unittest.main()
