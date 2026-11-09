"""0.6.0: the agent handshake. The one rule: no tool answer and no CLI JSON
can carry a secret value. Canary keys are planted everywhere this process can
reach; every answer is searched for them (raw and re-written)."""
import base64
import io
import json
import os
import unittest
import urllib.parse
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import agent, manifest
from stuntkey import cli as cli_mod
from stuntkey import mcp as mcp_mod
from stuntkey import recipes as recipes_mod

CAT = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
CANARY_ENV = "sk-CANARYENV-9f8e7d6c5b4a39281706"
CANARY_FILE = "sk_" "live_CANARYFILE9f8e7d6c5b4a39"
CANARY_OTHER = "postgres-pass-CANARYOTHER-1a2b3c4d"
CANARIES = (CANARY_ENV, CANARY_FILE, CANARY_OTHER)


def forms(value):
    raw = value.encode()
    return {value, base64.b64encode(raw).decode(), base64.b64encode(raw).decode().rstrip("="),
            raw.hex(), urllib.parse.quote(value, safe=""), json.dumps(value)[1:-1]}


class cd:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self.old = os.getcwd()
        os.chdir(self.path)

    def __exit__(self, *a):
        os.chdir(self.old)


def project():
    d = _isolation.mktemp()
    with open(os.path.join(d, ".env"), "w") as f:
        f.write(f"STRIPE_SECRET_KEY={CANARY_FILE}\nDATABASE_PASSWORD={CANARY_OTHER}\n")
    with open(os.path.join(d, ".env.example"), "w") as f:
        f.write("OPENAI_API_KEY=\nGROQ_API_KEY=\nSTRIPE_SECRET_KEY=\n")
    with open(os.path.join(d, "app.py"), "w") as f:
        f.write('import os\nos.environ["TAVILY_API_KEY"]\n')
    return d


def call(name, arguments, cwd=None, **kw):
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}}
    return mcp_mod.handle(req, CAT, cwd=cwd, **kw)


def text_of(resp):
    return json.dumps(resp)


class Base(unittest.TestCase):
    def setUp(self):
        self.d = project()
        patcher = mock.patch.dict(os.environ, {"OPENAI_API_KEY": CANARY_ENV})
        patcher.start()
        self.addCleanup(patcher.stop)

    def assertClean(self, text, where=""):
        for canary in CANARIES:
            for form in forms(canary):
                self.assertNotIn(form, text, f"{where}: leaked {form[:12]}...")


class TestRequestConnect(Base):
    def test_shape_for_a_missing_key(self):
        r = json.loads(call("request_connect", {"service": "groq"}, self.d)["result"]["content"][0]["text"])
        self.assertEqual(r["service"], "groq")
        self.assertEqual(r["env_var"], "GROQ_API_KEY")
        self.assertEqual(r["status"], "missing")
        self.assertIn("stuntkey connect groq", r["instructions"])

    def test_only_whitelisted_fields(self):
        r = json.loads(call("request_connect", {"service": "groq"}, self.d)["result"]["content"][0]["text"])
        self.assertLessEqual(set(r), {"service", "env_var", "env_vars", "status", "instructions", "key_page", "opened_key_page", "browser", "rules", "note", "capture_help"})

    def test_present_when_the_env_file_has_it(self):
        r = json.loads(call("request_connect", {"service": "stripe"}, self.d)["result"]["content"][0]["text"])
        self.assertEqual(r["status"], "present")
        self.assertNotIn("connect", r["instructions"].split("already")[0])
        self.assertClean(json.dumps(r))

    def test_manifest_keychain_store_is_unknown_not_read(self):
        with open(os.path.join(self.d, manifest.FILE_NAME), "w") as f:
            json.dump({"version": 1, "services": [{"service": "groq", "store": "keychain"}]}, f)
        with mock.patch("stuntkey.keychain.read", side_effect=AssertionError("keychain read")):
            r = json.loads(call("request_connect", {"service": "groq"}, self.d)["result"]["content"][0]["text"])
        self.assertEqual(r["status"], "unknown")
        self.assertIn("--store keychain", r["instructions"])

    def test_two_part_credential_partly_there_is_missing(self):
        with open(os.path.join(self.d, ".env"), "a") as f:
            f.write("TWILIO_ACCOUNT_SID=ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
        r = json.loads(call("request_connect", {"service": "twilio"}, self.d)["result"]["content"][0]["text"])
        self.assertEqual(r["status"], "missing")
        self.assertEqual(r["env_vars"], ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"])

    def test_unknown_service_is_an_error_that_does_not_echo(self):
        resp = call("request_connect", {"service": CANARY_FILE}, self.d)
        self.assertTrue(resp["result"]["isError"])
        self.assertNotIn(CANARY_FILE, text_of(resp))

    def test_non_string_service(self):
        for bad in (5, ["a"], {"a": 1}):
            resp = call("request_connect", {"service": bad}, self.d)
            self.assertIn("error", text_of(resp).lower())

    def test_missing_argument_is_invalid_params(self):
        resp = call("request_connect", {}, self.d)
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)

    def test_open_key_page_uses_the_injected_opener_with_the_recipe_url_only(self):
        opened = []
        agent._LAST_OPEN.clear()
        r = json.loads(call("request_connect", {"service": "groq", "open_key_page": True}, self.d,
                            opener=opened.append)["result"]["content"][0]["text"])
        self.assertEqual(opened, [CAT["groq"]["key_url"]])
        self.assertTrue(r["opened_key_page"])

    def test_the_page_is_not_reopened_within_the_cooldown(self):
        agent._LAST_OPEN.clear()
        opened = []
        for _ in range(3):
            r = json.loads(call("request_connect", {"service": "groq", "open_key_page": True}, self.d,
                                opener=opened.append)["result"]["content"][0]["text"])
        self.assertEqual(len(opened), 1)
        self.assertFalse(r["opened_key_page"])

    def test_the_page_is_not_opened_unless_asked(self):
        opened = []
        call("request_connect", {"service": "groq"}, self.d, opener=opened.append)
        self.assertEqual(opened, [])

    def test_opener_failure_is_reported_not_raised(self):
        agent._LAST_OPEN.clear()

        def boom(url):
            raise RuntimeError("no browser")
        r = json.loads(call("request_connect", {"service": "groq", "open_key_page": True}, self.d,
                            opener=boom)["result"]["content"][0]["text"])
        self.assertFalse(r["opened_key_page"])

    def test_open_key_page_must_be_boolean(self):
        resp = call("request_connect", {"service": "groq", "open_key_page": "yes"}, self.d)
        self.assertEqual(resp["error"]["code"], mcp_mod.INVALID_PARAMS)

    def test_the_agent_rule_is_in_the_instructions(self):
        r = json.loads(call("request_connect", {"service": "groq"}, self.d)["result"]["content"][0]["text"])
        self.assertIn("Do not ask the person to paste a key into chat", r["instructions"])


class TestNeedsKeys(Base):
    def test_reads_names_from_the_template_and_code_and_reports_status(self):
        r = json.loads(call("needs_keys", {"project": self.d}, self.d)["result"]["content"][0]["text"])
        status = {s["service"]: s["status"] for s in r["services"]}
        self.assertEqual(status, {"groq": "missing", "openai": "missing", "stripe": "present", "tavily": "missing"})
        self.assertEqual(r["missing"], ["groq", "openai", "tavily"])
        self.assertIn("stuntkey setup", r["instructions"])

    def test_the_process_environment_is_not_counted_as_present(self):
        # OPENAI_API_KEY is in os.environ (a canary) but not stored in the project
        r = json.loads(call("needs_keys", {"project": self.d}, self.d)["result"]["content"][0]["text"])
        self.assertIn("openai", r["missing"])

    def test_manifest_is_the_source_when_present(self):
        with open(os.path.join(self.d, manifest.FILE_NAME), "w") as f:
            json.dump({"version": 1, "services": [{"service": "mistral"}]}, f)
        r = json.loads(call("needs_keys", {"project": self.d}, self.d)["result"]["content"][0]["text"])
        self.assertEqual(r["source"], "stuntkey.json")
        self.assertIn("mistral", [s["service"] for s in r["services"]])

    def test_nothing_missing(self):
        d = _isolation.mktemp()
        with open(os.path.join(d, ".env.example"), "w") as f:
            f.write("GROQ_API_KEY=\n")
        with open(os.path.join(d, ".env"), "w") as f:
            f.write(f"GROQ_API_KEY={CANARY_OTHER}\n")
        r = json.loads(call("needs_keys", {"project": d}, d)["result"]["content"][0]["text"])
        self.assertEqual((r["missing"], r["instructions"]), ([], "Nothing is missing."))
        self.assertClean(json.dumps(r))

    def test_default_project_is_the_cwd(self):
        r = json.loads(call("needs_keys", {}, self.d)["result"]["content"][0]["text"])
        self.assertIn("groq", r["missing"])

    def test_missing_folder_is_an_error_without_echo(self):
        resp = call("needs_keys", {"project": "/no/such/" + CANARY_FILE}, self.d)
        self.assertTrue(resp["result"]["isError"])
        self.assertNotIn(CANARY_FILE, text_of(resp))

    def test_bad_type(self):
        self.assertEqual(call("needs_keys", {"project": 5}, self.d)["error"]["code"], mcp_mod.INVALID_PARAMS)

    def test_a_real_env_in_the_project_is_not_parsed_for_names(self):
        # DATABASE_PASSWORD only exists in the real .env: it is not reported
        r = json.loads(call("needs_keys", {"project": self.d}, self.d)["result"]["content"][0]["text"])
        self.assertNotIn("DATABASE_PASSWORD", json.dumps(r))

    def test_corrupt_manifest_falls_back_to_detection(self):
        with open(os.path.join(self.d, manifest.FILE_NAME), "w") as f:
            f.write("{bad")
        r = json.loads(call("needs_keys", {"project": self.d}, self.d)["result"]["content"][0]["text"])
        self.assertNotEqual(r["source"], "stuntkey.json")


class TestNoSecretCanLeave(Base):
    """The canary test: every tool, every error path, the wire loop."""

    def all_requests(self):
        for c in CANARIES:
            yield ("list_services", {})
            yield ("get_recipe", {"service": c})
            yield ("get_recipe", {"service": "stripe"})
            yield ("request_connect", {"service": c})
            yield ("request_connect", {"service": "stripe"})
            yield ("request_connect", {"service": "openai"})
            yield ("needs_keys", {"project": c})
            yield ("needs_keys", {"project": self.d})
            yield ("find_public_apis", {"query": c})
            yield ("get_public_api", {"name": c})
            yield (c, {})
            yield ("get_recipe", {"service": c, c: c})

    def loader(self):
        return [{"name": "A", "description": "d", "auth": "apiKey", "url": "https://a.test", "category": "x"}]

    def test_every_tool_output_is_free_of_every_canary(self):
        for name, args in self.all_requests():
            resp = call(name, args, self.d, pa_loader=self.loader)
            self.assertClean(text_of(resp), f"{name} {list(args)}")

    def test_wire_loop_including_garbage_and_odd_methods(self):
        lines = []
        for i, (name, args) in enumerate(self.all_requests()):
            lines.append(json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                     "params": {"name": name, "arguments": args}}))
        lines += [f"not json {CANARY_ENV}", json.dumps({"jsonrpc": "2.0", "id": 1, "method": CANARY_FILE}),
                  json.dumps({"jsonrpc": "2.0", "id": CANARY_OTHER, "method": "tools/list"}),
                  json.dumps([CANARY_ENV])]
        stdin = io.BytesIO(("\n".join(lines) + "\n").encode())
        stdout = io.BytesIO()
        with cd(self.d):
            mcp_mod.serve(CAT, pa_loader=self.loader, stdin=stdin, stdout=stdout)
        output = stdout.getvalue().decode()
        self.assertTrue(output.strip())
        self.assertClean(output.replace(json.dumps(CANARY_OTHER), ""), "wire")

    def test_the_request_id_echo_is_the_one_documented_exception(self):
        # JSON-RPC echoes the caller's own id; that is the caller's own text
        resp = mcp_mod.handle({"jsonrpc": "2.0", "id": CANARY_OTHER, "method": "ping"}, CAT)
        self.assertEqual(resp["id"], CANARY_OTHER)

    def test_guard_blanks_a_reachable_secret_even_if_a_tool_were_to_emit_it(self):
        with mock.patch.object(agent, "request_connect",
                               return_value={"service": "x", "status": "present", "note": CANARY_ENV + CANARY_FILE}):
            resp = call("request_connect", {"service": "groq"}, self.d)
        text = text_of(resp)
        self.assertClean(text)
        self.assertIn("[REDACTED]", text)

    def test_guard_catches_rewritten_forms(self):
        sneaky = base64.b64encode(CANARY_ENV.encode()).decode()
        out = agent.guard_text(f"x {sneaky} y {CANARY_FILE.encode().hex()}", CAT, self.d)
        self.assertNotIn(sneaky, out)
        self.assertNotIn(CANARY_FILE.encode().hex(), out)

    def test_guard_covers_values_of_any_variable_in_the_projects_env(self):
        out = agent.guard_text(f"p={CANARY_OTHER}", CAT, self.d)
        self.assertNotIn(CANARY_OTHER, out)

    def test_guard_with_nothing_to_hide_is_the_identity(self):
        self.assertEqual(agent.guard_text("hello", CAT, _isolation.mktemp(), environ={}), "hello")

    def test_internal_errors_are_guarded_too(self):
        with mock.patch.object(mcp_mod, "_handle", side_effect=RuntimeError("boom " + CANARY_ENV)):
            stdin = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
            stdout = io.BytesIO()
            mcp_mod.serve(CAT, stdin=stdin, stdout=stdout)
        self.assertNotIn(CANARY_ENV, stdout.getvalue().decode())

    def test_error_messages_never_echo_service_arguments(self):
        for tool in ("get_recipe", "request_connect"):
            self.assertNotIn(CANARY_FILE, text_of(call(tool, {"service": CANARY_FILE}, self.d)))

    def test_long_unknown_method_and_tool_names_are_not_echoed(self):
        long_name = "x" * 60
        self.assertNotIn(long_name, text_of(mcp_mod.handle({"jsonrpc": "2.0", "id": 1, "method": long_name}, CAT)))
        self.assertNotIn(long_name, text_of(call(long_name, {})))

    def test_short_tool_name_is_still_echoed_for_old_clients(self):
        self.assertIn("unknown tool: nope", text_of(call("nope", {})))

    def test_no_tool_has_a_parameter_that_takes_a_value(self):
        for tool in mcp_mod._tool_defs():
            for prop in tool["inputSchema"].get("properties", {}):
                if prop == "open_key_page":      # a yes/no switch, not a value
                    continue
                self.assertNotRegex(prop, r"(?i)key|token|secret|value|password|credential", (tool["name"], prop))

    def test_tool_descriptions_forbid_pasting(self):
        d = {t["name"]: t["description"] for t in mcp_mod._tool_defs()}
        self.assertIn("never ask", d["request_connect"].lower())
        self.assertIn("never a value", d["needs_keys"])


class TestCliJsonNeverCarriesAValue(Base):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with cd(self.d), mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            try:
                cli_mod.main(list(argv))
            except SystemExit:
                pass
        return out.getvalue() + err.getvalue()

    def test_scan_json(self):
        with open(os.path.join(self.d, "CLAUDE.md"), "w") as f:
            f.write(f"my key is {CANARY_FILE}\n")
        text = self.run_cli("scan", "--json", self.d)
        self.assertIn("redacted", text)
        self.assertClean(text, "scan --json")

    def test_scan_text_and_sarif(self):
        with open(os.path.join(self.d, "CLAUDE.md"), "w") as f:
            f.write(f"my key is {CANARY_FILE}\n")
        for flag in ("--sarif", "--all"):
            self.assertClean(self.run_cli("scan", flag, self.d), flag)

    def test_status_json(self):
        with open(os.path.join(self.d, manifest.FILE_NAME), "w") as f:
            json.dump({"version": 1, "services": [{"service": "stripe"}, {"service": "openai"}]}, f)
        with mock.patch("stuntkey.keychain.detect_backend", return_value=None):
            text = self.run_cli("status", "--json")
        self.assertIn('"stripe"', text)
        self.assertClean(text, "status --json")

    def test_init_and_list(self):
        self.assertClean(self.run_cli("init"), "init")
        self.assertClean(self.run_cli("list"), "list")

    def test_doctor_json(self):
        from stuntkey import doctor
        with mock.patch.object(doctor, "fetch", return_value=(200, None, None)):
            text = self.run_cli("doctor-recipes", "--json", "stripe")
        self.assertClean(text)

    def test_unknown_service_message(self):
        self.assertClean(self.run_cli("connect", CANARY_FILE), "connect unknown")


if __name__ == "__main__":
    unittest.main()
