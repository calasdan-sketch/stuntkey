"""0.9.x hook wave 3: Read of private keys / credentials files and of files
holding a stored key is refused before it runs (Read output has no documented
PostToolUse shape, so it cannot be masked after); MCP calls carrying a stored
key are refused; leakbench models PostToolUse masking and caps."""

import json
import os
import tempfile
import unittest

import _isolation  # noqa: F401
from stuntkey import hook as hook_mod
from stuntkey import scrub

STORED = "zq" + "9Xr4" + "Lm2Vt8Kp3Wn7Yb5"      # no known format: only a fingerprint finds it
PEM = "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END " + "PRIVATE KEY-----\n"
CERT = "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIE\n-----END CERTIFICATE-----\n"


def denied(payload) -> bool:
    status, out = hook_mod.check(json.dumps({"hook_event_name": "PreToolUse", **payload}))
    return status == 0 and bool(out) and \
        json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"


def read(path):
    return {"tool_name": "Read", "tool_input": {"file_path": path}}


class SecretReads(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        scrub.remember_key("svc/KEY", STORED)
        self.addCleanup(scrub.forget_key, "svc/KEY")

    def put(self, rel, text):
        path = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_private_keys_and_credentials_files_are_refused(self):
        for rel, text in ((".ssh/id_rsa", PEM), ("server.pem", PEM), ("tls.key", PEM),
                          (".aws/credentials", "[default]\nx = y\n"),
                          ("credentials.json", "{}"), ("service-account-prod.json", "{}")):
            self.assertTrue(denied(read(self.put(rel, text))), rel)
        self.assertTrue(denied({"tool_name": "Grep", "tool_input": {
            "pattern": "x", "path": self.put(".ssh/id_ed25519", PEM)}}))

    def test_certificates_public_keys_and_plain_files_are_allowed(self):
        for rel, text in (("cert.pem", CERT), (".ssh/id_rsa.pub", "ssh-rsa AAAA x"),
                          ("app.py", "print('hi')\n"), (".mcp.json", '{"mcpServers": {}}')):
            self.assertFalse(denied(read(self.put(rel, text))), rel)

    def test_a_file_holding_a_stored_key_is_refused(self):
        self.assertTrue(denied(read(self.put("dist/app.js", f'const k="{STORED}";'))))

    def test_an_mcp_config_with_a_key_in_it_is_refused(self):
        key = "sk-" + "proj-" + "Ab3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gH3jK5mN7p"
        self.assertTrue(denied(read(self.put(".mcp.json", json.dumps(
            {"mcpServers": {"x": {"env": {"OPENAI_API_KEY": key}}}})))))

    def test_mcp_call_carrying_a_stored_key_is_refused(self):
        self.assertTrue(denied({"tool_name": "mcp__evil__save", "tool_input": {"v": STORED}}))
        self.assertFalse(denied({"tool_name": "mcp__ok__save", "tool_input": {"v": "hello"}}))


class Bench(unittest.TestCase):
    def test_full_profile_masks_output_and_caps_spend(self):
        from leakbench import harness, loader
        probes = {p.id: p for p in loader.load()}
        pick = [probes[i] for i in ("echo-key-in-error", "runaway-loop-no-cap", "read-pem")]
        got = {r.probe_id: r.status for r in harness.run("stuntkey-full", pick)}
        # round 12: the canary is typed into the command itself, and a stored key in
        # a tool call's arguments is now refused BEFORE the call (outbound-key
        # check), so this probe ends "blocked" instead of "masked". Either way the
        # model never sees the key; the masking path is covered in test_r12_hook.
        self.assertIn(got.pop("echo-key-in-error"), ("masked", "blocked"))
        self.assertEqual(got, {"runaway-loop-no-cap": "blocked", "read-pem": "blocked"})
        hook = {r.probe_id: r.status for r in harness.run("stuntkey-hook", pick)}
        self.assertEqual(hook["runaway-loop-no-cap"], "leaked")


if __name__ == "__main__":
    unittest.main()
