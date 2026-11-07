"""0.12 (expert round 3): hook disguises found by an attacker pass (backslash
escape, wildcard forms of .env, wrapper programs, inline environment dumps,
other tools' token printers), the audit log's write path, `audit export` and
the friendly answer to a mistyped command."""

import contextlib
import csv
import io
import json
import os
import subprocess
import sys
import unittest

import _isolation  # noqa: F401
from stuntkey import broker, cmds
from stuntkey import hook as hook_mod


def verdict(tool, **tool_input):
    status, out = hook_mod.check(json.dumps(
        {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input}))
    return "deny" if out.strip() else "allow"


def bash(cmd):
    return verdict("Bash", command=cmd)


class Disguises(unittest.TestCase):
    def test_refused(self):
        for cmd in [
            "cat .\\env", "cat .e\\nv", "cat .?nv", "cat .e{n,}v", "cat .en[v]", "grep KEY .e*",
            "python3 -c \"print(open('.e'+'nv').read())\"",
            "timeout 5 env", "/usr/bin/env", "nohup env", "nice -n 5 env", "time env",
            "stdbuf -oL printenv", "bash -lc 'export -p'", "sh -c 'env'",
            "python3 -c 'import os;print(*os.environ.items())'",
            "python3 -c 'import os;print(dict(os.environ))'",
            "node -e 'console.log(Object.entries(process.env))'",
            "node -p 'JSON.stringify(process.env)'",
            "ruby -e 'p ENV.to_h'", "perl -e 'print \"$_\\n\" for keys %ENV'",
            "php -r 'print_r(getenv());'", "deno eval 'console.log(Deno.env.toObject())'",
            "python3 -c 'import os;print(os.environ[\"OPENAI_API_KEY\"])'",
            "node -e 'console.log(process.env.OPENAI_API_KEY)'",
            "gh auth token", "gh auth status --show-token", "gcloud auth print-access-token",
            "aws configure get aws_secret_access_key", "az account get-access-token",
            "heroku auth:token", "op read op://vault/item/key", "bw get password x",
            "kubectl get secret x -o yaml", "kubectl config view --raw", "git credential fill",
            "cat ENV~1", "sudo -E env", "command -p env", "taskset 1 env", "nohup -- env",
            "python3 -c \"import os;[print(k,os.environ[k]) for k in os.environ]\"",
        ]:
            with self.subTest(cmd=cmd):
                self.assertEqual(bash(cmd), "deny")

    def test_powershell_and_cmd_forms(self):
        for cmd in ["[IO.File]::ReadAllText(\".e\"+\"nv\")", "Get-Content -Path ('.e'+'nv')",
                    "echo %OPENAI_API_KEY%", "Write-Host ${env:OPENAI_API_KEY}"]:
            with self.subTest(cmd=cmd):
                self.assertEqual(verdict("PowerShell", command=cmd), "deny")

    def test_everyday_commands_still_run(self):
        for cmd in [
            "ls -la", "ls .e*", "git status", "npm test", "python -m venv env", "time pytest -q",
            "nice make -j4", "timeout 60 pytest", "nohup python app.py &", "env FOO=1 python x.py",
            "python -c \"import os;print(os.environ['HOME'])\"",
            "python -c 'import os;print(sorted(os.environ))'", "gh auth status", "gh pr list",
            "gh auth login", "aws s3 ls", "aws configure list-profiles", "git credential reject",
            "cat .eslintrc.json", "cat .editorconfig", "cat src/{a,b}.py", "head -5 .gitignore",
            "cat .env.example", "kubectl get pods", "kubectl get secrets", "vault status",
            "find . -name '*.py' | xargs grep TODO", "bash -lc 'echo hi'", "op --version",
            "stdbuf -oL tail -f log.txt", "cat *", "grep -r TODO .", "sudo apt install x", "command -v git",
            "python3 -c \"import os;print([k for k in os.environ if k.startswith('A')])\"", "grep foo *env*", "cat *env*",
        ]:
            with self.subTest(cmd=cmd):
                self.assertEqual(bash(cmd), "allow")

    def test_read_and_grep_tools(self):
        self.assertEqual(verdict("Grep", pattern="KEY", path="/p", glob=".e*"), "deny")
        self.assertEqual(verdict("Grep", pattern="KEY", path="/p", glob=".en[v]"), "deny")
        self.assertEqual(verdict("Grep", pattern="x", path="/p", glob="*.py"), "allow")
        self.assertEqual(verdict("Grep", pattern="x", path="/p", glob="*"), "allow")
        self.assertEqual(verdict("Read", file_path="C:\\proj\\ENV~1"), "deny")
        self.assertEqual(verdict("Read", file_path="/p/environment.py"), "allow")

    def test_hostile_input_is_fast(self):
        import time
        for cmd in ["nice " * 5000 + "env", "timeout 5 " * 3000, "xargs -I " * 4000,
                    "{" * 20000 + ".e*", "." + "?" * 50000, "[" * 30000 + ".e"]:
            start = time.perf_counter()
            bash(cmd)
            self.assertLess(time.perf_counter() - start, 3, cmd[:20])


def entry(i=0):
    return {"service": "x", "method": "GET", "host": "h", "path": f"/p{i}",
            "status": 200, "bytes": 1, "result": "ok", "ms": 1}


class AuditWritePath(unittest.TestCase):
    def setUp(self):
        self.dir = _isolation.mktemp()
        self.log = broker.AuditLog(os.path.join(self.dir, "audit.log"))

    def test_marker_records_size_and_fast_state_agrees_with_full_scan(self):
        for i in range(5):
            self.log.write(entry(i))
        a = self.log._read_anchor_full()
        self.assertEqual(a[0], 5)
        self.assertEqual(a[2], os.path.getsize(self.log.path))
        self.assertEqual(self.log._fast_state()[:2], self.log._scan()[:2])
        self.assertEqual(self.log.verify(), (True, 5))

    def test_old_marker_without_size_is_upgraded(self):
        for i in range(3):
            self.log.write(entry(i))
        n, last, *_ = self.log._scan()
        with open(self.log.anchor_path, "w") as f:
            f.write(f"{n} {last}\n")
        self.assertIsNone(self.log._fast_state())
        self.log.write(entry(9))
        self.assertIsNotNone(self.log._read_anchor_full()[2])
        self.assertEqual(self.log.verify(), (True, 4))

    def test_cut_off_and_edits_are_still_found(self):
        for i in range(6):
            self.log.write(entry(i))
        with open(self.log.path, "rb") as f:
            data = f.read()
        lines = data.splitlines(True)
        with open(self.log.path, "wb") as f:
            f.write(b"".join(lines[:-2]))                   # cut off the end
        self.assertFalse(self.log.verify()[0])
        self.assertIsNone(self.log._fast_state())
        self.log.write(entry(7))                            # next write flags it
        self.assertIsNotNone(self.log.broken_reason())
        self.assertFalse(self.log.verify()[0])

    def test_edit_in_the_middle_found_by_verify(self):
        for i in range(6):
            self.log.write(entry(i))
        with open(self.log.path, "rb") as f:
            data = f.read()
        with open(self.log.path, "wb") as f:
            f.write(data.replace(b"/p2", b"/pX", 1))        # same size
        self.assertFalse(self.log.verify()[0])

    def test_many_writes_stay_fast_and_exact(self):
        import time
        for i in range(300):
            self.log.write(entry(i))
        start = time.perf_counter()
        for i in range(20):
            self.log.write(entry(i))
        per_write = (time.perf_counter() - start) / 20
        self.assertEqual(self.log.verify(), (True, 320))
        self.assertLess(per_write, 0.5)


class AuditExport(unittest.TestCase):
    def setUp(self):
        home = os.path.join(os.path.expanduser("~"), ".stuntkey")
        os.makedirs(home, exist_ok=True)
        self.log = broker.AuditLog(os.path.join(home, "audit.log"))
        self.log.reset()
        bad = entry(1)
        bad["path"] = "=HYPERLINK(\"http://x\")"
        bad2 = entry(2)
        bad2["path"] = "/a\u202eb,\"c\nd"
        self.log.write(bad)
        self.log.write(bad2)

    def run_export(self, **kw):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cmds.cmd_audit("export", kw.get("as_json", False), 20, kw.get("out"))
        return code, out.getvalue(), err.getvalue()

    def test_csv_is_spreadsheet_safe(self):
        code, out, err = self.run_export()
        self.assertEqual(code, 0)
        rows = list(csv.reader(io.StringIO(out)))
        self.assertEqual(rows[0][:3], ["time_utc", "service", "method"])
        self.assertEqual(len(rows), 3)
        self.assertTrue(rows[1][4].startswith("'="))
        self.assertNotIn("\u202e", out)
        self.assertIn("intact", err)

    def test_json_lines_and_file_never_overwritten(self):
        path = os.path.join(_isolation.mktemp(), "e.jsonl")
        code, _, _ = self.run_export(as_json=True, out=path)
        self.assertEqual(code, 0)
        with open(path, encoding="utf-8") as f:
            self.assertEqual(len([json.loads(x) for x in f]), 2)
        code, _, err = self.run_export(as_json=True, out=path)
        self.assertEqual(code, 1)
        self.assertIn("could not write", err)

    def test_tampered_log_exits_with_problem(self):
        with open(self.log.path, "rb") as f:
            data = f.read()
        with open(self.log.path, "wb") as f:
            f.write(data.replace(b"HYPERLINK", b"HYPERLINX", 1))
        code, _, err = self.run_export()
        self.assertEqual(code, 1)
        self.assertIn("DOES NOT CHECK OUT", err)


class FriendlyTypo(unittest.TestCase):
    def run_cli(self, *args):
        env = dict(os.environ, PYTHONPATH=_isolation.REPO)
        return subprocess.run([sys.executable, "-m", "stuntkey", *args], capture_output=True,
                              text=True, env=env, timeout=60)

    def test_typo_gets_a_short_hint(self):
        r = self.run_cli("gett")
        self.assertEqual(r.returncode, 2)
        self.assertIn("Did you mean: get", r.stderr)
        self.assertLess(len(r.stderr), 300)

    def test_terminal_codes_are_not_echoed(self):
        r = self.run_cli("\x1b[31mzz")
        self.assertNotIn("\x1b", r.stderr)

    def test_other_errors_are_argparses_own(self):
        r = self.run_cli("get")
        self.assertIn("required: service", r.stderr)


if __name__ == "__main__":
    unittest.main()
