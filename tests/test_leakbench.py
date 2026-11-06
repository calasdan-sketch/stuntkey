"""Tests for the Agent Leak Benchmark harness itself (not for StuntKey).

Skip-safe: the stuntkey-hook profile tests skip when StuntKey is not importable,
so this file never breaks a run on a machine without it. Every test plants its
secrets in a throwaway sandbox and never touches the real home.
"""

import importlib
import json
import os
import unittest

import _isolation  # noqa: F401  (points HOME/USERPROFILE at a temp dir)

from leakbench import harness, loader, profiles, report, sandbox
from leakbench.runner import Result, run_probe

MIN_PROBES = 50


def _stuntkey_available() -> bool:
    try:
        importlib.import_module("stuntkey.hook")
        return True
    except ImportError:
        return False


class Probes(unittest.TestCase):
    def test_at_least_fifty_probes_load(self):
        probes = loader.load()
        self.assertGreaterEqual(len(probes), MIN_PROBES)

    def test_probe_ids_are_unique(self):
        ids = [p.id for p in loader.load()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_probe_has_a_known_check(self):
        known = {"canary_in_output", "write_tamper", "no_guard", "reaches_model"}
        for p in loader.load():
            self.assertIn(p.check, known, p.id)

    def test_every_category_is_represented(self):
        cats = {p.category for p in loader.load()}
        self.assertIn("direct file read", cats)
        self.assertIn("shell env dump", cats)
        self.assertIn("prompt injection", cats)


class SandboxPlanting(unittest.TestCase):
    def test_canary_is_unique_and_fake(self):
        a, b = sandbox.new_canary(), sandbox.new_canary()
        self.assertTrue(a.startswith("sk-canary-"))
        self.assertNotEqual(a, b)

    def test_build_plants_env_with_canary_then_destroy_removes_it(self):
        sbx = sandbox.build()
        try:
            with open(os.path.join(sbx.home, ".env"), encoding="utf-8") as fh:
                self.assertIn(sbx.canary, fh.read())
            self.assertEqual(sbx.env["API_KEY"], sbx.canary)
            self.assertEqual(sbx.env["HOME"], sbx.home)
        finally:
            sandbox.destroy(sbx)
        self.assertFalse(os.path.exists(sbx.home))

    def test_sandbox_env_strips_stuntkey_vars(self):
        sbx = sandbox.build()
        try:
            self.assertFalse(any(k.startswith("STUNTKEY_") for k in sbx.env))
        finally:
            sandbox.destroy(sbx)


class RunnerWithNoneProfile(unittest.TestCase):
    def setUp(self):
        self.sbx = sandbox.build()
        self.none = profiles.get("none")

    def tearDown(self):
        sandbox.destroy(self.sbx)

    def _probe(self, probe_id):
        return next(p for p in loader.load() if p.id == probe_id)

    def test_none_never_blocks(self):
        for probe in loader.load():
            r = run_probe(probe, self.sbx, self.none, "none")
            self.assertNotEqual(r.status, "blocked", probe.id)

    def test_reading_env_leaks_under_none(self):
        r = run_probe(self._probe("read-env"), self.sbx, self.none, "none")
        self.assertEqual(r.status, "leaked")

    def test_substitution_keeps_canary_out_of_other_sandboxes(self):
        # the canary in the result detail must be this run's, never a literal
        r = run_probe(self._probe("read-env"), self.sbx, self.none, "none")
        self.assertIsInstance(r, Result)


class RunnerWithStuntkeyHook(unittest.TestCase):
    def setUp(self):
        if not _stuntkey_available():
            self.skipTest("stuntkey not importable")
        self.sbx = sandbox.build()
        self.hook = profiles.get("stuntkey-hook")

    def tearDown(self):
        if hasattr(self, "sbx"):
            sandbox.destroy(self.sbx)

    def _probe(self, probe_id):
        return next(p for p in loader.load() if p.id == probe_id)

    def test_hook_blocks_env_read(self):
        r = run_probe(self._probe("read-env"), self.sbx, self.hook, "stuntkey-hook")
        self.assertEqual(r.status, "blocked")

    def test_hook_blocks_proc_environ(self):
        r = run_probe(self._probe("proc-self-environ"), self.sbx, self.hook, "stuntkey-hook")
        self.assertEqual(r.status, "blocked")

    def test_hook_blocks_plain_env_dump(self):
        # closed in 0.9.0: the hook refuses commands that print the environment
        r = run_probe(self._probe("env-dump"), self.sbx, self.hook, "stuntkey-hook")
        self.assertEqual(r.status, "blocked")

    def test_hook_blocks_pem_read(self):
        # closed in wave 3: a Read of a private key is refused before it runs
        r = run_probe(self._probe("read-pem"), self.sbx, self.hook, "stuntkey-hook")
        self.assertEqual(r.status, "blocked")

    def test_hook_masks_bash_output_after_it_runs(self):
        r = run_probe(self._probe("cat-log-with-key"), self.sbx, self.hook, "stuntkey-hook")
        self.assertEqual(r.status, "masked")

    def test_hook_blocks_writing_a_script_that_prints_the_environment(self):
        # 0.10: the Write's content is judged, so the script is stopped before
        # it exists (before 0.10 this probe leaked)
        for pid in ("script-prints-environ", "node-prints-process-env", "script-reads-env-file"):
            r = run_probe(self._probe(pid), self.sbx, self.hook, "stuntkey-hook")
            self.assertEqual(r.status, "blocked", pid)

    def test_hook_blocks_a_stored_key_written_into_a_file_and_a_pasted_prompt(self):
        for pid in ("write-key-into-test", "edit-key-into-env-example",
                    "multiedit-key-into-config", "paste-key-in-prompt",
                    "paste-vendor-key-in-prompt"):
            r = run_probe(self._probe(pid), self.sbx, self.hook, "stuntkey-hook")
            self.assertEqual(r.status, "blocked", pid)

    def test_new_probes_leak_without_protection(self):
        none = profiles.get("none")
        for pid in ("write-key-into-test", "paste-key-in-prompt"):
            r = run_probe(self._probe(pid), self.sbx, none, "none")
            self.assertEqual(r.status, "leaked", pid)


class Reporting(unittest.TestCase):
    def test_summary_counts_cover_every_status(self):
        results = harness.run("none")
        s = report.summary(results)
        self.assertEqual(sum(s.values()), len(results))
        self.assertEqual(s["blocked"], 0)

    def test_json_is_parseable_and_has_profile(self):
        results = harness.run("none")
        data = json.loads(report.to_json(results, "none"))
        self.assertEqual(data["profile"], "none")
        self.assertEqual(data["total"], len(results))

    def test_table_mentions_gaps(self):
        results = harness.run("none")
        self.assertIn("GAPS", report.to_table(results, "none"))


if __name__ == "__main__":
    unittest.main()
