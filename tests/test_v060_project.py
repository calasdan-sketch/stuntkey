"""0.6.0: stuntkey.json, the local record, init / setup / status."""
import datetime
import io
import json
import os
import unittest
from unittest import mock

import _isolation  # noqa: F401
from stuntkey import cli as cli_mod
from stuntkey import detect, ledger, manifest, presence, projectcmds
from stuntkey import recipes as recipes_mod
from stuntkey import store as store_mod

CAT = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
KEY = "sk-test-CANARY-0123456789abcdef"


def proj(files=None):
    d = _isolation.mktemp()
    for name, text in (files or {}).items():
        path = os.path.join(d, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    return d


def jload(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def man(*services, **extra):
    data = {"version": 1, "services": [dict(s) if isinstance(s, dict) else {"service": s} for s in services]}
    data.update(extra)
    return data


class cd:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self.old = os.getcwd()
        os.chdir(self.path)

    def __exit__(self, *a):
        os.chdir(self.old)


class TestManifestValidation(unittest.TestCase):
    def bad(self, data, text=None):
        with self.assertRaises(manifest.ManifestError) as cm:
            manifest.validate(data)
        if text:
            self.assertIn(text, str(cm.exception))

    def test_minimal_is_valid(self):
        manifest.validate(man("openai"))

    def test_unknown_top_member_refused(self):
        self.bad(man("openai", api_key="x"), "unknown member")

    def test_unknown_service_member_refused_so_no_value_can_hide(self):
        self.bad(man({"service": "openai", "value": KEY}), "unknown member")

    def test_env_vars_must_be_names_not_values(self):
        self.bad(man({"service": "openai", "env_vars": [KEY]}), "NAMES")
        self.bad(man({"service": "openai", "env_vars": ["OPENAI_API_KEY=abc"]}), "NAMES")
        self.bad(man({"service": "openai", "env_vars": ["A B"]}), "NAMES")

    def test_slug_checked(self):
        self.bad(man("../etc"), "service")
        self.bad(man({"service": 5}), "service")

    def test_duplicate_refused(self):
        self.bad(man("openai", "openai"), "twice")

    def test_store_values(self):
        self.bad(man({"service": "openai", "store": "cloud"}), "store")
        manifest.validate(man({"service": "openai", "store": "keychain"}))

    def test_max_age_range(self):
        self.bad(man("a", max_age_days=0), "max_age_days")
        self.bad(man("a", max_age_days="90"), "max_age_days")
        self.bad(man("a", max_age_days=True), "max_age_days")

    def test_env_file_must_stay_inside(self):
        self.bad(man("a", env_file="/etc/passwd"), "env_file")
        self.bad(man("a", env_file="../x"), "env_file")
        manifest.validate(man("a", env_file="config/.env"))

    def test_version(self):
        self.bad({"version": 2, "services": []}, "version")

    def test_not_an_object(self):
        self.bad([], "object")

    def test_services_must_be_a_list(self):
        self.bad({"version": 1, "services": "x"}, "list")


class TestManifestFiles(unittest.TestCase):
    def test_save_and_load_roundtrip_is_committable(self):
        d = proj()
        path = os.path.join(d, manifest.FILE_NAME)
        manifest.save(path, man("openai", "stripe"))
        self.assertEqual(manifest.load(path)["services"][1]["service"], "stripe")
        with open(path, encoding="utf-8") as f:
            self.assertTrue(f.read().endswith("}\n"))

    def test_save_refuses_a_bad_manifest_and_writes_nothing(self):
        d = proj()
        path = os.path.join(d, manifest.FILE_NAME)
        with self.assertRaises(manifest.ManifestError):
            manifest.save(path, man({"service": "a", "env_vars": [KEY]}))
        self.assertFalse(os.path.exists(path))

    def test_invalid_json_is_a_sentence_not_a_traceback(self):
        d = proj({manifest.FILE_NAME: "{nope"})
        with self.assertRaises(manifest.ManifestError) as cm:
            manifest.load(os.path.join(d, manifest.FILE_NAME))
        self.assertIn("not valid JSON", str(cm.exception))

    def test_bom_is_tolerated(self):
        d = proj()
        path = os.path.join(d, manifest.FILE_NAME)
        with open(path, "wb") as f:
            f.write(b"\xef\xbb\xbf" + json.dumps(man("openai")).encode())
        self.assertTrue(manifest.load(path))

    def test_huge_file_refused(self):
        d = proj()
        path = os.path.join(d, manifest.FILE_NAME)
        with open(path, "w") as f:
            f.write(" " * (manifest.MAX_BYTES + 5))
        with self.assertRaises(manifest.ManifestError):
            manifest.load(path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks")
    def test_symlinked_manifest_refused(self):
        d = proj({"real.json": json.dumps(man("openai"))})
        link = os.path.join(d, manifest.FILE_NAME)
        try:
            os.symlink(os.path.join(d, "real.json"), link)
        except OSError:
            self.skipTest("no symlink right")
        with self.assertRaises(manifest.ManifestError):
            manifest.load(link)

    def test_find_walks_up(self):
        d = proj({manifest.FILE_NAME: json.dumps(man("openai")), "a/b/x.txt": "", ".git/HEAD": ""})
        self.assertEqual(manifest.find(os.path.join(d, "a", "b")), os.path.realpath(os.path.join(d, manifest.FILE_NAME)))

    def test_find_none(self):
        self.assertIsNone(manifest.find(proj()))

    def test_service_vars_default_to_the_recipes(self):
        self.assertEqual(manifest.service_vars({"service": "twilio"}, CAT["twilio"]),
                         ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"])
        self.assertEqual(manifest.service_vars({"service": "x", "env_vars": ["A"]}, None), ["A"])


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.idx = os.path.join(_isolation.mktemp(), "index.json")
        self.p = proj()

    def test_record_and_get(self):
        ledger.record(self.p, "openai", "env", index_path=self.idx)
        e = ledger.get(self.p, "openai", self.idx)
        self.assertEqual(e["store"], "env")
        self.assertTrue(e["created_at"])

    def test_the_index_holds_no_key_material(self):
        ledger.record(self.p, "openai", "keychain", index_path=self.idx)
        with open(self.idx, encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("sk-", text)
        self.assertEqual(set(json.loads(text)["projects"][os.path.realpath(self.p)]["openai"]),
                         {"created_at", "updated_at", "store"})

    @unittest.skipIf(os.name == "nt", "mode bits")
    def test_the_index_is_owner_only(self):
        ledger.record(self.p, "openai", "env", index_path=self.idx)
        self.assertEqual(store_mod.file_mode(self.idx), 0o600)

    def test_created_at_survives_a_rotation(self):
        t1 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        t2 = datetime.datetime(2026, 3, 1, tzinfo=datetime.timezone.utc)
        ledger.record(self.p, "openai", "env", index_path=self.idx, now=t1)
        ledger.record(self.p, "openai", "env", rotated=True, index_path=self.idx, now=t2)
        e = ledger.get(self.p, "openai", self.idx)
        self.assertTrue(e["created_at"].startswith("2026-01-01"))
        self.assertTrue(e["rotated_at"].startswith("2026-03-01"))

    def test_age_counts_from_the_last_rotation(self):
        e = {"created_at": "2026-01-01T00:00:00+00:00", "rotated_at": "2026-03-01T00:00:00+00:00"}
        now = datetime.datetime(2026, 3, 11, tzinfo=datetime.timezone.utc)
        self.assertEqual(ledger.age_days(e, now), 10)

    def test_age_none_without_a_record_or_with_junk(self):
        self.assertIsNone(ledger.age_days(None))
        self.assertIsNone(ledger.age_days({"created_at": "yesterday"}))

    def test_naive_timestamp_is_treated_as_utc(self):
        now = datetime.datetime(2026, 1, 3, tzinfo=datetime.timezone.utc)
        self.assertEqual(ledger.age_days({"created_at": "2026-01-01T00:00:00"}, now), 2)

    def test_forget(self):
        ledger.record(self.p, "openai", "env", index_path=self.idx)
        ledger.forget(self.p, "openai", self.idx)
        self.assertIsNone(ledger.get(self.p, "openai", self.idx))

    def test_projects_are_separate(self):
        other = proj()
        ledger.record(self.p, "openai", "env", index_path=self.idx)
        self.assertIsNone(ledger.get(other, "openai", self.idx))

    def test_a_corrupt_index_is_empty_not_a_crash(self):
        with open(self.idx, "w") as f:
            f.write("{{{")
        self.assertEqual(ledger.load(self.idx), {})
        ledger.record(self.p, "openai", "env", index_path=self.idx)
        self.assertTrue(ledger.get(self.p, "openai", self.idx))

    def test_get_drops_unknown_members(self):
        with open(self.idx, "w") as f:
            json.dump({"projects": {os.path.realpath(self.p): {"openai": {"created_at": "x", "secret": "s"}}}}, f)
        self.assertNotIn("secret", ledger.get(self.p, "openai", self.idx))

    def test_cli_connect_records_the_key_without_it(self):
        env = os.path.join(self.p, ".env")
        # own home folder: an index another test signed with a different (memory)
        # key would otherwise be, correctly, refused as unverifiable
        fresh_home = _isolation.mktemp()
        with mock.patch.dict(os.environ, {"HOME": fresh_home, "USERPROFILE": fresh_home}), \
                cd(self.p), mock.patch.object(cli_mod.connect_mod, "connect", return_value=0):
            code = cli_mod.connect_service(CAT["openai"], env_file=env, no_browser=True)
            self.assertEqual(code, 0)
            self.assertTrue(ledger.get(self.p, "openai"))

    def test_a_failed_connect_records_nothing(self):
        with cd(self.p), mock.patch.object(cli_mod.connect_mod, "connect", return_value=1):
            cli_mod.connect_service(CAT["openai"], env_file=os.path.join(self.p, ".env"), no_browser=True)
        self.assertIsNone(ledger.get(self.p, "openai"))


class TestPresence(unittest.TestCase):
    def test_env_names_nonempty_only(self):
        d = proj({".env": f"A={KEY}\nB=\nC='  '\n"})
        self.assertEqual(presence.env_names(os.path.join(d, ".env")), {"A"})

    def test_missing_file(self):
        self.assertEqual(presence.env_names(os.path.join(proj(), ".env")), set())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks")
    def test_a_link_is_not_read(self):
        d = proj({"real": f"A={KEY}\n"})
        try:
            os.symlink(os.path.join(d, "real"), os.path.join(d, ".env"))
        except OSError:
            self.skipTest("no symlink right")
        self.assertEqual(presence.env_names(os.path.join(d, ".env")), set())

    def test_locate_complete_and_missing(self):
        d = proj({".env": "TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"})
        r = presence.locate("twilio", ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"],
                            os.path.join(d, ".env"), check_keychain=False)
        self.assertFalse(r["complete"])
        self.assertEqual(r["missing"], ["TWILIO_AUTH_TOKEN"])

    def test_locate_uses_the_keychain_when_asked(self):
        r = presence.locate("openai", ["OPENAI_API_KEY"], os.path.join(proj(), ".env"),
                            True, read=lambda s, v, b: KEY, backend="fake")
        self.assertTrue(r["complete"])
        self.assertEqual(r["keychain"], ["OPENAI_API_KEY"])

    def test_no_keychain_is_none_not_false(self):
        r = presence.locate("openai", ["OPENAI_API_KEY"], os.path.join(proj(), ".env"),
                            True, read=lambda s, v, b: None, backend=None)
        with mock.patch.object(presence.keychain_mod, "detect_backend", return_value=None):
            r = presence.locate("openai", ["OPENAI_API_KEY"], os.path.join(proj(), ".env"), True)
        self.assertIsNone(r["keychain"])

    def test_presence_never_returns_a_value(self):
        d = proj({".env": f"OPENAI_API_KEY={KEY}\n"})
        r = presence.locate("openai", ["OPENAI_API_KEY"], os.path.join(d, ".env"), False)
        self.assertNotIn(KEY, json.dumps(r))


class TestDetect(unittest.TestCase):
    def test_reads_names_from_a_template_and_drops_values(self):
        d = proj({".env.example": f"OPENAI_API_KEY={KEY}\nOTHER=1\n# STRIPE_SECRET_KEY=x\n"})
        names, read = detect.names_in_project(d)
        self.assertIn("OPENAI_API_KEY", names)
        self.assertNotIn(KEY, names)
        self.assertEqual(read, [".env.example"])

    def test_never_opens_a_real_env_file(self):
        d = proj({".env": f"STRIPE_SECRET_KEY={KEY}\n", ".env.local": "GROQ_API_KEY=x\n",
                  "prod.env": "TAVILY_API_KEY=y\n"})
        with mock.patch.object(detect, "_read_limited", wraps=detect._read_limited) as rd:
            names, read = detect.names_in_project(d)
        self.assertEqual((names, read), (set(), []))
        self.assertEqual(rd.call_count, 0)

    def test_finds_names_in_code(self):
        d = proj({"app.py": 'import os\nk = os.environ["GROQ_API_KEY"]\n',
                  "src/a.ts": "const k = process.env.TAVILY_API_KEY\n",
                  "run.sh": "echo $STRIPE_SECRET_KEY\n"})
        names, _ = detect.names_in_project(d)
        self.assertTrue({"GROQ_API_KEY", "TAVILY_API_KEY", "STRIPE_SECRET_KEY"} <= names)

    def test_skips_node_modules_and_git(self):
        d = proj({"node_modules/x/a.js": "GROQ_API_KEY", ".git/a.py": "GROQ_API_KEY"})
        self.assertEqual(detect.names_in_project(d)[0], set())

    def test_skips_non_code_files(self):
        d = proj({"README.md": "GROQ_API_KEY", "notes.txt": "GROQ_API_KEY"})
        self.assertEqual(detect.names_in_project(d)[0], set())

    def test_big_and_binary_files_skipped(self):
        d = proj({"a.py": "x" * (detect.MAX_FILE_BYTES + 10)})
        with open(os.path.join(d, "b.py"), "wb") as f:
            f.write(b"GROQ_API_KEY\x00")
        self.assertEqual(detect.names_in_project(d)[0], set())

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks")
    def test_symlinked_files_not_followed(self):
        d = proj({"real.py": "GROQ_API_KEY"})
        try:
            os.symlink(os.path.join(d, "real.py"), os.path.join(d, "link.py"))
        except OSError:
            self.skipTest("no symlink right")
        _, read = detect.names_in_project(d)
        self.assertEqual(read, ["real.py"])

    @unittest.skipUnless(hasattr(os, "symlink") and hasattr(os, "O_NOFOLLOW"), "symlinks")
    def test_symlinked_files_not_followed_where_there_is_no_o_nofollow(self):
        # Windows: no O_NOFOLLOW, so the link must be refused by name
        d = proj({"real.py": "GROQ_API_KEY"})
        try:
            os.symlink(os.path.join(d, "real.py"), os.path.join(d, "link.py"))
        except OSError:
            self.skipTest("no symlink right")
        with mock.patch.object(detect.os, "O_NOFOLLOW", 0):
            _, read = detect.names_in_project(d)
        self.assertEqual(read, ["real.py"])

    def test_match_recipes_returns_all_vars_of_a_service(self):
        found = detect.match_recipes({"TWILIO_AUTH_TOKEN"}, CAT)
        self.assertEqual(found, [{"service": "twilio", "env_vars": ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN"]}])

    def test_unrelated_names_match_nothing(self):
        self.assertEqual(detect.match_recipes({"HOME", "PATH_X"}, CAT), [])

    def test_detect_end_to_end(self):
        d = proj({".env.example": "OPENAI_API_KEY=\nSTRIPE_SECRET_KEY=\n"})
        found, _ = detect.detect(d, CAT)
        self.assertEqual([f["service"] for f in found], ["openai", "stripe"])

    def test_file_cap(self):
        d = proj({f"f{i}.py": "x" for i in range(5)})
        with mock.patch.object(detect, "MAX_FILES", 2):
            _, read = detect.names_in_project(d)
        self.assertLessEqual(len(read), 2)


def run_cmd(fn, args, d, **kw):
    out = io.StringIO()
    with cd(d):
        code = fn(args, CAT, out=out, **kw) if "connect_fn" not in kw else None
    return code, out.getvalue()


class A:
    def __init__(self, **kw):
        self.__dict__.update(dict(write=False, add=False, force=False, service=[], env_file=None,
                                  dry_run=False, json=False, max_age=None), **kw)


class TestInit(unittest.TestCase):
    def init(self, d, **kw):
        out = io.StringIO()
        with cd(d):
            code = projectcmds.cmd_init(A(**kw), CAT, out)
        return code, out.getvalue()

    def test_preview_writes_nothing(self):
        d = proj({".env.example": "OPENAI_API_KEY=\n"})
        code, text = self.init(d)
        self.assertEqual(code, 0)
        self.assertIn("openai", text)
        self.assertFalse(os.path.exists(os.path.join(d, manifest.FILE_NAME)))
        self.assertIn("--write", text)

    def test_write_saves_names_only(self):
        d = proj({".env.example": f"OPENAI_API_KEY={KEY}\n", "app.py": "STRIPE_SECRET_KEY"})
        code, _ = self.init(d, write=True)
        self.assertEqual(code, 0)
        raw = json.dumps(jload(os.path.join(d, manifest.FILE_NAME)))
        self.assertNotIn(KEY, raw)
        data = json.loads(raw)
        self.assertEqual([s["service"] for s in data["services"]], ["openai", "stripe"])

    def test_refuses_to_overwrite(self):
        d = proj({manifest.FILE_NAME: json.dumps(man("groq")), ".env.example": "OPENAI_API_KEY=\n"})
        code, text = self.init(d, write=True)
        self.assertEqual(code, 1)
        self.assertIn("--add", text)
        self.assertEqual(jload(os.path.join(d, manifest.FILE_NAME))["services"][0]["service"], "groq")

    def test_add_keeps_existing_and_adds_new(self):
        d = proj({manifest.FILE_NAME: json.dumps(man({"service": "groq", "store": "keychain"})),
                  ".env.example": "OPENAI_API_KEY=\nGROQ_API_KEY=\n"})
        code, _ = self.init(d, write=True, add=True)
        data = jload(os.path.join(d, manifest.FILE_NAME))
        self.assertEqual(code, 0)
        self.assertEqual([s["service"] for s in data["services"]], ["groq", "openai"])
        self.assertEqual(data["services"][0]["store"], "keychain")

    def test_force_starts_over(self):
        d = proj({manifest.FILE_NAME: json.dumps(man("groq")), ".env.example": "OPENAI_API_KEY=\n"})
        self.init(d, write=True, force=True)
        data = jload(os.path.join(d, manifest.FILE_NAME))
        self.assertEqual([s["service"] for s in data["services"]], ["openai"])

    def test_nothing_found_says_so(self):
        code, text = self.init(proj())
        self.assertEqual(code, 0)
        self.assertIn("No variable names", text)
        self.assertIn("never a real .env", text)

    def test_real_env_in_the_folder_is_not_read(self):
        d = proj({".env": f"STRIPE_SECRET_KEY={KEY}\n"})
        code, text = self.init(d, write=True)
        self.assertNotIn(KEY, text)
        self.assertNotIn("stripe", text)

    def test_cli_wires_init(self):
        d = proj({".env.example": "GROQ_API_KEY=\n"})
        out = io.StringIO()
        with cd(d), mock.patch("sys.stdout", out):
            self.assertEqual(cli_mod.main(["init", "--write"]), 0)
        self.assertTrue(os.path.exists(os.path.join(d, manifest.FILE_NAME)))


class TestSetup(unittest.TestCase):
    def setup_(self, d, connect, **kw):
        out = io.StringIO()
        with cd(d):
            code = projectcmds.cmd_setup(A(**kw), CAT, connect, out, check_keychain=False)
        return code, out.getvalue()

    def fixture(self, env_text="", *services):
        files = {manifest.FILE_NAME: json.dumps(man(*services)), ".env": env_text}
        return proj(files)

    def test_connects_only_missing_services_in_order(self):
        d = self.fixture(f"GROQ_API_KEY={KEY}\n", "openai", "groq", "stripe")
        got = []
        code, text = self.setup_(d, lambda r, s, e: got.append(r["service"]) or 0)
        self.assertEqual(got, ["openai", "stripe"])
        self.assertEqual(code, 0)
        self.assertIn("groq", text)
        self.assertIn("already there", text)

    def test_a_failure_does_not_stop_the_rest_and_exit_is_1(self):
        d = self.fixture("", "openai", "groq")
        got = []

        def conn(r, s, e):
            got.append(r["service"])
            return 1 if r["service"] == "openai" else 0
        code, text = self.setup_(d, conn)
        self.assertEqual(got, ["openai", "groq"])
        self.assertEqual(code, 1)
        self.assertIn("failed", text)
        self.assertIn("`stuntkey setup` again", text)

    def test_interrupt_stops_and_names_what_was_not_reached(self):
        d = self.fixture("", "openai", "groq", "stripe")

        def conn(r, s, e):
            if r["service"] == "groq":
                raise KeyboardInterrupt
            return 0
        code, text = self.setup_(d, conn)
        self.assertEqual(code, 1)
        self.assertIn("interrupted", text)
        self.assertIn("not reached", text)

    def test_resumable_second_run_skips_what_the_first_stored(self):
        d = self.fixture("", "openai", "groq")
        envf = os.path.join(d, ".env")

        def conn(r, s, e):
            if r["service"] == "openai":
                store_mod.store_key("OPENAI_API_KEY", KEY, envf)
                return 0
            return 1
        self.setup_(d, conn)
        got = []
        self.setup_(d, lambda r, s, e: got.append(r["service"]) or 0)
        self.assertEqual(got, ["groq"])

    def test_store_from_the_manifest_is_passed_on(self):
        d = self.fixture("", {"service": "openai", "store": "keychain"})
        seen = []
        self.setup_(d, lambda r, s, e: seen.append(s) or 0)
        self.assertEqual(seen, ["keychain"])

    def test_dry_run_connects_nothing(self):
        d = self.fixture("", "openai")
        got = []
        code, text = self.setup_(d, lambda r, s, e: got.append(1) or 0, dry_run=True)
        self.assertEqual((got, code), ([], 0))
        self.assertIn("needed", text)

    def test_service_filter(self):
        d = self.fixture("", "openai", "groq")
        got = []
        self.setup_(d, lambda r, s, e: got.append(r["service"]) or 0, service=["groq"])
        self.assertEqual(got, ["groq"])

    def test_unknown_service_in_the_manifest_is_reported(self):
        d = self.fixture("", "nosuchvendor")
        code, text = self.setup_(d, lambda r, s, e: 0)
        self.assertEqual(code, 1)
        self.assertIn("no recipe", text)

    def test_no_manifest(self):
        out = io.StringIO()
        with cd(proj()):
            self.assertEqual(projectcmds.cmd_setup(A(), CAT, lambda *a: 0, out), 1)
        self.assertIn("stuntkey init", out.getvalue())

    def test_all_present_is_a_clean_exit(self):
        d = self.fixture(f"OPENAI_API_KEY={KEY}\n", "openai")
        code, text = self.setup_(d, lambda *a: self.fail("should not connect"))
        self.assertEqual(code, 0)
        self.assertIn("all keys are in place", text)

    def test_two_part_credential_is_only_done_when_both_are_there(self):
        d = self.fixture("TWILIO_ACCOUNT_SID=ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "twilio")
        got = []
        self.setup_(d, lambda r, s, e: got.append(r["service"]) or 0)
        self.assertEqual(got, ["twilio"])

    def test_output_never_contains_the_key(self):
        d = self.fixture(f"GROQ_API_KEY={KEY}\n", "openai", "groq")
        _, text = self.setup_(d, lambda *a: 0)
        self.assertNotIn(KEY, text)

    def test_env_file_from_the_manifest(self):
        d = proj({manifest.FILE_NAME: json.dumps(man("openai", env_file="cfg/.env")),
                  "cfg/.env": f"OPENAI_API_KEY={KEY}\n"})
        code, _ = self.setup_(d, lambda *a: self.fail("present in cfg/.env"))
        self.assertEqual(code, 0)


class TestKeychainIsAskedOnlyWhenItMatters(unittest.TestCase):
    def test_env_services_never_touch_the_keychain(self):
        d = proj({manifest.FILE_NAME: json.dumps(man("openai")), ".env": ""})
        out = io.StringIO()
        with cd(d):
            projectcmds.cmd_status(A(), CAT, out, check_keychain=True,
                                   read=lambda *a: self.fail("keychain asked"),
                                   index_path=os.path.join(_isolation.mktemp(), "i.json"))
            projectcmds.cmd_setup(A(dry_run=True), CAT, lambda *a: 0, out, check_keychain=True,
                                  read=lambda *a: self.fail("keychain asked"))

    def test_manifest_keychain_services_are_asked(self):
        d = proj({manifest.FILE_NAME: json.dumps(man({"service": "openai", "store": "keychain"})), ".env": ""})
        asked = []
        out = io.StringIO()
        with cd(d), mock.patch.object(presence.keychain_mod, "detect_backend", return_value="fake"):
            projectcmds.cmd_status(A(), CAT, out, check_keychain=True,
                                   read=lambda s, v, b: asked.append(v) or KEY,
                                   index_path=os.path.join(_isolation.mktemp(), "i.json"))
        self.assertEqual(asked, ["OPENAI_API_KEY"])
        self.assertIn("OS keychain", out.getvalue())

    def test_the_record_can_send_us_to_the_keychain_too(self):
        d = proj({manifest.FILE_NAME: json.dumps(man("openai")), ".env": ""})
        idx = os.path.join(_isolation.mktemp(), "i.json")
        ledger.record(d, "openai", "keychain", index_path=idx)
        self.assertTrue(projectcmds.wants_keychain({"service": "openai"}, d, idx))
        self.assertFalse(projectcmds.wants_keychain({"service": "groq"}, d, idx))


class TestStatus(unittest.TestCase):
    def status(self, d, idx=None, now=None, **kw):
        out = io.StringIO()
        with cd(d):
            code = projectcmds.cmd_status(A(**kw), CAT, out, check_keychain=False,
                                          index_path=idx, now=now)
        return code, out.getvalue()

    def fixture(self, env_text, *services, **extra):
        return proj({manifest.FILE_NAME: json.dumps(man(*services, **extra)), ".env": env_text})

    def test_table_and_where(self):
        d = self.fixture(f"OPENAI_API_KEY={KEY}\n", "openai")
        code, text = self.status(d, os.path.join(_isolation.mktemp(), "i.json"))
        self.assertEqual(code, 0)
        self.assertIn("stored", text)
        self.assertIn(".env", text)
        self.assertIn("(before records)", text)

    def test_missing_gives_the_command_and_exit_1(self):
        d = self.fixture("", "openai")
        code, text = self.status(d, os.path.join(_isolation.mktemp(), "i.json"))
        self.assertEqual(code, 1)
        self.assertIn("stuntkey connect openai", text)

    def test_age_and_rotate_hint_beyond_the_limit(self):
        d = self.fixture(f"OPENAI_API_KEY={KEY}\n", "openai")
        idx = os.path.join(_isolation.mktemp(), "i.json")
        t0 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        ledger.record(d, "openai", "env", index_path=idx, now=t0)
        now = t0 + datetime.timedelta(days=120)
        code, text = self.status(d, idx, now)
        self.assertEqual(code, 1)
        self.assertIn("120 days old (limit 90)", text)
        self.assertIn("stuntkey rotate openai", text)

    def test_young_key_no_hint(self):
        d = self.fixture(f"OPENAI_API_KEY={KEY}\n", "openai")
        idx = os.path.join(_isolation.mktemp(), "i.json")
        t0 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        ledger.record(d, "openai", "env", index_path=idx, now=t0)
        code, text = self.status(d, idx, t0 + datetime.timedelta(days=5))
        self.assertEqual(code, 0)
        self.assertNotIn("rotate", text)
        self.assertIn("5d", text)

    def test_max_age_flag_and_manifest_value(self):
        d = self.fixture(f"OPENAI_API_KEY={KEY}\n", "openai", max_age_days=10)
        idx = os.path.join(_isolation.mktemp(), "i.json")
        t0 = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        ledger.record(d, "openai", "env", index_path=idx, now=t0)
        now = t0 + datetime.timedelta(days=20)
        self.assertEqual(self.status(d, idx, now)[0], 1)
        self.assertEqual(self.status(d, idx, now, max_age=30)[0], 0)

    def test_json_has_no_secret_and_is_valid(self):
        d = self.fixture(f"OPENAI_API_KEY={KEY}\n", "openai", "groq")
        code, text = self.status(d, os.path.join(_isolation.mktemp(), "i.json"), json=True)
        data = json.loads(text)
        self.assertNotIn(KEY, text)
        self.assertEqual({s["service"]: s["state"] for s in data["services"]},
                         {"openai": "stored", "groq": "missing"})

    def test_partly_stored(self):
        d = self.fixture("TWILIO_ACCOUNT_SID=ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "twilio")
        code, text = self.status(d, os.path.join(_isolation.mktemp(), "i.json"), json=True)
        row = json.loads(text)["services"][0]
        self.assertEqual((row["state"], row["missing"]), ("partly stored", ["TWILIO_AUTH_TOKEN"]))

    def test_unknown_recipe_is_listed_not_crashed(self):
        d = self.fixture("", "nosuchvendor")
        code, text = self.status(d, os.path.join(_isolation.mktemp(), "i.json"))
        self.assertEqual(code, 1)

    def test_no_manifest(self):
        code, text = self.status(proj())
        self.assertEqual(code, 1)
        self.assertIn("init", text)

    def test_cli_status_runs(self):
        d = self.fixture(f"OPENAI_API_KEY={KEY}\n", "openai")
        out = io.StringIO()
        with cd(d), mock.patch("sys.stdout", out), \
                mock.patch.object(projectcmds.keychain_mod, "read", return_value=None), \
                mock.patch.object(projectcmds.keychain_mod, "detect_backend", return_value=None):
            code = cli_mod.main(["status"])
        self.assertIn("openai", out.getvalue())
        self.assertNotIn(KEY, out.getvalue())


if __name__ == "__main__":
    unittest.main()


class DetectBoundsTests(unittest.TestCase):
    def test_walk_stops_at_dir_cap(self):
        import tempfile, os
        from stuntkey import detect
        with tempfile.TemporaryDirectory() as d:
            for i in range(6):
                os.makedirs(os.path.join(d, f"d{i}"))
                with open(os.path.join(d, f"d{i}", "a.py"), "w") as f:
                    f.write("import os\nos.environ['OPENAI_API_KEY']\n")
            old = detect.MAX_DIRS
            detect.MAX_DIRS = 2
            try:
                _, read = detect.names_in_project(d)
            finally:
                detect.MAX_DIRS = old
            self.assertLess(len(read), 6)


class ReadNoFollowTests(unittest.TestCase):
    def test_symlink_not_followed(self):
        import tempfile, os
        from stuntkey import store
        if not hasattr(os, "symlink") or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("no symlinks")
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real"); open(real, "w").write("A=1\n")
            link = os.path.join(d, ".env"); os.symlink(real, link)
            with self.assertRaises(store.EnvFileRefused):
                store._read_bytes(link)
            self.assertEqual(store._read_bytes(os.path.join(d, "none")), b"")
