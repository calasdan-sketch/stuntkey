"""`stuntkey get <any site>`: a site with no built-in recipe. No network: the
catalog lookup, the browser, the clipboard and the keychain are all fakes."""
import io
import os
import tempfile
import unittest
from unittest import mock

import _isolation  # noqa: F401  (fake HOME/USERPROFILE for the whole run)
from stuntkey import anysite, cli, clipboard, connect, recipes

FAKE_KEY = "mg-0123456789abcdef0123456789abcdef"


def catalog():
    return recipes.load_recipes(recipes.RECIPES_DIR)


class Resolve(unittest.TestCase):
    def test_address_is_used_without_a_question(self):
        ask = mock.Mock(side_effect=AssertionError("asked"))
        for typed in ("mailgun.com", "https://app.mailgun.com/x", "Mailgun.com"):
            self.assertEqual(anysite.resolve(typed, ask, io.StringIO(), lambda n: None),
                             "mailgun.com")

    def test_name_from_catalog_needs_a_yes(self):
        self.assertEqual(anysite.resolve("mailgun", lambda q: "y", io.StringIO(),
                                         lambda n: "mailgun.com"), "mailgun.com")

    def test_no_to_the_catalog_guess_stops(self):
        out = io.StringIO()
        self.assertIsNone(anysite.resolve("mailgun", lambda q: "", out,
                                          lambda n: "mailgun.com"))
        self.assertIn("nothing was saved", out.getvalue())

    def test_unknown_name_asks_for_the_address(self):
        self.assertEqual(anysite.resolve("acme", lambda q: "acme.io", io.StringIO(),
                                         lambda n: None), "acme.io")

    def test_a_pasted_key_is_not_a_site(self):
        jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
               "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        for text in (jwt, FAKE_KEY, "sk-" + "a" * 60):
            self.assertFalse(anysite.looks_like_site(text), text)


class Typos(unittest.TestCase):
    def test_a_near_typo_is_not_a_new_site(self):
        self.assertFalse(anysite.looks_like_site("githb", catalog()))
        self.assertTrue(anysite.looks_like_site("acmewidgets", catalog()))


class BuildRecipe(unittest.TestCase):
    def test_key_only_goes_to_that_site(self):
        r = anysite.build_recipe("acme.io", catalog())
        self.assertTrue(r["untested"])
        self.assertEqual(recipes._hosts(r), frozenset({"api.acme.io"}))
        self.assertTrue(connect.same_owner(r["key_url"], r["validate"]["url"]))

    def test_built_in_site_uses_the_built_in_recipe(self):
        for domain, slug in (("github.com", "github"), ("mailgun.com", "mailgun")):
            r = anysite.build_recipe(domain, catalog())
            self.assertEqual(r["service"], slug)
            self.assertFalse(r.get("untested"))

    def test_a_taken_name_on_another_site_gets_its_own(self):
        cat = catalog()
        r = anysite.build_recipe("github.example", cat)
        self.assertNotEqual(r["service"], "github")
        self.assertTrue(r["untested"])
        self.assertNotIn(r["env_var"], {v for x in cat.values() for v in recipes.env_vars(x)})


class Flow(unittest.TestCase):
    def _connect(self, recipe, confirm="y"):
        """The real connect flow with fake browser, clipboard and keychain."""
        out, opened, stored = io.StringIO(), [], {}
        sent = mock.Mock(side_effect=AssertionError("the key was sent"))
        clip = ["", FAKE_KEY]             # empty when waiting starts, then a Copy

        def get():
            return clip.pop(0) if len(clip) > 1 else clip[0]

        def clear():
            clip[:] = [""]
            return True
        code = connect.connect(recipe, browser_open=opened.append, out=out,
                               prompt=mock.Mock(side_effect=AssertionError("prompted")),
                               validate_fn=sent, confirm_in=lambda q: "",
                               store_fn=lambda var, key: stored.setdefault(var, key) and
                               f"saved {var}", clipboard=(get, clear))
        return code, out.getvalue(), opened, stored

    def test_untested_key_is_saved_never_sent_and_says_so(self):
        r = anysite.build_recipe("acme.io", catalog())
        with mock.patch.object(clipboard, "WAIT_SECONDS", 1):
            code, text, opened, stored = self._connect(r)
        self.assertEqual(code, 0, text)
        self.assertEqual(stored, {r["env_var"]: FAKE_KEY})
        self.assertIn("NOT be tested", text)
        self.assertIn("Not tested", text)
        self.assertNotIn("validating", text)
        self.assertNotIn(FAKE_KEY, text)

    def test_cmd_get_saves_recipe_only_after_the_key(self):
        saved = []
        with tempfile.TemporaryDirectory() as d:
            code = anysite.cmd_get("acme", catalog(), lambda r, url: 0, ask=lambda q: "acme.io",
                                   out=io.StringIO(), lookup=lambda n: None,
                                   save=lambda r: saved.append(recipes.save_recipe(r, d)))
            self.assertEqual(code, 0)
            self.assertEqual(len(saved), 1)
            back = recipes.load_recipes(d)["acme"]
            self.assertTrue(back["untested"])
            self.assertEqual(os.path.basename(saved[0]), "acme.json")

    def test_declined_or_failed_saves_nothing(self):
        saved = []
        anysite.cmd_get("mailgun", catalog(), lambda r, url: 0, ask=lambda q: "n",
                        out=io.StringIO(), lookup=lambda n: "mailgun.com", save=saved.append)
        anysite.cmd_get("acme.io", catalog(), lambda r, url: 1, out=io.StringIO(),
                        save=saved.append)
        self.assertEqual(saved, [])

    def test_browser_opens_a_search_for_the_key_page(self):
        urls = []
        anysite.cmd_get("acme.io", catalog(), lambda r, url: urls.append(url) or 1,
                        out=io.StringIO(), save=lambda r: None)
        self.assertTrue(urls[0].startswith("https://duckduckgo.com/?q="))
        self.assertIn("acme.io", urls[0])


class CliRouting(unittest.TestCase):
    def _run(self, argv):
        seen = {}

        def fake_connect(recipe, **kw):
            seen["recipe"] = recipe
            return 1                      # stop before anything is saved
        with mock.patch.object(connect, "connect", fake_connect), \
                mock.patch.object(clipboard, "backend", lambda: (lambda: "", lambda: None)), \
                mock.patch.object(cli.keychain_mod, "detect_backend", lambda: "test"), \
                mock.patch.object(cli, "keychain_store", lambda r, e: "STORE"), \
                mock.patch("webbrowser.open", lambda u: None):
            code = cli.main(argv)
        return code, seen

    def test_built_in_get_is_unchanged(self):
        _, seen = self._run(["get", "github"])
        self.assertEqual(seen["recipe"]["service"], "github")
        self.assertFalse(seen["recipe"].get("untested"))

    def test_get_any_site_runs_the_new_flow(self):
        _, seen = self._run(["get", "acme.io"])
        self.assertTrue(seen["recipe"]["untested"])

    def test_connect_still_refuses_an_unknown_service(self):
        code, seen = self._run(["connect", "acme.io"])
        self.assertEqual(code, 3)
        self.assertEqual(seen, {})


if __name__ == "__main__":
    unittest.main()
