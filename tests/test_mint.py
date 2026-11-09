"""`stuntkey mint`: a fresh Cloudflare key made by API, checked, saved in the
keychain, never shown. Fake HTTP and keychain only - no network."""
import contextlib
import io
import json
import tempfile
import unittest
import urllib.parse

import _isolation  # noqa: F401
from stuntkey import mint as mint_mod, recipes

ACCT = "9c5b166d981d18966737476631e557a3"
PARENT = "cfut_PARENTparentPARENTparent0123"
NEW = "cfut_NEWnewNEWnewNEWnew456789abc"


def recipe(**mint):
    return recipes.validate_recipe({
        "service": "cloudflare-analytics", "display": "Cloudflare traffic",
        "env_var": "CF_ANALYTICS_TOKEN", "key_url": "https://dash.cloudflare.com/profile/api-tokens",
        "steps": ["x"], "validate": {"method": "GET", "expect": [200], "auth": {"type": "bearer"},
                                     "url": "https://api.cloudflare.com/client/v4/user/tokens/verify"},
        "mint": dict({"vendor": "cloudflare", "permissions": ["Account Analytics Read"],
                      "account": ACCT}, **mint)})


class FakeKeychain:
    def __init__(self, parent=PARENT):
        self.items = {("cloudflare-keymaker", "CLOUDFLARE_KEYMAKER_TOKEN"): parent} if parent else {}

    def read(self, service, env_var):
        return self.items.get((service, env_var))

    def store(self, service, env_var, key):
        self.items[(service, env_var)] = key


class FakeCloudflare:
    def __init__(self, groups=None):
        self.calls = []
        self.groups = groups if groups is not None else [{"id": "g-analytics", "name": "Account Analytics Read"}]

    def send(self, req, ip, timeout):
        host = urllib.parse.urlsplit(req.full_url).hostname
        self.calls.append((req.get_method(), host, req.full_url, req.get_header("Authorization"),
                           json.loads(req.data) if req.data else None))
        path = urllib.parse.urlsplit(req.full_url).path
        if path.endswith("/permission_groups"):
            result = self.groups
        elif req.get_method() == "POST":
            result = {"id": "tok-new", "value": NEW}
        else:
            result = {"id": path.rsplit("/", 1)[-1]}
        return 200, {}, json.dumps({"success": True, "errors": [], "result": result}).encode()


def resolver(host, port, type=None):
    return [(2, 1, 6, "", ("104.16.0.1", port))]


class Valid:
    status = "valid"


def run(rec, kc, cf, state=None):
    state = state or tempfile.mktemp(suffix=".json")
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        mint_mod.mint(rec, keychain=kc, send=cf.send, resolver=resolver,
                      validate_fn=lambda spec, key: Valid(), state_path=state, sleep=lambda s: None)
    return buf.getvalue(), state


class Mint(unittest.TestCase):
    def test_happy_path_stores_the_new_key_and_never_prints_it(self):
        kc, cf = FakeKeychain(), FakeCloudflare()
        out, _ = run(recipe(), kc, cf)
        self.assertEqual(kc.read("cloudflare-analytics", "CF_ANALYTICS_TOKEN"), NEW)
        self.assertNotIn(NEW, out)
        self.assertNotIn(PARENT, out)
        post = [c for c in cf.calls if c[0] == "POST"][0]
        self.assertEqual(post[4]["policies"][0]["permission_groups"], [{"id": "g-analytics"}])
        self.assertEqual(list(post[4]["policies"][0]["resources"]), [f"com.cloudflare.api.account.{ACCT}"])

    def test_keymaker_token_goes_only_to_cloudflare_api(self):
        cf = FakeCloudflare()
        run(recipe(), FakeKeychain(), cf)
        self.assertTrue(cf.calls)
        for method, host, url, auth, body in cf.calls:
            self.assertEqual(host, "api.cloudflare.com")
            self.assertTrue(url.startswith("https://"))

    def test_remint_deletes_the_previous_token_after_saving(self):
        kc, cf = FakeKeychain(), FakeCloudflare()
        _, state = run(recipe(), kc, cf)
        with open(state, "w") as f:
            json.dump({"cloudflare-analytics": "tok-old"}, f)
        run(recipe(), kc, cf, state)
        self.assertIn(("DELETE", "https://api.cloudflare.com/client/v4/user/tokens/tok-old"),
                      [(c[0], c[2]) for c in cf.calls])

    def test_missing_keymaker_says_one_plain_thing(self):
        with self.assertRaises(mint_mod.MintFailed) as e:
            run(recipe(), FakeKeychain(parent=None), FakeCloudflare())
        self.assertIn("stuntkey get cloudflare-keymaker", str(e.exception))

    def test_unknown_permission_stores_nothing(self):
        kc, cf = FakeKeychain(), FakeCloudflare(groups=[{"id": "x", "name": "Zone Read"}])
        with self.assertRaises(mint_mod.MintFailed) as e:
            run(recipe(), kc, cf)
        self.assertIn("Account Analytics Read", str(e.exception))
        self.assertIsNone(kc.read("cloudflare-analytics", "CF_ANALYTICS_TOKEN"))
        self.assertFalse([c for c in cf.calls if c[0] == "POST"])

    def test_failed_check_deletes_the_new_token_and_stores_nothing(self):
        kc, cf = FakeKeychain(), FakeCloudflare()

        class Bad:
            status = "invalid"
        with self.assertRaises(mint_mod.MintFailed):
            mint_mod.mint(recipe(), keychain=kc, send=cf.send, resolver=resolver,
                          validate_fn=lambda s, k: Bad(), state_path=tempfile.mktemp(),
                          sleep=lambda s: None, out=lambda *a: None)
        self.assertIsNone(kc.read("cloudflare-analytics", "CF_ANALYTICS_TOKEN"))
        self.assertIn("DELETE", [c[0] for c in cf.calls])


class RecipeCheck(unittest.TestCase):
    def test_bad_mint_blocks_are_refused(self):
        for bad in ({"vendor": "aws"}, {"permissions": []}, {"permissions": "Account Analytics Read"},
                    {"account": "not-hex"}):
            with self.subTest(bad=bad), self.assertRaises(recipes.RecipeError):
                recipe(**bad)

    def test_mint_key_may_only_be_checked_at_cloudflare(self):
        data = recipe()
        data = dict(data, validate=dict(data["validate"], url="https://evil.example/verify"))
        with self.assertRaises(recipes.RecipeError):
            recipes.validate_recipe(data)

    def test_keymaker_recipe_ships(self):
        self.assertIn("cloudflare-keymaker", recipes.load_recipes())


if __name__ == "__main__":
    unittest.main()
