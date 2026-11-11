"""0.6.0: the shipped recipes carry the corrections from the vendors' own docs."""
import json
import os
import re
import unittest

import _isolation  # noqa: F401
import stuntkey
from _stub import Stub
from stuntkey import clipboard as clipboard_mod
from stuntkey import recipes as recipes_mod
from stuntkey import scan as scan_mod
from stuntkey import validate as validate_mod

CAT = recipes_mod.load_recipes(recipes_mod.RECIPES_DIR)
def _raw(n):
    with open(os.path.join(recipes_mod.RECIPES_DIR, n), encoding="utf-8") as f:
        return json.load(f)


RAW = {n[:-5]: _raw(n) for n in os.listdir(recipes_mod.RECIPES_DIR) if n.endswith(".json")}

# the six whose shape the vendors' docs do NOT give: no copy-and-go gate
NO_GATE = ("groq", "huggingface", "openai", "openrouter", "sendgrid", "tavily")
# documented prefix kept loose
LOOSE = {"anthropic": "sk-ant-api03-xyz", "stripe": "sk_live_abc", "aws": "AKIAABCDEFGHIJKLMNOP"}


def field(slug, i=0):
    return recipes_mod.fields(CAT[slug])[i]


def steps(slug):
    return " ".join(CAT[slug]["steps"])


class TestEveryRecipe(unittest.TestCase):
    pass


def _make(slug):
    def schema(self):
        recipes_mod.validate_recipe(json.loads(json.dumps(RAW[slug])))

    def lp(self):
        r = CAT[slug]
        self.assertTrue(r["least_privilege"]["summary"].strip())

    def only_documented_gate_text(self):
        # no step claims a key "starts with" a shape unless the vendor documents it
        text = steps(slug).lower()
        if slug in NO_GATE or slug in ("google-gemini", "supabase", "airtable", "openai"):
            self.assertNotRegex(text, r"starts? with ['\"]")

    def no_file_is_unformatted(self):
        with open(os.path.join(recipes_mod.RECIPES_DIR, slug + ".json"), encoding="utf-8") as f:
            raw = f.read()
        self.assertTrue(raw.endswith("}\n"))
        self.assertEqual(json.loads(raw), RAW[slug])
    return schema, lp, only_documented_gate_text, no_file_is_unformatted


for _slug in sorted(RAW):
    for _name, _fn in zip(("schema", "least_privilege", "no_undocumented_prefix_claims", "file_is_tidy"), _make(_slug)):
        setattr(TestEveryRecipe, f"test_{_slug.replace('-', '_')}_{_name}", _fn)


class TestAcceptGateNeverRefusesAValidKey(unittest.TestCase):
    def test_no_gate_for_the_six_undocumented_shapes(self):
        for slug in NO_GATE:
            self.assertIsNone(field(slug)["accept"], slug)

    def test_their_scan_heuristics_are_kept_and_called_guesses(self):
        for slug in NO_GATE:
            f = field(slug)
            self.assertTrue(f["detect"], slug)
            self.assertEqual(f["detect_confidence"], "guess", slug)

    def test_documented_prefixes_are_prefix_only(self):
        for slug, sample in LOOSE.items():
            self.assertTrue(re.search(field(slug)["accept"], sample), slug)
        self.assertEqual(field("anthropic")["accept"], "^sk-ant-")

    def test_stripe_accepts_every_documented_key_family(self):
        for key in ("sk_test_a", "sk_live_a", "rk_test_a", "rk_live_a"):
            self.assertTrue(clipboard_mod.looks_like(key + "BCDEFGH", field("stripe")["accept"]), key)

    def test_stripe_gate_does_not_demand_a_length(self):
        self.assertTrue(clipboard_mod.looks_like("sk_live_" + "A" * 8, field("stripe")["accept"]))
        self.assertTrue(clipboard_mod.looks_like("sk_live_" + "A" * 300, field("stripe")["accept"]))

    def test_aws_gate_is_akia_only(self):
        self.assertTrue(clipboard_mod.looks_like("AKIAIOSFODNN7EXAMPLE", field("aws", 0)["accept"]))
        self.assertFalse(clipboard_mod.looks_like("ASIAIOSFODNN7EXAMPLE", field("aws", 0)["accept"]))

    def test_github_has_no_gate_because_old_tokens_have_no_prefix(self):
        self.assertIsNone(field("github")["accept"])
        self.assertTrue(clipboard_mod.looks_like("a" * 40, field("github")["accept"]))

    def test_vercel_and_cloudflare_have_no_gate(self):
        self.assertIsNone(field("vercel")["accept"])
        self.assertIsNone(field("cloudflare")["accept"])

    def test_documented_exact_shapes_are_kept(self):
        self.assertEqual(field("replicate")["accept"], "^r8_.{37}$")
        self.assertEqual(field("twilio", 0)["accept"], "^AC[0-9a-fA-F]{32}$")

    def test_a_real_looking_key_for_each_gate_less_service_passes_the_generic_shape(self):
        for slug, key in (("openai", "sk-proj-abcdEFGH1234_-xyz"), ("groq", "gsk_abcdEFGH1234567890"),
                          ("sendgrid", "SG.abcdEFGH1234.xyz"), ("tavily", "tvly-dev-abcdEFGH"),
                          ("huggingface", "hf_abcdEFGH1234567890"), ("openrouter", "sk-or-v1-abcdEFGH12")):
            self.assertTrue(clipboard_mod.looks_like(key, field(slug)["accept"]), slug)
            self.assertTrue(clipboard_mod.looks_like("a-completely-different-shape-9", field(slug)["accept"]), slug)


class TestScanKeepsItsCoverage(unittest.TestCase):
    def finds(self, text, provider):
        res = scan_mod.scan_text(text, "x.txt", scan_mod.build_rules(CAT), CAT)
        return [f for f in res if f.provider == provider] if res else []

    def test_every_dropped_gate_is_still_detected(self):
        samples = {"groq": "GROQ_API_KEY=gsk_" + "aB3dE6gH9jK2mN5pQ8sT1vW4",
                   "openai": "OPENAI_API_KEY=sk-proj-" + "aB3dE6gH9jK2mN5pQ8sT1vW4",
                   "sendgrid": "SENDGRID_API_KEY=SG." + "aB3dE6gH9jK2mN5pQ8sT1v.xY7zA0bC3dE6gH9jK2mN5pQ8sT1vW4",
                   "tavily": "TAVILY_API_KEY=tvly-" + "aB3dE6gH9jK2mN5pQ8sT1vW4",
                   "huggingface": "HF_TOKEN=hf_" + "aB3dE6gH9jK2mN5pQ8sT1vW4",
                   "openrouter": "OPENROUTER_API_KEY=sk-or-v1-" + "aB3dE6gH9jK2mN5pQ8sT1vW4"}
        for slug, line in samples.items():
            hits = self.finds(line, slug)
            self.assertTrue(hits, slug)

    def test_guessed_shapes_say_so(self):
        hits = self.finds("GROQ_API_KEY=gsk_aB3dE6gH9jK2mN5pQ8sT1vW4", "groq")
        self.assertTrue(any(h.confidence == "guess" for h in hits))

    def test_documented_shapes_stay_known(self):
        hits = self.finds("X=sk_live_" + "aB3dE6gH9jK2mN5pQ8sT1vW4", "stripe")
        self.assertTrue(any(h.confidence == "known" for h in hits))

    def test_supabase_new_secret_key_is_found(self):
        res = scan_mod.scan_text("k=sb_secret_" + "aB3dE6gH9jK2mN5pQ8sT1vW4xY", "x.txt", scan_mod.build_rules(CAT), CAT)
        self.assertTrue(res)

    def test_sbp_is_labelled_a_guess(self):
        res = scan_mod.scan_text("k=sbp_" + "a1b2c3d4e5" * 4, "x.txt", scan_mod.build_rules(CAT), CAT)
        self.assertTrue(res and all(h.confidence == "guess" for h in res))


class TestFindingsApplied(unittest.TestCase):
    def test_airtable_step_says_opaque_not_pat(self):
        self.assertNotIn("starts with", steps("airtable"))
        self.assertIn("opaque", steps("airtable"))

    def test_aws_uses_the_documented_post(self):
        v = CAT["aws"]["validate"]
        self.assertEqual((v["method"], v["body"]), ("POST", recipes_mod.STS_BODY))
        self.assertIn("'Other'", steps("aws"))
        self.assertIn("session token", steps("aws"))

    def test_brave_requires_a_plan_and_drops_the_free_claim(self):
        self.assertNotIn("free plan", steps("brave-search").lower())
        self.assertIn("activate a plan", steps("brave-search"))

    def test_cloudflare_notes_account_tokens_and_cfut(self):
        self.assertIn("cfut_", field("cloudflare")["detect"])
        self.assertTrue(CAT["cloudflare"]["unverified"])

    def test_cohere_uses_v1_models_and_flags_it(self):
        self.assertTrue(CAT["cohere"]["validate"]["url"].endswith("/v1/models"))
        self.assertTrue(CAT["cohere"]["unverified"])

    def test_discord_wording_is_flagged_unverified(self):
        self.assertTrue(CAT["discord"]["unverified"])

    def test_ebay_checks_the_token_call_alone(self):
        v = CAT["ebay"]["validate"]
        self.assertTrue(v["auth"]["token_only"])
        self.assertNotIn("browse", v["url"])
        self.assertEqual([f["label"] for f in recipes_mod.fields(CAT["ebay"])],
                         ["Client ID (App ID)", "Client secret (Cert ID)"])

    def test_elevenlabs_key_page_and_limited_rules(self):
        self.assertEqual(CAT["elevenlabs"]["key_url"], "https://elevenlabs.io/app/api/api-keys")
        self.assertEqual(CAT["elevenlabs"]["validate"]["limited"][0]["status"], 403)
        self.assertTrue(CAT["elevenlabs"]["unverified"])

    def test_github_recommends_fine_grained(self):
        self.assertEqual(CAT["github"]["key_url"], "https://github.com/settings/personal-access-tokens/new")
        self.assertIn("Fine-grained", steps("github"))
        self.assertEqual(CAT["github"]["validate"]["reject"], [401])
        self.assertEqual(CAT["github"]["validate"]["limited"][0]["status"], 403)
        self.assertEqual(CAT["github"]["scopes"], [])

    def test_github_detect_is_loosened_but_documented_prefixes_only(self):
        rx = re.compile(field("github")["detect"])
        for tok in ("ghp_" + "A" * 36, "github_pat_" + "B" * 40, "gho_" + "c" * 30, "ghs_" + "d" * 25):
            self.assertTrue(rx.fullmatch(tok), tok)

    def test_gemini_no_longer_claims_aiza(self):
        self.assertNotIn("AIza", steps("google-gemini"))
        self.assertIn("Copy the key", steps("google-gemini"))

    def test_groq_and_huggingface_steps_do_not_claim_a_prefix(self):
        self.assertNotIn("gsk_", steps("groq"))
        self.assertNotIn("hf_", steps("huggingface"))
        self.assertIn("Fine-grained", steps("huggingface"))

    def test_mailgun_asks_for_the_main_key(self):
        self.assertIn("main account API key", steps("mailgun"))
        self.assertIn("sending key", steps("mailgun"))
        self.assertTrue(CAT["mailgun"]["unverified"])

    def test_netlify_notes_saml(self):
        self.assertIn("SAML", steps("netlify"))

    def test_openai_not_starts_with_sk(self):
        self.assertNotIn("starts with", steps("openai"))
        self.assertIn("Admin keys", steps("openai"))

    def test_openrouter_url_limit_and_no_google(self):
        self.assertTrue(CAT["openrouter"]["validate"]["url"].endswith("/api/v1/key"))
        self.assertIn("credit limit", steps("openrouter"))
        self.assertNotIn("Leave the credit limit empty", steps("openrouter"))
        self.assertNotIn("Google", steps("openrouter"))

    def test_openweather_warns_new_keys_look_wrong_and_use_quota(self):
        self.assertIn("2 hours", steps("openweather"))
        self.assertIn("quota", steps("openweather"))

    def test_paypal_has_a_sandbox_sibling(self):
        sb = CAT["paypal-sandbox"]
        self.assertIn("sandbox", sb["validate"]["auth"]["token_url"])
        self.assertNotEqual(sb["env_var"], CAT["paypal"]["env_var"])
        self.assertIn("paypal-sandbox", steps("paypal"))
        self.assertTrue(CAT["paypal"]["unverified"])

    def test_postmark_needs_a_server_token(self):
        self.assertIn("SERVER token", steps("postmark"))
        self.assertIn("'API Tokens' tab", steps("postmark"))

    def test_resend_restricted_key_is_valid_but_limited(self):
        rule = CAT["resend"]["validate"]["body_rules"][0]
        self.assertEqual((rule["status"], rule["body_contains"], rule["result"]),
                         (401, "restricted_api_key", "limited"))
        self.assertIn("Sending access", steps("resend"))
        self.assertIn("Create API Key", steps("resend"))

    def test_sendgrid_permission_names_are_current(self):
        self.assertIn("Custom Access", steps("sendgrid"))
        self.assertNotIn("Restricted Access", steps("sendgrid"))
        self.assertEqual(CAT["sendgrid"]["validate"]["limited"][0]["status"], 403)

    def test_spotify_checks_only_the_token_step(self):
        self.assertTrue(CAT["spotify"]["validate"]["auth"]["token_only"])
        self.assertIn("Premium", steps("spotify"))

    def test_stripe_prefers_restricted_and_403_is_limited(self):
        self.assertIn("restricted", steps("stripe").lower())
        self.assertEqual(CAT["stripe"]["validate"]["limited"][0]["status"], 403)

    def test_vercel_invalid_token_403_is_not_called_limited(self):
        # Vercel is believed to answer a bad token with 403 + invalidToken:true
        self.assertEqual(self.run_vercel('{"error":{"code":"forbidden","invalidToken":true}}'), "invalid")
        self.assertEqual(self.run_vercel('{"error":{"code":"forbidden","invalidToken": true}}'), "invalid")
        self.assertEqual(self.run_vercel('{"error":{"code":"forbidden","invalidToken":false}}'), "limited")
        self.assertTrue(CAT["vercel"]["unverified"])

    def run_vercel(self, body):
        spec = json.loads(json.dumps(CAT["vercel"]["validate"]))
        with Stub({("*", "/x"): (403, body)}) as stub:
            spec["url"] = stub.base + "/x"
            return validate_mod.validate_key(spec, "k" * 20).status

    def test_supabase_403_limited_and_no_prefix_claim(self):
        self.assertEqual(CAT["supabase"]["validate"]["limited"][0]["status"], 403)
        self.assertNotIn("sbp_", steps("supabase"))
        self.assertIn("legacy anon/service_role", steps("supabase"))

    def test_together_flags_the_unconfirmed_endpoint(self):
        self.assertTrue(CAT["together"]["unverified"])

    def test_twilio_mentions_api_keys(self):
        self.assertIn("API keys", steps("twilio"))

    def test_vercel_page_scope_and_limited(self):
        self.assertEqual(CAT["vercel"]["key_url"], "https://vercel.com/account/tokens")
        self.assertIn("Scope", steps("vercel"))
        self.assertEqual(CAT["vercel"]["validate"]["limited"][0]["status"], 403)
        self.assertIn("vcp_", field("vercel")["detect"])

    def test_anthropic_400_note_and_prefix_gate(self):
        self.assertIn("400", steps("anthropic"))
        self.assertEqual(field("anthropic")["detect_confidence"], "guess")

    def test_urls_that_a_real_doctor_run_found_moved_were_updated(self):
        self.assertEqual(CAT["notion"]["key_url"], "https://app.notion.com/developers/tokens")
        self.assertIn("api_reference", CAT["openrouter"]["docs"])
        self.assertIn("account-management", CAT["assemblyai"]["docs"])

    def test_assemblyai_deepgram_pinecone_mistral_notion_unchanged_urls(self):
        self.assertEqual(CAT["pinecone"]["validate"]["url"], "https://api.pinecone.io/indexes")
        self.assertEqual(CAT["notion"]["validate"]["headers"]["Notion-Version"], "2026-03-11")

    def test_limited_statuses_exist_on_the_vendors_named_in_the_brief(self):
        for slug in ("stripe", "supabase", "vercel", "github", "elevenlabs", "sendgrid"):
            self.assertTrue(CAT[slug]["validate"].get("limited"), slug)


class TestAwsPostIsSignedAndRead(unittest.TestCase):
    def test_request_is_a_signed_post_with_the_documented_body(self):
        spec = dict(CAT["aws"]["validate"])
        creds = {"access_key_id": "AKIAEXAMPLEEXAMPLE", "secret_access_key": "secret" * 6}
        req = validate_mod._build_request(spec, creds)
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.data, recipes_mod.STS_BODY.encode())
        auth = req.get_header("Authorization")
        self.assertIn("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEEXAMPLE/", auth)
        self.assertIn("SignedHeaders=content-type;host;x-amz-date", auth)
        self.assertNotIn("secret" * 6, auth)

    def test_signature_changes_with_the_body(self):
        import datetime
        auth = {"region": "us-east-1", "service": "sts"}
        creds = {"access_key_id": "AKIAEXAMPLEEXAMPLE", "secret_access_key": "s" * 30}
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        a = validate_mod._sigv4_headers(auth, creds, "POST", "https://sts.amazonaws.com/", now, b"a=1")
        b = validate_mod._sigv4_headers(auth, creds, "POST", "https://sts.amazonaws.com/", now, b"a=2")
        self.assertNotEqual(a["Authorization"], b["Authorization"])

    def test_a_get_without_a_body_is_signed_as_before(self):
        import datetime
        auth = {"region": "us-east-1", "service": "sts"}
        creds = {"access_key_id": "AKIAEXAMPLEEXAMPLE", "secret_access_key": "s" * 30}
        now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
        h = validate_mod._sigv4_headers(auth, creds, "GET", "https://sts.amazonaws.com/?Action=X", now)
        self.assertIn("SignedHeaders=host;x-amz-date,", h["Authorization"])

    def test_a_recipe_cannot_use_post_to_anywhere_else(self):
        spec = {"method": "POST", "url": "https://x.test/", "auth": {"type": "bearer"}, "expect": [200]}
        with self.assertRaises(validate_mod.ValidationError):
            validate_mod._build_request(spec, "k" * 10)


class TestVerdictsThroughShippedRecipes(unittest.TestCase):
    """Each shipped 'limited' rule, exercised against a stand-in vendor."""

    def run_recipe(self, slug, status, body, creds="k" * 20):
        spec = json.loads(json.dumps(CAT[slug]["validate"]))
        with Stub({("*", "/x"): (status, body)}) as stub:
            spec["url"] = stub.base + "/x"
            spec["trusted_hosts"] = []
            if spec["auth"]["type"] == "oauth2_client_credentials":
                spec["auth"]["token_url"] = stub.base + "/x"
            return validate_mod.validate_key(spec, creds)

    def test_stripe_403_is_a_valid_restricted_key(self):
        self.assertEqual(self.run_recipe("stripe", 403, "{}").status, "limited")

    def test_stripe_401_is_dead(self):
        self.assertEqual(self.run_recipe("stripe", 401, "{}").status, "invalid")

    def test_resend_restricted_is_limited_and_other_401_is_dead(self):
        self.assertEqual(self.run_recipe("resend", 401, '{"name":"restricted_api_key"}').status, "limited")
        self.assertEqual(self.run_recipe("resend", 401, '{"name":"invalid_api_key"}').status, "invalid")

    def test_github_403_limited_401_dead(self):
        self.assertEqual(self.run_recipe("github", 403, "{}").status, "limited")
        self.assertEqual(self.run_recipe("github", 401, "{}").status, "invalid")

    def test_supabase_vercel_sendgrid_403_limited(self):
        for slug in ("supabase", "vercel", "sendgrid"):
            self.assertEqual(self.run_recipe(slug, 403, "{}").status, "limited", slug)

    def test_elevenlabs_both_shapes(self):
        self.assertEqual(self.run_recipe("elevenlabs", 403, "{}").status, "limited")
        self.assertEqual(self.run_recipe("elevenlabs", 401, '{"detail":{"status":"missing_permissions"}}').status, "limited")
        self.assertEqual(self.run_recipe("elevenlabs", 401, '{"detail":{"status":"invalid_api_key"}}').status, "invalid")

    def test_sendgrid_401_is_dead(self):
        self.assertEqual(self.run_recipe("sendgrid", 401, "{}").status, "invalid")

    def test_a_working_key_is_valid_everywhere_a_limited_rule_exists(self):
        for slug in ("stripe", "resend", "github", "supabase", "vercel", "sendgrid", "elevenlabs"):
            self.assertEqual(self.run_recipe(slug, 200, "{}").status, "valid", slug)


class TestConnectShowsTheNewFields(unittest.TestCase):
    def test_least_privilege_and_unverified_are_printed_before_the_key_is_asked_for(self):
        import io
        from stuntkey import connect as connect_mod
        out = io.StringIO()
        connect_mod._print_steps(CAT["mailgun"], out)
        text = out.getvalue()
        self.assertIn("Least privilege:", text)
        # the plain wording that replaced "Not confirmed by the vendor's docs" (round 11)
        self.assertIn("I could not check this site's key test settings", text)

    def test_a_limited_key_is_stored_and_the_note_is_shown(self):
        import io
        from stuntkey import connect as connect_mod
        env = os.path.join(_isolation.mktemp(), ".env")
        out = io.StringIO()
        code = connect_mod.connect(
            CAT["stripe"], env_file=env, browser_open=lambda u: None,
            prompt=lambda _: "sk_live_ABCDEFGHIJKLMN", out=out,
            validate_fn=lambda spec, key: validate_mod.Result("limited", "lacks permission X"),
            confirm_in=lambda _: "yes")
        self.assertEqual(code, 0)
        self.assertIn("the key is real, but: lacks permission X", out.getvalue())
        self.assertIn("STRIPE_SECRET_KEY=sk_live_ABCDEFGHIJKLMN", open(env).read())
        self.assertNotIn("sk_live_ABCDEFGHIJKLMN", out.getvalue())

    def test_the_version_is_075(self):
        self.assertEqual(stuntkey.__version__, "0.9.4")


if __name__ == "__main__":
    unittest.main()
