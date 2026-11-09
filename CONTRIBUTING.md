# Contributing

The most useful contribution is a correct recipe. A recipe is a small JSON
file in `stuntkey/recipes/` that says where a key is made, the click path,
and one harmless call that proves the key works.

## The rules for a recipe change

1. **Cite the vendor's docs.** Every URL, header, status code and step must be
   shown on a page by the vendor itself. Put the link in your pull request.
   If you cannot find it, do not guess: list it under `"unverified"` in the
   recipe and `connect` will tell the user.
2. **`accept` is not `detect`.** `accept` decides what `connect --clipboard`
   will take from the clipboard. It must never refuse a valid key, so use
   only a shape the vendor documents, loosely (`^sk-ant-`), or leave it out.
   `detect` is what `scan` looks for; a commonly seen shape is fine there if
   you leave `detect_confidence` at `"guess"`.
3. **Check one thing, read only.** GET (or HEAD). The one exception is AWS's
   documented STS call. No call may cost money or use quota if there is any
   alternative.
4. **Say what a limited key looks like.** If a restricted key gets 403 (or a
   401 with a telltale word), add it under `validate.limited` or
   `validate.body_rules` so a real key is not reported as dead.
5. **Least privilege.** Fill in `least_privilege` with the smallest scope or
   permission that works.

## A recipe template

Copy this into `stuntkey/recipes/<slug>.json`, then replace every value. The
full schema (two-value keys, other auth shapes, `accept`) is at the top of
[`stuntkey/recipes.py`](stuntkey/recipes.py); `stuntkey add` writes a first draft
for you.

```json
{
  "service": "example",
  "display": "Example",
  "key_url": "https://example.com/settings/api-keys",
  "env_var": "EXAMPLE_API_KEY",
  "docs": "https://docs.example.com/authentication",
  "steps": [
    "Click 'Create key'",
    "Give it read-only access to the one project it needs",
    "Copy the key now - it is shown only once"
  ],
  "validate": {
    "method": "GET",
    "url": "https://api.example.com/v1/me",
    "auth": {"type": "bearer"},
    "expect": [200],
    "reject": [401]
  },
  "least_privilege": {
    "summary": "A read-only key for one project.",
    "url": "https://example.com/settings/api-keys"
  }
}
```

## Submitting a community recipe

Community recipes are reviewed, pinned and never trusted automatically.

1. **Open a pull request** that adds the JSON file and its test (see below).
   Put the vendor docs links in the description.
2. **Pin it.** Put the file's SHA-256 in the pull request description
   (`sha256sum stuntkey/recipes/<slug>.json`, or on Windows
   `certutil -hashfile stuntkey
ecipes\<slug>.json SHA256`). A maintainer
   checks that the hash matches the file being merged; any later change is a
   new pull request with a new hash.
3. **Review.** A maintainer checks every address against the vendor docs and
   runs `stuntkey doctor-recipes <slug>`. Only a merged, released recipe ships
   with stuntkey.
4. **Never auto-trusted.** stuntkey does not download recipes from anywhere. A
   recipe someone sends you as a file is yours to check: compare its SHA-256
   with the one the author published, read it, then copy it into your own
   recipes folder. Even then it cannot send a built-in service's key to a
   different server.

## Smoke test with a FAKE key

Never use a real key to test. For every manual trial and every test that stores
or reads a key, set `STUNTKEY_KEYCHAIN=memory` (keys kept in the process only)
or `STUNTKEY_KEYCHAIN=file:<temp folder>` (a plain JSON file, **not secure**), so
the real OS keychain is never touched. Start a local stand-in for the vendor and point
a copy of your recipe at it:

```bash
python -m unittest discover -s tests          # the whole suite, no network
python -m stuntkey doctor-recipes <slug>   # visits the real addresses, no key
```

For a new recipe add a test in `tests/` that loads it with
`recipes.load_recipes(recipes.RECIPES_DIR)`, runs `validate.validate_key` against
a local `http.server` that answers like the vendor (200 for the fake key, 401
otherwise, and your `limited` cases), and checks the verdict. Tests must not
make real network calls.

## Everything else

Python 3.10 to 3.14, standard library only: no dependencies, ever. Keep
messages in plain words. Anything that touches a key must never print it,
put it in a command line or write it to a log.
