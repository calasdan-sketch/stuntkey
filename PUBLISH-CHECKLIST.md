# Publish checklist for Dan (do not run until you have read it)

Release version: **0.11.0**. PyPI has 0.9.0 today, so 0.11.0 is still the right
number. Nothing removed. What is new since 0.9.0: `stuntkey keep` (save any key),
the hook reads odd-shaped calls, a macOS/Windows keychain fix, plus everything in
`CHANGELOG.md`.

## Look first
1. Open the latest GitHub Actions run for this branch. All 9 test jobs (Linux,
   Windows, macOS x Python 3.10, 3.12, 3.14) must be green. This is the only
   Windows/macOS/3.10 check there is; `keep` and the keychain changes were never
   run on Windows or macOS by hand.
2. Read the top of `CHANGELOG.md`.
3. Make sure `main` holds this branch (merge it yourself).

## Then, from a clean clone of main
```
python -m pip install --upgrade build twine
python -m build
python -m twine check --strict dist/*
python -m venv /tmp/try && /tmp/try/bin/pip install dist/*.whl && /tmp/try/bin/stuntkey --version
```
The last line must print `stuntkey 0.11.0`. To see the author that ships:
`unzip -p dist/*.whl '*/METADATA' | grep ^Author` must say `Calas Automations Inc.`

## Publish (your step)
```
git tag v0.11.0 && git push origin v0.11.0
python -m twine upload dist/*
```
The tag builds the `.pyz` and Windows zip on GitHub. The upload uses your PyPI
sign-in. Cost: none.

## After
`pip index versions stuntkey` lists 0.11.0. In a new folder: `pipx install stuntkey`,
`stuntkey doctor`, `stuntkey selftest`, then try `stuntkey keep TEST_API_KEY` with a
throwaway value and `stuntkey forget test`. On Windows also try a 2,000-character
value: it should say the limit is 1280 and save nothing.
The npm package and winget manifests are not ready; leave them.
