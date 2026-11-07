# Publish checklist for Dan (do not run until you have read it)

Release version: **0.11.0**. PyPI has 0.9.0 today. Nothing in 0.10 or 0.11 removes a
command, so this is a normal minor release. One thing behaves differently: the
activity log now notices an edit in the middle of the file when you check it,
not on the next write.

## Look first
1. Open the latest GitHub Actions run for this branch. All 9 test jobs (Linux,
   Windows, macOS x Python 3.10, 3.12, 3.14) must be green. This is the only
   Windows/macOS/3.10 check there is.
2. Read the top of `CHANGELOG.md`.
3. Make sure `main` holds this branch (merge it yourself).

## Then, from a clean clone of main
```
python -m pip install --upgrade build twine
python -m build
python -m twine check --strict dist/*
python -m venv /tmp/try && /tmp/try/bin/pip install dist/*.whl && /tmp/try/bin/stuntkey --version
```
The last line must print `stuntkey 0.11.0`.

## Publish
```
git tag v0.11.0 && git push origin v0.11.0
```
The tag runs `.github/workflows/release.yml` (builds the `.pyz` and Windows zip,
attaches them to a GitHub release). Upload to PyPI the way you did 0.9.0
(`python -m twine upload dist/*`, with your PyPI token). Costs: none.

## After
`pip index versions stuntkey` should list 0.11.0. In a new folder run
`pipx install stuntkey`, `stuntkey doctor`, `stuntkey selftest`.
The npm package (`packaging/npm`) and winget manifests are not ready; leave them.
