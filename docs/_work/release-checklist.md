# StuntKey release checklist (no CI; run by hand, by the lead)

Run from `C:\Users\danie\oathkey` on the release branch after the full suite is green.
Nothing below is committed, pushed or published until a step says so. Everything costs
nothing; the only possible cost is a code-signing certificate, which is NOT part of this.

Quick check while working: `python -m pytest -q -p no:cacheprovider --fast` skips tests
marked `slow` (the same as `-m "not slow"`). The release run uses no flag: the full suite.

## A. Before the tag

1. One version: `python -c "import stuntkey;print(stuntkey.__version__)"`. `pyproject.toml`,
   `packaging/npm/package.json`, the three winget manifest files, `CHANGELOG.md` agree (tests check).
2. Full suite, no flags: `python -m pytest -q -p no:cacheprovider`.
3. Leak benchmark, in a throwaway home (HOME, USERPROFILE, APPDATA, LOCALAPPDATA set to an empty
   temp folder, `STUNTKEY_KEYCHAIN=memory`): `python -m leakbench --profile stuntkey-hook --extended`.
   Numbers in `leakbench/README.md` must match what you see.
4. Build everything into a temp folder, without touching the repo:
   `python packaging/make_release.py --out $env:TEMP\dist-release`
   It writes the wheel, `stuntkey.pyz`, `stuntkey-<v>-windows.zip`, `SHA256SUMS` and a FILLED COPY of
   the winget manifest. The committed manifest keeps its placeholder on purpose.
5. Release gate on the filled copy (fails if the placeholder is still there):
   `$env:SK_RELEASE_CHECK="1"; $env:SK_MANIFEST_DIR="$env:TEMP\dist-release\winget\manifests\c\Calas\StuntKey\0.9.4"; python -m pytest -q -p no:cacheprovider tests/test_r14_release.py`
6. Installer: `powershell -NoProfile -File packaging\windows\install.ps1 -WhatIf` prints the plan.
   On a spare Windows account or VM, run it for real with `-Wheel <the wheel>` and check
   `stuntkey doctor`.
7. Look inside the wheel: `python -m zipfile -l <wheel>` shows `stuntkey/web/` and `stuntkey/recipes/`.

## B. Publish (each is one-way except where noted)

1. Tag `v<version>`, push the tag. The release workflow builds and attaches the files.
2. Compare the release's `SHA256SUMS` with the one from step A4. They must match for the zip.
3. PyPI: upload the wheel and sdist (an upload cannot be replaced; a bad one can only be yanked).
4. winget: copy the filled manifest folder to a fork of `microsoft/winget-pkgs`, run
   `winget validate --manifest <folder>`, open the pull request.
5. npm: `python scripts/build_pyz.py packaging/npm`, then `npm pack --dry-run`, then `npm publish`.

## C. Rollback

- **A user on the new version, wants the old one:** `pipx install --force stuntkey==<old>`
  (the old version stays on PyPI; yanking only hides it from fresh installs).
  Then `stuntkey --version` shows the old number. Their keys and `~/.stuntkey` are untouched
  by an install of either version.
- **A bad PyPI release:** yank it on pypi.org (Manage > the release > Yank), then publish a
  fixed higher version. Never reuse a version number.
- **A bad winget release:** open a pull request on winget-pkgs that removes or replaces the
  version folder; until it merges, tell people to use `pipx install stuntkey==<old>`.
- **A bad npm release:** `npm deprecate stuntkey@<v> "use <old>"`; `npm unpublish` only in the
  first 72 hours.
- **A bad tag/release on GitHub:** mark the release as pre-release or delete it; the files
  and SHA256SUMS go with it. Do not move a tag that someone may already have used.
- **Local PC (Dan's):** `pipx install --force <old wheel>` from a copy kept before the upgrade.
  Callers (`C:\Users\danie\my-agent\stuntkey_run.py`) look for `stuntkey` on PATH, then
  `C:\Users\danie\.local\bin\stuntkey.exe`.

## D. Independent security review

No outside review exists. Plan, in order of cost (free first):
1. Post `docs/SECURITY_REVIEW_BRIEF.md` where security-minded people look (GitHub
   discussions, a post on a security forum). Ask for findings by private report.
2. Ask one named reviewer (a friend of the project, a university lab, a bug-bounty hobbyist)
   for a time-boxed look at the scope in the brief.
3. Only when there is revenue: a paid review. A price is a quote, not a number to assume.
Until a written result exists, the README and SECURITY.md keep saying "not independently reviewed".
