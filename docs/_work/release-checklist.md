# StuntKey 0.9.2 - local install checklist (for the lead)

Run from `C:\Users\danie\oathkey` on branch `fix/stuntkey-perfect`, after the full test suite is green.
Nothing here is committed, pushed or published.

1. Check the version in one place and the files agree:
   `python -c "import stuntkey;print(stuntkey.__version__)"` -> 0.9.2 (pyproject.toml says the same; a test checks it).
2. Build the wheel into a temp folder (needs setuptools>=77 already installed; no network needed with `--no-isolation`):
   `$out = Join-Path $env:TEMP "sk-wheel"; Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue`
   `python -m build --wheel --no-isolation --outdir $out`
3. Look inside it: the web page and brand module must be there.
   `python -c "import zipfile,glob,sys;z=zipfile.ZipFile(glob.glob(sys.argv[1]+'/stuntkey-0.9.2-*.whl')[0]);print([n for n in z.namelist() if 'web/' in n or n.endswith('brand.py')])" $out`
4. Install it (replaces 0.9.0 in the pipx environment):
   `pipx install --force (Get-ChildItem $out\stuntkey-0.9.2-*.whl).FullName`
5. Verify: `stuntkey --version` -> `stuntkey 0.9.2`; then `stuntkey selftest` and `stuntkey list`.
6. Rollback to 0.9.0 if anything is wrong:
   `pipx install --force stuntkey==0.9.0`
   (if 0.9.0 is not on the package index, keep a copy of its wheel first, or rebuild it from branch `feat/oathkey-0.9`, then `pipx install --force <that wheel>`).
   Then `stuntkey --version` -> 0.9.0.
7. Callers: `C:\Users\danie\my-agent\stuntkey_run.py` finds `stuntkey` on PATH, else `C:\Users\danie\.local\bin\stuntkey.exe`.

Not changed by this work (still 0.9.0, release-time job): `packaging/npm/package.json`, `packaging/winget/manifests/.../0.9.0`.
