# Packaging: stuntkey.pyz, winget and npx

None of these is published yet. This page says how to build each one and how
to submit it. PyPI stays the main way in (`pipx install stuntkey`).

## stuntkey.pyz (one file, any Python 3.10+)

```
python scripts/build_pyz.py            # writes dist/stuntkey.pyz and dist/stuntkey-<version>-windows.zip
python dist/stuntkey.pyz doctor
```

The release workflow builds both files on every `v*` tag, attaches them to
the GitHub release, lists them in `SHA256SUMS` and gives them a build
provenance attestation. They are not uploaded to PyPI.

On its first run the `.pyz` unpacks itself once into
`~/.stuntkey/pyz/<hash>/` (stuntkey reads its recipes and `SKILL.md` as files).
`install`, `setup-agent`, `wrap`, `scan-git --install-hook` and `hook install`
write `python <flag> <path to stuntkey.pyz> ...`, so keep the file where it is.

## winget (Windows)

winget wants an installer (exe, msi, msix or zip), and a Python program is
none of those, so the package is a **portable zip**: `stuntkey.pyz` plus
`stuntkey.cmd`, a launcher that runs it with `py -3` (or `python`). The
manifest lists `Python.Python.3.12` as a dependency, so winget installs Python
first. `ArchiveBinariesDependOnPath: true` puts the folder on PATH; a
`PortableCommandAlias` is not used because winget names a link to a `.cmd`
`stuntkey.exe`, which then does not start
([winget-cli #3807](https://github.com/microsoft/winget-cli/issues/3807)).

The manifests (schema 1.10.0) are in
`packaging/winget/manifests/c/Calas/StuntKey/0.9.3/`.

To submit a release:

1. Push the tag and wait for the GitHub release.
2. In `Calas.StuntKey.installer.yaml`, replace
   `REPLACE_WITH_THE_SHA256_OF_THE_ZIP_FROM_SHA256SUMS` with the line for
   `stuntkey-<version>-windows.zip` in the release's `SHA256SUMS`. For a new
   version, also change `0.9.3` in all three files, the folder name and the URL.
3. Check it on a Windows PC:
   `winget validate --manifest <folder>`, then
   `winget install --manifest <folder>` (turn on local manifests first:
   `winget settings --enable LocalManifestFiles`, as admin), then open a new
   window and run `stuntkey doctor`.
4. Fork https://github.com/microsoft/winget-pkgs, copy the folder to the same
   path under `manifests/`, and open a pull request. `wingetcreate submit
   <folder>` does the fork and the pull request for you.

Without winget, `packaging/winget/install-stuntkey.cmd` installs from PyPI
with pipx if it is there, else `py -m pip install --user stuntkey`.

## npx (Node.js)

`packaging/npm/` is a package called `stuntkey` with no dependencies.
`bin/stuntkey.js` finds Python 3.10+ (`py -3`, `python` or `python3`) and runs
the `stuntkey.pyz` shipped next to it, or `python -m stuntkey` when there is
none. Without Python it says: "Install Python 3.10+ from python.org, then run
again."

To publish:

```
python scripts/build_pyz.py packaging/npm      # puts stuntkey.pyz in the package
cd packaging/npm
# set "version" in package.json to the release version
npm pack --dry-run                             # check the list: bin/stuntkey.js, stuntkey.pyz, README.md, package.json
npm publish
```

`packaging/npm/stuntkey.pyz` is git-ignored; build it fresh each time.
