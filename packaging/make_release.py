"""Build the release files into a fresh folder and fill a COPY of the winget manifest.

Standard library only (the wheel step uses `python -m build` when it is installed).
Nothing in the repo is changed: the committed manifest keeps its placeholder, and the
output goes to a folder you name (default: a new temp folder).

    python packaging/make_release.py [--out DIR] [--skip-wheel]

Writes into DIR:
    stuntkey-<version>-windows.zip   (the file the winget manifest points at)
    stuntkey.pyz
    stuntkey-<version>-py3-none-any.whl     (unless --skip-wheel or `build` is missing)
    SHA256SUMS                       (sha256 of each file, "hash  name" lines)
    winget/manifests/c/Calas/StuntKey/<version>/*.yaml   (copy with the real InstallerSha256)

After you upload the zip to the GitHub release, check that the release's SHA256SUMS
matches this one, then copy the filled manifest folder to winget-pkgs.
"""
import argparse
import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLACEHOLDER = "REPLACE_WITH_THE_SHA256_OF_THE_ZIP_FROM_SHA256SUMS"
MANIFEST_REL = os.path.join("packaging", "winget", "manifests", "c", "Calas", "StuntKey")


def _load_build_pyz():
    path = os.path.join(ROOT, "scripts", "build_pyz.py")
    spec = importlib.util.spec_from_file_location("build_pyz_for_release", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fill_manifest(src_dir: str, dst_dir: str, sha: str) -> list:
    """Copy the manifest files, replacing the placeholder with `sha`. Returns the new paths."""
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ValueError("not a sha256: %r" % sha)
    os.makedirs(dst_dir, exist_ok=True)
    written = []
    for name in sorted(os.listdir(src_dir)):
        with open(os.path.join(src_dir, name), encoding="utf-8", newline="") as f:
            text = f.read()
        text = text.replace(PLACEHOLDER, sha.upper())
        out = os.path.join(dst_dir, name)
        with open(out, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        written.append(out)
    return written


def build_wheel(out_dir: str) -> str:
    """Build the wheel with `python -m build --no-isolation` into out_dir; '' if not possible."""
    if importlib.util.find_spec("build") is None:
        return ""
    # build from a copy so no build/ or *.egg-info folder appears in the repo
    stage = tempfile.mkdtemp(prefix="stuntkey-wheel-src-")
    try:
        for item in ("stuntkey", "pyproject.toml", "README.md", "LICENSE", "MANIFEST.in"):
            src = os.path.join(ROOT, item)
            if os.path.isdir(src):
                shutil.copytree(src, os.path.join(stage, item),
                                ignore=shutil.ignore_patterns("__pycache__", "*.py[cod]"))
            elif os.path.exists(src):
                shutil.copy(src, stage)
        r = subprocess.run([sys.executable, "-m", "build", "--wheel", "--no-isolation",
                            "--outdir", out_dir], cwd=stage, capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stdout[-800:] + r.stderr[-800:])
            return ""
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    for n in os.listdir(out_dir):
        if n.endswith(".whl"):
            return os.path.join(out_dir, n)
    return ""


def make_release(out_dir: str, skip_wheel: bool = False) -> dict:
    bp = _load_build_pyz()
    version = bp.version()
    os.makedirs(out_dir, exist_ok=True)
    pyz, win = bp.build(out_dir)
    files = [win, pyz]
    if not skip_wheel:
        whl = build_wheel(out_dir)
        if whl:
            files.append(whl)
    sums = os.path.join(out_dir, "SHA256SUMS")
    with open(sums, "w", encoding="utf-8", newline="\n") as f:
        for p in files:
            f.write("%s  %s\n" % (sha256_of(p), os.path.basename(p)))
    src = os.path.join(ROOT, MANIFEST_REL, version)
    dst = os.path.join(out_dir, "winget", "manifests", "c", "Calas", "StuntKey", version)
    manifest = fill_manifest(src, dst, sha256_of(win))
    return {"version": version, "zip": win, "sums": sums, "manifest_dir": dst,
            "manifest": manifest, "files": files}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", help="folder to write into (default: a new temp folder)")
    ap.add_argument("--skip-wheel", action="store_true", help="do not build the wheel")
    a = ap.parse_args(argv)
    out = a.out or tempfile.mkdtemp(prefix="dist-release-")
    res = make_release(out, a.skip_wheel)
    print("version:", res["version"])
    for p in res["files"] + [res["sums"]]:
        print("wrote  :", p)
    print("manifest (filled copy):", res["manifest_dir"])
    print("The committed manifest was not changed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
