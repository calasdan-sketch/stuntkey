"""How many randomly generated keys does a detector find in `NAME=value`?

`python -m leakbench.detect_bench [--n 300] [--seed 1]`

Keys are made at run time from a seeded random generator in the shapes real
services use that carry NO vendor prefix (hex of 20, 32, 40 and 64 characters,
base64url of 32 and 43, UUID, 24 letters and digits) and written as
`SERVICE_API_KEY=<key>`. A detector "finds" a key when it reports that line.
Measured here: stuntkey's scanner, the entropy-only rule stuntkey used before
0.11 (for comparison), and Yelp's `detect-secrets` when it is installed
(`pip install detect-secrets`; default plugins, not tuned).

This is recall on one easy case (a clearly named variable). It says nothing
about false positives; `tests/test_scan.py` holds those.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import tempfile
import uuid

SHAPES = {
    "hex-20": lambda r: "%020x" % r.getrandbits(80),
    "hex-32": lambda r: "%032x" % r.getrandbits(128),
    "hex-40": lambda r: "%040x" % r.getrandbits(160),
    "hex-64": lambda r: "%064x" % r.getrandbits(256),
    "base64url-32": lambda r: base64.urlsafe_b64encode(r.randbytes(24)).decode().rstrip("=")[:32],
    "base64url-43": lambda r: base64.urlsafe_b64encode(r.randbytes(32)).decode().rstrip("="),
    "uuid": lambda r: str(uuid.UUID(int=r.getrandbits(128), version=4)),
    "alnum-24": lambda r: "".join(r.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
                                  for _ in range(24)),
}


def make_keys(n: int, seed: int) -> dict[str, list[str]]:
    rng = random.Random(seed)
    return {shape: [fn(rng) for _ in range(n)] for shape, fn in SHAPES.items()}


def stuntkey_finds(key: str) -> bool:
    from stuntkey import recipes, scan
    cat = getattr(stuntkey_finds, "_cat", None)
    if cat is None:
        cat = stuntkey_finds._cat = recipes.load_recipes(recipes.RECIPES_DIR)
        stuntkey_finds._rules = scan.build_rules(cat)
        stuntkey_finds._words = scan._name_tokens(cat)
    found = scan.scan_text(f"SERVICE_API_KEY={key}\n", "x", stuntkey_finds._rules, cat,
                           stuntkey_finds._words, scan.Budget(5))
    return any(f._value == key for f in found)


def entropy_only_finds(key: str) -> bool:
    """The test used before 0.11: 3.5 bits per character, letters and digits."""
    from stuntkey import scan
    return (len(key) >= 20 and any(c.isdigit() for c in key) and any(c.isalpha() for c in key)
            and scan.entropy(key) >= 3.5)


def detect_secrets_finds_all(keys: list[str]) -> list[bool] | None:
    try:
        from detect_secrets import SecretsCollection
        from detect_secrets.settings import default_settings
    except ImportError:
        return None
    out = []
    with tempfile.TemporaryDirectory() as d, default_settings():
        for i, key in enumerate(keys):
            path = os.path.join(d, f"{i}.env")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(f"SERVICE_API_KEY={key}\n")
        col = SecretsCollection()
        for i in range(len(keys)):
            col.scan_file(os.path.join(d, f"{i}.env"))
        hit = {os.path.basename(f) for f in col.files}
        out = [f"{i}.env" in hit for i in range(len(keys))]
    return out


def run(n: int = 300, seed: int = 1) -> dict:
    keys = make_keys(n, seed)
    table = {}
    for shape, items in keys.items():
        row = {"stuntkey": sum(map(stuntkey_finds, items)) / n,
               "entropy-only (before 0.11)": sum(map(entropy_only_finds, items)) / n}
        ds = detect_secrets_finds_all(items)
        if ds is not None:
            row["detect-secrets"] = sum(ds) / n
        table[shape] = row
    return table


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="leakbench.detect_bench")
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    table = run(args.n, args.seed)
    if args.json:
        print(json.dumps(table, indent=2))
        return 0
    cols = sorted({c for row in table.values() for c in row})
    print(f"share of {args.n} random keys found per shape (seed {args.seed})")
    print(f"{'shape':14}" + "".join(f"{c:>28}" for c in cols))
    for shape, row in table.items():
        print(f"{shape:14}" + "".join(f"{row.get(c, float('nan')) * 100:>27.1f}%" for c in cols))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
