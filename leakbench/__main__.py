"""``python -m leakbench --profile none|stuntkey-hook [--json]``."""

from __future__ import annotations

import argparse
import sys

from . import harness, profiles, report, sandbox


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="leakbench",
        description="Agent Leak Benchmark: score a secret-protection setup "
                    "against ways an AI coding agent can expose an API key.")
    parser.add_argument("--profile", default="none", choices=profiles.AVAILABLE,
                        help="protection profile to score (default: none)")
    parser.add_argument("--canary", default="vendor", choices=sandbox.CANARY_STYLES,
                        help="shape of the planted secret: 'vendor' (sk-canary-...) or "
                             "'opaque' (40 hex chars, no recognisable format)")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of a table")
    args = parser.parse_args(argv)

    try:
        results = harness.run(args.profile, canary_style=args.canary)
    except ImportError:
        print(f"profile '{args.profile}' unavailable: StuntKey is not importable "
              f"(install it or run from the repo).", file=sys.stderr)
        return 2

    out = (report.to_json(results, args.profile) if args.json
           else report.to_table(results, args.profile))
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
