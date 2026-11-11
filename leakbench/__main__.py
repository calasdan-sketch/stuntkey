"""``python -m leakbench --profile none|stuntkey-hook [--json]``."""

from __future__ import annotations

import argparse
import sys

from . import harness, profiles, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="leakbench",
        description="Agent Leak Benchmark: score a secret-protection setup "
                    "against ways an AI coding agent can expose an API key.")
    parser.add_argument("--profile", default="none", choices=profiles.AVAILABLE,
                        help="protection profile to score (default: none)")
    parser.add_argument("--canary", default="prefixed", choices=("prefixed", "opaque"),
                        help="prefixed: the fake key looks like an OpenAI key (default); "
                             "opaque: it has no recognisable format")
    parser.add_argument("--extended", action="store_true",
                        help="also run the extended probes (harder disguises), "
                             "scored apart from the core set")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of a table")
    args = parser.parse_args(argv)

    try:
        results = harness.run(args.profile, canary=args.canary, extended=args.extended)
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
