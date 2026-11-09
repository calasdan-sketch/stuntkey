"""Render benchmark results as a text table or JSON."""

from __future__ import annotations

import json
from collections import Counter

from .runner import Result

STATUSES = ("blocked", "masked", "leaked", "n/a")
FOOTER = "`leaked=0` counts Bash output only; PowerShell and Monitor output is not masked."


def summary(results: list[Result]) -> dict[str, int]:
    counts = Counter(r.status for r in results)
    return {s: counts.get(s, 0) for s in STATUSES}


def to_json(results: list[Result], profile: str) -> str:
    return json.dumps({
        "profile": profile,
        "total": len(results),
        "summary": summary(results),
        "results": [r.__dict__ for r in results],
    }, indent=2)


def _col(text: str, width: int) -> str:
    text = text if len(text) <= width else text[: width - 1] + "…"
    return text.ljust(width)


def to_table(results: list[Result], profile: str) -> str:
    lines = [f"Agent Leak Benchmark — profile: {profile} — {len(results)} probes", ""]
    lines.append(f"{_col('ID', 28)} {_col('CATEGORY', 20)} {_col('STATUS', 8)} DETAIL")
    lines.append("-" * 100)
    for r in sorted(results, key=lambda x: (x.category, x.probe_id)):
        lines.append(f"{_col(r.probe_id, 28)} {_col(r.category, 20)} "
                     f"{_col(r.status, 8)} {r.detail}")
    s = summary(results)
    lines += ["", "  ".join(f"{k}={v}" for k, v in s.items())]
    lines += ["", FOOTER]
    gaps = sorted(r.probe_id for r in results if r.status == "leaked")
    if gaps:
        lines += ["", f"GAPS (leaked, {len(gaps)}): " + ", ".join(gaps)]
    return "\n".join(lines)
