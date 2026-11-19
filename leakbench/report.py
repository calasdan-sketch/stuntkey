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


BENIGN_STATUSES = ("allowed", "over-blocked", "over-masked", "n/a")


def benign_summary(benign: list[Result]) -> dict[str, int]:
    counts = Counter(r.status for r in benign)
    return {s: counts.get(s, 0) for s in BENIGN_STATUSES}


def lines_two(results: list[Result], benign: list[Result]) -> list[str]:
    """The two headline lines: Protection (over the attack probes) and
    Usability (over the harmless ones), and whether the profile is "perfect"."""
    s = summary(results)
    out = [f"Protection: blocked before the call {s['blocked']}, masked after the call {s['masked']} "
           f"(not verified live in Claude Code), leaked {s['leaked']}, n/a {s['n/a']} (of {len(results)})"]
    if benign:
        b = benign_summary(benign)
        out.append(f"Usability: allowed {b['allowed']} of {len(benign)} harmless commands "
                   f"(over-blocked {b['over-blocked']}, over-masked {b['over-masked']}, n/a {b['n/a']})")
        out.append("Verdict: " + ("perfect" if perfect(results, benign)
                                  else "not perfect (perfect needs leaked=0 AND over-blocked=0)"))
    return out


def perfect(results: list[Result], benign: list[Result]) -> bool:
    """Perfect only if nothing leaked AND no harmless work was blocked."""
    return (bool(benign) and summary(results)["leaked"] == 0
            and benign_summary(benign)["over-blocked"] == 0)


def to_json(results: list[Result], profile: str, benign: list[Result] | None = None) -> str:
    data = {
        "profile": profile,
        "total": len(results),
        "summary": summary(results),
        "results": [r.__dict__ for r in results],
    }
    if benign:
        data["benign"] = {"total": len(benign), "summary": benign_summary(benign),
                          "perfect": perfect(results, benign),
                          "results": [r.__dict__ for r in benign]}
    return json.dumps(data, indent=2)


def _col(text: str, width: int) -> str:
    text = text if len(text) <= width else text[: width - 1] + "…"
    return text.ljust(width)


def to_table(results: list[Result], profile: str, benign: list[Result] | None = None) -> str:
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
    if benign:
        lines += ["", "Harmless work that must not be stopped:"]
        for r in sorted(benign, key=lambda x: x.probe_id):
            lines.append(f"  {_col(r.probe_id, 28)} {_col(r.status, 12)} {r.detail}")
        lines += [""] + lines_two(results, benign)
    return "\n".join(lines)
