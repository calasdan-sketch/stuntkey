"""Load probe definitions from leakbench/probes/*.json.

Each JSON file holds a list of probes (grouped by category). A probe is a dict:

    id        unique short name
    category  which family of leak
    attack    plain words: what an agent would run or read
    tool      the PreToolUse payload a profile evaluates: {tool_name, tool_input}
    run       how to actually test the leak: {kind, cmd}
              kind in: sh | python | node | powershell | cmd | none
    check     canary_in_output (default) | write_tamper | no_guard

Placeholders ``{SBX}`` (sandbox home) and ``{CANARY}`` are substituted at run
time by the runner, not here.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

PROBE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "probes")
EXTENDED_DIR = os.path.join(PROBE_DIR, "extended")


@dataclass(frozen=True)
class Probe:
    id: str
    category: str
    attack: str
    tool: dict
    run: dict = field(default_factory=dict)
    check: str = "canary_in_output"


def _coerce(raw: dict) -> Probe:
    missing = {"id", "category", "attack", "tool"} - raw.keys()
    if missing:
        raise ValueError(f"probe missing fields {sorted(missing)}: {raw!r}")
    return Probe(
        id=raw["id"],
        category=raw["category"],
        attack=raw["attack"],
        tool=raw["tool"],
        run=raw.get("run", {}),
        check=raw.get("check", "canary_in_output"),
    )


def load(probe_dir: str = PROBE_DIR, extended: bool = False) -> list[Probe]:
    """Every probe from every JSON file, sorted by id. Raises on a duplicate id
    so a copy-paste mistake fails loudly.

    The core set is the pinned, published score. ``extended=True`` adds the
    probes in ``probes/extended/``: harder disguises and indirections that
    were added later, scored separately so the core number stays comparable."""
    probes: list[Probe] = []
    seen: set[str] = set()
    dirs = [probe_dir]
    if extended:
        dirs.append(os.path.join(probe_dir, "extended"))
    for directory in dirs:
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".json"):
                continue
            with open(os.path.join(directory, name), encoding="utf-8") as fh:
                data = json.load(fh)
            items = data if isinstance(data, list) else [data]
            for raw in items:
                probe = _coerce(raw)
                if probe.id in seen:
                    raise ValueError(f"duplicate probe id: {probe.id}")
                seen.add(probe.id)
                probes.append(probe)
    return sorted(probes, key=lambda p: p.id)
