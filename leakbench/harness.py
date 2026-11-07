"""Tie the pieces together: build a sandbox, run every probe under a profile."""

from __future__ import annotations

from . import profiles, sandbox
from .loader import Probe, load
from .runner import Result, run_probe


def run(profile_name: str, probes: list[Probe] | None = None,
        canary_style: str = "vendor") -> list[Result]:
    """Run all probes once under ``profile_name`` in a fresh sandbox.

    Raises KeyError for an unknown profile and ImportError when
    ``stuntkey-hook`` is requested but StuntKey is not importable.
    """
    probe_list = probes if probes is not None else load()
    profile = profiles.get(profile_name)
    sbx = sandbox.build(canary_style)
    try:
        return [run_probe(p, sbx, profile, profile_name) for p in probe_list]
    finally:
        sandbox.destroy(sbx)
