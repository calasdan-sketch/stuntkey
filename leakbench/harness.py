"""Tie the pieces together: build a sandbox, run every probe under a profile."""

from __future__ import annotations

from . import profiles, sandbox
from .loader import Probe, load, load_benign
from .runner import Result, run_probe


def run(profile_name: str, probes: list[Probe] | None = None,
        canary: str = "prefixed", extended: bool = False) -> list[Result]:
    """Run all probes once under ``profile_name`` in a fresh sandbox.

    Raises KeyError for an unknown profile and ImportError when
    ``stuntkey-hook`` is requested but StuntKey is not importable.
    """
    probe_list = probes if probes is not None else load(extended=extended)
    profile = profiles.get(profile_name)
    sbx = sandbox.build(canary)
    try:
        return [run_probe(p, sbx, profile, profile_name) for p in probe_list]
    finally:
        sandbox.destroy(sbx)


def run_benign(profile_name: str, canary: str = "prefixed",
               probes: list[Probe] | None = None) -> list[Result]:
    """The harmless probes under ``profile_name``, in their own fresh sandbox (the
    64-probe attack run is not touched). A local server answers the curl probe."""
    probe_list = probes if probes is not None else load_benign()
    profile = profiles.get(profile_name)
    sbx = sandbox.build(canary)
    server = None
    try:
        sandbox.plant_benign(sbx.home)
        server, port = sandbox.start_ping_server()
        sbx.env["LB_BENIGN_PORT"] = str(port)
        return [run_probe(p, sbx, profile, profile_name) for p in probe_list]
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()
        sandbox.destroy(sbx)
