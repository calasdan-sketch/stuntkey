"""pytest glue for tests/_isolation.py: no STUNTKEY_* variable leaks into or out of a test."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolation  # noqa: E402


def pytest_addoption(parser):
    parser.addoption("--fast", action="store_true", default=False,
                     help="skip tests marked 'slow' (the ones that start many programs)")


def pytest_configure(config):
    _isolation.scrub_env()          # whatever the caller exported never reaches a test
    config.addinivalue_line(
        "markers", "slow: starts many subprocesses; skip with --fast or -m 'not slow'")


def pytest_collection_modifyitems(config, items):
    if not config.getoption("--fast"):
        return
    skip = pytest.mark.skip(reason="slow test skipped by --fast")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def _stuntkey_env_does_not_leak():
    snap = _isolation.snapshot_env()
    yield
    _isolation.restore_env(snap)
