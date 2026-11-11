"""pytest glue for tests/_isolation.py: no STUNTKEY_* variable leaks into or out of a test."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _isolation  # noqa: E402


def pytest_configure(config):
    _isolation.scrub_env()          # whatever the caller exported never reaches a test


@pytest.fixture(autouse=True)
def _stuntkey_env_does_not_leak():
    snap = _isolation.snapshot_env()
    yield
    _isolation.restore_env(snap)
