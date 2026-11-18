"""leakbench/ is a frozen mirror of keycanary's probes; fail if they drift."""
import pytest

from leakbench import loader as lb

kc = pytest.importorskip("keycanary.loader")


def test_probe_ids_match_keycanary():
    for extended in (False, True):
        assert [p.id for p in lb.load(extended=extended)] == \
               [p.id for p in kc.load(extended=extended)]
