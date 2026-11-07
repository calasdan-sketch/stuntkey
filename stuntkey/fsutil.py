"""Small file helpers shared by the modules that save settings and keys."""
from __future__ import annotations

import os
import sys
import time


def replace(src: str, dst: str) -> None:
    """`os.replace`, with a short retry on Windows only.

    On Windows a rename onto a file that another program has open for a
    moment (a virus scanner, a backup tool, an editor, a search indexer)
    fails with PermissionError although nothing is wrong. Waiting a few
    tenths of a second is what every installer does. On Linux and macOS a
    PermissionError is real and is raised at once. This was read, not run,
    on Windows.
    """
    if sys.platform != "win32":
        os.replace(src, dst)
        return
    for attempt in range(8):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt == 7:
                raise
            time.sleep(0.05 * (attempt + 1))
