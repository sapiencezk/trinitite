#!/usr/bin/env python3
"""Serialize Trinitite builds that publish the compatibility image paths."""

from __future__ import annotations

import fcntl
from pathlib import Path
import subprocess
import sys


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("usage: with_build_lock.py COMMAND [ARG ...]")
    with Path(".trinitite-build.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        completed = subprocess.run(sys.argv[1:], close_fds=False, check=False)
        return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
