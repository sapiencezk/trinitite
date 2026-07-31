#!/usr/bin/env python3
"""Run the exact 32-bank M8 fake-input test with BCM output linked."""

from __future__ import annotations

import os
from pathlib import Path
import selectors
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
process = subprocess.Popen([
    "qemu-system-aarch64", "-machine", "raspi4b", "-m", "2G",
    "-kernel", str(ROOT / "kernel8.img"), "-display", "none",
    "-serial", "stdio", "-monitor", "none",
], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
assert process.stdin is not None and process.stdout is not None
selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
buffer = bytearray()


def wait_for(pattern: bytes, timeout: float):
    deadline = time.monotonic() + timeout
    while pattern not in buffer:
        remaining = deadline - time.monotonic()
        if remaining <= 0: raise TimeoutError(buffer.decode(errors="replace"))
        for key, _mask in selector.select(remaining):
            chunk = os.read(key.fileobj.fileno(), 4096)
            if not chunk: raise RuntimeError("QEMU exited")
            buffer.extend(chunk.replace(b"\x00", b""))


try:
    wait_for(b"> ", 15)
    process.stdin.write(b"M8DI .\n"); process.stdin.flush()
    wait_for(b"0000000000000000  ok", 15)
    print("PASS  trinitite:m8-fake-input-bcm-output-build")
finally:
    if process.poll() is None:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)
