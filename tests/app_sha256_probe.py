#!/usr/bin/env python3
"""SHA-256 admission gate probe (decision 151/152, lite-node mirror).

Boots the I3 host under QEMU (qemu-virt) with a minimal nockapp kernel and a
diagnostic plan holding a single ``%load-app`` step.  The bundle is delivered
as a blob at ``I3_APP_BASE`` (0x53000000)::

    [0..8)   uint64_t LE jam byte length
    [8..72)  64 ASCII hex expected SHA-256 (lowercase; all '0' = no gate)
    [72..)   jam bytes

Three cases are exercised:

  * right digest  -> gate matches: bundle cued, ``%load-bundle`` poke attempted.
                     The minimal kernel (``[[0 1] [0 0]]``) has no arm 23, so the
                     poke aborts with a nock crash; the observable is
                     ``abort=crash`` plus ``nock crash:`` lines.
  * wrong digest  -> gate refuses *before* cue/poke: no poke, no ``nock crash``,
                     ``abort=none``; kernel state untouched.
  * no digest     -> all-zero expected digest skips the gate: poke attempted
                     (identical to pre-gate behaviour).

Each assertion is gate-sensitive: deleting the SHA-256 comparison in
``i3_host_load_app`` flips the wrong-digest case to ``abort=crash``, so the
wrong-digest assertion fails.

Usage:
  python3 tests/app_sha256_probe.py [--image path/to/kernel8.img]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from jam import jam  # noqa: E402

PILL_BASE = 0x50000000
I3_PLAN_BASE = 0x51000000
I3_APP_BASE = 0x53000000
APP_SHA256_HEX_LEN = 64
TERMINAL = b"I3L1 terminal="
QEMU_TIMEOUT = 60.0


def cord(text: str) -> int:
    if not text:
        return 0
    return int.from_bytes(text.encode("ascii"), "little")


def nock_cell(*items) -> object:
    out = items[-1]
    for item in reversed(items[:-1]):
        out = (item, out)
    return out


def nock_list(items) -> object:
    out = 0
    for item in reversed(items):
        out = (item, out)
    return out


def atom_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    return bytes(out)


def jam_bytes(noun: object) -> bytes:
    return atom_to_bytes(jam(noun))


def pack_pill(jam_data: bytes) -> bytes:
    return (
        struct.pack("<Q", len(jam_data))
        + b"\x02"  # shape nockapp
        + struct.pack("<I", 0)
        + b"\x00\x00\x00"
        + jam_data
    )


def pack_plan(plan: bytes) -> bytes:
    return struct.pack("<Q", len(plan)) + plan


def pack_app(jam_data: bytes, expected_hex: str) -> bytes:
    assert len(expected_hex) == APP_SHA256_HEX_LEN, "expected digest must be 64 hex"
    return (
        struct.pack("<Q", len(jam_data))
        + expected_hex.encode("ascii")
        + jam_data
    )


def minimal_kernel_noun() -> object:
    return ((0, 1), (0, 0))


def load_app_plan_noun() -> object:
    step = nock_cell(cord("load-app"), nock_cell(cord("app1"), 0))
    return nock_list([step])


def run_guest(image: Path, pill: Path, plan: Path, app: Path) -> tuple[str, str, bool]:
    qemu = shutil.which("qemu-system-aarch64")
    if not qemu:
        raise SystemExit("qemu-system-aarch64 not found on PATH")
    cmd = [
        qemu,
        "-machine", "virt",
        "-cpu", "cortex-a72",
        "-m", "2G",
        "-kernel", str(image.resolve()),
        "-device", f"loader,file={pill.resolve()},addr={PILL_BASE:#x},force-raw=on",
        "-device", f"loader,file={plan.resolve()},addr={I3_PLAN_BASE:#x},force-raw=on",
        "-device", f"loader,file={app.resolve()},addr={I3_APP_BASE:#x},force-raw=on",
        "-display", "none",
        "-nographic",
        "-no-reboot",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert proc.stdout is not None
    import time
    buf = bytearray()
    deadline = time.monotonic() + QEMU_TIMEOUT
    try:
        while time.monotonic() < deadline:
            chunk = proc.stdout.read1(8192)
            if chunk:
                buf.extend(chunk)
                if TERMINAL in buf:
                    break
            elif proc.poll() is not None:
                break
            else:
                time.sleep(0.05)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    out = bytes(buf).decode("utf-8", errors="replace")
    timed_out = TERMINAL not in buf
    return out, "", timed_out


def probe_case(image: Path, app_blob: bytes, name: str) -> str:
    tmp = Path(tempfile.mkdtemp(prefix="app-sha256-"))
    try:
        pill = tmp / "kernel.pill"
        plan = tmp / "kernel.plan"
        app = tmp / "app.blob"
        pill.write_bytes(pack_pill(jam_bytes(minimal_kernel_noun())))
        plan.write_bytes(pack_plan(jam_bytes(load_app_plan_noun())))
        app.write_bytes(app_blob)
        out, err, timed_out = run_guest(image, pill, plan, app)
        if timed_out:
            raise SystemExit(f"{name}: QEMU timed out: {err}")
        if TERMINAL not in out.encode("utf-8", "replace"):
            raise SystemExit(f"{name}: no terminal marker in guest output:\n{out}")
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    raise SystemExit(1)


def expect(cond: bool, msg: str) -> None:
    if not cond:
        fail(msg)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", type=Path, default=ROOT / "kernel8.img")
    args = ap.parse_args()
    image = args.image
    if not image.is_file():
        raise SystemExit(f"{image} not found; build with "
                         "`make PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1 all`")

    bundle_jam = jam_bytes(nock_cell(cord("bundle"), 0))
    right_digest = hashlib.sha256(bundle_jam).hexdigest()
    # A wrong digest must be non-zero (all-zero is the "no gate" sentinel) and
    # different from the real digest.
    wrong_digest = "f" * 64
    if wrong_digest == right_digest:
        wrong_digest = "e" * 64
    no_gate = "0" * 64

    cases = {
        "right-digest": pack_app(bundle_jam, right_digest),
        "wrong-digest": pack_app(bundle_jam, wrong_digest),
        "no-digest": pack_app(bundle_jam, no_gate),
    }
    outputs = {name: probe_case(image, blob, name) for name, blob in cases.items()}

    # ── right digest ────────────────────────────────────────────────────────
    right = outputs["right-digest"]
    expect("I3H app-sha256 sha256 " in right, "right-digest: missing gate line")
    expect(" match=yes" in right, "right-digest: gate did not match")
    expect(" != expected " not in right, "right-digest: unexpected refusal")
    # gate passed, so the %load-bundle poke was attempted -> minimal-kernel crash
    expect("I3L1 load-app name=" in right, "right-digest: missing load-app line")
    expect("abort=crash" in right, "right-digest: poke was not attempted (no crash)")

    # ── wrong digest ────────────────────────────────────────────────────────
    wrong = outputs["wrong-digest"]
    expect("I3H app-sha256 sha256 " in wrong, "wrong-digest: missing gate line")
    expect(" != expected " in wrong, "wrong-digest: mismatch not reported")
    expect(" match=yes" not in wrong, "wrong-digest: gate wrongly matched")
    expect("abort=none" in wrong, "wrong-digest: poke was attempted on mismatch")
    expect("nock crash:" not in wrong,
           "wrong-digest: a poke reached the kernel on mismatch")

    # ── no digest ───────────────────────────────────────────────────────────
    none = outputs["no-digest"]
    expect("I3H app-sha256 sha256 " in none, "no-digest: missing gate line")
    expect(" gate=no" in none, "no-digest: gate not skipped")
    expect(" != expected " not in none, "no-digest: unexpected refusal")
    expect("abort=crash" in none, "no-digest: poke was not attempted (as today)")

    print("right-digest:  ok (gate match, poke attempted)")
    print("wrong-digest:  ok (refused before cue/poke)")
    print("no-digest:     ok (unchanged behaviour)")
    print("all app-sha256 probe cases passed")


if __name__ == "__main__":
    main()
