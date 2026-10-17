#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Row 212 PR 1c, test only: replay a recorder ring on the FULL node.

The plan's gate for the ring is an exact replay off the device on the full node. The full
node boots a kernel jam, or its own host snapshot (`full-node run --ephemeral --snapshot S`,
crates/snapshot: "I3SNAP" header + jam of the NockApp kernel state, axis 6 = the wrapper's
outer state [%0 desk-hash internal]). This tool writes such a snapshot from a ring checkpoint,
with no change to the full node or the kernel:

  1. Boot the full node from the kernel jam with no snapshot file, and ask it for one
     ({"snapshot": true}). Its core gives the booted build's desk-hash (axis 2 of the outer
     state), as the lite node's own checkpoint boot takes it from the booted kernel (axis 26).
  2. Core = jam([0 desk-hash S]), S = the ring checkpoint's state (++jam of axis 27; sha256 of
     those bytes is D). Snapshot = I3SNAP v1 with this kernel jam's bytes and blake3, event N.
  3. Boot the full node from that snapshot (--ephemeral), poke-jam the cause of every ring
     input after N in order (each input is the lite log entry [num wire 0 0 0 cause]), and
     read the kernel's /state-hash with a peek (an ephemeral boot has no event log, so the
     event number is N plus the inputs poked).

  python3 TRINITITE/tests/ring_full_replay.py RING FULL_NODE TARGET [FROM] [--out DIR]
Run from a 1499kernel checkout (its build/kernel/kernel.jam). TARGET is full-node or lite-node
(the --target the write boot's causes were made for). FROM is oldest (default), newest or N.
Prints one JSON line; exit 0 when the full node accepted every input and answered /state-hash.
"""
import hashlib, json, os, shutil, subprocess, sys, tempfile, time
from pathlib import Path
import blake3
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
sys.path.insert(0, os.getcwd())
import ring_image as R  # noqa: E402
from jam import cue, jam  # noqa: E402
from tools.oracle.basicfb_trace import Control  # noqa: E402

I3SNAP_MAGIC, I3SNAP_VERSION = b"I3SNAP\0\0", 1


def i3snap_encode(jam_bytes: int, jam_blake3: bytes, event: int, core: bytes) -> bytes:
    """crates/snapshot encode(): sha256 over everything but the sha256 field itself."""
    head = (I3SNAP_MAGIC + I3SNAP_VERSION.to_bytes(4, "little") + jam_bytes.to_bytes(8, "little")
            + jam_blake3 + event.to_bytes(8, "little"))
    tail = len(core).to_bytes(8, "little") + core
    return head + hashlib.sha256(head + tail).digest() + tail


def i3snap_core(b: bytes) -> bytes:
    assert b[:8] == I3SNAP_MAGIC and int.from_bytes(b[8:12], "little") == I3SNAP_VERSION
    n = int.from_bytes(b[92:100], "little")
    assert len(b) == 100 + n
    return b[100:]


def atom_bytes(a: int) -> bytes:
    return a.to_bytes(max(1, (a.bit_length() + 7) // 8), "little")


def nth(n, i):
    """Element i of a Nock list-ish tuple (0-based), the last one being the tail."""
    for _ in range(i):
        n = n[1]
    return n


class Node:
    def __init__(self, full: Path, kernel: Path, target: str, d: Path, snap: Path):
        self.d = d
        sock = d / "s.sock"
        self.log = (d / "node.log").open("w")
        self.p = subprocess.Popen([str(full), "run", "--kernel", str(kernel), "--ephemeral",
                                   "--snapshot", str(snap), "--control", str(sock), "--diagnostic",
                                   "--no-clock", "--target", target],
                                  stdout=self.log, stderr=subprocess.STDOUT)
        t = time.monotonic()
        while not sock.exists() and time.monotonic() - t < 120:
            if self.p.poll() is not None:
                raise SystemExit(f"full node exited: see {d / 'node.log'}")
            time.sleep(0.05)
        self.c = Control(sock)

    def close(self):
        self.p.terminate()
        self.p.wait()
        self.log.close()


def state_hash(reply: dict) -> str | None:
    """The peek reply's /state-hash atom as 64 hex digits (little-endian bytes, as row 199)."""
    def find(x):
        if isinstance(x, int):
            return x
        if isinstance(x, str) and x.isdigit():
            return int(x)
        if isinstance(x, dict):
            for k in ("peek", "noun", "result", "value", "atom"):
                if k in x:
                    v = find(x[k])
                    if v is not None:
                        return v
        if isinstance(x, list):
            for y in reversed(x):
                v = find(y)
                if v is not None:
                    return v
        return None
    v = find(reply)
    return None if v is None else v.to_bytes(32, "little").hex()


def main() -> int:
    a = sys.argv[1:]
    out = None
    if "--out" in a:
        i = a.index("--out"); out = Path(a[i + 1]); del a[i:i + 2]
    if len(a) not in (3, 4):
        sys.exit(__doc__)
    ring, full, target = Path(a[0]), Path(a[1]), a[2]
    start = a[3] if len(a) == 4 else "oldest"
    kernel = Path("build/kernel/kernel.jam").resolve()
    kj = kernel.read_bytes()
    d = out or Path(tempfile.mkdtemp(prefix="ring-full-", dir="/tmp"))
    d.mkdir(parents=True, exist_ok=True)

    h, recs = R.records(ring)
    segs = R.segments(recs)
    seg = (segs[0] if start == "oldest" else segs[-1] if start == "newest"
           else next(s for s in segs if s["n"] == int(start)))
    if seg["kind"] != "ckpt" or not seg["sha_ok"]:
        raise SystemExit("start segment is not a checkpoint whose jam hashes to its D")
    i = recs.index(seg["rec"])
    inputs = [r for r in recs[i + 1:] if r["kind"] == "input"]
    if [r["n"] for r in inputs] != list(range(seg["n"] + 1, seg["n"] + 1 + len(inputs))):
        raise SystemExit("inputs after the checkpoint are not consecutive")

    # 1. desk-hash of the booted build, from the full node's own snapshot of a fresh boot
    (d / "fresh").mkdir(exist_ok=True)
    fresh = d / "fresh" / "fresh.snap"
    n0 = Node(full, kernel, target, d / "fresh", fresh)
    try:
        r0 = n0.c.request({"snapshot": True})
    finally:
        n0.close()
    outer = cue(int.from_bytes(i3snap_core(fresh.read_bytes()), "little"))
    if not (isinstance(outer, tuple) and outer[0] == 0 and isinstance(outer[1], tuple)):
        raise SystemExit(f"fresh full-node state is not [%0 desk-hash internal]: {r0}")
    desk = outer[1][0]

    # 2. the snapshot from the ring checkpoint
    state = cue(int.from_bytes(seg["jam"], "little"))
    core = atom_bytes(jam((0, (desk, state))))
    snap = d / "ring.snap"
    snap.write_bytes(i3snap_encode(len(kj), blake3.blake3(kj).digest(), seg["n"], core))

    # 3. boot it, poke the ring inputs' causes, read /state-hash
    (d / "replay").mkdir(exist_ok=True)
    shutil.copy(snap, d / "replay" / "ring.snap")
    n1 = Node(full, kernel, target, d / "replay", d / "replay" / "ring.snap")
    pokes, refused, steps = [], [], []
    try:
        h0 = state_hash(n1.c.request({"peek": "/state-hash"}))
        for r in inputs:
            job = cue(int.from_bytes(r["payload"], "little"))
            if job[0] != r["n"]:
                raise SystemExit(f"input {r['n']} has event number {job[0]}")
            cause = nth(job[1][1], 3)  # [num wire 0 0 0 cause]
            rep = n1.c.request({"poke-jam": atom_bytes(jam(cause)).hex()})
            pokes.append(r["n"])
            steps.append(state_hash(n1.c.request({"peek": "/state-hash"})))
            if not rep.get("ok", False):
                refused.append({"n": r["n"], "reply": str(rep)[:200]})
        peek = n1.c.request({"peek": "/state-hash"})
    finally:
        n1.close()
    booted = "booting from host snapshot" in (d / "replay" / "node.log").read_text()
    res = {"ok": booted and not refused and state_hash(peek) is not None,
           "from": seg["n"], "d": seg["d"].hex(), "boot_hash": h0, "booted_from_snapshot": booted,
           "inputs": [pokes[0], pokes[-1]] if pokes else [], "event": seg["n"] + len(pokes),
           "hash": state_hash(peek), "steps": [x[:8] for x in steps], "refused": refused, "snapshot_bytes": snap.stat().st_size,
           "dir": str(d)}
    print(json.dumps(res))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
