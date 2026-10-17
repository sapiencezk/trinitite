#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Row 212 PR 1c: read the lite node's recorder ring image off the device.

The ring layout is in src/i3_ring.h. This tool reads a ring image (on QEMU the
semihost file build/ring.img; on the board the ring extent read off the SD card),
checks it (header checksum, record digests, consecutive seq, consecutive event
numbers within each segment, sha256 of each checkpoint's jam = its D), and can
turn it into a cold-store image that an unmodified lite node (the same flag-on
image, I3_LITE_LOG=1) boots for an exact replay off the device: the chosen
checkpoint as a state BLOB and its `[%i3-ckpt N sid D kernel-blake3]` header,
then every input after it as LOG entries, with the superblock's log base at N
(entries 1..N dropped). The node then boots from that checkpoint (row 212 (3)),
replays the inputs and answers /state-hash.

  python3 tools/ring_image.py show RING            JSON summary, exit 1 if the ring is bad
  python3 tools/ring_image.py cold RING OUT [FROM] cold image from the segment FROM:
                                                   oldest (default), newest, or an event N
Needs the `blake3` module (pip). Stdlib otherwise; jam is tools/jam.py.
"""
import hashlib, json, struct, sys
from pathlib import Path
import blake3
sys.path.insert(0, str(Path(__file__).resolve().parent))
from jam import jam  # noqa: E402

RING_MAGIC, REC_MAGIC = 0x0031474E49523349, 0x52523349
DATA0, SLOT, REC_HDR = 1024, 512, 64
GENESIS, CKPT, INPUT, WRAP = 1, 2, 3, 4
KIND = {GENESIS: "genesis", CKPT: "ckpt", INPUT: "input"}
HDR = struct.Struct("<QIIQQQQQQQQQQ32s")
REC = struct.Struct("<IIQQQ32s")
assert HDR.size == 128 and REC.size == REC_HDR

COLD_MAGIC, COLD_OBJ_MAGIC = 0x32444C4F433249, 0x324A424F433249
COLD_COMMIT, COLD_DATA0, COLD_SIZE = 0xC011D00DC0DE17ED, 0x1000, 0x800000
KIND_BLOB, KIND_LOG = 1, 2
OBJ = struct.Struct("<QIIIIQQ32s32sQ")
SUP = struct.Struct("<QIIQQQQQQ32s32s")
assert OBJ.size == 112 and SUP.size == 128


def b3(b: bytes) -> bytes:
    return blake3.blake3(b).digest()


def align8(n: int) -> int:
    return (n + 7) & ~7


class RingError(Exception):
    pass


def headers(img: bytes) -> list[dict]:
    """The valid header slots, newest first."""
    out = []
    for slot in (0, 1):
        raw = img[slot * SLOT: slot * SLOT + 128]
        if len(raw) < 128:
            continue
        f = HDR.unpack(raw)
        h = dict(zip(("magic", "version", "header_len", "ring_bytes", "gen", "head", "tail",
                      "tail_seq", "next_seq", "wraps", "evicted", "last_n", "zero", "checksum"), f))
        if (h["magic"] != RING_MAGIC or h["version"] != 1 or h["header_len"] != 128 or h["zero"]
                or not h["gen"] or b3(raw[:96]) != h["checksum"]):
            continue
        h["slot"] = slot
        out.append(h)
    if not out:
        raise RingError("no valid header slot")
    return sorted(out, key=lambda h: -h["gen"])


def chain(img: bytes, h: dict, prefix: bool = False) -> list[dict]:
    """The records from the tail, checked as the node's walk() does. With prefix, stop at the
    first bad record and return the valid records before it (the longest valid prefix)."""
    R = h["ring_bytes"]
    img = img + bytes(max(0, R - len(img)))
    rec = lambda p: REC.unpack_from(img, p)

    def norm(q):
        if R - q < REC_HDR:
            return DATA0
        m, k, *_ = rec(q)
        return DATA0 if (m == REC_MAGIC and k == WRAP) else q

    out, p, seq = [], h["tail"], h["tail_seq"]
    limit = min(h["next_seq"], h["tail_seq"] + R // REC_HDR)

    def bad(msg):
        if prefix:
            return out
        raise RingError(msg)
    while seq < limit:
        if p < DATA0 or R - p < REC_HDR:
            return bad(f"record offset {p} out of the ring")
        m, k, s, n, ln, dig = rec(p)
        if (m != REC_MAGIC or s != seq or k not in KIND or p + align8(REC_HDR + ln) > R
                or (seq == h["tail_seq"] and k == INPUT)):
            return bad(f"bad record at {p} seq {seq}")
        payload = img[p + REC_HDR: p + REC_HDR + ln]
        if b3(payload) != dig:
            return bad(f"payload digest at {p} seq {seq}")
        out.append({"off": p, "kind": KIND[k], "seq": s, "n": n, "payload": payload,
                    "size": align8(REC_HDR + ln)})
        q = p + align8(REC_HDR + ln)
        seq += 1
        if seq == h["next_seq"]:
            if (q != h["head"] and norm(q) != h["head"]) or n != h["last_n"]:
                return bad("records do not end at head")
            break
        p = q if q == h["head"] else norm(q)
    if seq < h["next_seq"] and not prefix:
        raise RingError("more records than fit in the ring")
    return out


def records(path) -> tuple[dict, list[dict]]:
    """As the node opens the ring (src/i3_ring.c open_slots): the newest valid header whose
    chain is intact (fallback 0, status=ok), else the other slot (fallback 1, torn-older),
    else the longest valid prefix from the tail of either slot, newest first (prefix true,
    torn-prefix; head and last_n then describe the prefix, as the node commits them).
    No valid prefix raises RingError (the node's status=corrupt)."""
    img = Path(path).read_bytes()
    err = None
    hs = headers(img)
    for i, h in enumerate(hs):
        try:
            recs = chain(img, h)
            h["fallback"], h["prefix"] = i, False
            return h, recs
        except RingError as e:
            err = err or e
    for i, h in enumerate(hs):
        recs = chain(img, h, prefix=True)
        if recs:
            last = recs[-1]
            h.update(fallback=i, prefix=True, last_n=last["n"],
                     next_seq=h["tail_seq"] + len(recs), head=last["off"] + last["size"],
                     broken=str(err))
            return h, recs
    raise err


def segments(recs: list[dict]) -> list[dict]:
    segs = []
    for r in recs:
        if r["kind"] in ("genesis", "ckpt"):
            seg = {"kind": r["kind"], "n": r["n"], "rec": r, "inputs": []}
            if r["kind"] == "ckpt":
                d, kb, j = r["payload"][:32], r["payload"][32:64], r["payload"][72:]
                js = int.from_bytes(r["payload"][64:72], "little")
                seg.update(d=d, kb=kb, jam=j, job_sum=js, sha_ok=hashlib.sha256(j).digest() == d)
            else:
                seg.update(kb=r["payload"][:32])
            segs.append(seg)
        else:
            segs[-1]["inputs"].append(r)
    for s in segs:
        ns = [r["n"] for r in s["inputs"]]
        s["contiguous"] = ns == list(range(s["n"] + 1, s["n"] + 1 + len(ns)))
    return segs


def summary(path) -> dict:
    h, recs = records(path)
    segs = segments(recs)
    return {
        "ring_bytes": h["ring_bytes"], "gen": h["gen"], "head": h["head"], "tail": h["tail"],
        "records": len(recs), "wraps": h["wraps"], "evicted": h["evicted"], "last_n": h["last_n"],
        "slot": h["slot"], "fallback": h["fallback"], "prefix": h["prefix"],
        "segments": [{"kind": s["kind"], "n": s["n"], "off": s["rec"]["off"],
                      "seg_bytes": s["rec"]["size"] + sum(r["size"] for r in s["inputs"]),
                      "ckpt_record_bytes": s["rec"]["size"],
                      "inputs": [s["inputs"][0]["n"], s["inputs"][-1]["n"]] if s["inputs"] else [],
                      "input_bytes": sum(r["size"] for r in s["inputs"]),
                      "contiguous": s["contiguous"],
                      **({"sha256": s["d"].hex(), "sha_ok": s["sha_ok"], "job_sum": s["job_sum"]}
                         if s["kind"] == "ckpt" else {})}
                     for s in segs],
        "ok": all(s["contiguous"] and s.get("sha_ok", True) for s in segs),
    }


def atom_bytes(a: int) -> bytes:
    return a.to_bytes(max(1, (a.bit_length() + 7) // 8), "little")


def cord(s: str) -> int:
    return int.from_bytes(s.encode(), "little")


def hash62(payload: bytes) -> int:
    v = int.from_bytes(b3(payload)[:8], "little") & 0x3FFFFFFFFFFFFFFF
    return v or 1


def cold_image(path, out, start="oldest") -> dict:
    """Cold image: the start segment's checkpoint plus every later input (see the docstring)."""
    h, recs = records(path)
    segs = [s for s in segments(recs)]
    if start == "oldest":
        seg = segs[0]
    elif start == "newest":
        seg = segs[-1]
    else:
        seg = next(s for s in segs if s["n"] == int(start))
    if seg["kind"] == "ckpt" and not seg["sha_ok"]:
        raise RingError("checkpoint jam does not hash to its D")
    i = recs.index(seg["rec"])
    inputs = [r for r in recs[i + 1:] if r["kind"] == "input"]
    ns = [r["n"] for r in inputs]
    if ns != list(range(seg["n"] + 1, seg["n"] + 1 + len(ns))):
        raise RingError(f"inputs after {seg['n']} are not consecutive")
    data = bytearray(COLD_SIZE)
    off, gen, logs, first_log = COLD_DATA0, 2, 0, None

    def put(kind, payload):
        nonlocal off, gen
        pre = struct.pack("<QIIIIQQ", COLD_OBJ_MAGIC, 2, 112, kind, 0, gen, len(payload)) + b3(payload)
        hd = pre + b3(pre) + struct.pack("<Q", COLD_COMMIT)
        if off + align8(112 + len(payload)) > COLD_SIZE:
            raise RingError("cold image full")
        data[off:off + 112] = hd
        data[off + 112: off + 112 + len(payload)] = payload
        at = off
        off = align8(off + 112 + len(payload)); gen += 1
        return at

    base, job_sum = 0, 0
    if seg["kind"] == "ckpt":
        sid = hash62(seg["jam"])
        put(KIND_BLOB, seg["jam"])
        hdr = (cord("i3-ckpt"), (seg["n"], (sid, (int.from_bytes(seg["d"], "little"),
                                                  int.from_bytes(seg["kb"], "little")))))
        put(KIND_BLOB, atom_bytes(jam(hdr)))
        base, job_sum = seg["n"], seg["job_sum"]
    for r in inputs:
        at = put(KIND_LOG, r["payload"]); logs += 1
        first_log = at if first_log is None else first_log
    pre = struct.pack("<QIIQQQQQQ", COLD_MAGIC, 2, 128, gen - 1, 0, 0, off, logs, COLD_COMMIT)
    chk = b3(pre)
    if base:
        # job_sum: the row 213 job-cell sum of entries 1..N, from the ring checkpoint record,
        # so the reserve check during the off-device replay counts as the device did.
        b = struct.pack("<QQQ", base, first_log if first_log is not None else off, job_sum)
        c = int.from_bytes(b3(pre + b)[:8], "little") or 1
        res = b + struct.pack("<Q", c)
    else:
        res = bytes(32)
    data[0:128] = pre + chk + res
    Path(out).write_bytes(bytes(data))
    return {"from": seg["kind"], "n": seg["n"], "inputs": [ns[0], ns[-1]] if ns else [],
            "events": seg["n"] + len(ns), "base": base, "job_sum": job_sum, "data_head": off}


def main() -> int:
    a = sys.argv[1:]
    try:
        if a[:1] == ["show"] and len(a) == 2:
            s = summary(a[1]); print(json.dumps(s)); return 0 if s["ok"] else 1
        if a[:1] == ["cold"] and len(a) in (3, 4):
            print(json.dumps(cold_image(a[1], a[2], a[3] if len(a) == 4 else "oldest"))); return 0
    except RingError as e:
        print(json.dumps({"ok": False, "error": str(e)})); return 1
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main())
