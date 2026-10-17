#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Row 212 PR 1b: lite boot from a checkpoint plus the log tail, and its fallback legs.

Every hash compared here is computed by a node (the lite /state-hash peek, the
writer's `I3H ckpt ok ... sha256=D` line, or the full node's /state-hash); none in Python.

Event sequences (N = accepted log entries; %load-bundle is two logged steps, the bundle
then its %trace re-poke), the chain-5 app of 1499kernel tools/lite_state_hash.py:
  N=6: %load-bundle, %trace, %manage 2, REQ [0 1], REQ [1 1], REQ [0 1]
       (lite_state_hash.py cross-host leg, full node --target lite-node)
  N=7: [%target %full-node], then the N=6 sequence
       (lite_state_hash.py cross-host leg, full node --target full-node)

  boot legs (N, K) = (6, 4), (6, 5), (7, 4): a write boot with I3_CHECKPOINT_EVERY=K (one
      checkpoint, at N=K) takes the sequence with a /state-hash read after every step; a reboot
      of its cold image with the same image must log `I3H ckpt boot event=K`, replay only the
      entries after K (`I3H replay done event=N+1`), and read the same /state-hash as a
      flag-off reboot of the same cold image (replay from zero), as the write boot's own read
      at N, and as the full node after the same causes. (6, 5) is there because at (6, 4) the
      state at N=4 already hashes like N=6 (REQ [1 1] then [0 1] moves it away and back).
      It also records open question 1: each checkpoint digest D (sha256(jam(axis 27))) against
      the lite /state-hash peek at the same N in the same boot.
  fallback legs (N=6 sequence, I3_CHECKPOINT_EVERY=2, headers at N=2,4,6), each rebooted with
      the plain K=2 image; row 212 (3): try the next older checkpoint, and with none valid and
      the log starting at entry 1, replay from zero:
        shape   writer knob hdrshape: every header lacks kernel-blake3      -> 3 x reason=shape, zero
        sid     writer knob hdrsid: every header names an absent state blob -> 3 x reason=sid, zero
        d       writer knob hdrd: every header's D has one bit flipped      -> 3 x reason=hash, zero
        kernel  plain write; reboot with the pill's jam plus one trailing zero byte (same cue,
                different bytes, so g_jam_blake3 differs)                  -> 3 x reason=kernel, zero
        none    flag-off write (no header at all)                           -> none rejected=0, zero
        older   hdrd from N>=3: headers 6 and 4 bad, 2 good                 -> 2 x reason=hash, boot event=2
      Each must end with the from-zero /state-hash at N=6.

Run from a 1499kernel checkout (PATH=$HOME/.cargo/bin first); each make and each QEMU boot
waits for MemAvailable >= 4 GB. CKPT_SRC=DIR builds another trinitite tree instead of this one:
  python3 TRINITITE/tests/checkpoint_boot.py OUT FULL_NODE
Exit 0 when every leg passes.
"""
import json, os, re, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, os.getcwd())
import checkpoint_axis
from checkpoint_axis import flag_build
import tools.lite_probe as lp
import tools.lite_replay_ceiling as t
from tools.bundle_build.build import jam_bytes
from tools.legacy_oracle.m48_reference import LocalRequest
from tools.oracle.basicfb_trace import event_cause
from tools.oracle.ir_to_noun import app_to_noun, cord, id_tables, nock_cell, nock_list
from tools.oracle.resident_turn_trace import turn_cause
from tools.lite_state_hash import full_hash, reads
import tools.scale_scan as sc

CKPT_OK = re.compile(r"I3H ckpt ok event=(\d+) bytes=\d+ sha256=([0-9a-f]{64})$")
BOOT_OK = re.compile(r"I3H ckpt boot event=(\d+) sha256=([0-9a-f]{64}) log=(\d+)$")
REJECT = re.compile(r"I3H ckpt boot reject event=(\d+) reason=(\S+)$")
NONE = re.compile(r"I3H ckpt boot none rejected=(\d+) fallback=zero$")
XS = [0, 1, 0]
# From-zero /state-hash at N with the 1499kernel #258 kernel jam (bff56583, row 216 drops the
# wrapper +load trace; row 211 (5) as amended for the #258 re-pin). Before #258: df590166, f27d583f.
STEWARD = {6: "9f64c2d2", 7: "46775984"}


def mem_wait(what: str) -> None:
    while True:
        kb = int(next(l.split()[1] for l in open("/proc/meminfo") if l.startswith("MemAvailable")))
        if kb >= 4 * 1024 * 1024:
            return
        print(f"MEM wait {what} {kb}kB", flush=True)
        time.sleep(30)


def build(out: Path, extra: list[str]) -> Path:
    mem_wait(f"make {out.name}")
    return flag_build(out, extra)


def boot(img, pill, plan, run, cold=None):
    mem_wait(f"boot {run.name}")
    return t.boot(img, pill, plan, run, cold)


def main() -> int:
    if os.environ.get("CKPT_SRC"):
        checkpoint_axis.TT = Path(os.environ["CKPT_SRC"]).resolve()
    out, full = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    ir = sc.generate("chain", 5); app, tabs = app_to_noun(ir), id_tables(ir)
    lp.start_builder(full)
    jam = Path("build/kernel/kernel.jam").read_bytes()
    pill = out / "k.pill"; pill.write_bytes(lp.pack_pill(jam))
    # Same kernel noun, different bytes as read: g_jam_blake3 differs.
    padded = out / "k-pad.pill"; padded.write_bytes(lp.pack_pill(jam + b"\0"))

    ld = lp.load_bundle_cause(app)
    go = turn_cause(LocalRequest.manage(2), None, None, tabs, None)
    tg = nock_cell(cord("target"), cord("full-node"))
    evs = [event_cause(tabs, "B0", "REQ", [x, 1]) for x in XS]

    def plan(tag: str, target: bool, reads_each: bool = True, live: bool = True) -> bytes:
        s, n = lp.Steps(tag), 0
        def peek():
            if reads_each:
                s.steps.append(nock_cell(cord("state-hash"), cord(s._name(f"h{n}")), 0))
        if live:
            if target:
                s.poke("tg", tg); n += 1; peek()
            s.poke("ld", ld); n += 2; peek()
            s.poke("go", go); n += 1; peek()
            for i, e in enumerate(evs):
                s.poke(f"e{i}", e); n += 1; peek()
        if not live or not reads_each:
            s.steps.append(nock_cell(cord("state-hash"), cord(s._name("z")), 0))
        return jam_bytes(nock_list(s.steps))

    reboot = plan("r", False, live=False)
    img_off = build(out / "img-off", [])
    imgs = {k: build(out / f"img-k{k}", [f"I3_CHECKPOINT_EVERY={k}"]) for k in (4, 5)}
    img_k2 = build(out / "img-k2", ["I3_CHECKPOINT_EVERY=2"])
    bad: list[str] = []
    report: dict = {"boot": {}, "q1": [], "fallback": {}}

    def zero_of(cold: Path, name: str, pl: Path = pill) -> dict | None:
        ls = boot(img_off, pl, reboot, out / name, cold)
        if any(l.startswith("I3H ckpt ") for l in ls):
            bad.append(f"{name}:flag-off-ckpt-line")
        return reads(ls).get("r-z")

    zero6 = None
    for n_want, k, target, tname in ((6, 4, False, "lite-node"), (6, 5, False, "lite-node"),
                                     (7, 4, True, "full-node")):
        tag, img_k = f"n{n_want}k{k}", imgs[k]
        wl = boot(img_k, pill, plan("w", target), out / f"{tag}-write")
        wr = reads(wl)
        live = wr.get(f"w-h{n_want}")
        ck = {int(m.group(1)): m.group(2) for l in wl for m in [CKPT_OK.match(l)] if m}
        for n, d in sorted(ck.items()):
            peek = (wr.get(f"w-h{n}") or {}).get("hash")
            report["q1"].append({"seq": tag, "N": n, "D": d, "peek": peek, "equal": d == peek})
            if d != peek:
                bad.append(f"{tag}:q1:N={n}")
        cold = out / f"{tag}-write/build/cold.img"
        z = zero_of(cold, f"{tag}-zero")
        cl = boot(img_k, pill, reboot, out / f"{tag}-ckboot", cold)
        cb = reads(cl).get("r-z")
        bo = [m.groups() for l in cl for m in [BOOT_OK.match(l)] if m]
        rep = [l for l in cl if l.startswith("I3H replay done")]
        loads = [l for l in cl if l.startswith("I3H ckpt boot load ")]
        # The full node with --target full-node logs [%target %full-node] itself as event 1.
        causes = [ld, nock_cell(cord("trace"), 0), go] + evs
        fr = full_hash(full, tname, causes) or {}
        row = {"K": k, "ckpts": ck, "live": live, "zero": z, "ckpt_boot": cb, "boot_line": bo,
               "load": loads, "replay": rep,
               "full": {k: fr.get(k) for k in ("event", "hash")}}
        report["boot"][tag] = row
        print(f"boot {tag}: {json.dumps(row)}", flush=True)
        hs = {(r or {}).get("hash") for r in (live, z, cb)} | {fr.get("hash")}
        evn = {(r or {}).get("event") for r in (live, z, cb)} | {fr.get("event")}
        if len(hs) != 1 or None in hs or evn != {n_want}:
            bad.append(f"{tag}:hash-mismatch")
        if bo != [(str(k), ck.get(k), str(n_want))] or not ck.get(k):
            bad.append(f"{tag}:no-ckpt-boot-at-{k}")
        if rep != [f"I3H replay done event={n_want + 1}"]:
            bad.append(f"{tag}:replay-line")
        if not (cb or {}).get("hash", "").startswith(STEWARD[n_want]):
            bad.append(f"{tag}:steward-{STEWARD[n_want]}")
        if tag == "n6k4":
            zero6 = z

    legs = [  # name, writer extra, boot pill, write image off?, want rejects, want boot N
        ("shape", ["I3_CKPT_TEST=hdrshape"], pill, False, [(6, "shape"), (4, "shape"), (2, "shape")], None),
        ("sid", ["I3_CKPT_TEST=hdrsid"], pill, False, [(6, "sid"), (4, "sid"), (2, "sid")], None),
        ("d", ["I3_CKPT_TEST=hdrd"], pill, False, [(6, "hash"), (4, "hash"), (2, "hash")], None),
        ("kernel", None, padded, False, [(6, "kernel"), (4, "kernel"), (2, "kernel")], None),
        ("none", None, pill, True, [], None),
        ("older", ["I3_CKPT_TEST=hdrd", "I3_CKPT_TEST_FROM=3"], pill, False, [(6, "hash"), (4, "hash")], 2),
    ]
    for name, extra, bpill, off, want_rej, want_boot in legs:
        wimg = img_off if off else (build(out / f"img-{name}", ["I3_CHECKPOINT_EVERY=2"] + extra)
                                    if extra else img_k2)
        wl = boot(wimg, pill, plan("w", False, reads_each=False), out / f"fb-{name}-write")
        w = reads(wl).get("w-z")
        cold = out / f"fb-{name}-write/build/cold.img"
        cl = boot(img_k2, bpill, reboot, out / f"fb-{name}-boot", cold)
        cb = reads(cl).get("r-z")
        rej = [(int(a), b) for l in cl for m in [REJECT.match(l)] if m for a, b in [m.groups()]]
        bo = [int(m.group(1)) for l in cl for m in [BOOT_OK.match(l)] if m]
        none = [int(m.group(1)) for l in cl for m in [NONE.match(l)] if m]
        rep = [l for l in cl if l.startswith("I3H replay done")]
        wck = sorted(int(m.group(1)) for l in wl for m in [CKPT_OK.match(l)] if m)
        ok = (rej == want_rej and (bo == [want_boot] if want_boot else (bo == [] and none == [len(want_rej)]))
              and rep == ["I3H replay done event=7"] and wck == ([] if off else [2, 4, 6])
              and cb and zero6 and w and (cb["event"], cb["hash"]) == (zero6["event"], zero6["hash"])
              == (w["event"], w["hash"]))
        row = {"write_ckpts": wck, "rejects": rej, "load": [l for l in cl if l.startswith("I3H ckpt boot load ")],
               "boot": bo, "none": none, "final": cb, "ok": bool(ok)}
        report["fallback"][name] = row
        print(f"fallback {name}: {json.dumps(row)}", flush=True)
        if not ok:
            bad.append(f"fallback:{name}")
    (out / "report.json").write_text(json.dumps(report, indent=1))
    print("checkpoint boot: " + ("PASS" if not bad else f"FAIL {bad}"), flush=True)
    return 0 if not bad else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main())
