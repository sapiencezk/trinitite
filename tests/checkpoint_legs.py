#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Row 212 PR 1a: checkpoint writer skip legs, and no checkpoint during replay or after a stop.

  skip LEG   LEG in cells, jam, stack, wrapper. Builds with I3_CHECKPOINT_EVERY=2 and
             I3_CKPT_TEST=LEG (a test-only Makefile knob that shrinks that one bound:
             cells 8, jam 8 bytes, walk stack 2, wrapper tag 1 instead of 0) and boots
             %load-bundle, %manage 2 and 8 events. Every N=2,4,.. must log
             `I3H ckpt skip event=N reason=R` (R = cells, jam-size, stack, wrapper), no
             `I3H ckpt ok`, and every step must still be accepted (the run ends done).
  replay [MODE]
             MODE --multiboot (default), --reserve or --reserve3 of
             1499kernel tools/lite_replay_ceiling.py with I3_CHECKPOINT_EVERY=2 added.
             The leg itself must PASS with the same accepted count as flag off (FLAG_OFF_ACCEPTED:
             the checkpoint writer must cost no persist cells), the write
             boots must write checkpoints, no ckpt line may appear between
             `I3H replay entries=` and `I3H replay done` of any boot nor after
             `I3H stop reason=persist`, and the stopped boots (2-4) log no ckpt line.
             `I3H ckpt boot ...` lines (1b's boot-time search) are not writes and are allowed.
             --multiboot with the flag on (1b, approved by the Steward): the flag-off stop came from
             replaying the whole log from zero at every boot; checkpoint plus tail removes it. So the
             pinned expectation is MULTIBOOT_ON below: no stop in any boot, 203 accepted over the 8
             write boots, checkpoint writes only at live steps at exactly the pinned events, every
             boot after the first boots from the pinned checkpoint, and the final /state-hash (read by
             a flag-on boot of the last cold image) equals a flag-off replay from zero of that image
             and the pinned hash. The flag-off --multiboot leg (68 accepted, stop at 69) is unchanged.

Run from the 1499kernel root (PATH=$HOME/.cargo/bin first):
  python3 TRINITITE/tests/checkpoint_legs.py skip LEG OUT FULL_NODE
  python3 TRINITITE/tests/checkpoint_legs.py replay OUT FULL_NODE [MODE]
"""
import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, os.getcwd())
from checkpoint_axis import TT, flag_build
import tools.lite_probe as lp
import tools.lite_replay_ceiling as t
from tools.bundle_build.build import jam_bytes
from tools.legacy_oracle.m48_reference import LocalRequest
from tools.oracle.basicfb_trace import event_cause
from tools.oracle.ir_to_noun import app_to_noun, cord, id_tables, nock_cell, nock_list
from tools.lite_state_hash import reads
from tools.oracle.resident_turn_trace import turn_cause
import tools.scale_scan as sc

REASON = {"cells": "cells", "jam": "jam-size", "stack": "stack", "wrapper": "wrapper"}
EVENTS = 8
# Accepted live steps before the persist stop with the flag off, measured with the 1499kernel
# #258 kernel jam (bff56583) and again, unchanged, with the landing kernel jam (main 3d100787).
# With the pre-#258 kernel (trinitite 9927b88c) --reserve3 was 33.
FLAG_OFF_ACCEPTED = {"--reserve": 32, "--reserve3": 35, "--multiboot": 68}
# 1b: the boot-time checkpoint search logs `I3H ckpt boot ...` lines (none/reject/load/boot) at the
# start of replay; they are not checkpoint writes, so the misplaced-write checks skip them.
BOOT_LINE = "I3H ckpt boot "
# Flag-on --multiboot (I3_CHECKPOINT_EVERY=2, H=12000), pinned with the landing kernel jam
# (1499kernel main 3d100787); the counts are as at #258's head bff56583, the final hash moved
# with the kernel jam (bff56583: 71fb60e5). Boots in order: the 8 write boots of 25 events (the first also loads the bundle and
# %manage 2), then replay/third/fourth, each feeding one probe event.
MULTIBOOT_ON = {
    "accepted": 203,  # in the 8 write boots: %load-bundle (2) + %manage + 200 events
    "boots": ["write", "write1", "write2", "write3", "write4", "write5", "write6", "write7",
              "replay", "third", "fourth"],
    # `I3H ckpt boot event=` per boot (None: the first boot, `none rejected=0 fallback=zero`)
    "boot_from": {"write": None, "write1": 28, "write2": 52, "write3": 78, "write4": 102,
                  "write5": 128, "write6": 152, "write7": 178, "replay": 202, "third": 204,
                  "fourth": 204},
    # `I3H ckpt ok event=` per boot, all after `I3H replay done`
    "writes": {"write": list(range(2, 29, 2)), "write1": list(range(30, 53, 2)),
               "write2": list(range(54, 79, 2)), "write3": list(range(80, 103, 2)),
               "write4": list(range(104, 129, 2)), "write5": list(range(130, 153, 2)),
               "write6": list(range(154, 179, 2)), "write7": list(range(180, 203, 2)),
               "replay": [204], "third": [], "fourth": [206]},
    "final_event": 206,
    "final_hash": "0c36f958e76162abc5fe13e6a3b53e6710f47e4c180a2be43c6b5e991e4acdec",
}


def mem_wait(what: str) -> None:
    import time
    while True:
        kb = int(next(l.split()[1] for l in open("/proc/meminfo") if l.startswith("MemAvailable")))
        if kb >= 4 * 1024 * 1024:
            print(f"MEM {what} {kb}kB", flush=True)
            return
        print(f"MEM wait {what} {kb}kB", flush=True)
        time.sleep(30)


def multiboot_on(out: Path) -> int:
    """The pinned flag-on --multiboot expectation (see MULTIBOOT_ON)."""
    M, bad, accepted = MULTIBOOT_ON, [], 0
    ev = lambda l: int(l.split("event=")[1].split()[0])
    for name in M["boots"]:
        f = out / name / "uart.log"
        if not f.exists():
            bad.append(f"{name}:missing"); continue
        ls = f.read_text().splitlines()
        if name.startswith("write"):
            accepted += sum(l.startswith("I3L1 effects name=w-") for l in ls)
        if any(l.startswith(("I3H stop reason=", "I3H trip-stop reason=", "I3H refused stopped=")) for l in ls):
            bad.append(f"{name}:stop")
        bad += [f"{name}: {l}" for l in ckpt_misplaced(ls)]
        if [l for l in ls if l.startswith("I3H ckpt ") and not l.startswith(BOOT_LINE)
                and not l.startswith("I3H ckpt ok ")]:
            bad.append(f"{name}:ckpt-skip")
        writes = [ev(l) for l in ls if l.startswith("I3H ckpt ok ")]
        froms = [ev(l) for l in ls if l.startswith("I3H ckpt boot event=")]
        nones = [l for l in ls if l.startswith("I3H ckpt boot none ")]
        want_from = M["boot_from"][name]
        if writes != M["writes"][name]:
            bad.append(f"{name}:writes={writes}")
        if want_from is None:
            if froms or nones != ["I3H ckpt boot none rejected=0 fallback=zero"]:
                bad.append(f"{name}:first-boot froms={froms} none={nones}")
        elif froms != [want_from] or nones:
            bad.append(f"{name}:boot_from={froms} none={nones}")
    if accepted != M["accepted"]:
        bad.append(f"accepted={accepted}")
    # Final state: a flag-on boot of the last cold image (boots from its newest checkpoint) and a
    # flag-off replay from zero of the same image (huge headroom, so no persist stop) must agree.
    cold = out / "fourth/build/cold.img"; pill = out / "normal.pill"
    s = lp.Steps("z"); s.steps.append(nock_cell(cord("state-hash"), cord(s._name("h")), 0))
    pl = jam_bytes(nock_list(s.steps))
    mem_wait("final-ckpt boot")
    on = t.boot(out / "tt-h12000/kernel8.img", pill, pl, out / "final-ckpt", cold)
    mem_wait("make img-off")
    off_img = flag_build(out / "img-off", [])
    mem_wait("final-zero boot")
    off = t.boot(off_img, pill, pl, out / "final-zero", cold)
    h_on, h_off = reads(on).get("z-h") or {}, reads(off).get("z-h") or {}
    fe = M["final_event"]
    on_from = [ev(l) for l in on if l.startswith("I3H ckpt boot event=")]
    if on_from != [fe] or f"I3H replay done event={fe + 1}" not in on:
        bad.append(f"final-ckpt:boot_from={on_from}")
    if f"I3H replay entries={fe}" not in off or f"I3H replay done event={fe + 1}" not in off \
            or any(l.startswith("I3H ckpt ") for l in off):
        bad.append("final-zero:replay")
    hs = {h_on.get("hash"), h_off.get("hash")}
    if len(hs) != 1 or None in hs or {h_on.get("event"), h_off.get("event")} != {fe} \
            or h_on.get("hash") != M["final_hash"]:
        bad.append(f"final-hash on={h_on.get('event')}/{h_on.get('hash')} zero={h_off.get('event')}/{h_off.get('hash')}")
    print(f"multiboot flag on: accepted={accepted} boots={len(M['boots'])} "
          f"final ckpt-boot={h_on.get('event')}/{h_on.get('hash')} from-zero={h_off.get('event')}/{h_off.get('hash')} "
          f"bad={bad[:6]}")
    print("PASS" if not bad else "FAIL")
    return 0 if not bad else 1


def skip_leg(leg: str, out: Path, full: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    ir = sc.generate("chain", 5); app, tabs = app_to_noun(ir), id_tables(ir)
    lp.start_builder(full)
    pill = out / "k.pill"; pill.write_bytes(lp.pack_pill(Path("build/kernel/kernel.jam").read_bytes()))
    img = flag_build(out, ["I3_CHECKPOINT_EVERY=2", f"I3_CKPT_TEST={leg}"])
    s = lp.Steps("w")
    s.poke("ld", lp.load_bundle_cause(app))
    s.poke("go", turn_cause(LocalRequest.manage(2), None, None, tabs, None))
    for i in range(EVENTS):
        s.poke(f"e{i}", event_cause(tabs, "B0", "REQ", [1, 1]))
    lines = t.boot(img, pill, jam_bytes(nock_list(s.steps)), out / "w")
    steps = EVENTS + 3  # %load-bundle is two logged steps
    # 1b: a fresh boot (empty store) first logs the search result, then replays from zero.
    want = ["I3H ckpt boot none rejected=0 fallback=zero"] + [
        f"I3H ckpt skip event={n} reason={REASON[leg]}" for n in range(2, steps + 1, 2)]
    got = [l for l in lines if l.startswith("I3H ckpt ")]
    persists = [l for l in lines if l.startswith("I3L1 persist_copy name=w-") and "ok=yes" in l]
    done = any("terminal=done" in l for l in lines)
    ok = got == want and done and len(persists) == steps
    print(f"skip {leg}: ckpt lines={got} want={len(want)} x reason={REASON[leg]} "
          f"persisted={len(persists)}/{steps} done={done}")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


def ckpt_misplaced(lines: list[str]) -> list[str]:
    """ckpt lines inside a replay window or after a stop."""
    bad, replaying, stopped = [], False, False
    for l in lines:
        if l.startswith("I3H replay entries="):
            replaying = True
        elif "I3H replay done" in l or "I3H replay fail" in l:
            replaying = False
        elif l.startswith("I3H stop reason=") or l.startswith("I3H trip-stop reason="):
            stopped = True
        elif l.startswith("I3H ckpt ") and not l.startswith(BOOT_LINE) and (replaying or stopped):
            bad.append(l)
    return bad


def replay_leg(out: Path, full: Path, mode: str) -> int:
    out.mkdir(parents=True, exist_ok=True)
    run = t.subprocess.run
    def patched(cmd, *a, **kw):
        if cmd[:1] == ["make"]:
            # CKPT_LEGS_EXTRA (PR 1c): extra make args, e.g. "I3_LITE_LOG=1".
            cmd = cmd[:-1] + ["I3_CHECKPOINT_EVERY=2"] + os.environ.get("CKPT_LEGS_EXTRA", "").split() + [cmd[-1]]
        return run(cmd, *a, **kw)
    t.subprocess.run = patched
    sys.argv = ["lite_replay_ceiling.py", mode, str(out), str(full), str(TT)]
    try:
        rc = t.main()
    finally:
        t.subprocess.run = run
    if mode == "--multiboot":
        # The 1a stop expectation (rc 0, accepted == flag off) no longer applies with 1b's boot
        # from checkpoint; t.main() reports FAIL because no write boot stops. Pinned instead.
        print(f"(lite_replay_ceiling rc={rc}: its stop expectation is the flag-off one)")
        return multiboot_on(out)
    writes = sorted(p for p in out.glob("write*") if (p / "uart.log").exists())
    stopped = [out / d for d in ("replay", "third", "fourth") if (out / d / "uart.log").exists()]
    ok_lines, bad, accepted = 0, [], 0
    for d in writes:
        ls = (d / "uart.log").read_text().splitlines()
        accepted += sum(l.startswith("I3L1 effects name=w-") for l in ls)
        ok_lines += sum(l.startswith("I3H ckpt ok ") for l in ls)
        bad += [f"{d.name}: {l}" for l in ckpt_misplaced(ls)]
    for d in stopped:
        ls = (d / "uart.log").read_text().splitlines()
        bad += [f"{d.name}: {l}" for l in ls if l.startswith("I3H ckpt ") and not l.startswith(BOOT_LINE)]
    want = FLAG_OFF_ACCEPTED.get(mode)
    ok = rc == 0 and ok_lines > 0 and not bad and len(stopped) == 3 and (want is None or accepted == want)
    print(f"replay {mode}: leg rc={rc} write boots={len(writes)} accepted={accepted} (flag off {want}) "
          f"ckpt ok in write boots={ok_lines} "
          f"stopped boots={len(stopped)} misplaced={bad[:5]}")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    a = sys.argv[1:]
    if a[:1] == ["skip"] and len(a) >= 4 and a[1] in REASON:
        return skip_leg(a[1], Path(a[2]), Path(a[3]))
    if a[:1] == ["replay"] and len(a) >= 3:
        return replay_leg(Path(a[1]), Path(a[2]), a[3] if len(a) > 3 else "--multiboot")
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main())
