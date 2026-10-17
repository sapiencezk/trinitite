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
             The leg itself must PASS (same accepted/stop counts as flag off), the write
             boots must write checkpoints, no ckpt line may appear between
             `I3H replay entries=` and `I3H replay done` of any boot nor after
             `I3H stop reason=persist`, and the stopped boots (2-4) log no ckpt line.

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
from tools.oracle.ir_to_noun import app_to_noun, id_tables, nock_list
from tools.oracle.resident_turn_trace import turn_cause
import tools.scale_scan as sc

REASON = {"cells": "cells", "jam": "jam-size", "stack": "stack", "wrapper": "wrapper"}
EVENTS = 8


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
    want = [f"I3H ckpt skip event={n} reason={REASON[leg]}" for n in range(2, steps + 1, 2)]
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
        elif l.startswith("I3H ckpt ") and (replaying or stopped):
            bad.append(l)
    return bad


def replay_leg(out: Path, full: Path, mode: str) -> int:
    out.mkdir(parents=True, exist_ok=True)
    run = t.subprocess.run
    def patched(cmd, *a, **kw):
        if cmd[:1] == ["make"]:
            cmd = cmd[:-1] + ["I3_CHECKPOINT_EVERY=2", cmd[-1]]
        return run(cmd, *a, **kw)
    t.subprocess.run = patched
    sys.argv = ["lite_replay_ceiling.py", mode, str(out), str(full), str(TT)]
    try:
        rc = t.main()
    finally:
        t.subprocess.run = run
    writes = sorted(p for p in out.glob("write*") if (p / "uart.log").exists())
    stopped = [out / d for d in ("replay", "third", "fourth") if (out / d / "uart.log").exists()]
    ok_lines, bad = 0, []
    for d in writes:
        ls = (d / "uart.log").read_text().splitlines()
        ok_lines += sum(l.startswith("I3H ckpt ok ") for l in ls)
        bad += [f"{d.name}: {l}" for l in ckpt_misplaced(ls)]
    for d in stopped:
        ls = (d / "uart.log").read_text().splitlines()
        bad += [f"{d.name}: {l}" for l in ls if l.startswith("I3H ckpt ")]
    ok = rc == 0 and ok_lines > 0 and not bad and len(stopped) == 3
    print(f"replay {mode}: leg rc={rc} write boots={len(writes)} ckpt ok in write boots={ok_lines} "
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
