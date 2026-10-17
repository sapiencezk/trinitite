#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Row 212 PR 1a: lite checkpoint digest vs the full node's /state-hash.

Builds this tree with I3_CHECKPOINT_EVERY=K (qemu-virt, I3_HOST, semihost cold),
boots a %load-bundle, %manage 2 and one chain event per X, collects every
`I3H ckpt ok event=N ... sha256=D`, and requires D to equal the 1499kernel full
node's /state-hash after the same N causes. Needs a 1499kernel checkout (its
tools/ and build/kernel/kernel.jam) and its full-node binary. Run from the
1499kernel root (PATH=$HOME/.cargo/bin first):

  python3 TRINITITE/tests/checkpoint_axis.py OUT FULL_NODE [K] [XS]

K defaults to 2, XS (comma list) to 1,1,1,1,0,1,0,1. Exit 0 when every
checkpoint equals /state-hash and at least one was written.
"""
import json, os, re, subprocess, sys
from pathlib import Path
TT = Path(__file__).resolve().parent.parent
sys.path.insert(0, os.getcwd())
import tools.lite_probe as lp
import tools.lite_replay_ceiling as t
from tools.bundle_build.build import jam_bytes
from tools.legacy_oracle.m48_reference import LocalRequest
from tools.oracle.basicfb_trace import event_cause
from tools.oracle.ir_to_noun import app_to_noun, cord, id_tables, nock_cell, nock_list
from tools.oracle.resident_turn_trace import turn_cause
from tools.lite_state_hash import full_hash
import tools.scale_scan as sc

CKPT_OK = re.compile(r"I3H ckpt ok event=(\d+) bytes=\d+ sha256=([0-9a-f]{64})$")


def flag_build(out: Path, extra: list[str], headroom: int = 1_000_000_000) -> Path:
    """t.build with the checkpoint flags added to its make line."""
    run = subprocess.run
    def patched(cmd, *a, **kw):
        if cmd[:1] == ["make"]:
            cmd = cmd[:-1] + extra + [cmd[-1]]
        return run(cmd, *a, **kw)
    t.subprocess.run = patched
    try:
        return t.build(TT, out, headroom)
    finally:
        t.subprocess.run = run


def main() -> int:
    out, full = Path(sys.argv[1]), Path(sys.argv[2])
    k = sys.argv[3] if len(sys.argv) > 3 else "2"
    xs = [int(v) for v in (sys.argv[4] if len(sys.argv) > 4 else "1,1,1,1,0,1,0,1").split(",")]
    out.mkdir(parents=True, exist_ok=True)
    ir = sc.generate("chain", 5); app, tabs = app_to_noun(ir), id_tables(ir)
    lp.start_builder(full)
    pill = out / "k.pill"; pill.write_bytes(lp.pack_pill(Path("build/kernel/kernel.jam").read_bytes()))
    img = flag_build(out, [f"I3_CHECKPOINT_EVERY={k}"])
    s = lp.Steps("w")
    s.poke("ld", lp.load_bundle_cause(app))
    s.poke("go", turn_cause(LocalRequest.manage(2), None, None, tabs, None))
    for i, x in enumerate(xs):
        s.poke(f"e{i}", event_cause(tabs, "B0", "REQ", [x, 1]))
    lines = t.boot(img, pill, jam_bytes(nock_list(s.steps)), out / "w")
    ck = {int(m.group(1)): m.group(2) for l in lines for m in [CKPT_OK.match(l)] if m}
    print("lite ckpts:", json.dumps(ck))
    # %load-bundle is two logged steps (the bundle, then the %trace cause).
    causes = [lp.load_bundle_cause(app), nock_cell(cord("trace"), 0),
              turn_cause(LocalRequest.manage(2), None, None, tabs, None)]
    causes += [event_cause(tabs, "B0", "REQ", [x, 1]) for x in xs]
    ok = bool(ck)
    for n, d in sorted(ck.items()):
        fr = full_hash(full, "lite-node", causes[:n])
        eq = bool(fr) and fr.get("hash") == d and fr.get("event") == n
        ok &= eq
        print(f"N={n} lite={d[:16]} full={fr and fr.get('event')}/{(fr or {}).get('hash', '')[:16]} equal={eq}")
    print("distinct:", len(set(ck.values())), "of", len(ck))
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
