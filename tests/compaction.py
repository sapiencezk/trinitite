#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Row 221 (row 212 (c)): compaction after a verified checkpoint, on QEMU (I3_LITE_LOG=1).

Images: I3_CHECKPOINT_EVERY=2 I3_LITE_LOG=1 (compaction rides on the row 212 flags), qemu-virt,
I3_HOST, semihost cold image; the control image is flag off (no checkpoint, no compaction).
App: the chain-5 app of 1499kernel tools/lite_state_hash.py. Sequence: %load-bundle (two
logged steps), %manage 2, then REQ [x 1] with x = 0,1,0,1,... Every hash compared is computed by
a node (the lite /state-hash peek, the `I3H ckpt ok ... sha256=D` line, the full node).

  running   N = 6 + EXTRA (16) with a /state-hash read after every step. Every checkpoint (2, 4, ..
            16) verifies and compacts (`I3H compact ok`, none skipped), the persist half flips
            each time, and each compaction's atom store rebuild is byte-identical (the check
            digest over the kept records before the slide equals the one over the store after
            it) with every live atom re-hashed to its name (missing=0) and no wild root. Each
            checkpoint's D and every per-step read equal the flag-off control run's read at that
            N, and the final read equals the full node. The store returns to the same size after
            each rebuild. A reboot of the cold image boots from 16 and reads the same hash;
            row 221 (7): its job sum counted from the log base (`I3H replay job_sum=`) equals the
            live node's after the compaction at 16 and the base record's audit field.
  crash-P   for P in before, copy, after-copy, after-flip, rebuild (writer knobs cmpbefore,
            cmpcopy, cmpafter, cmpflip, cmprebuild, I3_CKPT_TEST_FROM=4): the N=6 sequence; the
            compaction after checkpoint 4 stops dead at P (`I3H compact test crash event=4
            at=P`). The reboot (plain image) boots from 4, reads the control hash at 4, takes the
            remaining two REQ events and reads the full node's hash at 6.
  skip      writer knob cmpskip (FROM=4): the copy of the compaction at 4 fails, the transaction
            aborts (`I3H compact skip event=4 reason=copy`), the node keeps running on the old
            half, compacts at 6, and reads the full node's hash at 6.
OUT/report.json also has the code region size and each compaction's walk, slide, index and total
ticks (cntvct at 62.5 MHz on QEMU TCG: host time, not board time).

Run from a 1499kernel checkout (PATH=$HOME/.cargo/bin first); each make and QEMU boot waits for
MemAvailable >= 4 GB. CKPT_SRC=DIR builds another trinitite tree.
  python3 TRINITITE/tests/compaction.py OUT FULL_NODE
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

EXTRA = 10
ON = ["I3_CHECKPOINT_EVERY=2", "I3_LITE_LOG=1"]
CKPT_OK = re.compile(r"I3H ckpt ok event=(\d+) bytes=\d+ sha256=([0-9a-f]{64})$")
BOOT_OK = re.compile(r"I3H ckpt boot event=(\d+) ")
CMP_OK = re.compile(r"I3H compact ok event=(\d+) (.*)$")
CMP_WALK = re.compile(r"I3H compact walk event=(\d+) (.*)$")
SKIP = re.compile(r"I3H compact skip event=(\d+) reason=(\S+)$")
CRASH = re.compile(r"I3H compact test crash event=(\d+) at=(\S+)$")
CODE = re.compile(r"I3H code region bytes=(\d+) cells=(\d+) size=(\d+)$")
LOGBOOT = re.compile(r"I3H log boot base=(\d+) len=(\d+) job_sum=(\d+)$")
RJS = re.compile(r"I3H replay job_sum=(\d+)$")
CRASH_LEGS = [("before", "cmpbefore"), ("copy", "cmpcopy"), ("after-copy", "cmpafter"),
              ("after-flip", "cmpflip"), ("rebuild", "cmprebuild")]


def mem_wait(what: str) -> None:
    while True:
        kb = int(next(l.split()[1] for l in open("/proc/meminfo") if l.startswith("MemAvailable")))
        if kb >= 4 * 1024 * 1024:
            print(f"MEM {what} {kb}kB", flush=True)
            return
        print(f"MEM wait {what} {kb}kB", flush=True)
        time.sleep(30)


def build(out: Path, extra: list[str]) -> Path:
    mem_wait(f"make {out.name}")
    return flag_build(out, extra)


def boot(img, pill, plan, run, cold=None):
    mem_wait(f"boot {run.name}")
    ls = t.boot(img, pill, plan, run, cold)
    (run / "uart.txt").write_text("\n".join(ls))
    return ls


def kv(s: str) -> dict:
    return {a: b for a, b in (x.split("=", 1) for x in s.split() if "=" in x)}


def main() -> int:
    if os.environ.get("CKPT_SRC"):
        checkpoint_axis.TT = Path(os.environ["CKPT_SRC"]).resolve()
    out, full = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    ir = sc.generate("chain", 5); app, tabs = app_to_noun(ir), id_tables(ir)
    lp.start_builder(full)
    pill = out / "k.pill"; pill.write_bytes(lp.pack_pill(Path("build/kernel/kernel.jam").read_bytes()))
    ld = lp.load_bundle_cause(app)
    go = turn_cause(LocalRequest.manage(2), None, None, tabs, None)
    xs = [i % 2 for i in range(3 + EXTRA)]
    evs = [event_cause(tabs, "B0", "REQ", [x, 1]) for x in xs]
    n_all = 3 + len(evs)

    def plan(tag: str, causes: list, start: int, each: bool) -> bytes:
        """causes: (name, cause, logged steps); a /state-hash read after each (or at the end)."""
        s, n = lp.Steps(tag), start
        def peek(name):
            s.steps.append(nock_cell(cord("state-hash"), cord(s._name(name)), 0))
        if start:
            peek(f"h{n}")
        for name, c, k in causes:
            s.poke(name, c); n += k
            if each:
                peek(f"h{n}")
        if not each:
            peek("z")
        return jam_bytes(nock_list(s.steps))

    seq = [("ld", ld, 2), ("go", go, 1)] + [(f"e{i}", e, 1) for i, e in enumerate(evs)]
    full_causes = [ld, nock_cell(cord("trace"), 0), go] + evs
    img_off = build(out / "img-off", [])
    img_on = build(out / "img-on", ON)
    bad: list[str] = []
    rep: dict = {}

    # control: flag off, a read after every step
    cl = boot(img_off, pill, plan("w", seq, 0, True), out / "control")
    ctl = {int(k[3:]): v for k, v in reads(cl).items() if k.startswith("w-h")}
    fr = full_hash(full, "lite-node", full_causes) or {}
    fr6 = full_hash(full, "lite-node", full_causes[:6]) or {}
    rep["control"] = {n: v.get("hash") for n, v in sorted(ctl.items())}
    rep["full"] = {"16": fr.get("hash"), "6": fr6.get("hash")}
    if (ctl.get(n_all) or {}).get("hash") != fr.get("hash") or not fr.get("hash"):
        bad.append("control-vs-full")

    # running
    wl = boot(img_on, pill, plan("w", seq, 0, True), out / "running")
    wr = {int(k[3:]): v for k, v in reads(wl).items() if k.startswith("w-h")}
    ck = {int(m.group(1)): m.group(2) for l in wl for m in [CKPT_OK.match(l)] if m}
    cmps = [(int(m.group(1)), kv(m.group(2))) for l in wl for m in [CMP_OK.match(l)] if m]
    walks = [(int(m.group(1)), kv(m.group(2))) for l in wl for m in [CMP_WALK.match(l)] if m]
    skips = [l for l in wl if SKIP.match(l)]
    code = [m.groups() for l in wl for m in [CODE.match(l)] if m]
    want_n = list(range(2, n_all + 1, 2))
    row = {"ckpts": sorted(ck), "compactions": [n for n, _ in cmps], "skips": skips, "code": code,
           "detail": [{"N": n, **c, **{"walk_" + k: v for k, v in w.items()}}
                      for (n, c), (_, w) in zip(cmps, walks)]}
    if sorted(ck) != want_n or [n for n, _ in cmps] != want_n or skips:
        bad.append("running:compactions")
    halves = [c.get("half") for _, c in cmps]
    if halves != ["0->1" if i % 2 == 0 else "1->0" for i in range(len(halves))]:
        bad.append(f"running:halves={halves}")
    for n, c in cmps:
        if c.get("kept_digest") != c.get("after_digest") or c.get("missing") != "0":
            bad.append(f"running:rebuild@{n}")
    for n, w in walks:
        if w.get("wild") != "0" or w.get("overflow") != "0":
            bad.append(f"running:walk@{n}")
    after = {c.get("atom_bytes", "").split("->")[-1] for _, c in cmps}
    row["atom_bytes_after"] = sorted(after)
    if len(after) != 1:
        bad.append(f"running:store-size {sorted(after)}")
    for n, d in ck.items():
        if (ctl.get(n) or {}).get("hash") != d:
            bad.append(f"running:D@{n}")
    for n in range(1, n_all + 1):
        if n in ctl and (wr.get(n) or {}).get("hash") != ctl[n].get("hash"):
            bad.append(f"running:read@{n}")
    if not code or int(code[0][0]) > int(code[0][2]):
        bad.append("running:code-region")
    live_js = cmps[-1][1].get("job_sum") if cmps else None
    rb = boot(img_on, pill, plan("r", [], 0, False), out / "running-reboot", out / "running/build/cold.img")
    rz = reads(rb).get("r-z") or {}
    lb = [m.groups() for l in rb for m in [LOGBOOT.match(l)] if m]
    rjs = [m.group(1) for l in rb for m in [RJS.match(l)] if m]
    bo = [m.group(1) for l in rb for m in [BOOT_OK.match(l)] if m]
    row.update({"final": wr.get(n_all), "reboot": rz, "boot": bo, "log_boot": lb,
                "job_sum": {"live": live_js, "reboot": rjs, "base_record": lb[0][2] if lb else None}})
    if rz.get("hash") != fr.get("hash") or (wr.get(n_all) or {}).get("hash") != fr.get("hash") \
            or bo != [str(n_all)]:
        bad.append("running:final")
    if not live_js or rjs != [live_js] or not lb or lb[0][2] != live_js:
        bad.append("running:job_sum")
    rep["running"] = row
    print("running:", json.dumps(row), flush=True)

    # crash points
    seq6 = seq[:5]  # ld go e0 e1 e2 -> N=6
    rest = [(f"e{i}", evs[i], 1) for i in (1, 2)]
    for at, knob in CRASH_LEGS:
        img = build(out / f"img-{knob}", ON + [f"I3_CKPT_TEST={knob}", "I3_CKPT_TEST_FROM=4"])
        w = boot(img, pill, plan("w", seq6, 0, False), out / f"crash-{at}")
        cr = [m.groups() for l in w for m in [CRASH.match(l)] if m]
        wck = sorted(int(m.group(1)) for l in w for m in [CKPT_OK.match(l)] if m)
        r = boot(img_on, pill, plan("r", rest, 4, True), out / f"crash-{at}-reboot",
                 out / f"crash-{at}/build/cold.img")
        rr = reads(r)
        bo = [m.group(1) for l in r for m in [BOOT_OK.match(l)] if m]
        h4, h6 = (rr.get("r-h4") or {}), (rr.get("r-h6") or {})
        row = {"crash": cr, "write_ckpts": wck, "boot": bo, "h4": h4.get("hash"), "h6": h6.get("hash"),
               "reboot_compactions": [int(m.group(1)) for l in r for m in [CMP_OK.match(l)] if m]}
        rep[f"crash-{at}"] = row
        print(f"crash-{at}:", json.dumps(row), flush=True)
        if cr != [("4", at)] or wck != [2, 4] or bo != ["4"] or h4.get("hash") != (ctl.get(4) or {}).get("hash") \
                or h6.get("hash") != fr6.get("hash") or not fr6.get("hash"):
            bad.append(f"crash-{at}")

    # skip
    img = build(out / "img-cmpskip", ON + ["I3_CKPT_TEST=cmpskip", "I3_CKPT_TEST_FROM=4"])
    w = boot(img, pill, plan("w", seq6, 0, False), out / "skip")
    sk = [m.groups() for l in w for m in [SKIP.match(l)] if m]
    co = [int(m.group(1)) for l in w for m in [CMP_OK.match(l)] if m]
    wz = reads(w).get("w-z") or {}
    row = {"skips": sk, "compactions": co, "final": wz}
    rep["skip"] = row
    print("skip:", json.dumps(row), flush=True)
    if sk != [("4", "copy")] or co != [2, 6] or wz.get("hash") != fr6.get("hash") or wz.get("event") != 6:
        bad.append("skip")

    (out / "report.json").write_text(json.dumps(rep, indent=1))
    print("compaction: " + ("PASS" if not bad else f"FAIL {bad}"), flush=True)
    return 0 if not bad else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main())
