#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Row 212 PR 1c: the running log and the SD recorder ring (I3_LITE_LOG=1), on QEMU.

Row 212 as amended (1499kernel #263, 5091bb19), (2): "The node keeps the last verified
checkpoint plus every entry after it, and the previous checkpoint until the next one
verifies. Entries before the kept checkpoint are dropped. Recorder ring. A fixed-size ring
on SD, sized in bytes with a configurable default, keeps periodic checkpoints and the inputs
between them. When full, the oldest checkpoint and its inputs are overwritten." (3): "if none
is valid and the log has been rotated, the node stops (row 141 stop) and reports it."

Images: I3_CHECKPOINT_EVERY=2 I3_LITE_LOG=1 I3_RING_EVERY=2 I3_RING_BYTES=RING (small, so the
ring wraps within a few events), qemu-virt, I3_HOST, semihost cold and ring files. The event
sequences are those of tests/checkpoint_boot.py (chain-5 app): N=6 (%load-bundle, %trace,
%manage 2, REQ [0 1], [1 1], [0 1]; full node --target lite-node) and N=7 ([%target %full-node]
first; full node --target full-node). Every hash compared is computed by a node.

  running   N=6 write boot, a /state-hash read after every step: checkpoints at 2, 4, 6; no base
            move at 2, `I3H log base event=2` right after the checkpoint at 4 verifies, `event=4`
            after 6 (the previous checkpoint stays until the next one verifies; entries before it
            are dropped); the cold superblock's base is 4. A reboot of the cold image reads base 4,
            boots from 6, replays nothing, and reads the same /state-hash as the write boot at 6
            and the full node (9f64c2d2).
  crash     I3_CKPT_TEST=crash I3_CKPT_TEST_FROM=6: the checkpoint at 6 is stored damaged and the
            node stops dead before verifying it. The reboot rejects 6 (reason=hash), boots from 4
            (kept: the base is still 2), replays 5 and 6 and reads 9f64c2d2.
  rotated   the running cold image (base 4) rebooted with the pill's jam plus one zero byte (so
            no checkpoint's kernel-blake3 matches): rejects 6 and 4 (reason=kernel), logs
            `fallback=stop base=4`, `I3H stop reason=rotated`, replays nothing, refuses the poke
            and /state-hash; a second such boot does the same (nothing was written).
  wrap      the N=6 sequence then EXTRA more REQ events: the ring wraps, the oldest segments
            (genesis first) are overwritten, every kept segment is contiguous, each checkpoint's
            jam hashes to its D; a reboot with the ring and cold images opens the ring with gap=0
            and two more events extend it.
  offdevice for N=6 and N=7: tools/ring_image.py turns the write boot's ring image into a cold
            image from its oldest kept checkpoint; the same flag-on image boots it (no ring
            loaded), replays every later ring input and reads /state-hash, which must equal the
            full node's after the same causes (N=6 9f64c2d2, N=7 46775984).

Run from a 1499kernel checkout (PATH=$HOME/.cargo/bin first); each make and QEMU boot waits for
MemAvailable >= 4 GB. CKPT_SRC=DIR builds another trinitite tree.
  python3 TRINITITE/tests/recorder_ring.py OUT FULL_NODE
Exit 0 when every leg passes; OUT/report.json has the measurements.
"""
import json, os, re, shutil, struct, subprocess, sys, time
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

RING = int(os.environ.get("RING_BYTES", "16384"))
EXTRA = 10
RING_ADDR = 0x70000000  # PLATFORM_DRAM_BASE + 0x30000000 on qemu-virt (src/i3_ring.c)
STEWARD = {6: "9f64c2d2", 7: "46775984"}
CKPT_OK = re.compile(r"I3H ckpt ok event=(\d+) ")
BASE = re.compile(r"I3H log base event=(\d+) ckpt=(\d+) kept_entries=(\d+) kept_bytes=(\d+) chain_bytes=(\d+)$")
BOOT_OK = re.compile(r"I3H ckpt boot event=(\d+) ")
REJECT = re.compile(r"I3H ckpt boot reject event=(\d+) reason=(\S+)$")
RING_CK = re.compile(r"I3H ring ckpt event=(\d+) bytes=(\d+) ")
XS = [0, 1, 0]


def mem_wait(what: str) -> None:
    while True:
        kb = int(next(l.split()[1] for l in open("/proc/meminfo") if l.startswith("MemAvailable")))
        if kb >= 4 * 1024 * 1024:
            print(f"MEM {what} {kb}kB", flush=True)
            return
        print(f"MEM wait {what} {kb}kB", flush=True)
        time.sleep(30)


def boot(img, pill, plan: bytes, run: Path, cold=None, ring=None, timeout=900):
    """tools/lite_replay_ceiling.boot plus the ring image at its window."""
    mem_wait(f"boot {run.name}")
    (run / "build").mkdir(parents=True, exist_ok=True)
    planf = run / "p.plan"; planf.write_bytes(lp.pack_plan(plan))
    cmd = [shutil.which("qemu-system-aarch64"), "-machine", "virt", "-cpu", "cortex-a72", "-m", "2G",
           "-semihosting", "-kernel", str(img),
           "-device", f"loader,file={pill},addr=0x50000000,force-raw=on",
           "-device", f"loader,file={planf},addr=0x51000000,force-raw=on"]
    if cold:
        cmd += ["-device", f"loader,file={cold},addr=0x47100000,force-raw=on"]
    if ring:
        cmd += ["-device", f"loader,file={ring},addr={RING_ADDR:#x},force-raw=on"]
    cmd += ["-display", "none", "-nographic", "-no-reboot"]
    p = subprocess.Popen(cmd, cwd=run, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    t0 = time.monotonic(); buf = b""; lines = []
    while time.monotonic() - t0 < timeout:
        ch = p.stdout.read1(65536)
        if not ch:
            break
        buf += ch
        while b"\n" in buf:
            l, buf = buf.split(b"\n", 1)
            lines.append(l.decode("latin1").rstrip("\r"))
        if any("terminal=" in l for l in lines[-4:]):
            time.sleep(0.5); break
    p.kill(); p.wait()
    (run / "uart.log").write_text("\n".join(lines) + "\n")
    return lines


def cold_base(cold: Path) -> dict:
    """The selected cold superblock's log base (src/cold.h)."""
    b = cold.read_bytes(); best = None
    for off in (0, 256):
        magic, _, _, gen, _, _, head, cnt, _ = struct.unpack_from("<QIIQQQQQQ", b, off)
        if magic == 0x32444C4F433249 and (best is None or gen > best["gen"]):
            idx, boff, js, chk = struct.unpack_from("<QQQQ", b, off + 96)
            best = {"gen": gen, "data_head": head, "log_count": cnt, "index": idx, "off": boff,
                    "job_sum": js}
    return best or {}


def ring_tool(*args) -> dict:
    r = subprocess.run([sys.executable, str(checkpoint_axis.TT / "tools/ring_image.py"), *map(str, args)],
                       capture_output=True, text=True)
    try:
        return json.loads(r.stdout)
    except ValueError:
        return {"ok": False, "error": r.stdout + r.stderr}


def main() -> int:
    if os.environ.get("CKPT_SRC"):
        checkpoint_axis.TT = Path(os.environ["CKPT_SRC"]).resolve()
    out, full = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    ir = sc.generate("chain", 5); app, tabs = app_to_noun(ir), id_tables(ir)
    lp.start_builder(full)
    jam = Path("build/kernel/kernel.jam").read_bytes()
    pill = out / "k.pill"; pill.write_bytes(lp.pack_pill(jam))
    padded = out / "k-pad.pill"; padded.write_bytes(lp.pack_pill(jam + b"\0"))
    ld = lp.load_bundle_cause(app)
    go = turn_cause(LocalRequest.manage(2), None, None, tabs, None)
    tg = nock_cell(cord("target"), cord("full-node"))
    ev = lambda x: event_cause(tabs, "B0", "REQ", [x, 1])
    evs = [ev(x) for x in XS]
    more = [ev(i % 2) for i in range(EXTRA)]

    def plan(tag, causes, reads_each=False, final=True):
        s, n = lp.Steps(tag), 0
        for i, (c, w) in enumerate(causes):
            s.poke(f"c{i}", c); n += w
            if reads_each:
                s.steps.append(nock_cell(cord("state-hash"), cord(s._name(f"h{n}")), 0))
        if final:
            s.steps.append(nock_cell(cord("state-hash"), cord(s._name("z")), 0))
        return jam_bytes(nock_list(s.steps))

    seq6 = [(ld, 2), (go, 1)] + [(e, 1) for e in evs]          # (cause, logged entries)
    seq7 = [(tg, 1)] + seq6
    full6 = [ld, nock_cell(cord("trace"), 0), go] + evs        # full node causes
    peek = plan("r", [])
    ll = ["I3_CHECKPOINT_EVERY=2", "I3_LITE_LOG=1", "I3_RING_EVERY=2", f"I3_RING_BYTES={RING}"]
    mem_wait("make img-ll"); img = flag_build(out / "img-ll", ll)
    mem_wait("make img-crash"); img_crash = flag_build(out / "img-crash", ll + ["I3_CKPT_TEST=crash", "I3_CKPT_TEST_FROM=6"])
    bad: list[str] = []
    rep: dict = {"ring_bytes": RING}
    fh6 = (full_hash(full, "lite-node", full6) or {})
    fh7 = (full_hash(full, "full-node", full6) or {})
    rep["full"] = {"6": fh6, "7": fh7}
    if not fh6.get("hash", "").startswith(STEWARD[6]) or not fh7.get("hash", "").startswith(STEWARD[7]):
        bad.append("full-node-steward")

    # running
    wl = boot(img, pill, plan("w", seq6, reads_each=True), out / "run-write")
    wr = reads(wl)
    cks = [int(m.group(1)) for l in wl for m in [CKPT_OK.match(l)] if m]
    bases = [tuple(int(x) for x in m.groups()) for l in wl for m in [BASE.match(l)] if m]
    order = [l.split()[1] + ":" + l.split("event=")[1].split()[0] for l in wl
             if l.startswith(("I3H ckpt ok ", "I3H log base "))]
    cold = out / "run-write/build/cold.img"; ring6 = out / "run-write/build/ring.img"
    cb = cold_base(cold)
    rl = boot(img, pill, peek, out / "run-boot", cold, ring6)
    rz = reads(rl).get("r-z") or {}
    row = {"ckpts": cks, "order": order, "bases": bases, "cold_base": cb,
           "write_h6": wr.get("w-h6"), "reboot": rz,
           "boot_lines": [l for l in rl if l.startswith(("I3H log boot", "I3H ckpt boot", "I3H replay", "I3H ring boot"))]}
    rep["running"] = row
    print("running:", json.dumps(row), flush=True)
    ok = (cks == [2, 4, 6] and order == ["ckpt:2", "ckpt:4", "log:2", "ckpt:6", "log:4"]
          and [b[:2] for b in bases] == [(2, 4), (4, 6)] and cb.get("index") == 4
          and "I3H log boot base=4 len=6 job_sum=" + str(cb.get("job_sum")) in rl
          and [m.group(1) for l in rl for m in [BOOT_OK.match(l)] if m] == ["6"]
          and "I3H replay entries=6" in rl and "I3H replay done event=7" in rl
          and rz.get("event") == 6 and rz.get("hash") == (wr.get("w-h6") or {}).get("hash") == fh6.get("hash"))
    if not ok:
        bad.append("running")

    # crash
    cl = boot(img_crash, pill, plan("w", seq6), out / "crash-write")
    cc = out / "crash-write/build/cold.img"
    xl = boot(img, pill, peek, out / "crash-boot", cc)
    xz = reads(xl).get("r-z") or {}
    row = {"write": [l for l in cl if l.startswith(("I3H ckpt ", "I3H log base", "I3H terminal"))],
           "cold_base": cold_base(cc),
           "rejects": [m.groups() for l in xl for m in [REJECT.match(l)] if m],
           "boot": [m.group(1) for l in xl for m in [BOOT_OK.match(l)] if m], "final": xz}
    rep["crash"] = row
    print("crash:", json.dumps(row), flush=True)
    ok = (any(l == "I3H ckpt test crash event=6" for l in cl) and cold_base(cc).get("index") == 2
          and not any(l.startswith("I3H ckpt ok event=6") for l in cl)
          and row["rejects"] == [("6", "hash")] and row["boot"] == ["4"]
          and "I3H replay done event=7" in xl and xz.get("event") == 6 and xz.get("hash") == fh6.get("hash"))
    if not ok:
        bad.append("crash")

    # rotated
    rot = plan("q", [(evs[0], 1)])
    rows = []
    for k in (1, 2):
        ql = boot(img, padded, rot, out / f"rot-{k}", cold, ring6)
        rows.append({"rejects": [m.groups() for l in ql for m in [REJECT.match(l)] if m],
                     "lines": [l for l in ql if l.startswith(("I3H ckpt boot none", "I3H stop", "I3H refused",
                                                              "I3H state-hash refused", "I3H replay"))],
                     "cold_after": cold_base(out / f"rot-{k}/build/cold.img") if (out / f"rot-{k}/build/cold.img").exists() else None})
    rep["rotated"] = rows
    print("rotated:", json.dumps(rows), flush=True)
    for r in rows:
        if not (r["rejects"] == [("6", "kernel"), ("4", "kernel")]
                and "I3H ckpt boot none rejected=2 fallback=stop base=4" in r["lines"]
                and "I3H stop reason=rotated base=4 log=6" in r["lines"]
                and "I3H refused stopped=rotated" in r["lines"]
                and "I3H state-hash refused stopped=rotated" in r["lines"]
                and not any(l.startswith("I3H replay") for l in r["lines"])
                and r["cold_after"] is None):
            bad.append("rotated")
            break

    # wrap
    wseq = seq6 + [(e, 1) for e in more]
    nw = 6 + EXTRA
    gl = boot(img, pill, plan("w", wseq), out / "wrap-write")
    ringw = out / "wrap-write/build/ring.img"; coldw = out / "wrap-write/build/cold.img"
    s1 = ring_tool("show", ringw)
    ringck = [(int(m.group(1)), int(m.group(2))) for l in gl for m in [RING_CK.match(l)] if m]
    gl2 = boot(img, pill, plan("v", [(ev(0), 1), (ev(1), 1)]), out / "wrap-more", coldw, ringw)
    s2 = ring_tool("show", out / "wrap-more/build/ring.img")
    row = {"ring_ckpts": ringck, "show": s1, "reboot_ring": [l for l in gl2 if l.startswith("I3H ring boot")],
           "show_after": s2}
    rep["wrap"] = row
    print("wrap:", json.dumps({**row, "show": {k: v for k, v in s1.items() if k != "segments"},
                               "segs": [(s["kind"], s["n"], s["inputs"]) for s in s1.get("segments", [])]}), flush=True)
    segs = s1.get("segments", [])
    ok = (s1.get("ok") and s1.get("wraps", 0) >= 1 and s1.get("evicted", 0) >= 1 and segs
          and segs[0]["kind"] == "ckpt" and segs[0]["n"] > 2 and s1.get("last_n") == nw
          and [s["n"] for s in segs] == list(range(segs[0]["n"], nw + 1, 2))
          and [x for x, _ in ringck] == list(range(2, nw + 1, 2))
          and any(re.match(rf"I3H ring boot status=ok .* last={nw} .*gap=0$", l) for l in row["reboot_ring"])
          and s2.get("ok") and s2.get("last_n") == nw + 2)
    if not ok:
        bad.append("wrap")

    # offdevice
    rep["offdevice"] = {}
    for n, seq, fh, src in ((6, seq6, fh6, ring6), (7, seq7, fh7, None)):
        if src is None:
            boot(img, pill, plan("w", seq), out / f"off{n}-write")
            src = out / f"off{n}-write/build/ring.img"
        show = ring_tool("show", src)
        ck = [s for s in show.get("segments", []) if s["kind"] == "ckpt"]
        oldest = ck[0]["n"] if ck else None
        made = ring_tool("cold", src, out / f"off{n}.cold", oldest) if ck else {}
        ol = boot(img, pill, peek, out / f"off{n}-boot", out / f"off{n}.cold")
        oz = reads(ol).get("r-z") or {}
        row = {"ring": {k: v for k, v in show.items() if k != "segments"},
               "segs": [(s["kind"], s["n"], s["inputs"], s["seg_bytes"]) for s in show.get("segments", [])],
               "image": made, "boot": [m.group(1) for l in ol for m in [BOOT_OK.match(l)] if m],
               "final": oz, "full": fh}
        rep["offdevice"][str(n)] = row
        print(f"offdevice {n}:", json.dumps(row), flush=True)
        if not (show.get("ok") and ck and made.get("events") == n and row["boot"] == [str(oldest)]
                and oz.get("event") == n and oz.get("hash") == fh.get("hash")
                and oz.get("hash", "").startswith(STEWARD[n])):
            bad.append(f"offdevice{n}")
    (out / "report.json").write_text(json.dumps(rep, indent=1, default=str))
    print("recorder ring: " + ("PASS" if not bad else f"FAIL {bad}"), flush=True)
    return 0 if not bad else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main())
