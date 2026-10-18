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
            and the full node (f5764f6f).
  crash     I3_CKPT_TEST=crash I3_CKPT_TEST_FROM=6: the checkpoint at 6 is stored damaged and the
            node stops dead before verifying it. The reboot rejects 6 (reason=hash), boots from 4
            (kept: the base is still 2), replays 5 and 6 and reads f5764f6f.
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
            full node's after the same causes (N=6 f5764f6f, N=7 bf0a761a).
  wrap4     the wrap leg's ring (4+ wraps): a cold image from its oldest kept checkpoint boots on the
            same lite image and reads the full node's /state-hash after all N=6+EXTRA causes; the
            image's base job_sum comes from the ring checkpoint record (row 221 (7): the jobs
            after the device's log base when it was written; audit only, boot counts from the base).
  torn      I3_RING_TEST=torn, 32 KiB ring: the first wrap marker never lands, the moved header does,
            then a power cut. The reboot opens the older slot (status=torn-older, never formats), the
            ring keeps its older segments and grows.
  prefix    the torn image with the older slot damaged too: status=torn-prefix (longest valid prefix
            from the tail, committed), older segments kept; tools/ring_image.py show opens the damaged
            image the same way (prefix, same records, segments and last).
  foreign   ring images the ring did not create (no magic in the header area; zero header area over
            non-zero data): status=foreign, ring off, nothing written, the node runs as usual.
  reformat  ring6 with whole headers of our own for another size (ring_bytes 8192, checksums
            recomputed): status=reformat, gen above the highest on the media,
            `I3H ring reformat old_bytes=8192 new_bytes=16384`.
  reformat-size  a 32 KiB ring's first 16 KiB booted by the 16 KiB build (valid own headers, other
            size): status=reformat and `I3H ring reformat old_bytes=32768 new_bytes=16384`.
  corrupt   ring6 with the tail record broken (valid slots, no valid prefix): status=corrupt, ring
            off, media untouched, the off line and the operator hint exactly once, node as usual.
  corrupt-hdr  ring6 with both slot checksums broken (own magic and version, no header to trust):
            status=corrupt as above, never reformat.
  fullreplay  tests/ring_full_replay.py: the FULL node boots a host snapshot written from the ring's
            oldest checkpoint (N=6 ring, N=7 ring, wrap4 ring), poke-jams the ring's inputs, and its
            /state-hash equals the full node's own hash of all N causes, and every step (the
            checkpoint and each input) equals a full node run from zero to that event.
  fault     COLD_MEDIA=fake, I3_RING_TEST=fault I3_RING_TEST_AT=RING_FAULT_AT (default 8): one ring
            sector write lands half (WRITE_UNKNOWN). It is logged, the ring turns off, and the cold log,
            checkpoints, base moves and /state-hash are as with no fault; the node never stops.
  rebase-fault  COLD_MEDIA=fake, I3_CKPT_TEST=rebasefault: the first base move meets a cold media
            timeout before anything is written; `I3H log base fail` is logged, nothing is dropped, the
            next checkpoint moves the base. It covers only a fault before anything is written: a fault
            after a sector was sent stops the node under the existing cold rule (intended, not tested).

Run from a 1499kernel checkout (PATH=$HOME/.cargo/bin first); each make and QEMU boot waits for
MemAvailable >= 4 GB. CKPT_SRC=DIR builds another trinitite tree.
  python3 TRINITITE/tests/recorder_ring.py OUT FULL_NODE
Exit 0 when every leg passes; OUT/report.json has the measurements.
"""
import json, os, re, shutil, struct, subprocess, sys, time
from pathlib import Path
import blake3
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
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
# Full-node /state-hash at N with the landing kernel jam, 1499kernel main 3d100787 (at #258's
# head bff56583: 9f64c2d2, 46775984; the kernel jam changed between the two).
STEWARD = {6: "f5764f6f", 7: "bf0a761a"}
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
    # wrap4: the wrap leg's ring has wrapped 4+ times; replay its oldest segment off the device
    fhw = full_hash(full, "lite-node", full6 + more) or {}
    rep["full"]["wrap"] = fhw
    ck = [x for x in s1.get("segments", []) if x["kind"] == "ckpt"]
    madew = ring_tool("cold", ringw, out / "offw.cold", ck[0]["n"]) if ck else {}
    owl = boot(img, pill, peek, out / "offw-boot", out / "offw.cold")
    owz = reads(owl).get("r-z") or {}
    row = {"wraps": s1.get("wraps"), "oldest": ck[0]["n"] if ck else None, "image": madew,
           "boot": [m.group(1) for l in owl for m in [BOOT_OK.match(l)] if m], "final": owz, "full": fhw}
    rep["wrap4"] = row
    print("wrap4:", json.dumps(row), flush=True)
    if not (s1.get("wraps", 0) >= 4 and ck and madew.get("events") == nw
            and madew.get("job_sum", 0) > 0 and row["boot"] == [str(ck[0]["n"])]
            and owz.get("event") == nw and owz.get("hash") == fhw.get("hash")):
        bad.append("wrap4")

    # fullreplay: the FULL node replays the ring's oldest checkpoint plus its inputs
    # (tests/ring_full_replay.py: a host snapshot written from the checkpoint, then poke-jam).
    # Every step is asserted twice: by the tool against its own from-zero run (--zero), and
    # here against a separate full node run of the first k causes (full_hash), for the
    # checkpoint and for each input. (N=6 and wrap4 start and end at the same hash.)
    rep["fullreplay"] = {}
    for name, src, tgt, n, fh, causes, off in (
            ("6", ring6, "lite-node", 6, fh6, full6, 0),
            ("7", out / "off7-write/build/ring.img", "full-node", 7, fh7, full6, 1),
            ("wrap4", ringw, "lite-node", nw, fhw, full6 + more, 0)):
        mem_wait(f"fullreplay {name}")
        rd = out / f"fullreplay-{name}"
        shutil.rmtree(rd, ignore_errors=True)
        zf = out / f"fullreplay-{name}.zero.json"
        zf.write_text(json.dumps({"offset": off, "causes": [jam_bytes(c).hex() for c in causes]}))
        pr = subprocess.run([sys.executable, str(HERE / "ring_full_replay.py"), str(src), str(full), tgt,
                             "--zero", str(zf), "--out", str(rd)], capture_output=True, text=True, timeout=900)
        try:
            row = json.loads(pr.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            row = {"ok": False, "stderr": pr.stderr[-400:]}
        ck = [x for x in ring_tool("show", src).get("segments", []) if x["kind"] == "ckpt"]
        zc = row.get("zero_check") or {}
        evn = zc.get("events") or []
        sep = [((full_hash(full, tgt, causes[:e - off]) or {}).get("hash") or "")[:8] for e in evn]
        row["separate_zero"] = sep
        rep["fullreplay"][name] = row
        print(f"fullreplay {name}:", json.dumps(row), flush=True)
        if not (pr.returncode == 0 and row.get("ok") and row.get("booted_from_snapshot")
                and ck and row.get("from") == ck[0]["n"] and row.get("event") == n
                and row.get("hash") == fh.get("hash")
                and evn == list(range(ck[0]["n"], n + 1)) and zc.get("match") and all(zc["match"])
                and sep == [row["boot_hash"][:8]] + row["steps"] and sep == zc.get("zero")):
            bad.append(f"fullreplay{name}")

    # torn: the first wrap marker never lands, the moved header does, then a power cut.
    # The reboot must open the older header slot (status=torn-older), never format,
    # and keep extending the ring.
    # A 32 KiB ring, so that segments survive the wrap (in 16 KiB a wrap evicts every segment).
    ll32 = [x for x in ll if not x.startswith("I3_RING_BYTES=")] + ["I3_RING_BYTES=32768"]
    mem_wait("make img-32"); img32 = flag_build(out / "img-32", ll32)
    mem_wait("make img-torn"); img_torn = flag_build(out / "img-torn", ll32 + ["I3_RING_TEST=torn"])
    tl = boot(img_torn, pill, plan("w", wseq), out / "torn-write")
    tring = out / "torn-write/build/ring.img"; tcold = out / "torn-write/build/cold.img"
    fired = [l for l in tl if l.startswith("I3H ring test torn-wrap")]
    tshow = ring_tool("show", tring)
    tl2 = boot(img32, pill, plan("v", [(ev(0), 1), (ev(1), 1), (ev(0), 1)]), out / "torn-boot", tcold, tring)
    tshow2 = ring_tool("show", out / "torn-boot/build/ring.img")
    rb = [l for l in tl2 if l.startswith("I3H ring boot")]
    row = {"fired": fired, "show_before": {k: v for k, v in tshow.items() if k != "segments"},
           "segs_before": [(x["kind"], x["n"]) for x in tshow.get("segments", [])],
           "reboot_ring": rb, "show_after": {k: v for k, v in tshow2.items() if k != "segments"},
           "segs_after": [(x["kind"], x["n"]) for x in tshow2.get("segments", [])]}
    rep["torn"] = row
    print("torn:", json.dumps(row), flush=True)
    keep = [x for x in row["segs_before"]]
    ok = (fired and tshow.get("fallback") == 1 and len(rb) == 1 and " status=torn-older " in rb[0]
          and not any("status=fresh" in l or "status=reformat" in l for l in rb)
          and tshow2.get("ok") and tshow2.get("fallback") == 0 and row["segs_before"]
          and row["segs_after"] and row["segs_after"][0][1] <= row["segs_before"][-1][1])
    if not ok:
        bad.append("torn")

    # prefix: the same torn image with the older slot damaged too: the newest slot's chain is
    # broken at its end, so the node keeps the longest valid prefix (status=torn-prefix).
    b = bytearray(tring.read_bytes())
    gens = [(struct.unpack_from("<Q", b, sl * 512 + 24)[0], sl) for sl in (0, 1)]
    older = min(gens)[1]
    b[older * 512 + 100] ^= 0xFF
    pring = out / "prefix.ring"; pring.write_bytes(bytes(b))
    pl = boot(img32, pill, plan("v", [(ev(0), 1), (ev(1), 1), (ev(0), 1)]), out / "prefix-boot", tcold, pring)
    pshow = ring_tool("show", out / "prefix-boot/build/ring.img")
    prb = [l for l in pl if l.startswith("I3H ring boot")]
    row = {"reboot_ring": prb, "show_after": {k: v for k, v in pshow.items() if k != "segments"},
           "segs_after": [(x["kind"], x["n"]) for x in pshow.get("segments", [])]}
    rep["prefix"] = row
    print("prefix:", json.dumps(row), flush=True)
    # tools/ring_image.py opens the damaged image as the node does: the longest valid prefix.
    pin = ring_tool("show", pring)
    pm = re.search(r" records=(\d+) segments=(\d+) last=(\d+) ", prb[0]) if prb else None
    row["show_damaged"] = {k: pin.get(k) for k in ("ok", "prefix", "fallback", "records", "last_n")}
    print("prefix tool:", json.dumps(row["show_damaged"]), flush=True)
    if not (pm and pin.get("ok") and pin.get("prefix") is True
            and [pin.get("records"), len(pin.get("segments", [])), pin.get("last_n")]
            == [int(x) for x in pm.groups()]):
        bad.append("prefix-tool")
    if not (len(prb) == 1 and " status=torn-prefix " in prb[0] and pshow.get("ok")
            and keep and row["segs_after"] and row["segs_after"][0][1] <= keep[-1][1]):
        bad.append("prefix")

    # foreign: data the ring did not create is never formatted; the ring stays off and the
    # node runs (cold log, checkpoints, /state-hash) as usual. Two images: no magic in the
    # header area, and a zero header area over non-zero data.
    pat = bytes((i * 151 + 7) & 0xFF for i in range(RING))
    rep["foreign"] = {}
    for name, data in (("hdr", pat), ("data", bytes(1024) + pat[1024:])):
        fr = out / f"foreign-{name}.ring"; fr.write_bytes(data)
        fl = boot(img, pill, plan("w", seq6), out / f"foreign-{name}", None, fr)
        wrote = out / f"foreign-{name}/build/ring.img"
        fz = reads(fl).get("w-z") or {}
        row = {"lines": [l for l in fl if l.startswith(("I3H ring boot", "I3H ring off", "I3H stop"))],
               "ckpts": [int(m.group(1)) for l in fl for m in [CKPT_OK.match(l)] if m],
               "ring_written": wrote.exists(), "final": fz}
        rep["foreign"][name] = row
        print(f"foreign {name}:", json.dumps(row), flush=True)
        if not (row["lines"] == ["I3H ring boot status=foreign", "I3H ring off reason=foreign"]
                and row["ckpts"] == [2, 4, 6] and not row["ring_written"] and fr.read_bytes() == data
                and fz.get("event") == 6 and fz.get("hash") == fh6.get("hash")):
            bad.append(f"foreign-{name}")

    # reformat: whole headers of our own (magic, version, checksum right) for another ring size
    # (ring_bytes 8192, checksums recomputed) are reformatted, and the generation continues above
    # the highest one on the media. This is the only reformat over non-zero data.
    b = bytearray(ring6.read_bytes())
    gmax = max(struct.unpack_from("<Q", b, sl * 512 + 24)[0] for sl in (0, 1))
    for sl in (0, 1):
        struct.pack_into("<Q", b, sl * 512 + 16, 8192)
        b[sl * 512 + 96: sl * 512 + 128] = blake3.blake3(bytes(b[sl * 512: sl * 512 + 96])).digest()
    rr = out / "reformat.ring"; rr.write_bytes(bytes(b))
    fl = boot(img, pill, plan("w", seq6), out / "reformat-boot", None, rr)
    rb = [l for l in fl if l.startswith("I3H ring boot")]
    m = re.search(r" gen=(\d+) ", rb[0]) if rb else None
    row = {"lines": rb, "gen_before": gmax, "gen_after": int(m.group(1)) if m else None}
    rep["reformat"] = row
    print("reformat:", json.dumps(row), flush=True)
    sz = [l for l in fl if l.startswith("I3H ring reformat")]
    row["size_lines"] = sz
    if not (rb and " status=reformat " in rb[0] and m and int(m.group(1)) > gmax
            and sz == [f"I3H ring reformat old_bytes=8192 new_bytes={RING}"]):
        bad.append("reformat")

    # reformat-size: a ring the 32 KiB build wrote, as the 16 KiB build loads it (its first
    # 16 KiB). Valid own headers with another ring size: reformat, logging both sizes in bytes.
    big = (out / "prefix-boot/build/ring.img").read_bytes()
    rsz = out / "reformat-size.ring"; rsz.write_bytes(big[:RING])
    big_rb = struct.unpack_from("<Q", big, 16)[0]
    fl = boot(img, pill, plan("w", seq6), out / "reformat-size-boot", None, rsz)
    rb = [l for l in fl if l.startswith("I3H ring boot")]
    sz = [l for l in fl if l.startswith("I3H ring reformat")]
    rshow = ring_tool("show", out / "reformat-size-boot/build/ring.img")
    row = {"old_ring_bytes": big_rb, "lines": rb, "size_lines": sz,
           "show_after": {k: v for k, v in rshow.items() if k != "segments"}}
    rep["reformat_size"] = row
    print("reformat-size:", json.dumps(row), flush=True)
    if not (big_rb == 32768 and rb and " status=reformat " in rb[0]
            and sz == [f"I3H ring reformat old_bytes=32768 new_bytes={RING}"]
            and rshow.get("ok") and rshow.get("last_n") == 6):
        bad.append("reformat-size")

    # corrupt: our ring, but nothing on it to trust. The ring stays off, the media is left as it
    # is, the node runs as usual, and the off line and the operator hint appear exactly once.
    #   corrupt      valid header slots, but the record at the tail is broken (no valid prefix)
    #   corrupt-hdr  our magic and version, but both slots' checksums broken (never reformatted)
    b = bytearray(ring6.read_bytes())
    for t in {struct.unpack_from("<Q", b, sl * 512 + 40)[0] for sl in (0, 1)}:
        b[t] ^= 0xFF
    bh = bytearray(ring6.read_bytes())
    for sl in (0, 1):
        bh[sl * 512 + 100] ^= 0xFF
    for name, data in (("corrupt", bytes(b)), ("corrupt-hdr", bytes(bh))):
        cr = out / f"{name}.ring"; cr.write_bytes(data)
        cl = boot(img, pill, plan("w", seq6), out / f"{name}-boot", None, cr)
        cz = reads(cl).get("w-z") or {}
        row = {"lines": [l for l in cl if l.startswith(("I3H ring boot", "I3H ring off", "I3H ring hint",
                                                         "I3H ring reformat", "I3H stop"))],
               "ckpts": [int(m.group(1)) for l in cl for m in [CKPT_OK.match(l)] if m],
               "ring_written": (out / f"{name}-boot/build/ring.img").exists(), "final": cz}
        rep[name.replace("-", "_")] = row
        print(f"{name}:", json.dumps(row), flush=True)
        ln = row["lines"]
        if not (ln[:2] == ["I3H ring boot status=corrupt", "I3H ring off reason=corrupt"] and len(ln) == 3
                and sum(l == "I3H ring off reason=corrupt" for l in cl) == 1
                and sum(l.startswith("I3H ring hint: ") for l in cl) == 1
                and row["ckpts"] == [2, 4, 6] and not row["ring_written"] and cr.read_bytes() == data
                and cz.get("event") == 6 and cz.get("hash") == fh6.get("hash")):
            bad.append(name)

    # fault (COLD_MEDIA=fake): a ring sector write lands half and reports WRITE_UNKNOWN. The
    # fault is logged, the ring turns off, and the cold log, checkpoints, base moves and
    # /state-hash go on as with no fault; the node never stops.
    fault_at = int(os.environ.get("RING_FAULT_AT", "8"))
    mem_wait("make img-fault")
    img_fault = flag_build(out / "img-fault", ll + ["COLD_MEDIA=fake", "I3_RING_TEST=fault",
                                                     f"I3_RING_TEST_AT={fault_at}"])
    fl = boot(img_fault, pill, plan("w", seq6, reads_each=True), out / "fault-write")
    fr_ = reads(fl)
    flt = [l for l in fl if l.startswith(("I3H ring media fault", "I3H ring off"))]
    row = {"fault_at": fault_at, "fault": flt,
           "ring_boot": [l for l in fl if l.startswith("I3H ring boot")],
           "ckpts": [int(m.group(1)) for l in fl for m in [CKPT_OK.match(l)] if m],
           "bases": [tuple(int(x) for x in m.groups())[:2] for l in fl for m in [BASE.match(l)] if m],
           "ring_ckpts": [int(m.group(1)) for l in fl for m in [RING_CK.match(l)] if m],
           "skips": [l for l in fl if l.startswith("I3H ring skip")],
           "stops": [l for l in fl if l.startswith(("I3H stop", "I3H refused"))],
           "final": fr_.get("w-z"), "h6": fr_.get("w-h6")}
    rep["fault"] = row
    print("fault:", json.dumps(row), flush=True)
    if not (len(flt) == 2 and flt[0].startswith("I3H ring media fault op=write status=-11 ")
            and flt[1] == "I3H ring off reason=media"
            and row["ring_boot"] and " status=fresh " in row["ring_boot"][0]
            and row["ckpts"] == [2, 4, 6] and row["bases"] == [(2, 4), (4, 6)]
            and not row["stops"] and (row["final"] or {}).get("event") == 6
            and (row["final"] or {}).get("hash") == fh6.get("hash")):
        bad.append("fault")

    # rebase-fault (COLD_MEDIA=fake): the first log base move meets a cold media timeout before
    # any sector is submitted. The move fails and is logged (`I3H log base fail`, i3_host.c),
    # nothing is dropped, and the next verified checkpoint moves the base (cold_media.c sets no
    # reset for a read that failed before a mutation). The node never stops. This leg covers only
    # a fault before anything is written; after a sector is sent the cold rule stops the node.
    mem_wait("make img-rbf")
    img_rbf = flag_build(out / "img-rbf", ll + ["COLD_MEDIA=fake", "I3_CKPT_TEST=rebasefault"])
    rl_ = boot(img_rbf, pill, plan("w", seq6), out / "rbf-write")
    rz_ = reads(rl_).get("w-z") or {}
    row = {"lines": [l for l in rl_ if l.startswith(("I3H ckpt test rebase-fault", "I3H log base",
                                                     "I3H stop", "I3H ring media fault"))],
           "ckpts": [int(m.group(1)) for l in rl_ for m in [CKPT_OK.match(l)] if m], "final": rz_}
    rep["rebase_fault"] = row
    print("rebase-fault:", json.dumps(row), flush=True)
    L = row["lines"]
    if not (len(L) == 3 and L[0] == "I3H ckpt test rebase-fault event=4"
            and L[1] == "I3H log base fail event=2 ckpt=4"
            and L[2].startswith("I3H log base event=4 ckpt=6 ")
            and row["ckpts"] == [2, 4, 6] and rz_.get("event") == 6 and rz_.get("hash") == fh6.get("hash")):
        bad.append("rebase-fault")

    (out / "report.json").write_text(json.dumps(rep, indent=1, default=str))
    print("recorder ring: " + ("PASS" if not bad else f"FAIL {bad}"), flush=True)
    return 0 if not bad else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main())
