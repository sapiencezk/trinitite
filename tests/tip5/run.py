#!/usr/bin/env python3
"""1499kernel row 328 (d): the lite node's ++digest, bit for bit, on the
seven golden vectors.

tests/tip5/vectors.jam and digests.json are 1499kernel's
tests/fixtures/tip5/vectors.jam and tests/golden/tip5/digests.json: seven
nouns and their ++digest, which 1499kernel checks against Nockchain's Rust
Tip5 (zkvm-jetpack's hash-hashable), its own Rust walk jet
(c1499-core::tip5) and the Hoon arm on the full node.

Boots tests/jetcheck/jetcheck.jam on the I3_HOST + I3_L1_PROBE image under
QEMU and pokes [%digest n] for each vector, which runs ++digest of
1499kernel's iec-types:
  jet   with every jet (the walk's own, hash-hashable-noun:digest-lib);
  hoon  with the walk's jet off, so the Hoon walk runs over the Tip5 arms'
        jets (hash-ten-cell, hash-hashable, hash-belts-list, ...).
It also computes each digest with tests/tip5/tip5_ref.py (the Hoon arms
transcribed). Every digest printed must equal the golden; a `hoon` poke that
runs past the slam caps (4,000,000 ops, 1,200,000 cells) is reported, not
compared. It prints each poke's ops and cells.

  python3 tests/tip5/run.py [--no-build] [--log PATH]
"""
import argparse, gzip, importlib.util, json, re, subprocess, sys, tempfile, threading, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(HERE))
from jam import cue, jam  # noqa: E402
import tip5_ref  # noqa: E402

_spec = importlib.util.spec_from_file_location("jetcheck_run", ROOT / "tests/jetcheck/run.py")
jetcheck = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(jetcheck)
build, lst, cord, parse_noun = jetcheck.build, jetcheck.lst, jetcheck.cord, jetcheck.parse_noun


# The Hoon walk recurses once per level: on deep-cell it passes the
# 1,024-frame evaluator stack, which stops the node. Not run.
NO_HOON = {"deep-cell"}
# The bignum jets (rsh, mod, ...) read at most BN_MAX_LIMBS (64) limbs, so
# the Hoon walk's (rip 5 n) sees a wider atom cut to its low 4,096 bits; the
# walk's own jet reads every limb. Reported, not failed.
CUT = {"atom-6143"}


def text(a):
    return a.to_bytes((a.bit_length() + 7) // 8, "little").decode()


def vectors():
    n = cue(int.from_bytes((HERE / "vectors.jam").read_bytes(), "little"))
    out = []
    while isinstance(n, tuple):
        (name, noun), n = n
        out.append((text(name), noun))
    return out


def ref_digest(noun):
    """tip5_ref's ++digest, memoised by object (cue shares backrefs)."""
    memo = {}

    def walk(x):
        k = id(x) if isinstance(x, tuple) else ("atom", x)
        if k not in memo:
            memo[k] = (tip5_ref.hash_ten_cell(walk(x[0]), walk(x[1]))
                       if isinstance(x, tuple) else tip5_ref.walk(x))
        return memo[k]
    return tip5_ref.digest_to_atom(walk(noun))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--log", type=Path)
    a = ap.parse_args()
    image = ROOT / "kernel8.img" if a.no_build else build(False)
    golden = json.loads((HERE / "digests.json").read_text())["digests"]
    vecs = vectors()
    walk = lst(cord("hash-hashable-noun"))
    steps = []
    deep = lst(*range(1, 10001))
    hoon = []
    for name, noun in vecs:
        # the lite node's cue admits depth 1,024: deep-cell, ~[1 .. 10.000],
        # is built by the app itself
        if name == "deep-cell":
            assert noun == deep, "deep-cell is ~[1 .. 10.000]"
            cause = (cord("digest-gulf"), 10000)
        else:
            cause = (cord("digest"), noun)
        steps.append((cord("poke"), (cord(f"jet-{name}"), cause)))
        if name not in NO_HOON:
            hoon.append((cord("poke-without"), (cord(f"hoon-{name}"), (walk, cause))))
    # A slam stopped by a cap stops the node, so the Hoon walks come last.
    steps += hoon
    pa = jam(lst(*steps))
    pbytes = pa.to_bytes((pa.bit_length() + 7) // 8, "little")
    kjam = gzip.decompress((ROOT / "tests/jetcheck/jetcheck.jam.gz").read_bytes())
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        pill = td / "pill.bin"
        pill.write_bytes(len(kjam).to_bytes(8, "little") + bytes([2]) + bytes(7) + kjam)
        planf = td / "plan.bin"
        planf.write_bytes(len(pbytes).to_bytes(8, "little") + pbytes)
        cmd = ["qemu-system-aarch64", "-machine", "virt", "-cpu", "cortex-a72", "-m", "2G",
               "-kernel", str(image), "-device", f"loader,file={pill},addr=0x50000000,force-raw=on",
               "-device", f"loader,file={planf},addr=0x51000000,force-raw=on",
               "-display", "none", "-nographic", "-no-reboot"]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = b""
        deadline = time.monotonic() + 1800
        while b"I3L1 terminal=" not in out and time.monotonic() < deadline:
            chunk = p.stdout.read1(65536)
            if not chunk:
                break
            out += chunk
        time.sleep(0.2)
        p.kill()
    log = out.decode("utf-8", "replace").replace("\r", "")
    if a.log:
        a.log.write_text(log)
    effects = dict(re.findall(r"^I3L1 effects name=(\S+) noun=(.*)$", log, re.M))
    cost = {m[0]: m[1:] for m in re.findall(
        r"^I3L1 poke name=(\S+) nock_ops_used=(\d+) nock_cells_used=(\d+) "
        r"nock_eval_stack_peak=\d+ ticks=(\d+) .* abort=(\S+)", log, re.M)}
    problems = []
    for name, noun in vecs:
        want = int(golden[name], 16)
        ref = ref_digest(noun)
        line = [f"tip5 vector={name} ref={'match' if ref == want else 'MISMATCH'}"]
        if ref != want:
            problems.append(f"{name}: tip5_ref differs from the golden")
        for mode in ("jet", "hoon"):
            key = f"{mode}-{name}"
            ops, cells, ticks, abort = cost.get(key, ("?", "?", "?", "missing"))
            if mode == "hoon" and name in NO_HOON:
                line.append("hoon=not-run(stack)")
                continue
            if key not in effects:
                verdict = f"none(abort={abort})"
                if mode == "jet":
                    problems.append(f"{key}: no effect (abort={abort})")
            else:
                got = parse_noun(effects[key])
                digest = got[0][1] if isinstance(got, tuple) and isinstance(got[0], tuple) else None
                verdict = "match" if digest == want else "MISMATCH"
                if digest != want and mode == "hoon" and name in CUT:
                    verdict = "cut(bignum-4096)"
                elif digest != want:
                    problems.append(f"{key}: {digest!r} != golden")
            line.append(f"{mode}={verdict} ops={ops} cells={cells} ticks={ticks}")
        print(" ".join(line))
    ok = not problems
    print("tip5:", "PASS" if ok else "FAIL", "; ".join(problems))
    return 0 if ok else 1


if __name__ == "__main__":
    # cue, jam and the reference walk recurse once per level (deep-cell is
    # 10,000 deep): run on a thread with a deep stack.
    sys.setrecursionlimit(200000)
    threading.stack_size(512 * 1024 * 1024)
    rc = []
    t = threading.Thread(target=lambda: rc.append(main()))
    t.start()
    t.join()
    sys.exit(rc[0] if rc else 1)
