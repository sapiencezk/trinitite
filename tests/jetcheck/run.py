#!/usr/bin/env python3
"""Jet-vs-Hoon equivalence test for the lite node (%fast jets).

Builds the LITE_HOST + LITE_PROBE image, boots tests/jetcheck/jetcheck.jam
under QEMU and runs one `poke-jetcheck` step: the %go poke constructs the @rs
door's add/sub/mul/div/lth cores before the integer ones, then every %fast
entry registered in that poke is slammed on the vectors below twice -- with
its jet and with its own Nock battery (that entry suppressed) -- and the
products must be equal. tests/jetcheck/build.sh rebuilds jetcheck.jam.gz.

  python3 tests/jetcheck/run.py            # expect: PASS
  python3 tests/jetcheck/run.py --plant-rsh  # rebuild with L3's raw-count rsh; expect: FAIL
  python3 tests/jetcheck/run.py --plant-label-only  # pre-fix label-only rule; expect: FAIL (dup bindings refused and counted, no crash)
  python3 tests/jetcheck/run.py --expect-fail ...

Fails if any vector mismatches or is inconclusive (budget), or if a hot label
the kernel uses was not registered and checked.
"""
import argparse, gzip, hashlib, re, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "tip5"))
from jam import jam  # noqa: E402
import tip5_ref  # noqa: E402

def cord(s):
    return int.from_bytes(s.encode(), "little")

def lst(*xs):
    out = 0
    for x in reversed(xs):
        out = (x, out)
    return out

F15, F225, NEG_TINY = 0x3FC00000, 0x40100000, 0x80000001
NZ, ONE = 0x80000000, 0x3F800000   # @rs -0 and 1.0
L123 = lst(1, 2, 3)
# Small first operands keep the unjetted integer Hoon (unary recursion) cheap;
# the float bit patterns make an @rs core that holds an integer jet disagree.
# The bignum jets read at most BN_MAX_LIMBS (64) limbs of an atom, so an
# atom wider than 4,096 bits is cut on both sides of a check that uses them
# (tests/tip5 checks ++digest of a 6,143-bit atom against the golden).
BIG = 2**4000 - 12345          # a 4,000-bit atom
GP = 2**64 - 2**32 + 1         # the Goldilocks prime
VECTORS = {
    # the signed-zero vectors stay cheap as @rs Hoon even with no integer jet
    # bound, so a float core holding an integer jet shows as a plain mismatch
    "add": [(0, NZ), (1, F15), (0, F225), (3, 5)],
    "sub": [(NZ, 0), (F225, 1), (5, 3), (3, 5)],
    "mul": [(0, NZ), (2, F15), (3, 4)],
    "div": [(NZ, ONE), (F15, F15), (7, 2), (1, 0)],
    "mod": [(7, 2), (F15, F15 + 1)],
    "dec": [7, 0],
    "lth": [(0, NZ), (1, NEG_TINY), (3, 2), (2, 3)],
    "gth": [(1, NEG_TINY), (3, 2), (2, 3)],
    "lte": [(1, NEG_TINY), (3, 2), (2, 2)],
    "gte": [(1, NEG_TINY), (3, 2), (2, 2)],
    "rsh": [((5, 1), BIG), ((5, 1), 2**200 + 7), (5, BIG), (6, 2**130 + 3),
            (3, 0x1234), ((3, 1), 0x123456), ((0, 4), 0xFF), ((1, 2), 0xABCD)],
    "lsh": [(3, 0x12), ((3, 1), 0x12), ((0, 4), 0xF), ((1, 2), 0xAB)],
    "con": [(5, 3), (0xFF00, 0x0FF0)],
    "dis": [(5, 3), (0xFF00, 0x0FF0)],
    "mix": [(5, 3), (0xFF00, 0x0FF0)],
    "lent": [L123, 0],
    "flop": [L123, 0],
    "weld": [(lst(1, 2), lst(3)), (0, L123)],
    # jam: backrefs (a repeated cell, a repeated atom), a wide atom
    "jam": [0, 1, (1, 2), ((1, 2), (1, 2)), (2**70, 2**70), ((1, 2), 3)],
    "shax": [0, cord("abc"), 2**200 + 5, 0xFF00],
}
# Tip5 (1499kernel row 328 (d)): the arms ++digest calls, and its walk.
# Values at or above p, short lists and %list hashables make the jet run
# the arm (both sides then run the same Hoon, or crash alike).
P = GP


def tup(*xs):
    out = xs[-1]
    for x in reversed(xs[:-1]):
        out = (x, out)
    return out


D1, D2 = tup(1, 2, 3, 4, 5), tup(P - 1, 0, 7, P - 2, 9)
DEEP = 0
for k in range(40):
    DEEP = (k, DEEP)
VECTORS.update({
    "permutation": [lst(*[0] * 16), lst(*range(16)), lst(*[P - 1] * 16),
                    lst(*[0] * 15)],
    "hash-varlen": [0, lst(1, 2, 3), lst(*range(10)), lst(*range(23)), lst(P)],
    "hash-belts-list": [0, lst(1, 2, 3), lst(*range(10)), lst(P - 1, 0), lst(1, P)],
    "hash-ten-cell": [(D1, D2), (D2, D1), ((1, 2), 3), (D1, (D2, 0))],
    "hash-noun-varlen": [0, 5, (1, 2), ((1, 2), (3, (4, 0))), P - 1, P],
    "hash-hashable": [(cord("leaf"), 5), (cord("leaf"), (1, 2)),
                      ((cord("leaf"), 1), (cord("leaf"), 2)), (cord("hash"), D2),
                      ((cord("hash"), D1), (cord("leaf"), 3)),
                      (cord("list"), lst((cord("leaf"), 1)))],
    "digest-to-atom": [D1, D2, tup(*[2**64 - 1] * 5), tup(0, 0, 0, 0, 0)],
    "hash-hashable-noun": [0, P - 1, P, BIG, (1, 2), ((1, 2), (1, 2)),
                           DEEP, (P, (2**100, cord("tip5")))],
})


def shax(a):
    """++shax: SHA-256 of the atom's (met 3) little-endian bytes, read back
    as a little-endian atom."""
    b = a.to_bytes((a.bit_length() + 7) // 8, "little")
    return int.from_bytes(hashlib.sha256(b).digest(), "little")


def unlist(n):
    out = []
    while isinstance(n, tuple):
        out.append(n[0])
        n = n[1]
    return out


# Two arms cannot run as plain Hoon on the lite node at all: ++shax
# recurses deeper than the 1,024-frame evaluator stack (LITE_SLAM_MAX_STACK,
# budget reason 4), and Tip5's ++permutation as Hoon rebuilds its round
# constants per element and needs more cells than the 32 MiB scratch holds
# (reason 3). For them alone, a Hoon side stopped for that reason is checked
# against a host reference instead: hashlib for ++shax, and for permutation
# tests/tip5/tip5_ref.py, ++permutation transcribed from the Hoon. Any other
# inconclusive vector still fails the run.
REFERENCE = {
    "shax": (lambda a: shax(a), 4),
    "permutation": (lambda l: lst(*tip5_ref.permutation(unlist(l))), 3),
}
# Registered labels that need a gate or trap as sample are reported as
# unvectored and do not fail the run.
UNVECTORED_OK = {"turn", "mole"}
# Labels the %go poke must exercise (and so register and check).
REQUIRED = set(VECTORS)


def parse_noun(text):
    """A noun as the probe prints it: atoms in decimal or 0x hex, cells in
    brackets, right-associated."""
    toks = re.findall(r"\[|\]|0x[0-9a-f]+|\d+", text)
    pos = 0

    def one():
        nonlocal pos
        t = toks[pos]
        pos += 1
        if t != "[":
            return int(t, 16) if t.startswith("0x") else int(t)
        items = []
        while toks[pos] != "]":
            items.append(one())
        pos += 1
        out = items[-1]
        for x in reversed(items[:-1]):
            out = (x, out)
        return out
    return one()


def reference_checks(rows):
    """For each REFERENCE label, the vectors whose Hoon side stopped for that
    label's reason: (number settled against the host reference, number
    wrong)."""
    settled = wrong = 0
    for label, (ref, reason) in REFERENCE.items():
        lines = [l for l in rows if l.startswith("LITE1 jetcheck name=")
                 and f" label={label} " in l]
        for line, sample in zip(lines, VECTORS[label]):
            if "verdict=inconclusive" not in line or f" hoon=budget:{reason}" not in line:
                continue
            jet = re.search(r" jet=(.*) hoon=", line).group(1)
            try:
                want = ref(sample)
            except AssertionError:
                want = None                     # the arm would crash
            ok = not jet.startswith(("crash", "budget")) and parse_noun(jet) == want
            print(f"LITE1 jetcheck_reference label={label} sample={str(sample)[:60]} "
                  f"verdict={'match' if ok else 'mismatch'}")
            settled += ok
            wrong += not ok
    return settled, wrong


def build(plant, label_only=False):
    args = ["make", "-C", str(ROOT), "PLATFORM=qemu-virt", "LITE_HOST=1", "LITE_PROBE=1"]
    if plant:
        args.append("LITE_PLANT_RSH_RAW=1")
    if label_only:
        args.append("LITE_PLANT_LABEL_ONLY=1")
    pill = ROOT / "pill.bin"
    prev = pill.read_bytes() if pill.exists() else None
    pill.write_bytes(bytes(16))
    try:
        subprocess.run(args + ["all"], check=True, capture_output=True, timeout=600)
    finally:
        pill.unlink() if prev is None else pill.write_bytes(prev)
    return ROOT / "kernel8.img"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plant-rsh", action="store_true")
    ap.add_argument("--plant-label-only", action="store_true")
    ap.add_argument("--expect-fail", action="store_true")
    ap.add_argument("--no-build", action="store_true")
    ap.add_argument("--log", type=Path)
    a = ap.parse_args()
    image = ROOT / "kernel8.img" if a.no_build else build(a.plant_rsh, a.plant_label_only)
    kjam = gzip.decompress((ROOT / "tests/jetcheck/jetcheck.jam.gz").read_bytes())
    vec = lst(*[(cord(k), lst(*v)) for k, v in VECTORS.items()])
    cause = (cord("go"), 0)
    plan = lst((cord("poke-jetcheck"), (cord("go"), (cause, vec))))
    pa = jam(plan)
    pbytes = pa.to_bytes((pa.bit_length() + 7) // 8, "little")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        pill = td / "pill.bin"
        pill.write_bytes(len(kjam).to_bytes(8, "little") + bytes([2]) + bytes(4) + bytes(3) + kjam)
        planf = td / "plan.bin"
        planf.write_bytes(len(pbytes).to_bytes(8, "little") + pbytes)
        cmd = ["qemu-system-aarch64", "-machine", "virt", "-cpu", "cortex-a72", "-m", "2G",
               "-kernel", str(image), "-device", f"loader,file={pill},addr=0x50000000,force-raw=on",
               "-device", f"loader,file={planf},addr=0x51000000,force-raw=on",
               "-display", "none", "-nographic", "-no-reboot"]
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = b""
        deadline = time.monotonic() + 900
        while b"LITE1 terminal=" not in out and time.monotonic() < deadline:
            chunk = p.stdout.read1(65536)
            if not chunk:
                break
            out += chunk
        time.sleep(0.2)
        p.kill()
    text = out.decode("utf-8", "replace").replace("\r", "")
    if a.log:
        a.log.write_text(text)
    rows = [l for l in text.splitlines() if l.startswith("LITE1 jetcheck")]
    for l in rows:
        print(l)
    summ = [l for l in rows if l.startswith("LITE1 jetcheck_summary")]
    checked = {re.search(r"label=(\S+)", l).group(1) for l in rows
               if l.startswith("LITE1 jetcheck name=")}
    unvec = {re.search(r"label=(\S+)", l).group(1) for l in rows
             if l.startswith("LITE1 jetcheck_unvectored")}
    problems = []
    if not summ:
        problems.append("no jetcheck_summary (terminal=%s)" % re.findall(r"terminal=(\S+)", text))
    dups = sorted(set(re.findall(r"LITEH fast_dup label=(\S+)", text)))
    if dups:
        problems.append("duplicate hot label bound: " + " ".join(dups))
    else:
        f = dict(re.findall(r"(\w+)=(\d+)", summ[0]))
        if int(f["mismatch"]):
            problems.append(f"{f['mismatch']} mismatch(es)")
        settled, wrong = reference_checks(rows)
        left = int(f["inconclusive"]) - settled
        if wrong:
            problems.append(f"{wrong} host-reference mismatch(es)")
        if left:
            problems.append(f"{left} inconclusive")
    missing = REQUIRED - checked
    if missing:
        problems.append("hot labels not registered/checked: " + " ".join(sorted(missing)))
    if unvec - UNVECTORED_OK:
        problems.append("unexpected unvectored labels: " + " ".join(sorted(unvec - UNVECTORED_OK)))
    ok = not problems
    print("jetcheck:", "PASS" if ok else "FAIL", "; ".join(problems))
    if a.expect_fail:
        return 0 if not ok else 1
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
