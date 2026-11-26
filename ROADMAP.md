# What remains of the original Trinitite

Trinitite started as a bare-metal Forth OS hosting a Nock 4K evaluator. The
lite node keeps the pieces below; the Forth system, the Arvo/Shrine kernel
loop, subject knowledge analysis, the scheduler, timers, MMIO and networking
effects, multi-core workers and live kernel swap were removed by 1499kernel
row 389. Further work on this tree is planned in 1499kernel's `docs/PLAN.md`.

## Noun representation (`src/noun.h`, `src/noun.c`)

| Bits 63:62 | Type | Representation |
|------------|------|----------------|
| `0x` (bit 63 = 0) | direct atom | value = noun word (0..2^63-1) |
| `10` | indirect atom | 62-bit BLAKE3 hash of the limb data |
| `11` | cell | 32-bit heap pointer in bits 31:0 |

`direct(42) == 42`: the raw integer is the noun. Indirect atoms live in a
content-addressed atom store (an open-addressed index from the 62-bit hash to
the `atom_t`, and a bump allocator for the records and limbs); equality of
atoms is a word compare. Cells are allocated in a split heap: two persist
semispaces and a scratch heap that holds one slam's product (`src/memory.h`).

## Nock evaluator (`src/nock.c`)

Opcodes 0–11 with tail calls (`goto loop`) and `hax()` for op 10. Op 11
dispatches `%wild` (jet registration by sock), `%fast` (battery and parent
path, as NockVM's hot state), `%slog`/`%xray` (print), and `%hand`, `%hunk`,
`%lose`, `%mean`, `%spot` (the trace stack `+mook` renders); every other hint
is inert. Every op ticks a deterministic op budget, every allocation a cell
budget, and every recursive evaluation an evaluator-stack bound; any of them
aborts the slam by `longjmp` (`src/setjmp.s`).

## Jets

`hot_state[]` in `src/nock.c` maps hot labels to C functions backed by
`src/bignum.c` and `src/tip5.c`: arithmetic (`dec add sub mul div mod lth gth
lte gte`), structural and bit operations (`eq lsh rsh con dis mix cap mas
peg`), lists (`lent flop weld turn`), `mole`, `jam`, `shax`, and the Tip5
hashes of 1499kernel's `++digest`. Op 9 dispatches to C jets only.

## Bignum (`src/bignum.c`)

Limb arithmetic on `uint64_t` with `__uint128_t` carries: add, sub, mul,
cmp, met, lsh/rsh, or/and/xor, and division (one-limb fast path, Knuth's
Algorithm D otherwise, `divlu64` to avoid `__udivti3`). Results are
normalised by `bn_normalize`: a value below 2^63 is always a direct atom.

## BLAKE3, SHA-256, Tip5

`src/blake3.c` (atom identities, cold store digests), `src/sha256.c`
(application gate, checkpoint digests), `src/tip5.c` (the Tip5 permutation
for the `++digest` jet).

## Jam and cue (`src/jam.c`, `src/bounded_cue.c`, `src/ckpt_jam.c`)

`++jam`-exact encoding (back-references by value) and a bounded cue with
explicit limits on input bytes, depth, nodes, cells, back-references, atom
bytes and work.

## Cold store (`src/cold.c`, `src/cold_media*.c`)

An append-only, content-addressed store of jammed blobs and log entries behind
two checksummed superblocks, in an 8 MB RAM window (`COLD_BASE`) mirrored to
the selected media: none, a QEMU semihosting file, a fault-injecting fake, or
the Pi 4's SD card (EMMC2, PIO).
