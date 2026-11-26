# Lite host contract

What the lite host image (`I3_HOST=1`, the only image this tree builds) does
with a NockApp kernel, and what it reads and writes. 1499kernel owns the
kernel, its causes and its effects (`docs/PLAN.md`, `docs/HANDOVER.md`); this
file covers the host side only. The checkpoint, running log, recorder ring
and compaction are in [lite-checkpoint-writer.md](lite-checkpoint-writer.md).

The host has no IEC 61499 code: no execution control, no function block
network, no IEC types. It is a bounded Nock machine with persistent state.

## 1. Inputs

The pill, the plan and the application bundle sit in RAM at fixed offsets from
`PILL_BASE` (DRAM + 0x10000000; qemu-virt 0x50000000, rpi4b 0x10000000):

| Blob | Offset | Layout |
|---|---|---|
| pill | `PILL_BASE` | `[u64 LE jam length][u8 shape][7 bytes][kernel jam]`; shape 2 (NockApp) is the only one accepted (`I3H terminal=pill-refuse` otherwise) |
| plan | `I3_PLAN_BASE` = `PILL_BASE` + 0x01000000 | `[u64 LE length][jam of the step list]`, read by the `I3_L1_PROBE` driver |
| application | `I3_APP_BASE` = `PILL_BASE` + 0x03000000 | `[u64 LE jam length][64 ASCII hex SHA-256][bundle jam]` |

The kernel jam may be up to `I3_CUE_MAX_INPUT_BYTES` (16 MiB less the 16-byte
header) and is cued with the bounds of `src/i3_admission.h`; a cue past a
bound halts with `I3H terminal=cue-refuse`.

An application bundle is loaded only if its SHA-256, computed natively before
any cue, equals the expected digest; an all-zero digest skips the gate. On a
match it is cued and poked as `[%load-bundle bundle]`.

## 2. Boot

1. Cue the pill's kernel, kick it (`[9 2 0 1]`) and build the poke and peek
   formulas (in the code region when compaction is on).
2. Read the cold store from the media; with a checkpoint cadence, boot from
   the newest verified checkpoint, else from the kicked kernel.
3. Replay every logged entry after it through the same slam, checking each
   event number, then install the result (`I3H replay …`).
4. `I3H ready`; the diagnostic driver (if built) then runs the plan.

## 3. Pokes and peeks

Each poke slams the kernel's poke arm with a job `[event_num ovum]` under the
per-slam caps (`I3_SLAM_MAX_OPS` 4,000,000, `I3_SLAM_MAX_CELLS` 1,200,000,
`I3_SLAM_MAX_STACK` 1,024 evaluator frames). The product must parse as
`[effects new-core]`; the new core is copied into the persist heap and becomes
the kernel. Peeks use the peek arm under the same caps and change nothing.

`%crud` carries the bail's goof `[mote tang]` as the full node does: a Nock
crash in a poke re-pokes the same event through the wire `~[/arvo]` as
`[%crud goof ovum]`. A trap `%mean` frame renders as `"####"` (the full
node's own fallback for an unrenderable trap; this host has no printing jets).

Input log (1499kernel decision 200): after each accepted step the host appends
one entry with `cold_log`, the jam of the job `[event_num ovum]` (for a crash,
the `%crud` ovum), the same entry as the full and web nodes. Nothing is
appended past `%crud`. A crash past `%crud`, a failed append, and a host abort
(ops, cells, stack) append nothing and stop the application: later pokes are
refused, and the next boot, after replay, applies a journaled `%manage` STOP
once. A step that would leave less persist room than replay needs also stops
it (`I3H stop reason=persist`). Under `COLD_MEDIA=semihost` each append
rewrites `build/cold.img`, so the run needs `-semihosting`.

## 4. Memory

| Region | Range | On exhaustion |
|---|---|---|
| Persist cells | two 16 MiB semispaces from `HEAP_BASE` | `heap exhausted` |
| Scratch cells | `HEAP_SCRATCH_BASE` .. `HEAP_TOP`, 32 MiB (64 MiB high in qemu RAM with `I3_UNJETTED`) | `scratch exhausted` |
| Atom store | 64k-slot index, 4 MiB of records | `atom store exhausted/collision` |
| Cold store | 8 MiB RAM window at `COLD_BASE`, mirrored to the media | append fails, the application stops |

A slam's product is built in scratch. On success the new core is copied into
the other persist semispace, which then becomes live; scratch is reset after
each step. `src/memory.h` is the single source of truth for every region and
checks their placement at build time.

## 5. Cold media

Selected at build time:

```text
COLD_MEDIA=ram       logical RAM window, no physical flush (default)
COLD_MEDIA=semihost  QEMU lab file transport (build/cold.img)
COLD_MEDIA=fake      deterministic bounded fault adapter (tests)
COLD_MEDIA=rpi4-sd   Pi 4B BCM2711 EMMC2 PIO target
```

The Pi 4 adapter maps the two superblocks to distinct 512-byte sectors behind
one versioned raw-extent descriptor. It checks the descriptor, presence,
read-only state, capacity, translated range, deadline and non-reentrancy, adds
barriers after the object commit and the inactive superblock, never retries a
submitted uncertain write, and latches reset-required after any controller,
read or write fault. A barrier proves only controller/card ready completion,
not power-cut durability. Semihost and RAM are volatile logical acceptance;
no durability claim is made for any medium, and per-step SD appends on the
board are unmeasured.

## 6. Jets

C jets only, registered by `%fast` (label and parent path, the first battery
per hot label, as NockVM's hot state) and `%wild`. The hot labels are listed
in `hot_state[]` (`src/nock.c`); `tests/jetcheck` checks each against its own
Nock battery. Every other hint is inert.

## 7. UART

Every host line starts with `I3H `, every diagnostic-driver line with `I3L1 `.
1499kernel's `tools/lite_probe.py`, `tools/lite_checkpoint_boot.py` and
related tools parse them; their names and fields are an interface (a change
is a 1499kernel row). The console is PL011 at 115200 8N1 (rpi4b: GPIO 14/15).

## 8. Verify

```sh
make test                                  # this tree
python3 tools/lite_probe.py --kernel build/kernel/kernel.jam   # from 1499kernel
```
