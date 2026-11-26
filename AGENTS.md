# Trinitite — agent briefing

## What this tree is

The lite node's bare-metal host for
[1499kernel](https://github.com/sapiencezk/1499kernel): one AArch64 image that
cues a NockApp kernel jam from RAM, kicks it, and pokes and peeks it under
fixed admission caps, keeping its state in a cold store with a checkpoint,
a running log and an SD recorder ring. 1499kernel holds this tree as its
`trinitite` submodule, builds it with `I3_*` make variables and parses its
UART lines. Changes here are 1499kernel PLAN rows; read its `docs/PLAN.md`
and `docs/HANDOVER.md` first.

## Layout

```
Makefile                 the only build; make test is the tree's check
src/
  boot.s                 core 0 entry: stack, BSS, main
  main.c                 Pi output-bank clear, UART, heap, cold store, i3_host_boot
  i3_host.c / .h         the host: pill cue, kick, poke/peek, %crud, input log,
                         replay, stop, checkpoint writer and boot, compaction
  i3_admission.h         the cue and per-slam caps
  i3_l1_probe.c / .h     I3_L1_PROBE: the diagnostic plan driver (I3L1 lines)
  i3_ring.c / .h         I3_LITE_LOG: the SD recorder ring
  nock.c / .h            Nock 4K evaluator, hints, budgets, hot jets, %fast
  noun.c / .h            noun tags, split cell heap, content-addressed atom store
  jam.c, ckpt_jam.c      ++jam-exact jam (ckpt_jam.c builds jam.c again for the checkpoint)
  bounded_cue.c / .h     the bounded cue
  bignum.c, tip5.c, blake3.c, sha256.c
  cold.c / .h            the cold store: blobs, log, superblocks, base, compaction
  cold_media*.c, cold_nv*.c  media backends: none, semihost file, fake, Pi 4 SD
  digital_out.c          rpi4b: GPIO 17/27/22 driven low at boot
  uart.c, runtime_stats.c (timer reads), freestanding.c, setjmp.s
  memory.h, platform.h   the memory map (single source of truth)
  linker.ld, linker-qemu-virt.ld
tests/                   see README.md "Tests"
tools/jam.py             Python jam/cue (1499kernel imports it)
tools/ring_image.py      reads and edits recorder-ring images (tests)
tools/with_build_lock.py serialises builds that publish kernel8.img
docs/HOST-CONTRACT.md    what the host does, its inputs and outputs
docs/lite-checkpoint-writer.md  the checkpoint, log, ring and compaction design
```

## Build and check

```sh
make PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1   # see README.md for every variable
make test                                         # all configurations, QEMU tests, jam.py
```

Toolchain: `aarch64-elf-gcc`, `aarch64-elf-binutils`, `qemu-system-aarch64`.
The full checks run from 1499kernel: `tools/lite_probe.py` (every leg, the
lite /state-hash and the checkpoint boot legs) on a tree that pins this one.

## Rules

- Everything here is reached by an image 1499kernel builds; code no image
  reaches is deleted, not kept behind a flag.
- The lines 1499kernel parses (`I3H …`, `I3L1 …`), the admission caps in
  `i3_admission.h`, the checkpoint and cold formats and the digest domains
  are interfaces: changing one is a 1499kernel row, with its tools and
  goldens in the same change.
- Bare metal, freestanding, no libc, no heap outside `memory.h`'s regions.
  Both platforms boot with the MMU off; build with `-mstrict-align`.
