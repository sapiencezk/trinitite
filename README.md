# Trinitite
### The 1499kernel lite node's bare-metal host

![](./img/hero.jpg)

This tree builds one image: the lite node of
[1499kernel](https://github.com/sapiencezk/1499kernel), a bare-metal AArch64
host that cues a NockApp kernel jam, kicks it, and runs it under fixed
admission caps. It runs on a Raspberry Pi 4 / CM4 and, for tests, on QEMU's
`virt` machine. It has no IEC 61499 code of its own: the kernel jam is the
application; this tree is the Nock evaluator, the noun heap, the cold store
and the checkpoint, log and ring that keep the kernel's state.

1499kernel holds this tree as its `trinitite` submodule and drives it with its
`tools/lite_*` scripts.

## Building

Toolchain: `aarch64-elf-gcc` and binutils (`brew install aarch64-elf-gcc
aarch64-elf-binutils`), QEMU for the tests (`brew install qemu`).

```sh
make PLATFORM=qemu-virt I3_HOST=1                 # the host image on QEMU virt
make PLATFORM=qemu-virt I3_HOST=1 I3_L1_PROBE=1   # plus the diagnostic plan driver
make PLATFORM=rpi4b I3_HOST=1                     # the Pi 4 image
```

`I3_HOST=1` is the default and the only value: the lite host is the only image.
The result is `kernel8.img` (and `kernel8.elf`); each configuration also keeps
its own copy under `.build/`.

| Variable | Values | Effect |
|---|---|---|
| `PLATFORM` | `rpi4b` (default), `qemu-virt` | memory map, UART, linker script |
| `COLD_MEDIA` | `ram` (default), `semihost`, `fake`, `rpi4-sd` | where the cold store lives: RAM only, a QEMU semihosting file (`build/cold.img`), a fault-injecting fake, the Pi's SD card |
| `I3_L1_PROBE=1` | | the diagnostic driver: pokes and peeks a plan blob, prints `I3L1` lines |
| `I3_UNJETTED=1` | qemu-virt, with `I3_L1_PROBE` | the diagnostic budget, 16x the slam caps |
| `I3_CHECKPOINT_EVERY=K` | default 2000; empty turns it off | the checkpoint writer and the boot from the newest checkpoint |
| `I3_LITE_LOG=1` | with a checkpoint cadence | the running log, the SD recorder ring and compaction |
| `I3_RING_BYTES`, `I3_RING_EVERY` | with `I3_LITE_LOG` | ring size and ring checkpoint cadence |
| `I3_PERSIST_HEADROOM_CELLS=N` | | test knob: cap persist growth at N cells past boot |
| `I3_CKPT_TEST`, `I3_CKPT_TEST_FROM`, `I3_RING_TEST`, `I3_RING_TEST_AT`, `I3_PLANT_RSH_RAW`, `I3_PLANT_LABEL_ONLY` | | test-only fault and plant knobs (see the Makefile) |

## Running under QEMU

The host reads three blobs that QEMU's loader places in RAM (qemu-virt
addresses):

| Blob | Address | Layout |
|---|---|---|
| pill | `0x50000000` | `[u64 jam length][u8 shape = 2 (NockApp)][7 bytes 0][kernel jam]` |
| plan (`I3_L1_PROBE`) | `0x51000000` | `[u64 length][jam of the plan steps]` |
| application | `0x53000000` | `[u64 jam length][64 hex SHA-256, all 0 = no gate][bundle jam]` |

```sh
qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 2G -nographic \
  -kernel kernel8.img \
  -device loader,file=kernel.pill,addr=0x50000000,force-raw=on \
  -device loader,file=kernel.plan,addr=0x51000000,force-raw=on
```

Add `-semihosting` for `COLD_MEDIA=semihost`. Every host line starts with
`I3H`, every diagnostic line with `I3L1`; 1499kernel's `tools/lite_probe.py`
builds the blobs and parses the lines. The host contract is
[docs/HOST-CONTRACT.md](docs/HOST-CONTRACT.md).

## Tests

```sh
make test         # every configuration builds, then the QEMU tests and tools/jam.py's self-tests
make test-build   # the builds only
make test-qemu    # tests/app_sha256_probe.py, tests/jetcheck/run.py (and its two plants), tests/tip5/run.py
```

The checkpoint, log and ring legs run from 1499kernel: `tools/lite_probe.py`
runs `tools/lite_checkpoint_boot.py` and `tools/lite_state_hash.py` on this
tree's images.

## On a Raspberry Pi 4

1499kernel's `tools/board/make-boot.sh` assembles the FAT boot directory
(`start4.elf`, `fixup4.dat`, `config.txt`, `kernel8.img` and the pill) from its
pinned firmware manifest. The console is UART0 (PL011) on GPIO 14/15, 115200
8N1, 3.3 V logic:

```
Pi GPIO 14  (TXD, pin 8)   →  RX  on the serial adapter
Pi GPIO 15  (RXD, pin 10)  →  TX  on the serial adapter
Pi GND      (pin 9)        →  GND on the serial adapter
```

Do not connect the adapter's power pin; power the Pi from its own USB-C port.
At boot the image drives the fixed output bank (GPIO 17, 27 and 22) low.

## History

Trinitite began as Sigilante's bare-metal Forth/Nock OS for the Raspberry Pi.
1499kernel grew its own host on it, and row 389 removed everything the lite
node does not run: the Forth system and REPL, the Arvo/Shrine kernel loop,
subject knowledge analysis, and the earlier native research line. What
remains of the original is described in [ROADMAP.md](ROADMAP.md).

![](./img/icon-64.jpg)

© 2026 Sigilante, released under the MIT License
