TARGET  = kernel8
SRCDIR  = src

PLATFORM ?= rpi4b
ifeq ($(PLATFORM),rpi4b)
PLATFORM_DEFINE = -DTRINITITE_PLATFORM_RPI4B=1
LINKER_SCRIPT = $(SRCDIR)/linker.ld
else ifeq ($(PLATFORM),qemu-virt)
PLATFORM_DEFINE = -DTRINITITE_PLATFORM_QEMU_VIRT=1
LINKER_SCRIPT = $(SRCDIR)/linker-qemu-virt.ld
else
$(error unsupported PLATFORM='$(PLATFORM)' (rpi4b, qemu-virt))
endif

CROSS   ?= aarch64-elf-
CC       = $(CROSS)gcc
LD       = $(CROSS)ld
OBJCOPY  = $(CROSS)objcopy

VPATH   = $(SRCDIR)

# Both platforms boot with the MMU off: do not combine adjacent 32-bit
# fields into unaligned wide accesses (-mstrict-align).
CFLAGS  = -Wall -O2 -ffreestanding -nostdlib -nostartfiles \
          -mcpu=cortex-a72 -mgeneral-regs-only \
          -fno-pic -fno-stack-protector -fno-builtin \
          -I$(SRCDIR) $(PLATFORM_DEFINE) -mstrict-align
LDFLAGS = -T $(LINKER_SCRIPT) -nostdlib -no-pie
ifeq ($(PLATFORM),qemu-virt)
LDFLAGS += -e _start
endif

# The lite node's host image is the only image this tree builds; I3_HOST=1
# (what 1499kernel passes) is the default.
I3_HOST ?= 1
ifneq ($(I3_HOST),1)
$(error the only image is the lite host: I3_HOST must be 1)
endif

COLD_MEDIA ?= ram
I3_L1_PROBE ?= 0
I3_UNJETTED ?= 0
I3_PLANT_RSH_RAW ?= 0
I3_PLANT_LABEL_ONLY ?= 0

ifeq ($(I3_L1_PROBE),1)
CFLAGS += -DI3_L1_PROBE=1
endif
# Test knob: cap persist growth at N cells past boot (lite replay ceiling test).
ifneq ($(I3_PERSIST_HEADROOM_CELLS),)
CFLAGS += -DI3_PERSIST_HEADROOM_CELLS=$(I3_PERSIST_HEADROOM_CELLS)
endif
# Row 212 PR 1a: lite checkpoint writer every K accepted entries, and (1b) boot
# from the newest verified checkpoint. Row 317 (3) turns it on for every
# image at row 212's cadence, K = 2,000; I3_CHECKPOINT_EVERY= (empty)
# compiles both out, as before.
I3_CHECKPOINT_EVERY ?= 2000
ifneq ($(I3_CHECKPOINT_EVERY),)
CFLAGS += -DI3_CHECKPOINT_EVERY=$(I3_CHECKPOINT_EVERY)
# Row 317 (3), Q7: the checkpoint writer's own jam (src/ckpt_jam.c).
CKPT_OBJS = ckpt_jam.o
endif
# Row 212 PR 1c (amended row 212 (2)): I3_LITE_LOG=1 adds the running log (the
# log base in the cold superblock) and the SD recorder ring (src/i3_ring.c).
# Nested under I3_CHECKPOINT_EVERY, default off. I3_RING_BYTES (bytes, a
# multiple of 512, default 67108864 = 64 MiB) and I3_RING_EVERY (events per ring
# checkpoint, a multiple of I3_CHECKPOINT_EVERY, default 2000) are build-time.
ifneq ($(I3_LITE_LOG),)
ifeq ($(I3_CHECKPOINT_EVERY),)
$(error I3_LITE_LOG requires I3_CHECKPOINT_EVERY)
endif
ifneq ($(I3_LITE_LOG),1)
$(error I3_LITE_LOG must be 1 or unset)
endif
CFLAGS += -DI3_LITE_LOG=1
endif
ifneq ($(I3_RING_BYTES)$(I3_RING_EVERY),)
ifeq ($(I3_LITE_LOG),)
$(error I3_RING_BYTES and I3_RING_EVERY require I3_LITE_LOG=1)
endif
endif
ifneq ($(I3_RING_BYTES),)
CFLAGS += -DI3_RING_BYTES=$(I3_RING_BYTES)ULL
endif
ifneq ($(I3_RING_EVERY),)
CFLAGS += -DI3_RING_EVERY=$(I3_RING_EVERY)
endif
# Test builds only (tests/recorder_ring.py fault legs): I3_RING_TEST=fault
# with I3_RING_TEST_AT=K (COLD_MEDIA=fake) makes the K-th ring sector write
# land half and report WRITE_UNKNOWN; I3_RING_TEST=torn (COLD_MEDIA=semihost)
# skips the first wrap marker, commits the header and stops dead.
ifneq ($(I3_RING_TEST),)
ifeq ($(I3_LITE_LOG),)
$(error I3_RING_TEST requires I3_LITE_LOG=1)
endif
ifeq ($(I3_RING_TEST),fault)
ifneq ($(COLD_MEDIA),fake)
$(error I3_RING_TEST=fault requires COLD_MEDIA=fake)
endif
ifeq ($(I3_RING_TEST_AT),)
$(error I3_RING_TEST=fault requires I3_RING_TEST_AT=K)
endif
CFLAGS += -DI3_RING_TEST_FAULT=1 -DI3_RING_TEST_AT=$(I3_RING_TEST_AT)
else ifeq ($(I3_RING_TEST),torn)
ifneq ($(COLD_MEDIA),semihost)
$(error I3_RING_TEST=torn requires COLD_MEDIA=semihost)
endif
CFLAGS += -DI3_RING_TEST_TORN=1
else
$(error I3_RING_TEST must be fault or torn)
endif
endif
# Test builds only: I3_CKPT_TEST=cells|jam|stack|wrapper shrinks one checkpoint
# bound so tests/checkpoint_legs.py reaches that skip leg; persist (row 317
# Q10) makes the writer see no boot persist room, so every checkpoint skips
# reason=persist (1499kernel lite_checkpoint_boot.py persist leg); dirty fills
# the checkpoint region with 0xA5 at boot, as stale RAM, before the reset
# (lite_checkpoint_boot.py dirty leg); appcells lowers the bundle cue's cells
# bound to 1,000 so a %load-bundle is refused reason=cells (lite_checkpoint_boot.py
# depth leg control); hdrshape|hdrsid|hdrd
# make the writer store a bad header for every N >= I3_CKPT_TEST_FROM (default 1)
# so tests/checkpoint_boot.py reaches each boot fallback leg (default unset);
# crash (PR 1c) stores a damaged header for N >= I3_CKPT_TEST_FROM and stops
# dead before verifying it (tests/recorder_ring.py crash leg); rebasefault
# (PR 1c, COLD_MEDIA=fake) arms a cold media timeout before the first log
# base move (tests/recorder_ring.py rebase-fault leg). Row 221 (row 212 (c),
# I3_LITE_LOG=1 only): cmpbefore|cmpcopy|cmpafter|cmpflip|cmprebuild stop the
# first compaction at N >= I3_CKPT_TEST_FROM dead at that crash point; cmpskip
# makes that compaction's copy fail so it aborts (tests/compaction.py).
ifneq ($(I3_CKPT_TEST),)
ifeq ($(I3_CHECKPOINT_EVERY),)
$(error I3_CKPT_TEST requires I3_CHECKPOINT_EVERY)
endif
ifeq ($(filter $(I3_CKPT_TEST),cells jam stack wrapper persist dirty appcells hdrshape hdrsid hdrd crash rebasefault cmpbefore cmpcopy cmpafter cmpflip cmprebuild cmpskip),)
$(error I3_CKPT_TEST must be one of cells jam stack wrapper persist dirty appcells hdrshape hdrsid hdrd crash rebasefault cmpbefore cmpcopy cmpafter cmpflip cmprebuild cmpskip)
endif
ifneq ($(filter $(I3_CKPT_TEST),cmpbefore cmpcopy cmpafter cmpflip cmprebuild cmpskip),)
ifneq ($(I3_LITE_LOG),1)
$(error I3_CKPT_TEST=$(I3_CKPT_TEST) requires I3_LITE_LOG=1)
endif
endif
ifeq ($(I3_CKPT_TEST),rebasefault)
ifneq ($(COLD_MEDIA)$(I3_LITE_LOG),fake1)
$(error I3_CKPT_TEST=rebasefault requires COLD_MEDIA=fake and I3_LITE_LOG=1)
endif
endif
CFLAGS += -DI3_CKPT_TEST_$(shell echo $(I3_CKPT_TEST) | tr a-z A-Z)=1
endif
ifneq ($(I3_CKPT_TEST_FROM),)
ifeq ($(filter $(I3_CKPT_TEST),hdrshape hdrsid hdrd crash cmpbefore cmpcopy cmpafter cmpflip cmprebuild cmpskip),)
$(error I3_CKPT_TEST_FROM requires I3_CKPT_TEST=hdrshape|hdrsid|hdrd|crash|cmpbefore|cmpcopy|cmpafter|cmpflip|cmprebuild|cmpskip)
endif
CFLAGS += -DI3_CKPT_TEST_FROM=$(I3_CKPT_TEST_FROM)
endif
ifeq ($(I3_UNJETTED),1)
ifneq ($(I3_L1_PROBE),1)
$(error I3_UNJETTED=1 requires I3_L1_PROBE=1)
endif
ifneq ($(PLATFORM),qemu-virt)
$(error I3_UNJETTED=1 requires PLATFORM=qemu-virt; unjetted scratch is qemu-virt only)
endif
CFLAGS += -DI3_UNJETTED=1
endif
# Test-only plant: re-introduce L3's raw-bit-count rsh jet so the jetcheck
# test can show it catches that class. Never set for a shipped image.
ifeq ($(I3_PLANT_RSH_RAW),1)
ifneq ($(I3_L1_PROBE),1)
$(error I3_PLANT_RSH_RAW=1 requires I3_L1_PROBE=1)
endif
CFLAGS += -DI3_PLANT_RSH_RAW=1
endif
# Test-only plant: the pre-fix label-only %fast rule, so the duplicate-label
# assertion can be shown to fire. Never set for a shipped image.
ifeq ($(I3_PLANT_LABEL_ONLY),1)
ifneq ($(I3_L1_PROBE),1)
$(error I3_PLANT_LABEL_ONLY=1 requires I3_L1_PROBE=1)
endif
CFLAGS += -DI3_PLANT_LABEL_ONLY=1
endif

ifeq ($(COLD_MEDIA),ram)
MEDIA_OBJS = cold_media.o cold_nv_none.o
else ifeq ($(COLD_MEDIA),semihost)
CFLAGS += -DCOLD_MEDIA_SEMIHOST=1
MEDIA_OBJS = cold_media.o cold_nv.o
else ifeq ($(COLD_MEDIA),fake)
CFLAGS += -DCOLD_MEDIA_FAKE=1
MEDIA_OBJS = cold_media.o cold_media_fake.o cold_nv_none.o
else ifeq ($(COLD_MEDIA),rpi4-sd)
CFLAGS += -DCOLD_MEDIA_RPI4_SD=1
MEDIA_OBJS = cold_media.o cold_media_rpi4_sd.o cold_nv_none.o
else
$(error unsupported COLD_MEDIA='$(COLD_MEDIA)' (ram, semihost, fake, rpi4-sd))
endif

# The Pi's fixed digital output bank is cleared at boot (src/digital_out.c).
DIGITAL_OUT_OBJS =
ifeq ($(PLATFORM),rpi4b)
DIGITAL_OUT_OBJS = digital_out.o
endif

I3_RING_OBJS =
ifeq ($(I3_LITE_LOG),1)
I3_RING_OBJS = i3_ring.o
endif
I3_L1_OBJS =
ifeq ($(I3_L1_PROBE),1)
I3_L1_OBJS = i3_l1_probe.o
endif
OBJ_NAMES = boot.o uart.o freestanding.o noun.o bignum.o blake3.o nock.o setjmp.o jam.o bounded_cue.o runtime_stats.o i2_admission_metrics.o i3_host.o $(I3_RING_OBJS) $(CKPT_OBJS) $(I3_L1_OBJS) $(DIGITAL_OUT_OBJS) cold.o $(MEDIA_OBJS) sha256.o tip5.o main.o
CONFIG_KEY = $(PLATFORM)-$(COLD_MEDIA)
ifeq ($(I3_L1_PROBE),1)
CONFIG_KEY := $(CONFIG_KEY)-i3l1
endif
ifeq ($(I3_UNJETTED),1)
CONFIG_KEY := $(CONFIG_KEY)-i3unjet
endif
ifneq ($(I3_CHECKPOINT_EVERY),)
CONFIG_KEY := $(CONFIG_KEY)-i3ck$(I3_CHECKPOINT_EVERY)
endif
ifeq ($(I3_LITE_LOG),1)
CONFIG_KEY := $(CONFIG_KEY)-i3ll
endif
ifneq ($(I3_RING_BYTES),)
CONFIG_KEY := $(CONFIG_KEY)-i3rb$(I3_RING_BYTES)
endif
ifneq ($(I3_RING_EVERY),)
CONFIG_KEY := $(CONFIG_KEY)-i3re$(I3_RING_EVERY)
endif
ifneq ($(I3_RING_TEST),)
CONFIG_KEY := $(CONFIG_KEY)-i3rt$(I3_RING_TEST)$(I3_RING_TEST_AT)
endif
ifneq ($(I3_CKPT_TEST),)
CONFIG_KEY := $(CONFIG_KEY)-i3ckt$(I3_CKPT_TEST)
endif
ifneq ($(I3_CKPT_TEST_FROM),)
CONFIG_KEY := $(CONFIG_KEY)-i3ckf$(I3_CKPT_TEST_FROM)
endif
ifneq ($(I3_PERSIST_HEADROOM_CELLS),)
CONFIG_KEY := $(CONFIG_KEY)-i3ph$(I3_PERSIST_HEADROOM_CELLS)
endif
ifeq ($(I3_PLANT_RSH_RAW),1)
CONFIG_KEY := $(CONFIG_KEY)-plantrsh
endif
ifeq ($(I3_PLANT_LABEL_ONLY),1)
CONFIG_KEY := $(CONFIG_KEY)-plantlabel
endif
BUILD_DIR = .build/$(CONFIG_KEY)
OBJDIR = $(BUILD_DIR)/obj
OBJS = $(addprefix $(OBJDIR)/,$(OBJ_NAMES))
CONFIG_ELF = $(BUILD_DIR)/$(TARGET).elf
CONFIG_IMG = $(BUILD_DIR)/$(TARGET).img

all:
	python3 tools/with_build_lock.py $(MAKE) locked-all

$(TARGET).elf:
	python3 tools/with_build_lock.py $(MAKE) locked-elf

$(TARGET).img:
	python3 tools/with_build_lock.py $(MAKE) locked-all

locked-all: publish-img

locked-elf: publish-elf

$(OBJDIR):
	mkdir -p $@

$(BUILD_DIR):
	mkdir -p $@

$(OBJDIR)/%.o: $(SRCDIR)/%.s | $(OBJDIR)
	$(CC) $(CFLAGS) -x assembler-with-cpp -c $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/noun.o: $(SRCDIR)/memory.h $(SRCDIR)/noun.h
$(OBJDIR)/i3_host.o: $(SRCDIR)/i3_admission.h $(SRCDIR)/memory.h
$(OBJDIR)/i3_ring.o: $(SRCDIR)/i3_ring.h $(SRCDIR)/cold.h $(SRCDIR)/cold_media.h $(SRCDIR)/memory.h
$(OBJDIR)/i3_l1_probe.o: $(SRCDIR)/i3_admission.h $(SRCDIR)/memory.h

# Configuration-specific directories prevent preprocessor/backend object reuse.
$(CONFIG_ELF): $(OBJS) | $(BUILD_DIR)
	$(LD) $(LDFLAGS) -o $@ $^

$(CONFIG_IMG): $(CONFIG_ELF)
	$(OBJCOPY) -O binary $< $@

# Preserve the historical top-level paths as atomically published aliases.
# The build lock serializes distinct configurations in one worktree.
publish-elf: $(CONFIG_ELF) FORCE
	cp $(CONFIG_ELF) $(TARGET).elf.tmp.$(CONFIG_KEY)
	mv $(TARGET).elf.tmp.$(CONFIG_KEY) $(TARGET).elf

publish-img: $(CONFIG_IMG) publish-elf FORCE
	cp $(CONFIG_IMG) $(TARGET).img.tmp.$(CONFIG_KEY)
	mv $(TARGET).img.tmp.$(CONFIG_KEY) $(TARGET).img

# The tree's own checks. test-build builds every image configuration
# 1499kernel builds (qemu-virt and rpi4b) and every test knob; test-qemu boots
# the qemu-virt diagnostic image (I3_L1_PROBE=1) on the self-contained tests;
# test-tools runs tools/jam.py's self-tests.
# The tests that need a 1499kernel checkout (tests/checkpoint_*.py,
# tests/compaction.py, tests/recorder_ring.py, tests/ring_full_replay.py) run
# from that checkout; see their docstrings.
TEST_BUILDS = \
	"PLATFORM=qemu-virt" \
	"PLATFORM=qemu-virt I3_L1_PROBE=1" \
	"PLATFORM=qemu-virt I3_L1_PROBE=1 I3_UNJETTED=1" \
	"PLATFORM=qemu-virt I3_L1_PROBE=1 COLD_MEDIA=semihost I3_PERSIST_HEADROOM_CELLS=1000000000" \
	"PLATFORM=qemu-virt I3_L1_PROBE=1 COLD_MEDIA=semihost I3_LITE_LOG=1" \
	"PLATFORM=qemu-virt I3_L1_PROBE=1 COLD_MEDIA=semihost I3_CHECKPOINT_EVERY=" \
	"PLATFORM=qemu-virt I3_L1_PROBE=1 COLD_MEDIA=semihost I3_CHECKPOINT_EVERY=4 I3_CKPT_TEST=persist" \
	"PLATFORM=qemu-virt I3_L1_PROBE=1 COLD_MEDIA=semihost I3_CHECKPOINT_EVERY=2 I3_CKPT_TEST=hdrd I3_CKPT_TEST_FROM=3" \
	"PLATFORM=qemu-virt I3_L1_PROBE=1 COLD_MEDIA=fake I3_CHECKPOINT_EVERY=2 I3_LITE_LOG=1 I3_RING_BYTES=32768 I3_RING_EVERY=2 I3_RING_TEST=fault I3_RING_TEST_AT=8" \
	"PLATFORM=qemu-virt I3_L1_PROBE=1 COLD_MEDIA=fake I3_CHECKPOINT_EVERY=2 I3_LITE_LOG=1 I3_CKPT_TEST=rebasefault" \
	"PLATFORM=qemu-virt I3_L1_PROBE=1 COLD_MEDIA=semihost I3_CHECKPOINT_EVERY=2 I3_LITE_LOG=1 I3_RING_BYTES=32768 I3_RING_EVERY=2 I3_RING_TEST=torn" \
	"PLATFORM=qemu-virt I3_L1_PROBE=1 COLD_MEDIA=semihost I3_CHECKPOINT_EVERY=2 I3_LITE_LOG=1 I3_CKPT_TEST=cmpcopy I3_CKPT_TEST_FROM=4" \
	"PLATFORM=rpi4b" \
	"PLATFORM=rpi4b COLD_MEDIA=rpi4-sd" \
	"PLATFORM=rpi4b COLD_MEDIA=rpi4-sd I3_LITE_LOG=1"

test: test-build test-qemu test-tools

test-build:
	@for cfg in $(TEST_BUILDS); do \
		echo "== make $$cfg"; \
		$(MAKE) -s $$cfg all || exit 1; \
	done

test-qemu:
	$(MAKE) PLATFORM=qemu-virt I3_L1_PROBE=1 all
	python3 tests/app_sha256_probe.py
	python3 tests/jetcheck/run.py
	python3 tests/jetcheck/run.py --plant-rsh --expect-fail
	python3 tests/jetcheck/run.py --plant-label-only --expect-fail
	python3 tests/tip5/run.py

test-tools:
	python3 tools/jam.py test

clean:
	python3 tools/with_build_lock.py $(MAKE) locked-clean
locked-clean:
	rm -f *.o *.elf *.img $(TARGET).elf.tmp.* $(TARGET).img.tmp.*
	rm -rf .build
FORCE:
.PHONY: all $(TARGET).elf $(TARGET).img locked-all locked-elf publish-elf publish-img \
	test test-build test-qemu test-tools clean locked-clean FORCE
