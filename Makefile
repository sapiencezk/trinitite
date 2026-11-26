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

# The lite node's host image is the only image this tree builds; LITE_HOST=1
# (what 1499kernel passes) is the default.
LITE_HOST ?= 1
ifneq ($(LITE_HOST),1)
$(error the only image is the lite host: LITE_HOST must be 1)
endif

COLD_MEDIA ?= ram
LITE_PROBE ?= 0
LITE_UNJETTED ?= 0
LITE_PLANT_RSH_RAW ?= 0
LITE_PLANT_LABEL_ONLY ?= 0

ifeq ($(LITE_PROBE),1)
CFLAGS += -DLITE_PROBE=1
endif
# Test knob: cap persist growth at N cells past boot (lite replay ceiling test).
ifneq ($(LITE_PERSIST_HEADROOM_CELLS),)
CFLAGS += -DLITE_PERSIST_HEADROOM_CELLS=$(LITE_PERSIST_HEADROOM_CELLS)
endif
# Row 212 PR 1a: lite checkpoint writer every K accepted entries, and (1b) boot
# from the newest verified checkpoint. Row 317 (3) turns it on for every
# image at row 212's cadence, K = 2,000; LITE_CHECKPOINT_EVERY= (empty)
# compiles both out, as before.
LITE_CHECKPOINT_EVERY ?= 2000
ifneq ($(LITE_CHECKPOINT_EVERY),)
CFLAGS += -DLITE_CHECKPOINT_EVERY=$(LITE_CHECKPOINT_EVERY)
# Row 317 (3), Q7: the checkpoint writer's own jam (src/ckpt_jam.c).
CKPT_OBJS = ckpt_jam.o
endif
# Row 212 PR 1c (amended row 212 (2)): LITE_LOG=1 adds the running log (the
# log base in the cold superblock) and the SD recorder ring (src/lite_ring.c).
# Nested under LITE_CHECKPOINT_EVERY, default off. LITE_RING_BYTES (bytes, a
# multiple of 512, default 67108864 = 64 MiB) and LITE_RING_EVERY (events per ring
# checkpoint, a multiple of LITE_CHECKPOINT_EVERY, default 2000) are build-time.
ifneq ($(LITE_LOG),)
ifeq ($(LITE_CHECKPOINT_EVERY),)
$(error LITE_LOG requires LITE_CHECKPOINT_EVERY)
endif
ifneq ($(LITE_LOG),1)
$(error LITE_LOG must be 1 or unset)
endif
CFLAGS += -DLITE_LOG=1
endif
ifneq ($(LITE_RING_BYTES)$(LITE_RING_EVERY),)
ifeq ($(LITE_LOG),)
$(error LITE_RING_BYTES and LITE_RING_EVERY require LITE_LOG=1)
endif
endif
ifneq ($(LITE_RING_BYTES),)
CFLAGS += -DLITE_RING_BYTES=$(LITE_RING_BYTES)ULL
endif
ifneq ($(LITE_RING_EVERY),)
CFLAGS += -DLITE_RING_EVERY=$(LITE_RING_EVERY)
endif
# Test builds only (1499kernel tools/lite_checkpoint_boot.py legs): persist
# (row 317 Q10) makes the writer see no boot persist room, so every checkpoint
# skips reason=persist; dirty fills the checkpoint region with 0xA5 at boot, as
# stale RAM, before the reset; appcells lowers the bundle cue's cells bound to
# 1,000 so a %load-bundle is refused reason=cells (the depth leg's control);
# hdrshape|hdrsid|hdrd make the writer store a bad header for every
# N >= LITE_CKPT_TEST_FROM (default 1), so each boot fallback leg is reached.
ifneq ($(LITE_CKPT_TEST),)
ifeq ($(LITE_CHECKPOINT_EVERY),)
$(error LITE_CKPT_TEST requires LITE_CHECKPOINT_EVERY)
endif
ifeq ($(filter $(LITE_CKPT_TEST),persist dirty appcells hdrshape hdrsid hdrd),)
$(error LITE_CKPT_TEST must be one of persist dirty appcells hdrshape hdrsid hdrd)
endif
CFLAGS += -DLITE_CKPT_TEST_$(shell echo $(LITE_CKPT_TEST) | tr a-z A-Z)=1
endif
ifneq ($(LITE_CKPT_TEST_FROM),)
ifeq ($(filter $(LITE_CKPT_TEST),hdrshape hdrsid hdrd),)
$(error LITE_CKPT_TEST_FROM requires LITE_CKPT_TEST=hdrshape|hdrsid|hdrd)
endif
CFLAGS += -DLITE_CKPT_TEST_FROM=$(LITE_CKPT_TEST_FROM)
endif
ifeq ($(LITE_UNJETTED),1)
ifneq ($(LITE_PROBE),1)
$(error LITE_UNJETTED=1 requires LITE_PROBE=1)
endif
ifneq ($(PLATFORM),qemu-virt)
$(error LITE_UNJETTED=1 requires PLATFORM=qemu-virt; unjetted scratch is qemu-virt only)
endif
CFLAGS += -DLITE_UNJETTED=1
endif
# Test-only plant: re-introduce L3's raw-bit-count rsh jet so the jetcheck
# test can show it catches that class. Never set for a shipped image.
ifeq ($(LITE_PLANT_RSH_RAW),1)
ifneq ($(LITE_PROBE),1)
$(error LITE_PLANT_RSH_RAW=1 requires LITE_PROBE=1)
endif
CFLAGS += -DLITE_PLANT_RSH_RAW=1
endif
# Test-only plant: the pre-fix label-only %fast rule, so the duplicate-label
# assertion can be shown to fire. Never set for a shipped image.
ifeq ($(LITE_PLANT_LABEL_ONLY),1)
ifneq ($(LITE_PROBE),1)
$(error LITE_PLANT_LABEL_ONLY=1 requires LITE_PROBE=1)
endif
CFLAGS += -DLITE_PLANT_LABEL_ONLY=1
endif

ifeq ($(COLD_MEDIA),ram)
MEDIA_OBJS = cold_media.o cold_nv_none.o
else ifeq ($(COLD_MEDIA),semihost)
CFLAGS += -DCOLD_MEDIA_SEMIHOST=1
MEDIA_OBJS = cold_media.o cold_nv.o
else ifeq ($(COLD_MEDIA),rpi4-sd)
CFLAGS += -DCOLD_MEDIA_RPI4_SD=1
MEDIA_OBJS = cold_media.o cold_media_rpi4_sd.o cold_nv_none.o
else
$(error unsupported COLD_MEDIA='$(COLD_MEDIA)' (ram, semihost, rpi4-sd))
endif

# The Pi's fixed digital output bank is cleared at boot (src/digital_out.c).
DIGITAL_OUT_OBJS =
ifeq ($(PLATFORM),rpi4b)
DIGITAL_OUT_OBJS = digital_out.o
endif

LITE_RING_OBJS =
ifeq ($(LITE_LOG),1)
LITE_RING_OBJS = lite_ring.o
endif
LITE_PROBE_OBJS =
ifeq ($(LITE_PROBE),1)
LITE_PROBE_OBJS = lite_probe.o
endif
OBJ_NAMES = boot.o uart.o freestanding.o noun.o bignum.o blake3.o nock.o setjmp.o jam.o bounded_cue.o runtime_stats.o admission_metrics.o lite_host.o $(LITE_RING_OBJS) $(CKPT_OBJS) $(LITE_PROBE_OBJS) $(DIGITAL_OUT_OBJS) cold.o $(MEDIA_OBJS) sha256.o tip5.o main.o
CONFIG_KEY = $(PLATFORM)-$(COLD_MEDIA)
ifeq ($(LITE_PROBE),1)
CONFIG_KEY := $(CONFIG_KEY)-probe
endif
ifeq ($(LITE_UNJETTED),1)
CONFIG_KEY := $(CONFIG_KEY)-unjet
endif
ifneq ($(LITE_CHECKPOINT_EVERY),)
CONFIG_KEY := $(CONFIG_KEY)-ck$(LITE_CHECKPOINT_EVERY)
endif
ifeq ($(LITE_LOG),1)
CONFIG_KEY := $(CONFIG_KEY)-ll
endif
ifneq ($(LITE_RING_BYTES),)
CONFIG_KEY := $(CONFIG_KEY)-rb$(LITE_RING_BYTES)
endif
ifneq ($(LITE_RING_EVERY),)
CONFIG_KEY := $(CONFIG_KEY)-re$(LITE_RING_EVERY)
endif
ifneq ($(LITE_CKPT_TEST),)
CONFIG_KEY := $(CONFIG_KEY)-ckt$(LITE_CKPT_TEST)
endif
ifneq ($(LITE_CKPT_TEST_FROM),)
CONFIG_KEY := $(CONFIG_KEY)-ckf$(LITE_CKPT_TEST_FROM)
endif
ifneq ($(LITE_PERSIST_HEADROOM_CELLS),)
CONFIG_KEY := $(CONFIG_KEY)-ph$(LITE_PERSIST_HEADROOM_CELLS)
endif
ifeq ($(LITE_PLANT_RSH_RAW),1)
CONFIG_KEY := $(CONFIG_KEY)-plantrsh
endif
ifeq ($(LITE_PLANT_LABEL_ONLY),1)
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
$(OBJDIR)/lite_host.o: $(SRCDIR)/lite_admission.h $(SRCDIR)/memory.h
$(OBJDIR)/lite_ring.o: $(SRCDIR)/lite_ring.h $(SRCDIR)/cold.h $(SRCDIR)/cold_media.h $(SRCDIR)/memory.h
$(OBJDIR)/lite_probe.o: $(SRCDIR)/lite_admission.h $(SRCDIR)/memory.h

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
# the qemu-virt diagnostic image (LITE_PROBE=1) on the self-contained tests;
# test-tools runs tools/jam.py's self-tests. The checkpoint boot legs run
# from 1499kernel (tools/lite_checkpoint_boot.py, part of tools/lite_probe.py).
TEST_BUILDS = \
	"PLATFORM=qemu-virt" \
	"PLATFORM=qemu-virt LITE_PROBE=1" \
	"PLATFORM=qemu-virt LITE_PROBE=1 LITE_UNJETTED=1" \
	"PLATFORM=qemu-virt LITE_PROBE=1 COLD_MEDIA=semihost LITE_PERSIST_HEADROOM_CELLS=1000000000" \
	"PLATFORM=qemu-virt LITE_PROBE=1 COLD_MEDIA=semihost LITE_LOG=1" \
	"PLATFORM=qemu-virt LITE_PROBE=1 COLD_MEDIA=semihost LITE_CHECKPOINT_EVERY=" \
	"PLATFORM=qemu-virt LITE_PROBE=1 COLD_MEDIA=semihost LITE_CHECKPOINT_EVERY=4 LITE_CKPT_TEST=persist" \
	"PLATFORM=qemu-virt LITE_PROBE=1 COLD_MEDIA=semihost LITE_CHECKPOINT_EVERY=2 LITE_CKPT_TEST=hdrd LITE_CKPT_TEST_FROM=3" \
	"PLATFORM=qemu-virt LITE_PROBE=1 COLD_MEDIA=semihost LITE_CHECKPOINT_EVERY=4 LITE_CKPT_TEST=dirty" \
	"PLATFORM=qemu-virt LITE_PROBE=1 COLD_MEDIA=semihost LITE_CHECKPOINT_EVERY=4 LITE_CKPT_TEST=appcells" \
	"PLATFORM=qemu-virt LITE_PROBE=1 COLD_MEDIA=semihost LITE_CHECKPOINT_EVERY=2 LITE_LOG=1 LITE_RING_BYTES=32768 LITE_RING_EVERY=2" \
	"PLATFORM=rpi4b" \
	"PLATFORM=rpi4b COLD_MEDIA=rpi4-sd" \
	"PLATFORM=rpi4b COLD_MEDIA=rpi4-sd LITE_LOG=1"

test: test-build test-qemu test-tools

test-build:
	@for cfg in $(TEST_BUILDS); do \
		echo "== make $$cfg"; \
		$(MAKE) -s $$cfg all || exit 1; \
	done

test-qemu:
	$(MAKE) PLATFORM=qemu-virt LITE_PROBE=1 all
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
