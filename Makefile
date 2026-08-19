TARGET  = kernel8
SRCDIR  = src

CROSS   ?= aarch64-elf-
CC       = $(CROSS)gcc
LD       = $(CROSS)ld
OBJCOPY  = $(CROSS)objcopy
GDB      = $(CROSS)gdb

VPATH   = $(SRCDIR)

CFLAGS  = -Wall -O2 -ffreestanding -nostdlib -nostartfiles \
          -mcpu=cortex-a72 -mgeneral-regs-only \
          -fno-pic -fno-stack-protector -fno-builtin \
          -I$(SRCDIR)
LDFLAGS = -T $(SRCDIR)/linker.ld -nostdlib -no-pie

COLD_MEDIA ?= ram
DIGITAL_OUT_BACKEND ?= bcm2838
DIGITAL_IN_BACKEND ?= bcm2838
M8_EVIDENCE ?= 0
I2_OPERATOR ?= 0

ifeq ($(M8_EVIDENCE),1)
CFLAGS += -DM8_EVIDENCE=1
endif

ifeq ($(I2_OPERATOR),1)
CFLAGS += -DI2_OPERATOR=1
endif

ifeq ($(COLD_MEDIA),ram)
MEDIA_OBJS = cold_media.o cold_nv_none.o
else ifeq ($(COLD_MEDIA),semihost)
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

ifeq ($(DIGITAL_IN_BACKEND),bcm2838)
DIGITAL_IN_OBJS = digital_in.o digital_in_bcm2838.o
else ifeq ($(DIGITAL_IN_BACKEND),fake)
CFLAGS += -DDIGITAL_IN_FAKE=1
DIGITAL_IN_OBJS = digital_in.o digital_in_fake.o
else
$(error unsupported DIGITAL_IN_BACKEND='$(DIGITAL_IN_BACKEND)' (bcm2838, fake))
endif

ifeq ($(DIGITAL_OUT_BACKEND),bcm2838)
DIGITAL_OUT_OBJS = digital_out.o digital_out_bcm2838.o
else ifeq ($(DIGITAL_OUT_BACKEND),fake)
CFLAGS += -DDIGITAL_OUT_FAKE=1
DIGITAL_OUT_OBJS = digital_out.o digital_out_fake.o
else
$(error unsupported DIGITAL_OUT_BACKEND='$(DIGITAL_OUT_BACKEND)' (bcm2838, fake))
endif

OBJ_NAMES = boot.o freestanding.o uart.o noun.o bignum.o blake3.o nock.o setjmp.o jam.o bounded_cue.o runtime_identity.o runtime_stats.o i2_admission_metrics.o i2_ingress.o i2_operator.o i2_admission_policy.o i2_closed_process.o $(DIGITAL_OUT_OBJS) $(DIGITAL_IN_OBJS) kernel.o m7_supervisor.o core.o cold.o $(MEDIA_OBJS) trace.o net.o ska.o forth.o pill_embed.o main.o
CONFIG_KEY = $(COLD_MEDIA)-$(DIGITAL_IN_BACKEND)-$(DIGITAL_OUT_BACKEND)-$(M8_EVIDENCE)-$(I2_OPERATOR)
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
	$(CC) $(CFLAGS) -c $< -o $@

# M3 fake-media test words are compiled only into the explicit fake build.
$(OBJDIR)/forth.o: $(SRCDIR)/forth.s | $(OBJDIR)
	$(CC) $(CFLAGS) -x assembler-with-cpp -c $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Configuration-specific directories prevent preprocessor/backend object reuse.
$(CONFIG_ELF): $(OBJS) | $(BUILD_DIR)
	$(LD) $(LDFLAGS) -o $@ $^

# Create an empty stub pill if none exists (so the build doesn't fail).
# Replace with a real pill using: python3 tools/mkpill.py <jam> <arvo|shrine> pill.bin
pill.bin:
	@echo "No pill.bin found; creating empty stub (KERNEL will return no-pill)"
	python3 -c "import struct; open('pill.bin','wb').write(struct.pack('<Q',0)+bytes(8))"

$(OBJDIR)/pill_embed.o: src/pill_embed.s pill.bin | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

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

run: all
	qemu-system-aarch64 \
	  -machine raspi4b \
	  -m 2G \
	  -kernel $(TARGET).img \
	  -display none \
	  -nographic

# Load a pill into QEMU memory and run the kernel loop.
# Build pill with: python3 tools/mkpill.py <jam-file> <arvo|shrine> pill.bin
# The shape byte in the pill selects Arvo or Shrine mode automatically.
# With no pill: falls back to interactive REPL.
PILL ?= pill.bin
run-pill: all
	qemu-system-aarch64 \
	  -machine raspi4b \
	  -m 2G \
	  -kernel $(TARGET).img \
	  -device loader,file=$(PILL),addr=0x10000000,force-raw=on \
	  -display none \
	  -nographic

run-kernel: run-pill

debug: all
	qemu-system-aarch64 \
	  -machine raspi4b \
	  -m 2G \
	  -kernel $(TARGET).img \
	  -display none \
	  -nographic \
	  -s -S &
	sleep 1
	$(GDB) $(TARGET).elf \
	  -ex "target remote :1234" \
	  -ex "break main" \
	  -ex "continue"

TFTP_ROOT ?= /private/tftpboot
deploy: all
	cp $(TARGET).img $(TFTP_ROOT)/
	@echo "Deployed. Reset the Pi."

test:
	$(MAKE) clean
	$(MAKE) M8_EVIDENCE=1 all
	./tests/run_tests.sh
	$(MAKE) test-build-config

test-build-config:
	$(MAKE) clean
	$(MAKE) -j8 COLD_MEDIA=ram DIGITAL_IN_BACKEND=bcm2838 \
		DIGITAL_OUT_BACKEND=bcm2838 M8_EVIDENCE=0 all
	$(MAKE) -j8 COLD_MEDIA=fake DIGITAL_IN_BACKEND=fake \
		DIGITAL_OUT_BACKEND=bcm2838 M8_EVIDENCE=1 all
	$(MAKE) -j8 COLD_MEDIA=rpi4-sd DIGITAL_IN_BACKEND=bcm2838 \
		DIGITAL_OUT_BACKEND=bcm2838 M8_EVIDENCE=0 all
	test -s .build/ram-bcm2838-bcm2838-0-0/kernel8.img
	test -s .build/fake-fake-bcm2838-1-0/kernel8.img
	test -s .build/rpi4-sd-bcm2838-bcm2838-0-0/kernel8.img
	test -s kernel8.elf
	test -s kernel8.img

test-media-fake:
	$(MAKE) clean
	$(MAKE) COLD_MEDIA=fake M8_EVIDENCE=1 all
	./tests/run_tests.sh
	./tests/media-fake-matrix.sh
	# Do not leave COLD_MEDIA=fake objects for a following RAM/semihost build.
	$(MAKE) clean

test-media-rpi4-build:
	$(MAKE) clean
	$(MAKE) COLD_MEDIA=rpi4-sd all

test-digital-out-fake:
	$(MAKE) clean
	$(MAKE) DIGITAL_OUT_BACKEND=fake all
	python3 tests/digital_out_fake_qemu.py

test-digital-in-fake:
	$(MAKE) clean
	$(MAKE) DIGITAL_IN_BACKEND=fake DIGITAL_OUT_BACKEND=bcm2838 all
	python3 tests/digital_in_fake_qemu.py

test-digital-in-production-source:
	python3 tests/digital_in_bcm_source.py

clean:
	python3 tools/with_build_lock.py $(MAKE) locked-clean
locked-clean:
	rm -f *.o *.elf *.img $(TARGET).elf.tmp.* $(TARGET).img.tmp.*
	rm -rf .build
FORCE:
.PHONY: all $(TARGET).elf $(TARGET).img locked-all locked-elf publish-elf publish-img \
	run run-pill run-kernel debug deploy test test-media-fake \
	test-media-rpi4-build test-digital-out-fake test-digital-in-fake \
	test-digital-in-production-source test-build-config clean locked-clean FORCE
