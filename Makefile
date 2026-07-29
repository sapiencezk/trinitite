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

OBJS    = boot.o freestanding.o uart.o noun.o bignum.o blake3.o nock.o setjmp.o jam.o bounded_cue.o runtime_identity.o runtime_stats.o i2_ingress.o kernel.o core.o cold.o $(MEDIA_OBJS) trace.o net.o ska.o forth.o pill_embed.o main.o

all: $(TARGET).img

%.o: %.s
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# The backend macro changes cold_media.c without changing its source mtime.
cold_media.o: FORCE

$(TARGET).elf: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^

# Create an empty stub pill if none exists (so the build doesn't fail).
# Replace with a real pill using: python3 tools/mkpill.py <jam> <arvo|shrine> pill.bin
pill.bin:
	@echo "No pill.bin found; creating empty stub (KERNEL will return no-pill)"
	python3 -c "import struct; open('pill.bin','wb').write(struct.pack('<Q',0)+bytes(8))"

pill_embed.o: src/pill_embed.s pill.bin
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET).img: $(TARGET).elf
	$(OBJCOPY) -O binary $< $@

run: $(TARGET).img
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
run-pill: $(TARGET).img
	qemu-system-aarch64 \
	  -machine raspi4b \
	  -m 2G \
	  -kernel $(TARGET).img \
	  -device loader,file=$(PILL),addr=0x10000000,force-raw=on \
	  -display none \
	  -nographic

run-kernel: run-pill

debug: $(TARGET).img
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
deploy: $(TARGET).img
	cp $(TARGET).img $(TFTP_ROOT)/
	@echo "Deployed. Reset the Pi."

test: all
	./tests/run_tests.sh

test-media-fake:
	$(MAKE) clean
	$(MAKE) COLD_MEDIA=fake all
	./tests/run_tests.sh
	./tests/media-fake-matrix.sh

test-media-rpi4-build:
	$(MAKE) clean
	$(MAKE) COLD_MEDIA=rpi4-sd all

clean:
	rm -f *.o *.elf *.img
FORCE:
.PHONY: all run run-pill run-kernel debug deploy test test-media-fake \
	test-media-rpi4-build clean FORCE
