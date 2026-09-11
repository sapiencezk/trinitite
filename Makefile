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

ifeq ($(M24_NATIVE),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M24_NATIVE=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
endif
ifeq ($(M25_TARGET),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M25_TARGET=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
endif
ifeq ($(M26_DUPLEX),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M26_DUPLEX=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
endif
ifeq ($(M27_COMMISSION),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M27_COMMISSION=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
endif
ifeq ($(M28_COMMISSION),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M28_COMMISSION=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
ifeq ($(M27_COMMISSION),1)
$(error M28_COMMISSION=1 cannot be combined with frozen M27_COMMISSION=1)
endif
endif
ifeq ($(M29_COMMISSION),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M29_COMMISSION=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
ifeq ($(M27_COMMISSION),1)
$(error M29_COMMISSION=1 cannot be combined with frozen M27_COMMISSION=1)
endif
ifeq ($(M28_COMMISSION),1)
$(error M29_COMMISSION=1 cannot be combined with frozen M28_COMMISSION=1)
endif
endif
ifeq ($(M36_TYPED),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M36_TYPED=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
ifneq ($(M29_COMMISSION),1)
$(error M36_TYPED=1 requires M29_COMMISSION=1)
endif
endif
ifeq ($(M37_A),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M37_A=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
ifneq ($(M29_COMMISSION),1)
$(error M37_A=1 requires M29_COMMISSION=1)
endif
ifeq ($(M36_TYPED),1)
$(error M37_A=1 cannot be combined with frozen M36_TYPED=1)
endif
endif
ifeq ($(M37_A_R),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M37_A_R=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
ifneq ($(M29_COMMISSION),1)
$(error M37_A_R=1 requires M29_COMMISSION=1)
endif
ifeq ($(M36_TYPED),1)
$(error M37_A_R=1 cannot be combined with M36_TYPED=1)
endif
ifeq ($(M37_A),1)
$(error M37_A_R=1 cannot be combined with original M37_A=1)
endif
endif
ifeq ($(M37_IEC_SERVICE),1)
ifneq ($(M37_A_R),1)
$(error M37_IEC_SERVICE=1 requires the frozen M37_A_R transport boundary)
endif
endif

CROSS   ?= aarch64-elf-
CC       = $(CROSS)gcc
LD       = $(CROSS)ld
OBJCOPY  = $(CROSS)objcopy
GDB      = $(CROSS)gdb

VPATH   = $(SRCDIR)

CFLAGS  = -Wall -O2 -ffreestanding -nostdlib -nostartfiles \
          -mcpu=cortex-a72 -mgeneral-regs-only \
          -fno-pic -fno-stack-protector -fno-builtin \
          -I$(SRCDIR) $(PLATFORM_DEFINE)
LDFLAGS = -T $(LINKER_SCRIPT) -nostdlib -no-pie
ifeq ($(PLATFORM),qemu-virt)
LDFLAGS += -e _start
endif

COLD_MEDIA ?= ram
ifeq ($(PLATFORM),qemu-virt)
DIGITAL_OUT_BACKEND ?= fake
DIGITAL_IN_BACKEND ?= fake
else
DIGITAL_OUT_BACKEND ?= bcm2838
DIGITAL_IN_BACKEND ?= bcm2838
endif
M8_EVIDENCE ?= 0
I2_OPERATOR ?= 0
I3_HOST ?= 0
I3_L0_PROBE ?= 0
I3_L1_PROBE ?= 0
I3_UNJETTED ?= 0
M21_SINK_EMBED ?= 0
M23_TEST_CONTROLS ?= 0
M24_NATIVE ?= 0
M24_NODE_ID ?= 22
M25_TARGET ?= 0
M26_DUPLEX ?= 0
M27_COMMISSION ?= 0
M28_COMMISSION ?= 0
M29_COMMISSION ?= 0
M29_TEST_CONTROLS ?= 0
M32_TEST_CONTROLS ?= 0
M36_TYPED ?= 0
M36_TEST_CONTROLS ?= 0
M37_A ?= 0
M37_A_R ?= 0
M37_IEC_SERVICE ?= 0
M38_C ?= 0
M38_D5_NATIVE ?= 0
M38_D5_NATIVE_WITNESS ?= 0
M38_D7_NATIVE ?= 0
M38_D8_NATIVE ?= 0
M38_D8_WAVE_A ?= 0
M39_RESOURCE_WITNESS ?= 0
M44_TWO_RESOURCE ?= 0
M44_G0_TEST_CONTROLS ?= 0
M47_MANAGED_SERVICES ?= 0
M50_PERIODIC ?= 0
ifeq ($(M50_PERIODIC),1)
ifneq ($(M49_MANAGED_DELAY),1)
$(error M50_PERIODIC=1 requires M49_MANAGED_DELAY=1)
endif
CFLAGS += -DM50_PERIODIC=1
endif

M51_CONTROLLER ?= 0
ifeq ($(M51_CONTROLLER),1)
ifneq ($(M50_PERIODIC),1)
$(error M51_CONTROLLER=1 requires M50_PERIODIC=1)
endif
CFLAGS += -DM51_CONTROLLER=1
endif

M52_RESIDENT_REPLACEMENT ?= 0
ifeq ($(M52_RESIDENT_REPLACEMENT),1)
ifneq ($(M51_CONTROLLER),1)
$(error M52_RESIDENT_REPLACEMENT=1 requires M51_CONTROLLER=1)
endif
CFLAGS += -DM52_RESIDENT_REPLACEMENT=1
endif
M53_RESIDENT_COMPOSITION ?= 0
ifeq ($(M53_RESIDENT_COMPOSITION),1)
ifneq ($(M52_RESIDENT_REPLACEMENT),1)
$(error M53_RESIDENT_COMPOSITION=1 requires M52_RESIDENT_REPLACEMENT=1)
endif
CFLAGS += -DM53_RESIDENT_COMPOSITION=1
endif
M54_RESIDENT_REPLACEMENT ?= 0
ifeq ($(M54_RESIDENT_REPLACEMENT),1)
ifneq ($(M53_RESIDENT_COMPOSITION),1)
$(error M54_RESIDENT_REPLACEMENT=1 requires M53_RESIDENT_COMPOSITION=1)
endif
CFLAGS += -DM54_RESIDENT_REPLACEMENT=1
endif
# Cumulative boot/include machinery; M55 applications cannot use M54 replacement.
M55_SIGNED_RESIDENT ?= 0
ifeq ($(M55_SIGNED_RESIDENT),1)
ifneq ($(M54_RESIDENT_REPLACEMENT),1)
$(error M55_SIGNED_RESIDENT=1 requires M54_RESIDENT_REPLACEMENT=1)
endif
CFLAGS += -DM55_SIGNED_RESIDENT=1
endif
M56_SIGNED_REPLACEMENT ?= 0
ifeq ($(M56_SIGNED_REPLACEMENT),1)
ifneq ($(M55_SIGNED_RESIDENT),1)
$(error M56_SIGNED_REPLACEMENT=1 requires M55_SIGNED_RESIDENT=1)
endif
CFLAGS += -DM56_SIGNED_REPLACEMENT=1
endif
M49_MANAGED_DELAY ?= 0
ifeq ($(M49_MANAGED_DELAY),1)
ifneq ($(M48_RESIDENT),1)
$(error M49_MANAGED_DELAY=1 requires M48_RESIDENT=1)
endif
CFLAGS += -DM49_MANAGED_DELAY=1
endif
M48_RESIDENT ?= 0
ifeq ($(M48_RESIDENT),1)
ifneq ($(M47_MANAGED_SERVICES),1)
$(error M48_RESIDENT=1 requires M47_MANAGED_SERVICES=1)
endif
CFLAGS += -DM48_RESIDENT=1
endif
ifeq ($(M47_MANAGED_SERVICES),1)
ifneq ($(M46_LIVE_REPLACEMENT),1)
$(error M47_MANAGED_SERVICES=1 requires M46_LIVE_REPLACEMENT=1)
endif
CFLAGS += -DM47_MANAGED_SERVICES=1
endif
M46_LIVE_REPLACEMENT ?= 0
ifeq ($(M46_LIVE_REPLACEMENT),1)
ifneq ($(M45_MANAGED_LIFECYCLE),1)
$(error M46_LIVE_REPLACEMENT=1 requires M45_MANAGED_LIFECYCLE=1)
endif
CFLAGS += -DM46_LIVE_REPLACEMENT=1
endif
M45_MANAGED_LIFECYCLE ?= 0
ifeq ($(M45_MANAGED_LIFECYCLE),1)
ifneq ($(M44_TWO_RESOURCE),1)
$(error M45_MANAGED_LIFECYCLE=1 requires M44_TWO_RESOURCE=1)
endif
CFLAGS += -DM45_MANAGED_LIFECYCLE=1
endif
ifeq ($(M44_TWO_RESOURCE),1)
ifneq ($(M39_RESOURCE_WITNESS),1)
$(error M44_TWO_RESOURCE=1 requires M39_RESOURCE_WITNESS=1)
endif
# M44 copies fixed typed records while the MMU is disabled. Do not combine
# adjacent 32-bit fields into unaligned wide accesses in device memory.
CFLAGS += -DM44_TWO_RESOURCE=1 -mstrict-align
endif
ifeq ($(M44_G0_TEST_CONTROLS),1)
ifneq ($(M44_TWO_RESOURCE),1)
$(error M44_G0_TEST_CONTROLS=1 requires M44_TWO_RESOURCE=1)
endif
CFLAGS += -DM44_G0_TEST_CONTROLS=1
endif
ifeq ($(M39_RESOURCE_WITNESS),1)
ifneq ($(M38_D8_WAVE_A),1)
$(error M39_RESOURCE_WITNESS=1 requires M38_D8_WAVE_A=1)
endif
CFLAGS += -DM39_RESOURCE_WITNESS=1
endif
M38_D8_WAVE_B_TEST_CONTROLS ?= 0
M38_D8_B0_OBSERVABILITY ?= 0
M38_D8_B1_QUALIFICATION ?= 0
M38_D8_B2_QUALIFICATION ?= 0
M38_D8_B3_OBSERVABILITY ?= 0
M38_D8_B3_SESSIONS ?= 2
M38_D8_B3_CORES ?= 2
M38_D8_WAVE_B_QUALIFICATION ?= 0
M38_D8_WAVE_B_SCENARIO ?=

ifeq ($(M38_D5_NATIVE),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M38_D5_NATIVE=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
ifeq ($(M38_C),1)
$(error M38_D5_NATIVE=1 cannot be combined with M38_C=1)
endif
endif
ifeq ($(M38_D7_NATIVE),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M38_D7_NATIVE=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
ifeq ($(M38_C),1)
$(error M38_D7_NATIVE=1 cannot be combined with M38_C=1)
endif
ifeq ($(M38_D5_NATIVE),1)
$(error M38_D7_NATIVE=1 cannot be combined with M38_D5_NATIVE=1)
endif
endif
ifeq ($(M38_D8_NATIVE),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M38_D8_NATIVE=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
ifeq ($(M38_C),1)
$(error M38_D8_NATIVE=1 cannot be combined with M38_C=1)
endif
ifeq ($(M38_D5_NATIVE),1)
$(error M38_D8_NATIVE=1 cannot be combined with M38_D5_NATIVE=1)
endif
ifeq ($(M38_D7_NATIVE),1)
$(error M38_D8_NATIVE=1 selects the D7 engine itself; do not pass M38_D7_NATIVE=1)
endif
endif
ifeq ($(M38_D8_WAVE_A),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M38_D8_WAVE_A=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
ifeq ($(M38_C),1)
$(error M38_D8_WAVE_A=1 cannot be combined with M38_C=1)
endif
ifeq ($(M38_D5_NATIVE),1)
$(error M38_D8_WAVE_A=1 cannot be combined with M38_D5_NATIVE=1)
endif
ifeq ($(M38_D7_NATIVE),1)
$(error M38_D8_WAVE_A=1 cannot be combined with M38_D7_NATIVE=1)
endif
ifeq ($(M38_D8_NATIVE),1)
$(error M38_D8_WAVE_A=1 cannot be combined with historical M38_D8_NATIVE=1)
endif
endif

ifeq ($(M38_D8_WAVE_B_TEST_CONTROLS),1)
ifneq ($(M38_D8_WAVE_A),1)
$(error M38_D8_WAVE_B_TEST_CONTROLS=1 requires M38_D8_WAVE_A=1)
endif
CFLAGS += -DM38_D8_WAVE_B_TEST_CONTROLS=1
endif

ifneq ($(filter 1,$(M38_D8_B0_OBSERVABILITY) $(M38_D8_B1_QUALIFICATION) $(M38_D8_B2_QUALIFICATION) $(M38_D8_B3_OBSERVABILITY)),)
ifneq ($(M38_D8_WAVE_B_QUALIFICATION),0)
$(error use either a historical Wave B lane flag or M38_D8_WAVE_B_QUALIFICATION, not both)
endif
ifneq ($(words $(filter 1,$(M38_D8_B0_OBSERVABILITY) $(M38_D8_B1_QUALIFICATION) $(M38_D8_B2_QUALIFICATION) $(M38_D8_B3_OBSERVABILITY))),1)
$(error exactly one historical Wave B lane flag may be selected)
endif
ifneq ($(M38_D8_WAVE_B_SCENARIO),)
$(error use either a historical Wave B lane flag or M38_D8_WAVE_B_SCENARIO, not both)
endif
M38_D8_WAVE_B_QUALIFICATION := 1
ifeq ($(M38_D8_B0_OBSERVABILITY),1)
M38_D8_WAVE_B_SCENARIO := b0
endif
ifeq ($(M38_D8_B1_QUALIFICATION),1)
M38_D8_WAVE_B_SCENARIO := b1
endif
ifeq ($(M38_D8_B2_QUALIFICATION),1)
M38_D8_WAVE_B_SCENARIO := b2
endif
ifeq ($(M38_D8_B3_OBSERVABILITY),1)
M38_D8_WAVE_B_SCENARIO := b3
endif
endif

ifeq ($(M38_D8_WAVE_B_QUALIFICATION),1)
ifeq ($(M39_RESOURCE_WITNESS),1)
$(error M39_RESOURCE_WITNESS=1 cannot be combined with Wave B qualification)
endif
ifneq ($(PLATFORM),qemu-virt)
$(error M38_D8_WAVE_B_QUALIFICATION=1 requires PLATFORM=qemu-virt)
endif
ifneq ($(M38_D8_WAVE_A),1)
$(error M38_D8_WAVE_B_QUALIFICATION=1 requires M38_D8_WAVE_A=1)
endif
ifneq ($(M38_D8_WAVE_B_TEST_CONTROLS),1)
$(error M38_D8_WAVE_B_QUALIFICATION=1 requires M38_D8_WAVE_B_TEST_CONTROLS=1)
endif
ifneq ($(filter b0 b1 b2 b3,$(M38_D8_WAVE_B_SCENARIO)),$(M38_D8_WAVE_B_SCENARIO))
$(error M38_D8_WAVE_B_SCENARIO must be one of b0, b1, b2, b3)
endif
ifeq ($(M38_D8_WAVE_B_SCENARIO),)
$(error M38_D8_WAVE_B_SCENARIO is required by the unified Wave B seam)
endif
CFLAGS += -DM38_D8_WAVE_B_QUALIFICATION=1 -DM38_D8_WAVE_B_TEST_CONTROLS=1
ifeq ($(M38_D8_WAVE_B_SCENARIO),b0)
CFLAGS += -DM38_D8_WAVE_B_B0=1
endif
ifeq ($(M38_D8_WAVE_B_SCENARIO),b1)
CFLAGS += -DM38_D8_WAVE_B_B1=1
endif
ifeq ($(M38_D8_WAVE_B_SCENARIO),b2)
CFLAGS += -DM38_D8_WAVE_B_B2=1
endif
ifeq ($(M38_D8_WAVE_B_SCENARIO),b3)
ifneq ($(filter 1 2,$(M38_D8_B3_SESSIONS)),$(M38_D8_B3_SESSIONS))
$(error M38_D8_B3_SESSIONS must be 1 or 2)
endif
ifneq ($(filter 1 2,$(M38_D8_B3_CORES)),$(M38_D8_B3_CORES))
$(error M38_D8_B3_CORES must be 1 or 2)
endif
CFLAGS += -DM38_D8_WAVE_B_B3=1 -DM38_D8_B3_SESSIONS=$(M38_D8_B3_SESSIONS) -DM38_D8_B3_CORES=$(M38_D8_B3_CORES)
endif
endif

ifeq ($(M36_TEST_CONTROLS),1)
ifneq ($(M36_TYPED),1)
$(error M36_TEST_CONTROLS=1 requires M36_TYPED=1)
endif
endif

ifeq ($(M37_A),1)
CFLAGS += -DM37_A=1
endif
ifeq ($(M37_A_R),1)
CFLAGS += -DM37_A_R=1 -DM29_COMMISSION=1 -DM26_DUPLEX=1 -DM25_TARGET=1 -DM24_NODE_ID=$(M24_NODE_ID)
endif
ifeq ($(M37_IEC_SERVICE),1)
CFLAGS += -DM37_IEC_SERVICE=1
endif
ifeq ($(M38_C),1)
ifneq ($(PLATFORM),qemu-virt)
$(error M38_C=1 requires PLATFORM=qemu-virt; refusing native MMIO on $(PLATFORM))
endif
CFLAGS += -DM38_C=1
endif
ifeq ($(M38_D5_NATIVE),1)
CFLAGS += -DM38_D5_NATIVE=1
endif
ifeq ($(M38_D7_NATIVE),1)
CFLAGS += -DM38_D7_NATIVE=1
endif
ifeq ($(M38_D8_NATIVE),1)
CFLAGS += -DM38_D8_NATIVE=1 -DM38_D7_NATIVE=1
endif
ifeq ($(M38_D8_WAVE_A),1)
CFLAGS += -DM38_D8_WAVE_A=1
endif
ifeq ($(M38_D5_NATIVE_WITNESS),1)
ifneq ($(M38_D5_NATIVE),1)
$(error M38_D5_NATIVE_WITNESS=1 requires M38_D5_NATIVE=1)
endif
CFLAGS += -DM38_D5_NATIVE_WITNESS=1
endif

ifeq ($(M29_TEST_CONTROLS),1)
ifneq ($(M29_COMMISSION),1)
$(error M29_TEST_CONTROLS=1 requires M29_COMMISSION=1)
endif
CFLAGS += -DM29_TEST_CONTROLS=1
endif

ifeq ($(M32_TEST_CONTROLS),1)
ifneq ($(M29_COMMISSION),1)
$(error M32_TEST_CONTROLS=1 requires M29_COMMISSION=1)
endif
ifneq ($(M23_TEST_CONTROLS),1)
$(error M32_TEST_CONTROLS=1 requires M23_TEST_CONTROLS=1)
endif
CFLAGS += -DM32_TEST_CONTROLS=1
endif

ifeq ($(M8_EVIDENCE),1)
CFLAGS += -DM8_EVIDENCE=1
endif

ifeq ($(I2_OPERATOR),1)
CFLAGS += -DI2_OPERATOR=1
endif
ifeq ($(I3_L0_PROBE),1)
$(error I3_L0_PROBE was removed in T1; use I3_HOST=1 (I3_L1_PROBE=1 is the diagnostic))
endif
ifeq ($(I3_HOST),1)
ifneq ($(PLATFORM),qemu-virt)
$(error I3_HOST=1 requires PLATFORM=qemu-virt; the board is T2)
endif
ifneq ($(filter 1,$(M38_C) $(M38_D5_NATIVE) $(M38_D7_NATIVE) $(M38_D8_NATIVE) $(M38_D8_WAVE_A) $(M39_RESOURCE_WITNESS) $(I2_OPERATOR)),)
$(error I3_HOST=1 cannot be combined with M38_C M38_D5_NATIVE M38_D7_NATIVE M38_D8_NATIVE M38_D8_WAVE_A M39_RESOURCE_WITNESS I2_OPERATOR)
endif
# qemu-virt boots with the MMU off. Same as M44: do not combine adjacent
# 32-bit fields into unaligned wide accesses.
CFLAGS += -DI3_HOST=1 -mstrict-align
endif
ifeq ($(I3_L1_PROBE),1)
ifneq ($(I3_HOST),1)
$(error I3_L1_PROBE=1 requires I3_HOST=1)
endif
CFLAGS += -DI3_L1_PROBE=1
endif
ifeq ($(I3_UNJETTED),1)
ifneq ($(I3_L1_PROBE),1)
$(error I3_UNJETTED=1 requires I3_L1_PROBE=1)
endif
CFLAGS += -DI3_UNJETTED=1
endif

ifeq ($(M21_SINK_EMBED),1)
CFLAGS += -DM21_SINK_EMBED=1
endif

ifeq ($(M23_TEST_CONTROLS),1)
CFLAGS += -DM23_TEST_CONTROLS=1
endif

ifeq ($(M24_NATIVE),1)
CFLAGS += -DM24_NATIVE=1 -DM24_NODE_ID=$(M24_NODE_ID)
endif

ifeq ($(M25_TARGET),1)
CFLAGS += -DM25_TARGET=1 -DM24_NODE_ID=$(M24_NODE_ID)
endif

ifeq ($(M26_DUPLEX),1)
CFLAGS += -DM26_DUPLEX=1 -DM25_TARGET=1 -DM24_NODE_ID=$(M24_NODE_ID)
endif
ifeq ($(M27_COMMISSION),1)
CFLAGS += -DM27_COMMISSION=1 -DM26_DUPLEX=1 -DM25_TARGET=1 -DM24_NODE_ID=$(M24_NODE_ID)
endif
ifeq ($(M28_COMMISSION),1)
CFLAGS += -DM28_COMMISSION=1 -DM26_DUPLEX=1 -DM25_TARGET=1 -DM24_NODE_ID=$(M24_NODE_ID)
endif
ifeq ($(M29_COMMISSION),1)
CFLAGS += -DM29_COMMISSION=1 -DM26_DUPLEX=1 -DM25_TARGET=1 -DM24_NODE_ID=$(M24_NODE_ID)
endif
ifeq ($(M36_TYPED),1)
CFLAGS += -DM36_TYPED=1 -DM29_COMMISSION=1 -DM26_DUPLEX=1 -DM25_TARGET=1 -DM24_NODE_ID=$(M24_NODE_ID)
endif
ifeq ($(M37_A),1)
CFLAGS += -DM37_A=1 -DM29_COMMISSION=1 -DM26_DUPLEX=1 -DM25_TARGET=1 -DM24_NODE_ID=$(M24_NODE_ID)
endif
ifeq ($(M36_TEST_CONTROLS),1)
CFLAGS += -DM36_TEST_CONTROLS=1
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

NATIVE_OBJS = sha256.o
ifeq ($(M24_NATIVE),1)
NATIVE_OBJS += virtio_net.o aethernet_native.o
endif
ifneq ($(filter 1,$(M26_DUPLEX) $(M27_COMMISSION) $(M28_COMMISSION) $(M29_COMMISSION)),)
NATIVE_OBJS += virtio_net.o m25_aethernet_native.o
else ifeq ($(M25_TARGET),1)
NATIVE_OBJS += virtio_net.o m25_aethernet_native.o
endif
ifeq ($(M27_COMMISSION),1)
NATIVE_OBJS += virtio_net.o m27_aethernet_native.o
endif
ifeq ($(M28_COMMISSION),1)
NATIVE_OBJS += virtio_net.o m28_aethernet_native.o
endif
ifeq ($(M29_COMMISSION),1)
NATIVE_OBJS += virtio_net.o m29_aethernet_native.o
endif
ifneq ($(filter 1,$(M26_DUPLEX) $(M27_COMMISSION) $(M28_COMMISSION) $(M29_COMMISSION)),)
M26_OBJS = m26_admission.o m26_plan_record.o m26_target_core.o
else
M26_OBJS =
endif
M27_OBJS =
ifeq ($(M27_COMMISSION),1)
M27_OBJS = m27_admission.o m27_target_core.o
endif
M28_OBJS =
ifeq ($(M28_COMMISSION),1)
M28_OBJS = m28_admission.o m28_target_core.o
endif
M29_OBJS =
ifeq ($(M29_COMMISSION),1)
M29_OBJS = m29_admission.o m34_local_allocation.o m29_target_core.o
endif
M36_OBJS =
ifeq ($(M36_TYPED),1)
M36_OBJS = m36_target_core.o
endif
M36_NATIVE_OBJS =
ifeq ($(M36_TYPED),1)
M36_NATIVE_OBJS = m36_aethernet_native.o
endif
M37_OBJS =
ifeq ($(M37_A),1)
M37_OBJS = m37_a_target_core.o candidate_execution_core.o
endif
M37_NATIVE_OBJS =
ifeq ($(M37_A),1)
M37_NATIVE_OBJS = m37_a_adapter.o
endif
M37_R_OBJS =
ifeq ($(M37_A_R),1)
M37_R_OBJS = m37_a_r_target_core.o candidate_execution_core_r.o
endif
M37_R_NATIVE_OBJS =
ifeq ($(M37_A_R),1)
M37_R_NATIVE_OBJS = m37_a_r_adapter.o m36_aethernet_native.o
endif
M37_SERVICE_OBJS =
ifeq ($(M37_IEC_SERVICE),1)
M37_SERVICE_OBJS = m37_service_facade.o m37_service_target_core.o
endif
M38_C_OBJS =
ifeq ($(M38_C),1)
M38_C_OBJS = m38_c_target.o
endif
M38_D5_NATIVE_OBJS =
ifeq ($(M38_D5_NATIVE),1)
M38_D5_NATIVE_OBJS = m38_resource_abi_target.o
endif
M38_D7_NATIVE_OBJS =
ifeq ($(M38_D7_NATIVE),1)
M38_D7_NATIVE_OBJS = m38_resource_abi_target.o
endif
M38_D8_NATIVE_OBJS =
ifeq ($(M38_D8_NATIVE),1)
M38_D8_NATIVE_OBJS = m38_resource_abi_target.o
endif
M38_D8_WAVE_A_OBJS =
ifeq ($(M39_RESOURCE_WITNESS),1)
ifneq ($(M38_D8_WAVE_B_SCENARIO),)
$(error M39_RESOURCE_WITNESS=1 cannot be combined with a Wave B scenario)
endif
ifeq ($(M38_D8_WAVE_B_TEST_CONTROLS),1)
$(error M39_RESOURCE_WITNESS=1 cannot be combined with Wave B test controls)
endif
endif
ifeq ($(M38_D8_WAVE_A),1)
ifneq ($(filter b1 b2 b3,$(M38_D8_WAVE_B_SCENARIO)),)
M38_D8_WAVE_A_OBJS = m38_resource_core_descriptor.o m38_resource_runtime.o
else
M38_D8_WAVE_A_OBJS = m38_resource_core_descriptor.o m38_resource_runtime.o m38_resource_wave_a_witness.o
endif
endif
M38_D8_B1_OBJS =
ifeq ($(M39_RESOURCE_WITNESS),1)
M38_D8_WAVE_A_OBJS = m38_resource_runtime.o m39_resource_witness.o virtio_net.o m25_aethernet_native.o m36_aethernet_native.o m37_a_r_adapter.o
ifeq ($(M44_TWO_RESOURCE),1)
M38_D8_WAVE_A_OBJS += m44_two_resource_supervisor.o m44_device_witness.o
ifeq ($(M48_RESIDENT),1)
M38_D8_WAVE_A_OBJS += m48_resident_driver.o m48_report.o
ifeq ($(M49_MANAGED_DELAY),1)
M38_D8_WAVE_A_OBJS += m49_clock_adapter.o
endif
endif
endif
ifeq ($(M44_G0_TEST_CONTROLS),1)
M38_D8_WAVE_A_OBJS += m44_g0_witness.o
endif
endif
ifeq ($(M38_D8_WAVE_B_SCENARIO),b1)
M38_D8_B1_OBJS = m38_resource_wave_b1_witness.o
endif
M38_D8_B2_OBJS =
ifeq ($(M38_D8_WAVE_B_SCENARIO),b2)
M38_D8_B2_OBJS = m38_resource_b2_witness.o
endif
M38_D8_B3_OBJS =
ifeq ($(M38_D8_WAVE_B_SCENARIO),b3)
M38_D8_B3_OBJS = m38_resource_b3_witness.o
endif
I3_HOST_OBJS =
ifeq ($(I3_HOST),1)
I3_HOST_OBJS = i3_host.o
endif
I3_L1_OBJS =
ifeq ($(I3_L1_PROBE),1)
I3_L1_OBJS = i3_l1_probe.o
endif
OBJ_NAMES = boot.o uart.o freestanding.o noun.o bignum.o blake3.o nock.o setjmp.o jam.o bounded_cue.o runtime_identity.o runtime_stats.o i2_admission_metrics.o i2_ingress.o i2_operator.o i2_admission_policy.o i2_application_surface.o m25_admission.o m25_plan_record.o m25_target_core.o $(M26_OBJS) $(M27_OBJS) $(M28_OBJS) $(M29_OBJS) $(M36_OBJS) $(M37_OBJS) $(M37_R_OBJS) $(M37_SERVICE_OBJS) $(M38_C_OBJS) $(M38_D5_NATIVE_OBJS) $(M38_D7_NATIVE_OBJS) $(M38_D8_NATIVE_OBJS) $(M38_D8_WAVE_A_OBJS) $(M38_D8_B1_OBJS) $(M38_D8_B2_OBJS) $(M38_D8_B3_OBJS) $(I3_HOST_OBJS) $(I3_L1_OBJS) i2_closed_process.o $(DIGITAL_OUT_OBJS) $(DIGITAL_IN_OBJS) kernel.o m7_supervisor.o m21_device.o m22_provider_core.o m23_session_core.o core.o cold.o $(MEDIA_OBJS) trace.o net.o $(NATIVE_OBJS) $(M36_NATIVE_OBJS) $(M37_NATIVE_OBJS) $(M37_R_NATIVE_OBJS) ska.o forth.o pill_embed.o m21_sink_embed.o main.o
OBJ_NAMES = boot.o uart.o freestanding.o noun.o bignum.o blake3.o nock.o setjmp.o jam.o bounded_cue.o runtime_identity.o runtime_stats.o i2_admission_metrics.o i2_ingress.o i2_operator.o i2_admission_policy.o i2_application_surface.o m25_admission.o m25_plan_record.o m25_target_core.o $(M26_OBJS) $(M27_OBJS) $(M28_OBJS) $(M29_OBJS) $(M36_OBJS) $(M37_OBJS) $(M37_R_OBJS) $(M37_SERVICE_OBJS) $(M38_C_OBJS) $(M38_D5_NATIVE_OBJS) $(M38_D7_NATIVE_OBJS) $(M38_D8_NATIVE_OBJS) $(M38_D8_WAVE_A_OBJS) $(M38_D8_B1_OBJS) $(M38_D8_B2_OBJS) $(M38_D8_B3_OBJS) $(I3_HOST_OBJS) $(I3_L1_OBJS) i2_closed_process.o $(DIGITAL_OUT_OBJS) $(DIGITAL_IN_OBJS) kernel.o m7_supervisor.o m21_device.o m22_provider_core.o m23_session_core.o core.o cold.o $(MEDIA_OBJS) trace.o net.o $(NATIVE_OBJS) $(M36_NATIVE_OBJS) $(M37_NATIVE_OBJS) $(M37_R_NATIVE_OBJS) ska.o forth.o pill_embed.o m21_sink_embed.o main.o
ifneq ($(filter 1,$(M26_DUPLEX) $(M27_COMMISSION) $(M28_COMMISSION) $(M29_COMMISSION)),)
OBJ_NAMES := $(filter-out m25_plan_record.o m25_target_core.o,$(OBJ_NAMES))
endif
CONFIG_KEY = $(PLATFORM)-$(COLD_MEDIA)-$(DIGITAL_IN_BACKEND)-$(DIGITAL_OUT_BACKEND)-$(M8_EVIDENCE)-$(I2_OPERATOR)-$(M21_SINK_EMBED)-$(M23_TEST_CONTROLS)-$(M24_NATIVE)-$(M25_TARGET)-$(M26_DUPLEX)-$(M27_COMMISSION)-$(M28_COMMISSION)-$(M29_COMMISSION)-$(M36_TYPED)-$(M37_A)-$(M37_A_R)-$(M38_C)-$(M38_D5_NATIVE)-$(M38_D7_NATIVE)-$(M38_D8_NATIVE)-$(M38_D8_WAVE_A)-$(M24_NODE_ID)
ifeq ($(M39_RESOURCE_WITNESS),1)
CONFIG_KEY := $(CONFIG_KEY)-m39
endif
ifeq ($(I3_HOST),1)
CONFIG_KEY := $(CONFIG_KEY)-i3host
endif
ifeq ($(I3_L1_PROBE),1)
CONFIG_KEY := $(CONFIG_KEY)-i3l1
endif
ifeq ($(I3_UNJETTED),1)
CONFIG_KEY := $(CONFIG_KEY)-i3unjet
endif
ifeq ($(M44_TWO_RESOURCE),1)
CONFIG_KEY := $(CONFIG_KEY)-m44-strict
endif
ifeq ($(M45_MANAGED_LIFECYCLE),1)
CONFIG_KEY := $(CONFIG_KEY)-m45
endif
ifeq ($(M46_LIVE_REPLACEMENT),1)
CONFIG_KEY := $(CONFIG_KEY)-m46
endif
ifeq ($(M47_MANAGED_SERVICES),1)
CONFIG_KEY := $(CONFIG_KEY)-m47
endif
ifeq ($(M48_RESIDENT),1)
CONFIG_KEY := $(CONFIG_KEY)-m48
endif
ifeq ($(M49_MANAGED_DELAY),1)
CONFIG_KEY := $(CONFIG_KEY)-m49
endif
ifeq ($(M50_PERIODIC),1)
CONFIG_KEY := $(CONFIG_KEY)-m50
endif
ifeq ($(M51_CONTROLLER),1)
CONFIG_KEY := $(CONFIG_KEY)-m51
endif
ifeq ($(M52_RESIDENT_REPLACEMENT),1)
CONFIG_KEY := $(CONFIG_KEY)-m52
endif
ifeq ($(M53_RESIDENT_COMPOSITION),1)
CONFIG_KEY := $(CONFIG_KEY)-m53
endif
ifeq ($(M54_RESIDENT_REPLACEMENT),1)
CONFIG_KEY := $(CONFIG_KEY)-m54
endif
ifeq ($(M55_SIGNED_RESIDENT),1)
CONFIG_KEY := $(CONFIG_KEY)-m55
endif
ifeq ($(M56_SIGNED_REPLACEMENT),1)
CONFIG_KEY := $(CONFIG_KEY)-m56
endif
ifeq ($(M44_G0_TEST_CONTROLS),1)
CONFIG_KEY := $(CONFIG_KEY)-g0test
endif
ifeq ($(M38_D8_WAVE_B_TEST_CONTROLS),1)
CONFIG_KEY := $(CONFIG_KEY)-m38wavebtest
endif
ifeq ($(M38_D8_WAVE_B_QUALIFICATION),1)
CONFIG_KEY := $(CONFIG_KEY)-waveb-$(M38_D8_WAVE_B_SCENARIO)
ifeq ($(M38_D8_WAVE_B_SCENARIO),b3)
CONFIG_KEY := $(CONFIG_KEY)-$(M38_D8_B3_SESSIONS)s-$(M38_D8_B3_CORES)c
endif
endif
ifeq ($(M38_D5_NATIVE_WITNESS),1)
CONFIG_KEY := $(CONFIG_KEY)-d5witness
endif
ifeq ($(M29_TEST_CONTROLS),1)
CONFIG_KEY := $(CONFIG_KEY)-m29test
endif
ifeq ($(M36_TEST_CONTROLS),1)
CONFIG_KEY := $(CONFIG_KEY)-m36test
endif
ifeq ($(M37_A),1)
CONFIG_KEY := $(CONFIG_KEY)-m37a
endif
ifeq ($(M37_A_R),1)
CONFIG_KEY := $(CONFIG_KEY)-m37ar
endif
ifeq ($(M37_IEC_SERVICE),1)
CONFIG_KEY := $(CONFIG_KEY)-m37svc
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

$(OBJDIR)/%.o: $(SRCDIR)/%.S | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# The second PILL is present only in the explicit ABI-1.8 two-slot image.
# It is a real input to that object so regenerated M21 artifacts cannot leave
# a stale embedded formula behind.
ifeq ($(M21_SINK_EMBED),1)
$(OBJDIR)/m21_sink_embed.o: $(SRCDIR)/m21_sink_embed.S m21_sink.pill | $(OBJDIR)
	$(CC) $(CFLAGS) -c $(SRCDIR)/m21_sink_embed.S -o $@
endif

# M3 fake-media test words are compiled only into the explicit fake build.
$(OBJDIR)/forth.o: $(SRCDIR)/forth.s | $(OBJDIR)
	$(CC) $(CFLAGS) -x assembler-with-cpp -c $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

ifeq ($(M44_TWO_RESOURCE),1)
$(OBJDIR)/m44_two_resource_supervisor.o $(OBJDIR)/m44_device_witness.o: \
	$(SRCDIR)/m44_two_resource_supervisor.h $(SRCDIR)/m44_resource_transaction.h $(SRCDIR)/m47_device_witness.inc
$(OBJDIR)/m38_resource_runtime.o $(OBJDIR)/m44_g0_witness.o: $(SRCDIR)/m44_resource_transaction.h
$(OBJDIR)/m39_resource_witness.o $(OBJDIR)/m44_device_witness.o $(OBJDIR)/m44_g0_witness.o: $(SRCDIR)/m39_resource_witness.h $(SRCDIR)/m47_transport_witness.inc
endif
ifeq ($(M48_RESIDENT),1)
$(OBJDIR)/m44_device_witness.o: $(SRCDIR)/m48_device_resident.inc $(SRCDIR)/m48_resident_driver.h $(SRCDIR)/m48_report.h
$(OBJDIR)/m48_resident_driver.o: $(SRCDIR)/m48_resident_driver.h $(SRCDIR)/m44_two_resource_supervisor.h
$(OBJDIR)/m48_report.o: $(SRCDIR)/m48_report.h $(SRCDIR)/uart.h
$(OBJDIR)/m39_resource_witness.o: $(SRCDIR)/m48_transport_adapter.inc $(SRCDIR)/m48_resident_driver.h
endif

# Generated admission data is a semantic target input.  The explicit edge
# prevents an M21 artifact regeneration from linking an old policy object.
$(OBJDIR)/i2_admission_policy.o: $(SRCDIR)/i2_admission_policy.c \
	$(SRCDIR)/i2_admission_envelope.h $(SRCDIR)/i2_admission_catalog.inc | $(OBJDIR)
	$(CC) $(CFLAGS) -c $(SRCDIR)/i2_admission_policy.c -o $@

# Configuration-specific directories prevent preprocessor/backend object reuse.
$(CONFIG_ELF): $(OBJS) | $(BUILD_DIR)
	$(LD) $(LDFLAGS) $(if $(filter 1,$(M38_D8_B0_OBSERVABILITY) $(M38_D8_B3_OBSERVABILITY) $(M38_D8_WAVE_B_QUALIFICATION)),-Map=$@.map,) -o $@ $^

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
	  -machine $(if $(filter qemu-virt,$(PLATFORM)),virt,raspi4b) \
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
	  -machine $(if $(filter qemu-virt,$(PLATFORM)),virt,raspi4b) \
	  -m 2G \
	  -kernel $(TARGET).img \
	  -device loader,file=$(PILL),addr=$(if $(filter qemu-virt,$(PLATFORM)),0x50000000,0x10000000),force-raw=on \
	  -display none \
	  -nographic

run-kernel: run-pill

debug: all
	qemu-system-aarch64 \
	  -machine $(if $(filter qemu-virt,$(PLATFORM)),virt,raspi4b) \
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
	test -s .build/rpi4b-ram-bcm2838-bcm2838-0-0-0-0-0-22/kernel8.img
	test -s .build/rpi4b-fake-fake-bcm2838-1-0-0-0-0-22/kernel8.img
	test -s .build/rpi4b-rpi4-sd-bcm2838-bcm2838-0-0-0-0-0-22/kernel8.img
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

ifeq ($(M49_MANAGED_DELAY),1)
$(OBJDIR)/m44_device_witness.o: $(SRCDIR)/m49_device_resident.inc

ifeq ($(M51_CONTROLLER),1)
$(OBJDIR)/m44_device_witness.o: $(SRCDIR)/m51_device_resident.inc
$(OBJDIR)/m44_two_resource_supervisor.o: $(SRCDIR)/m51_controller_authority.inc
endif
ifeq ($(M52_RESIDENT_REPLACEMENT),1)
$(OBJDIR)/m44_device_witness.o: $(SRCDIR)/m52_device_resident.inc
$(OBJDIR)/m44_two_resource_supervisor.o: $(SRCDIR)/m52_supervisor_replacement.inc
$(OBJDIR)/m38_resource_runtime.o: $(SRCDIR)/m52_resource_compatibility.inc
endif
ifeq ($(M54_RESIDENT_REPLACEMENT),1)
$(OBJDIR)/m44_device_witness.o: $(SRCDIR)/m54_device_package.inc $(SRCDIR)/m54_replacement_policy.h
$(OBJDIR)/m44_two_resource_supervisor.o: $(SRCDIR)/m54_supervisor_replacement.inc $(SRCDIR)/m54_replacement_policy.h
$(OBJDIR)/m38_resource_runtime.o: $(SRCDIR)/m54_resource_compatibility.inc $(SRCDIR)/m54_replacement_policy.h
endif
$(OBJDIR)/m44_two_resource_supervisor.o $(OBJDIR)/m49_clock_adapter.o: $(SRCDIR)/m49_clock_adapter.h
endif

ifeq ($(M56_SIGNED_REPLACEMENT),1)
$(OBJDIR)/m44_device_witness.o: $(SRCDIR)/m56_device_package.inc
$(OBJDIR)/m44_two_resource_supervisor.o: $(SRCDIR)/m56_supervisor_replacement.inc
endif
