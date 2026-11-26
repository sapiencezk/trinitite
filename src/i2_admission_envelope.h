/* Admission bounds of the earlier native line's envelope (profile
 * M21StaticTwoResourceDevice/dev), still used by the bounded cue, the jam and
 * copy tables and the admission metrics. Its generator is retired. */
#pragma once
#include <stdint.h>

#define I2_CUE_CACHE_ADMITTED 98304u
#define I2_COPY_MAP_ENTRIES 131072u
#define I2_COPY_MAP_ADMITTED 65536u
#define I2_JAM_CACHE_ENTRIES 131072u
#define I2_JAM_CACHE_ADMITTED 98304u
#define I2_CUE_MAX_INPUT_BYTES 1048576u
#define I2_CUE_MAX_DEPTH 256
#define I2_CUE_MAX_NODES 131072
#define I2_CUE_MAX_CELLS 65536
#define I2_CUE_MAX_BACKREFS 65536
#define I2_CUE_MAX_ATOM_BYTES 262144u
#define I2_CUE_MAX_TOTAL_ATOM_BYTES 1048576u
#define I2_CUE_MAX_WORK 2000000
#define I2_BSS_RESERVED_BYTES 33554432u
#define I2_BSS_ADMITTED_BYTES 25165824u
