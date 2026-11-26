/* The base admission envelope: the bounded cue's default limits
 * (cue_envelope_limits) and the sizes of the jam and copy tables. The lite
 * host's own cue and slam caps are in lite_admission.h. */
#pragma once
#include <stdint.h>

#define ENVELOPE_CUE_CACHE_ADMITTED 98304u
#define ENVELOPE_COPY_MAP_ENTRIES 131072u
#define ENVELOPE_COPY_MAP_ADMITTED 65536u
#define ENVELOPE_JAM_CACHE_ENTRIES 131072u
#define ENVELOPE_JAM_CACHE_ADMITTED 98304u
#define ENVELOPE_CUE_MAX_INPUT_BYTES 1048576u
#define ENVELOPE_CUE_MAX_DEPTH 256
#define ENVELOPE_CUE_MAX_NODES 131072
#define ENVELOPE_CUE_MAX_CELLS 65536
#define ENVELOPE_CUE_MAX_BACKREFS 65536
#define ENVELOPE_CUE_MAX_ATOM_BYTES 262144u
#define ENVELOPE_CUE_MAX_TOTAL_ATOM_BYTES 1048576u
#define ENVELOPE_CUE_MAX_WORK 2000000
