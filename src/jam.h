#pragma once
#include "noun.h"

/*
 * Noun serialization: jam / cue  (Phase 5a)
 *
 * jam: noun → atom   (bitstream encoding with back-reference deduplication)
 * cue: atom → noun   (inverse: decode bitstream back to noun)
 *
 * Encoding overview:
 *   Atom:       tag=0,  followed by mat(atom)
 *   Cell:       tag=01, followed by jam(head) jam(tail)
 *   Back-ref:   tag=11, followed by mat(bit-cursor of earlier occurrence)
 *
 * mat/rub: self-describing integer encoding.
 *   mat(0) = [len=1, bits=1]
 *   mat(k) = [len=2b+a, bits=(b zeros)(1)(b-1 low bits of a)(a bits of k)]
 *     where a = bn_met(k), b = bit_length(a)
 */

noun jam(noun n);   /* noun  → serialized atom              */
noun cue(noun a);   /* atom  → deserialized noun            */

/* Checked view of the fixed jam writer. The returned bytes remain valid
 * until the next jam operation and never enter the persistent atom store. */
int jam_encode_bytes_checked(noun n, const uint8_t **out,
                             uint64_t *out_bytes);
uint64_t jam_encode_bytes_selftest(void);

/* The target jam writer has a fixed 128 KiB output buffer.  This checked
 * preflight uses the same cache and encoding choices as jam(), but performs
 * no writes and therefore fails closed before the writer can overflow. */
#define JAM_MAX_BYTES (16384u * sizeof(uint64_t))
int jam_size_checked(noun n, uint64_t max_bytes, uint64_t *out_bytes);
