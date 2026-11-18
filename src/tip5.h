#pragma once

#include <stdint.h>

/*
 * Tip5 over the Goldilocks field p = 2^64 - 2^32 + 1, as Nockchain's Hoon
 * defines it (++tip5 in hoon/common/ztd/three.hoon at 1499kernel's nockchain
 * pin): 7 rounds, state 16, rate 10, digest 5, Montgomery form inside the
 * permutation. 1499kernel row 328 (d): the lite node's jets for the arms
 * ++digest (iec-types) calls. Every function here computes what its Hoon arm
 * computes on the inputs it accepts; the jets (nock.c) run the Hoon arm for
 * any other input.
 */

#define TIP5_P 0xFFFFFFFF00000001ULL
#define TIP5_STATE 16
#define TIP5_RATE 10
#define TIP5_DIGEST 5
#define TIP5_ROUNDS 7
/* A digest as an atom (++digest-to-atom) is below p^5 < 2^320: 40 bytes. */
#define TIP5_DIGEST_BYTES 40

/* ++permutation on a sponge of 16 melts, each below p. */
void tip5_permute(uint64_t s[TIP5_STATE]);

/* ++hash-10: ten belts (each below p) to a digest. */
void tip5_hash10(const uint64_t in[TIP5_RATE], uint64_t out[TIP5_DIGEST]);

/* ++hash-varlen, streamed: init, absorb each belt (below p) in order, then
 * finish (pads with [1 0 ...] and squeezes the first five belts). */
typedef struct {
    uint64_t s[TIP5_STATE];
    uint64_t buf[TIP5_RATE];
    uint32_t n;
} tip5_sponge_t;
void tip5_varlen_init(tip5_sponge_t *sp);
void tip5_varlen_absorb(tip5_sponge_t *sp, uint64_t belt);
void tip5_varlen_finish(tip5_sponge_t *sp, uint64_t out[TIP5_DIGEST]);

/* ++digest-to-atom: a + p*b + p^2*c + p^3*d + p^4*e, any five 64-bit
 * values, as six little-endian limbs. */
void tip5_digest_to_limbs(const uint64_t d[TIP5_DIGEST], uint64_t limbs[6]);

/* The leaf digest ++hash-hashable-noun:digest-lib gives an atom of n
 * little-endian 64-bit limbs (no high zero limb): [1 a] below p, else
 * [k limbs32...] over its k 32-bit limbs. */
void tip5_atom_digest(const uint64_t *limbs, uint64_t n, uint64_t out[TIP5_DIGEST]);
