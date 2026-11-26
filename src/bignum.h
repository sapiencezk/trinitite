#pragma once
#include <stdint.h>
#include "noun.h"

/*
 * Bignum arithmetic for indirect (tag=10) atoms.
 *
 * Representation (maintained as invariants by every function here):
 *   - Limbs are little-endian uint64_t: limbs[0] = least significant 64 bits.
 *   - No trailing zero limbs: limbs[size-1] != 0 when size > 1.
 *   - Canonical form: any value < 2^63 is ALWAYS a direct atom.
 *     make_atom() never returns indirect when the value fits in 63 bits.
 *
 * The boundary is exactly 2^63 = 0x8000_0000_0000_0000.
 * Incrementing a direct atom with value 2^63-1 produces an indirect atom
 * with size=1, limbs[0]=2^63.
 *
 * All functions return a properly tagged, canonical noun.
 */

/* ── Core ────────────────────────────────────────────────────────────────── */

/*
 * bn_normalize: given a scratch limb array `limbs[0..size-1]`, produce a
 * canonical noun.  Strips trailing zero limbs, then promotes to direct if
 * the value fits in 62 bits, otherwise allocates a fresh indirect atom.
 *
 * The scratch array is read-only; a new atom_t is always allocated when
 * the result must be indirect.
 */
noun bn_normalize(uint64_t *limbs, uint64_t size);

/*
 * bn_inc: Nock op 4 — increment an atom by 1.
 * Handles direct→direct, direct→indirect boundary, and multi-limb carry.
 * Crashes (via nock_crash) if `a` is a cell or unsupported atom type.
 */
noun bn_inc(noun a);

/* Maximum limbs for stack-allocated scratch buffers (64 × 64-bit = 4096 bits). */
#define BN_MAX_LIMBS 64

/* ── Arithmetic ───────────────────────────────────────────────────────────── */

noun bn_add(noun a, noun b);   /* addition                              */
noun bn_dec(noun a);           /* decrement; crashes on zero            */
noun bn_sub(noun a, noun b);   /* subtraction a-b; crashes if a < b    */

/* Compare two atoms.  Returns -1 / 0 / +1  (a < b / a == b / a > b). */
int  bn_cmp(noun a, noun b);

/* ── Bit ops and shifts ───────────────────────────────────────────────────── */

/* bn_met: number of significant bits.
 *   bn_met(0) = 0,  bn_met(1) = 1,  bn_met(2) = bn_met(3) = 2, ...
 *   Equivalent to Hoon (met 0 a).  Returns a raw uint64_t, not a noun. */
uint64_t bn_met(noun a);


/* bn_lsh / bn_rsh: left / right shift atom a by k bits.
 *   bn_lsh crashes if the result exceeds BN_MAX_LIMBS limbs.
 *   bn_rsh returns NOUN_ZERO if k >= bn_met(a). */
noun bn_lsh(noun a, uint64_t k);
noun bn_rsh(noun a, uint64_t k);

/* Bitwise OR, AND, XOR.  Operands zero-extended to match width. */
noun bn_or (noun a, noun b);
noun bn_and(noun a, noun b);
noun bn_xor(noun a, noun b);

/* ── Multiplication ───────────────────────────────────────────────────────── */

/* Schoolbook O(n²) multiplication.
 * Result may have up to BN_MAX_LIMBS*2 limbs; bn_normalize handles it.
 * Note: inputs are clipped to BN_MAX_LIMBS limbs by atom_limbs(); atoms
 * larger than 4096 bits have degraded accuracy as multiplication inputs. */
noun bn_mul(noun a, noun b);

/* ── Division ─────────────────────────────────────────────────────────────── */

/* bn_div: integer quotient floor(a / b).  Crashes if b == 0. */
noun bn_div(noun a, noun b);

/* bn_mod: remainder a mod b (Euclidean: 0 <= result < b).  Crashes if b == 0. */
noun bn_mod(noun a, noun b);
