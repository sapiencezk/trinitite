#include <stdint.h>

#include "tip5.h"

/*
 * Tip5 as ++tip5 (hoon/common/ztd/three.hoon) computes it. See tip5.h.
 * The MDS layer is ++mds-cyclomul-m, the circulant matrix product over the
 * integers then mod p (no FFT); the round constants are ++round-constants,
 * montified (they equal nockchain-math's ROUND_CONSTANTS_MONT_7).
 */

#define P TIP5_P
#define EPS 0xFFFFFFFFULL           /* 2^64 mod p */
#define R2 0xFFFFFFFE00000001ULL    /* 2^128 mod p = 2^-64 mod p (R^3 = 1) */

typedef unsigned __int128 u128;

/* x mod p, canonical, for any 128-bit x: 2^64 = 2^32 - 1 and 2^96 = -1. */
static uint64_t reduce128(u128 x)
{
    uint64_t lo = (uint64_t)x, hi = (uint64_t)(x >> 64);
    uint64_t hi_hi = hi >> 32, hi_lo = hi & EPS;
    uint64_t t0 = lo - hi_hi, t1, r;
    if (lo < hi_hi)
        t0 -= EPS;
    t1 = hi_lo * EPS;
    r = t0 + t1;
    if (r < t1)
        r += EPS;
    if (r >= P)
        r -= P;
    return r;
}

/* ++bmul and ++badd on belts (both below p). */
static uint64_t bmul(uint64_t a, uint64_t b) { return reduce128((u128)a * b); }

static uint64_t badd(uint64_t a, uint64_t b)
{
    uint64_t s = a + b;
    if (s < a || s >= P)
        s -= P;
    return s;
}

/* ++montify (x * 2^64 mod p) and ++mont-reduction (x * 2^-64 mod p). */
static uint64_t montify(uint64_t x) { return reduce128((u128)x << 64); }
static uint64_t mont_reduction(uint64_t x) { return bmul(x, R2); }

/* ++lookup-table: x -> (x+1)^3 - 1 mod 257 on 0..255 */
static const uint8_t LOOKUP[256] = {
    0, 7, 26, 63, 124, 215, 85, 254, 214, 228, 45, 185, 140, 173, 33, 240,
    29, 177, 176, 32, 8, 110, 87, 202, 204, 99, 150, 106, 230, 14, 235, 128,
    213, 239, 212, 138, 23, 130, 208, 6, 44, 71, 93, 116, 146, 189, 251, 81,
    199, 97, 38, 28, 73, 179, 95, 84, 152, 48, 35, 119, 49, 88, 242, 3,
    148, 169, 72, 120, 62, 161, 166, 83, 175, 191, 137, 19, 100, 129, 112, 55,
    221, 102, 218, 61, 151, 237, 68, 164, 17, 147, 46, 234, 203, 216, 22, 141,
    65, 57, 123, 12, 244, 54, 219, 231, 96, 77, 180, 154, 5, 253, 133, 165,
    98, 195, 205, 134, 245, 30, 9, 188, 59, 142, 186, 197, 181, 144, 92, 31,
    224, 163, 111, 74, 58, 69, 113, 196, 67, 246, 225, 10, 121, 50, 60, 157,
    90, 122, 2, 250, 101, 75, 178, 159, 24, 36, 201, 11, 243, 132, 198, 190,
    114, 233, 39, 52, 21, 209, 108, 238, 91, 187, 18, 104, 194, 37, 153, 34,
    200, 143, 126, 155, 236, 118, 64, 80, 172, 89, 94, 193, 135, 183, 86, 107,
    252, 13, 167, 206, 136, 220, 207, 103, 171, 160, 76, 182, 227, 217, 158, 56,
    174, 4, 66, 109, 139, 162, 184, 211, 249, 47, 125, 232, 117, 43, 16, 42,
    127, 20, 241, 25, 149, 105, 156, 51, 53, 168, 145, 247, 223, 79, 78, 226,
    15, 222, 82, 115, 70, 210, 27, 41, 1, 170, 40, 131, 192, 229, 248, 255
};

/* ++mds-matrix-first-column; row i of the circulant is c[(i - j) mod 16]. */
static const uint64_t MDS[TIP5_STATE] = {
    61402, 1108, 28750, 33823, 7454, 43244, 53865, 12034,
    56951, 27521, 41351, 40901, 12021, 59689, 26798, 17845
};

/* ++round-constants for 7 rounds, montified. */
static const uint64_t RC[TIP5_ROUNDS * TIP5_STATE] = {
    0x5e8caa078ef4b766ULL, 0x845e2b1b9527aaa0ULL, 0x72b98fd0dc61a27fULL, 0x8ea94dc99dd6176bULL,
    0xdfef38a090a906a0ULL, 0xa2125ec1503b8d24ULL, 0xfc427968019c2a98ULL, 0x763a4f578003d32bULL,
    0xd409acf8b5afdd3fULL, 0x4dc9116f9a3e7df0ULL, 0x2d53725dcfe7d045ULL, 0xeb9af8d4eb30664cULL,
    0x07fcb48ee1b42d6eULL, 0xc2667fbe52129136ULL, 0xeb4283153f0104c1ULL, 0x947d63eba6bcbeefULL,
    0xe1da01d9f5aadb38ULL, 0xe1e423e5d2235ad0ULL, 0xd7d22e81dded7e4aULL, 0xf61d69faa2af4800ULL,
    0x9395d901be0f8562ULL, 0xc5647bf290645a32ULL, 0x8a1b22641b58a7e2ULL, 0xba1bbf7532a0d699ULL,
    0xd72a3d09fe832c16ULL, 0xdb1bc1d2dc60cfc6ULL, 0x6494083a0b199141ULL, 0xd7bdf271ccfcdf05ULL,
    0x64b7350ce811bcf7ULL, 0x2488f27e4c866bb5ULL, 0x4be59c81fff564e4ULL, 0x2f4c4b49c8769036ULL,
    0x58ec16d5fdfd3114ULL, 0x922ae5b85b941248ULL, 0x8a422b85f75a9215ULL, 0xd0204131f372b9f3ULL,
    0x73d7894911b1b106ULL, 0x1976334d18fc78dcULL, 0x7bc71ad9186870c6ULL, 0xf924c6eadfe47edcULL,
    0x90afbcebeba52b04ULL, 0x318ef6f613bfe2d2ULL, 0x9b6293e298c1e090ULL, 0xf777e9bb287cc053ULL,
    0x668089abc2c826d7ULL, 0x00aee9aa0f4b8b91ULL, 0xdac2be2454519e44ULL, 0x61bbddc24f09d975ULL,
    0xcf223188abb1e7a1ULL, 0x4fa0fe6bcb1926f7ULL, 0x54d270c63507a0d3ULL, 0x6270c5c1278d583dULL,
    0xb37dfa74ca05b03cULL, 0x0ba9d02d7cc83607ULL, 0x23fdf8a37086dcffULL, 0x0b2dd3f82cb627beULL,
    0x0932a7ff868540abULL, 0x0f062476193576ceULL, 0x1f5faab4f0562037ULL, 0xfc0bba0f790f50e1ULL,
    0x9eb5701498566743ULL, 0x7f130725c49d81eaULL, 0xbdff0c1faf44465aULL, 0xe44c031949dd3d53ULL,
    0x2fc820ba9f6f8bc7ULL, 0xbb87aa923544c0e2ULL, 0xb1280a4504f7c55dULL, 0xe9f229d450ed29d9ULL,
    0x3d1d816f161f909eULL, 0xe29816025b902a6cULL, 0x85919154ac823dfdULL, 0xa3bb714d9de350d9ULL,
    0x42b358c9ecae4096ULL, 0xbf5db42e8189c579ULL, 0x6fb10ee6a35a9147ULL, 0xd5a40ec83f64a3daULL,
    0x4ab010603c3fa911ULL, 0x3f19325ab8b3b56dULL, 0xefe4ca382925b66bULL, 0xeb0ac21e80583a6aULL,
    0x99988bd3b53a433eULL, 0x4d1b2a120f66b54cULL, 0x35a735e7c8c6ae7fULL, 0x1e8b8e99644752efULL,
    0x96012c533c31ee2cULL, 0x813e5d8dcd167030ULL, 0xf10c6f400295defaULL, 0xb3c462396f08c04dULL,
    0xe5e081bded27e86fULL, 0x54e4040b726341fbULL, 0x210746ff46964550ULL, 0x8966248a7a06c5cbULL,
    0xc64de784d637dbe0ULL, 0xa7ff55526e04ed1fULL, 0xc3dd6725867ff63cULL, 0xba88b74c0411eb86ULL,
    0x73d5a463a96e002dULL, 0xb5ee504135e071edULL, 0xe148d4a0d8fe2170ULL, 0x339570a14b80d45fULL,
    0x37e66a8f45a221a3ULL, 0xeaef8d626fa5e21bULL, 0x06c07a56bf557e53ULL, 0xf64746013091212cULL,
    0x3aba48c2ec31e3f4ULL, 0x9e39b3444e4690b6ULL, 0xa6987c8f2ef3136fULL, 0x1a17f217cfa1e749ULL,
    0x682d5c8234ce76bcULL, 0x16fcda7f98901603ULL, 0x6b66c06c2ff63504ULL, 0xf90a9d15c79834dfULL,
};

/* ++split-and-lookup: each of the eight bytes through LOOKUP. */
static uint64_t split_and_lookup(uint64_t m)
{
    uint64_t r = 0;
    uint32_t i;
    for (i = 0; i < 8; i++)
        r |= (uint64_t)LOOKUP[(m >> (8u * i)) & 0xFFu] << (8u * i);
    return r;
}

void tip5_permute(uint64_t s[TIP5_STATE])
{
    uint64_t t[TIP5_STATE];
    uint32_t r, i, j;
    for (r = 0; r < TIP5_ROUNDS; r++) {
        /* ++sbox-layer */
        for (i = 0; i < 4; i++)
            t[i] = split_and_lookup(s[i]);
        for (i = 4; i < TIP5_STATE; i++) {
            uint64_t x = s[i], sq = bmul(x, x), qu = bmul(sq, sq);
            t[i] = bmul(x, bmul(sq, qu));
        }
        /* ++mds-cyclomul-m, then the round's constants (++round) */
        for (i = 0; i < TIP5_STATE; i++) {
            u128 acc = 0;
            for (j = 0; j < TIP5_STATE; j++)
                acc += (u128)MDS[(i - j) & 15u] * t[j];
            s[i] = badd(reduce128(acc), RC[r * TIP5_STATE + i]);
        }
    }
}

void tip5_hash10(const uint64_t in[TIP5_RATE], uint64_t out[TIP5_DIGEST])
{
    uint64_t s[TIP5_STATE];
    uint32_t i;
    for (i = 0; i < TIP5_RATE; i++)
        s[i] = montify(in[i]);
    for (; i < TIP5_STATE; i++)
        s[i] = EPS;                    /* (montify 1) */
    tip5_permute(s);
    for (i = 0; i < TIP5_DIGEST; i++)
        out[i] = mont_reduction(s[i]);
}

void tip5_varlen_init(tip5_sponge_t *sp)
{
    uint32_t i;
    for (i = 0; i < TIP5_STATE; i++)
        sp->s[i] = 0;
    sp->n = 0;
}

/* ++absorb-rate: the rate overwrites the first ten, then permute. */
static void absorb_rate(tip5_sponge_t *sp)
{
    uint32_t i;
    for (i = 0; i < TIP5_RATE; i++)
        sp->s[i] = montify(sp->buf[i]);
    tip5_permute(sp->s);
    sp->n = 0;
}

void tip5_varlen_absorb(tip5_sponge_t *sp, uint64_t belt)
{
    sp->buf[sp->n++] = belt;
    if (sp->n == TIP5_RATE)
        absorb_rate(sp);
}

void tip5_varlen_finish(tip5_sponge_t *sp, uint64_t out[TIP5_DIGEST])
{
    uint32_t i;
    sp->buf[sp->n++] = 1;              /* pad: [1 0 ... 0] */
    while (sp->n < TIP5_RATE)
        sp->buf[sp->n++] = 0;
    absorb_rate(sp);
    for (i = 0; i < TIP5_DIGEST; i++)  /* ++squeeze */
        out[i] = mont_reduction(sp->s[i]);
}

void tip5_digest_to_limbs(const uint64_t d[TIP5_DIGEST], uint64_t limbs[6])
{
    int k;
    uint32_t i;
    for (i = 0; i < 6; i++)
        limbs[i] = 0;
    /* Horner, high digit first: acc = acc * p + d[k] */
    for (k = TIP5_DIGEST - 1; k >= 0; k--) {
        u128 carry = d[k];
        for (i = 0; i < 6; i++) {
            u128 w = (u128)limbs[i] * P + carry;
            limbs[i] = (uint64_t)w;
            carry = w >> 64;
        }
    }
}

void tip5_atom_digest(const uint64_t *limbs, uint64_t n, uint64_t out[TIP5_DIGEST])
{
    tip5_sponge_t sp;
    uint64_t k, i;
    tip5_varlen_init(&sp);
    if (n == 0 || (n == 1 && limbs[0] < P)) {
        tip5_varlen_absorb(&sp, 1);
        tip5_varlen_absorb(&sp, n == 0 ? 0 : limbs[0]);
        tip5_varlen_finish(&sp, out);
        return;
    }
    /* (rip 5 a): the high 64-bit limb gives one or two 32-bit limbs */
    k = 2 * n - ((limbs[n - 1] >> 32) == 0 ? 1 : 0);
    tip5_varlen_absorb(&sp, k);
    for (i = 0; i < k; i++)
        tip5_varlen_absorb(&sp, (limbs[i / 2] >> (32u * (i % 2))) & EPS);
    tip5_varlen_finish(&sp, out);
}
