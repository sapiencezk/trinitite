#include <stdint.h>

#include "sha256.h"

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32u - n)); }
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint32_t big0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static uint32_t big1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
static uint32_t small0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static uint32_t small1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
        | ((uint32_t)p[2] << 8) | p[3];
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static void sha256_block(sha256_ctx_t *ctx, const uint8_t block[64])
{
    uint32_t w[64];
    for (uint32_t i = 0; i < 16; i++) w[i] = be32(block + i * 4u);
    for (uint32_t i = 16; i < 64; i++)
        w[i] = small1(w[i - 2]) + w[i - 7] + small0(w[i - 15]) + w[i - 16];
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (uint32_t i = 0; i < 64; i++) {
        uint32_t t1 = h + big1(e) + ch(e, f, g) + K[i] + w[i];
        uint32_t t2 = big0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(sha256_ctx_t *ctx)
{
    static const uint32_t initial[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    for (uint32_t i = 0; i < 8; i++) ctx->state[i] = initial[i];
    ctx->bit_count = 0;
    ctx->block_len = 0;
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, uint64_t len)
{
    if (!ctx || (!data && len)) return;
    while (len) {
        uint32_t take = 64u - ctx->block_len;
        if ((uint64_t)take > len) take = (uint32_t)len;
        for (uint32_t i = 0; i < take; i++) ctx->block[ctx->block_len + i] = data[i];
        ctx->block_len += take; data += take; len -= take;
        ctx->bit_count += (uint64_t)take * 8u;
        if (ctx->block_len == 64u) {
            sha256_block(ctx, ctx->block);
            ctx->block_len = 0;
        }
    }
}

void sha256_final(sha256_ctx_t *ctx, uint8_t digest[32])
{
    if (!ctx || !digest) return;
    uint32_t n = ctx->block_len;
    ctx->block[n++] = 0x80;
    while (n < 64u) ctx->block[n++] = 0;
    if (ctx->block_len >= 56u) {
        sha256_block(ctx, ctx->block);
        for (uint32_t i = 0; i < 64u; i++) ctx->block[i] = 0;
    }
    uint64_t bits = ctx->bit_count;
    for (uint32_t i = 0; i < 8u; i++) ctx->block[56u + i] = (uint8_t)(bits >> (56u - 8u * i));
    sha256_block(ctx, ctx->block);
    for (uint32_t i = 0; i < 8u; i++) put_be32(digest + i * 4u, ctx->state[i]);
}

void sha256_hash(const uint8_t *data, uint64_t len, uint8_t digest[32])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx); sha256_update(&ctx, data, len); sha256_final(&ctx, digest);
}

void hmac_sha256(const uint8_t *key, uint64_t key_len,
                 const uint8_t *data, uint64_t data_len,
                 uint8_t digest[32])
{
    uint8_t block_key[64], inner[32];
    for (uint32_t i = 0; i < 64u; i++) block_key[i] = 0;
    if (key_len > 64u) { sha256_hash(key, key_len, block_key); key_len = 32u; }
    else for (uint32_t i = 0; i < key_len; i++) block_key[i] = key[i];
    for (uint32_t i = 0; i < 64u; i++) block_key[i] ^= 0x36u;
    sha256_ctx_t ctx;
    sha256_init(&ctx); sha256_update(&ctx, block_key, 64); sha256_update(&ctx, data, data_len); sha256_final(&ctx, inner);
    for (uint32_t i = 0; i < 64u; i++) block_key[i] ^= (uint8_t)(0x36u ^ 0x5cu);
    sha256_init(&ctx); sha256_update(&ctx, block_key, 64); sha256_update(&ctx, inner, 32); sha256_final(&ctx, digest);
}
