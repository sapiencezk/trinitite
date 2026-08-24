#pragma once

#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t block[64];
    uint32_t block_len;
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, uint64_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t digest[32]);
void sha256_hash(const uint8_t *data, uint64_t len, uint8_t digest[32]);

/* HMAC-SHA-256 over at most the fixed M24 wire input. */
void hmac_sha256(const uint8_t *key, uint64_t key_len,
                 const uint8_t *data, uint64_t data_len,
                 uint8_t digest[32]);
