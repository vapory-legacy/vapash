// Vapash: C/C++ implementation of Vapash, the Vapory Proof of Work algorithm.
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0. See the LICENSE file.

#include <vapash/keccak.h>

#include <cstring>
#include <string>

#include <iostream>

extern "C" {

typedef struct sha3_ctx
{
    uint64_t hash[25];
    uint64_t message[24];
    unsigned rest;
    unsigned block_size;
} sha3_ctx;

void rhash_sha3_256_init(sha3_ctx* ctx) noexcept;
void rhash_sha3_512_init(sha3_ctx* ctx) noexcept;
void rhash_sha3_update(sha3_ctx* ctx, const unsigned char* msg, size_t size) noexcept;
void rhash_keccak_final(sha3_ctx* ctx, unsigned char* result) noexcept;

int keccak_tiny_256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) noexcept;
int keccak_tiny_512(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) noexcept;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* input, size_t size)
{
    // vapash:

    const auto h256_vapash = vapash_keccak256(input, size);
    const auto h512_vapash = vapash_keccak512(input, size);


    // tiny:

    vapash_hash256 h256_tiny;
    int r = keccak_tiny_256(h256_tiny.bytes, sizeof(h256_tiny), input, size);
    if (r != 0)
        __builtin_trap();

    vapash_hash512 h512_tiny;
    r = keccak_tiny_512(h512_tiny.bytes, sizeof(h512_tiny), input, size);
    if (r != 0)
        __builtin_trap();


    // rhash:

    sha3_ctx ctx;

    vapash_hash256 h256_rhash;
    rhash_sha3_256_init(&ctx);
    rhash_sha3_update(&ctx, input, size);
    rhash_keccak_final(&ctx, h256_rhash.bytes);

    vapash_hash512 h512_rhash;
    rhash_sha3_512_init(&ctx);
    rhash_sha3_update(&ctx, input, size);
    rhash_keccak_final(&ctx, h512_rhash.bytes);


    // Compare.

    if (std::memcmp(&h256_vapash, &h256_tiny, sizeof(h256_vapash)) != 0)
        __builtin_trap();

    if (std::memcmp(&h256_vapash, &h256_rhash, sizeof(h256_vapash)) != 0)
    {
        std::cerr << "Here!";
        __builtin_trap();
    }


    if (std::memcmp(&h512_vapash, &h512_tiny, sizeof(h512_vapash)) != 0)
        __builtin_trap();

    if (std::memcmp(&h512_vapash, &h512_rhash, sizeof(h512_vapash)) != 0)
        __builtin_trap();

    return 0;
}
