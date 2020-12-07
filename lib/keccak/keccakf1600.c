// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "../support/attributes.h"
#include <ethash/keccak.h>

/// Rotates the bits of x left by the count value specified by s.
/// The s must be in range <0, 64> exclusively, otherwise the result is undefined.
static inline uint64_t rol(uint64_t x, unsigned s)
{
    return (x << s) | (x >> (64 - s));
}

static const uint64_t round_constants[24] = {
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
};

/// Performs n-th Keccak-f[1600] permutation round, taking A as the initial state
/// and putting the result state to E.
static inline ALWAYS_INLINE void permute_round(uint64_t E[25], uint64_t A[25], int n)
{
    uint64_t C[5];
    uint64_t D[5];

    C[0] = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
    C[1] = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
    C[2] = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
    C[3] = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
    C[4] = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

    D[0] = C[4] ^ rol(C[1], 1);
    D[1] = C[0] ^ rol(C[2], 1);
    D[2] = C[1] ^ rol(C[3], 1);
    D[3] = C[2] ^ rol(C[4], 1);
    D[4] = C[3] ^ rol(C[0], 1);

    C[0] = A[0] ^ D[0];
    C[1] = rol(A[6] ^ D[1], 44);
    C[2] = rol(A[12] ^ D[2], 43);
    C[3] = rol(A[18] ^ D[3], 21);
    C[4] = rol(A[24] ^ D[4], 14);
    E[0] = C[0] ^ (~C[1] & C[2]) ^ round_constants[n];
    E[1] = C[1] ^ (~C[2] & C[3]);
    E[2] = C[2] ^ (~C[3] & C[4]);
    E[3] = C[3] ^ (~C[4] & C[0]);
    E[4] = C[4] ^ (~C[0] & C[1]);

    C[0] = rol(A[3] ^ D[3], 28);
    C[1] = rol(A[9] ^ D[4], 20);
    C[2] = rol(A[10] ^ D[0], 3);
    C[3] = rol(A[16] ^ D[1], 45);
    C[4] = rol(A[22] ^ D[2], 61);
    E[5] = C[0] ^ (~C[1] & C[2]);
    E[6] = C[1] ^ (~C[2] & C[3]);
    E[7] = C[2] ^ (~C[3] & C[4]);
    E[8] = C[3] ^ (~C[4] & C[0]);
    E[9] = C[4] ^ (~C[0] & C[1]);

    C[0] = rol(A[1] ^ D[1], 1);
    C[1] = rol(A[7] ^ D[2], 6);
    C[2] = rol(A[13] ^ D[3], 25);
    C[3] = rol(A[19] ^ D[4], 8);
    C[4] = rol(A[20] ^ D[0], 18);
    E[10] = C[0] ^ (~C[1] & C[2]);
    E[11] = C[1] ^ (~C[2] & C[3]);
    E[12] = C[2] ^ (~C[3] & C[4]);
    E[13] = C[3] ^ (~C[4] & C[0]);
    E[14] = C[4] ^ (~C[0] & C[1]);

    C[0] = rol(A[4] ^ D[4], 27);
    C[1] = rol(A[5] ^ D[0], 36);
    C[2] = rol(A[11] ^ D[1], 10);
    C[3] = rol(A[17] ^ D[2], 15);
    C[4] = rol(A[23] ^ D[3], 56);
    E[15] = C[0] ^ (~C[1] & C[2]);
    E[16] = C[1] ^ (~C[2] & C[3]);
    E[17] = C[2] ^ (~C[3] & C[4]);
    E[18] = C[3] ^ (~C[4] & C[0]);
    E[19] = C[4] ^ (~C[0] & C[1]);

    C[0] = rol(A[2] ^ D[2], 62);
    C[1] = rol(A[8] ^ D[3], 55);
    C[2] = rol(A[14] ^ D[4], 39);
    C[3] = rol(A[15] ^ D[0], 41);
    C[4] = rol(A[21] ^ D[1], 2);
    E[20] = C[0] ^ (~C[1] & C[2]);
    E[21] = C[1] ^ (~C[2] & C[3]);
    E[22] = C[2] ^ (~C[3] & C[4]);
    E[23] = C[3] ^ (~C[4] & C[0]);
    E[24] = C[4] ^ (~C[0] & C[1]);
}

/// The implementation of Keccak-f[1600] function.
///
/// The implementation based on:
/// - "simple" implementation by Ronny Van Keer, included in "Reference and optimized code in C",
///   https://keccak.team/archives.html,
///   CC0-1.0 / Public Domain.
/// - OpenSSL's Keccak implementation KECCAK_2X without KECCAK_COMPLEMENTING_TRANSFORM,
///   https://github.com/openssl/openssl/blob/openssl-3.0.0-alpha9/crypto/sha/keccak1600.c,
///   Apache-2.0.
void ethash_keccakf1600(uint64_t state[25])
{
    uint64_t* A = state;

    // Temporary intermediate state being the result of odd rounds (A -> E).
    uint64_t E[25];

    // Execute all permutation rounds with unrolling of 2.
    for (int n = 0; n < 24; n += 2)
    {
        permute_round(E, A, n);      // Round (n): A -> E.
        permute_round(A, E, n + 1);  // Round (n + 1): E -> A.
    }
}

__attribute__((target("bmi,bmi2"))) void ethash_keccakf1600_bmi(uint64_t state[25])
{
    uint64_t* A = state;

    // Temporary intermediate state being the result of odd rounds (A -> E).
    uint64_t E[25];

    // Execute all permutation rounds with unrolling of 2.
    for (int n = 0; n < 24; n += 2)
    {
        permute_round(E, A, n);      // Round (n): A -> E.
        permute_round(A, E, n + 1);  // Round (n + 1): E -> A.
    }
}
