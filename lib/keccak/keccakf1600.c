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
static inline ALWAYS_INLINE void permute_round(uint64_t E[5][5], uint64_t A[5][5], int n)
{
    uint64_t C[5];
    uint64_t D[5];

    C[0] = A[0][0] ^ A[1][0] ^ A[2][0] ^ A[3][0] ^ A[4][0];
    C[1] = A[0][1] ^ A[1][1] ^ A[2][1] ^ A[3][1] ^ A[4][1];
    C[2] = A[0][2] ^ A[1][2] ^ A[2][2] ^ A[3][2] ^ A[4][2];
    C[3] = A[0][3] ^ A[1][3] ^ A[2][3] ^ A[3][3] ^ A[4][3];
    C[4] = A[0][4] ^ A[1][4] ^ A[2][4] ^ A[3][4] ^ A[4][4];

    D[0] = C[4] ^ rol(C[1], 1);
    D[1] = C[0] ^ rol(C[2], 1);
    D[2] = C[1] ^ rol(C[3], 1);
    D[3] = C[2] ^ rol(C[4], 1);
    D[4] = C[3] ^ rol(C[0], 1);

    C[0] = A[0][0] ^ D[0];
    C[1] = rol(A[1][1] ^ D[1], 44);
    C[2] = rol(A[2][2] ^ D[2], 43);
    C[3] = rol(A[3][3] ^ D[3], 21);
    C[4] = rol(A[4][4] ^ D[4], 14);
    E[0][0] = C[0] ^ (~C[1] & C[2]) ^ round_constants[n];
    E[0][1] = C[1] ^ (~C[2] & C[3]);
    E[0][2] = C[2] ^ (~C[3] & C[4]);
    E[0][3] = C[3] ^ (~C[4] & C[0]);
    E[0][4] = C[4] ^ (~C[0] & C[1]);

    C[0] = rol(A[0][3] ^ D[3], 28);
    C[1] = rol(A[1][4] ^ D[4], 20);
    C[2] = rol(A[2][0] ^ D[0], 3);
    C[3] = rol(A[3][1] ^ D[1], 45);
    C[4] = rol(A[4][2] ^ D[2], 61);
    E[1][0] = C[0] ^ (~C[1] & C[2]);
    E[1][1] = C[1] ^ (~C[2] & C[3]);
    E[1][2] = C[2] ^ (~C[3] & C[4]);
    E[1][3] = C[3] ^ (~C[4] & C[0]);
    E[1][4] = C[4] ^ (~C[0] & C[1]);

    C[0] = rol(A[0][1] ^ D[1], 1);
    C[1] = rol(A[1][2] ^ D[2], 6);
    C[2] = rol(A[2][3] ^ D[3], 25);
    C[3] = rol(A[3][4] ^ D[4], 8);
    C[4] = rol(A[4][0] ^ D[0], 18);
    E[2][0] = C[0] ^ (~C[1] & C[2]);
    E[2][1] = C[1] ^ (~C[2] & C[3]);
    E[2][2] = C[2] ^ (~C[3] & C[4]);
    E[2][3] = C[3] ^ (~C[4] & C[0]);
    E[2][4] = C[4] ^ (~C[0] & C[1]);

    C[0] = rol(A[0][4] ^ D[4], 27);
    C[1] = rol(A[1][0] ^ D[0], 36);
    C[2] = rol(A[2][1] ^ D[1], 10);
    C[3] = rol(A[3][2] ^ D[2], 15);
    C[4] = rol(A[4][3] ^ D[3], 56);
    E[3][0] = C[0] ^ (~C[1] & C[2]);
    E[3][1] = C[1] ^ (~C[2] & C[3]);
    E[3][2] = C[2] ^ (~C[3] & C[4]);
    E[3][3] = C[3] ^ (~C[4] & C[0]);
    E[3][4] = C[4] ^ (~C[0] & C[1]);

    C[0] = rol(A[0][2] ^ D[2], 62);
    C[1] = rol(A[1][3] ^ D[3], 55);
    C[2] = rol(A[2][4] ^ D[4], 39);
    C[3] = rol(A[3][0] ^ D[0], 41);
    C[4] = rol(A[4][1] ^ D[1], 2);
    E[4][0] = C[0] ^ (~C[1] & C[2]);
    E[4][1] = C[1] ^ (~C[2] & C[3]);
    E[4][2] = C[2] ^ (~C[3] & C[4]);
    E[4][3] = C[3] ^ (~C[4] & C[0]);
    E[4][4] = C[4] ^ (~C[0] & C[1]);
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
void ethash_keccakf1600(uint64_t state[5][5])
{
    uint64_t(*A)[5] = state;

    // Temporary intermediate state being the result of odd rounds (A -> E).
    uint64_t E[5][5];

    // Execute all permutation rounds with unrolling of 2.
    for (int n = 0; n < 24; n += 2)
    {
        permute_round(E, A, n);      // Round (n): A -> E.
        permute_round(A, E, n + 1);  // Round (n + 1): E -> A.
    }
}
