// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

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

/// The implementation of Keccak-f[1600] function.
///
/// The implementation based on:
/// - "simple" implementation by Ronny Van Keer, included in "Reference and optimized code in C",
///   https://keccak.team/archives.html, CC0-1.0 / Public Domain.
void ethash_keccakf1600(uint64_t state[5][5])
{
    uint64_t(*A)[5] = state;

    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    for (int round = 0; round < 24; round += 2)
    {
        uint64_t C[5];
        uint64_t D[5];

        /* Round (round + 0): A -> Exx */

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
        Eba = C[0] ^ (~C[1] & C[2]) ^ round_constants[round];
        Ebe = C[1] ^ (~C[2] & C[3]);
        Ebi = C[2] ^ (~C[3] & C[4]);
        Ebo = C[3] ^ (~C[4] & C[0]);
        Ebu = C[4] ^ (~C[0] & C[1]);

        C[0] = rol(A[0][3] ^ D[3], 28);
        C[1] = rol(A[1][4] ^ D[4], 20);
        C[2] = rol(A[2][0] ^ D[0], 3);
        C[3] = rol(A[3][1] ^ D[1], 45);
        C[4] = rol(A[4][2] ^ D[2], 61);
        Ega = C[0] ^ (~C[1] & C[2]);
        Ege = C[1] ^ (~C[2] & C[3]);
        Egi = C[2] ^ (~C[3] & C[4]);
        Ego = C[3] ^ (~C[4] & C[0]);
        Egu = C[4] ^ (~C[0] & C[1]);

        C[0] = rol(A[0][1] ^ D[1], 1);
        C[1] = rol(A[1][2] ^ D[2], 6);
        C[2] = rol(A[2][3] ^ D[3], 25);
        C[3] = rol(A[3][4] ^ D[4], 8);
        C[4] = rol(A[4][0] ^ D[0], 18);
        Eka = C[0] ^ (~C[1] & C[2]);
        Eke = C[1] ^ (~C[2] & C[3]);
        Eki = C[2] ^ (~C[3] & C[4]);
        Eko = C[3] ^ (~C[4] & C[0]);
        Eku = C[4] ^ (~C[0] & C[1]);

        C[0] = rol(A[0][4] ^ D[4], 27);
        C[1] = rol(A[1][0] ^ D[0], 36);
        C[2] = rol(A[2][1] ^ D[1], 10);
        C[3] = rol(A[3][2] ^ D[2], 15);
        C[4] = rol(A[4][3] ^ D[3], 56);
        Ema = C[0] ^ (~C[1] & C[2]);
        Eme = C[1] ^ (~C[2] & C[3]);
        Emi = C[2] ^ (~C[3] & C[4]);
        Emo = C[3] ^ (~C[4] & C[0]);
        Emu = C[4] ^ (~C[0] & C[1]);

        C[0] = rol(A[0][2] ^ D[2], 62);
        C[1] = rol(A[1][3] ^ D[3], 55);
        C[2] = rol(A[2][4] ^ D[4], 39);
        C[3] = rol(A[3][0] ^ D[0], 41);
        C[4] = rol(A[4][1] ^ D[1], 2);
        Esa = C[0] ^ (~C[1] & C[2]);
        Ese = C[1] ^ (~C[2] & C[3]);
        Esi = C[2] ^ (~C[3] & C[4]);
        Eso = C[3] ^ (~C[4] & C[0]);
        Esu = C[4] ^ (~C[0] & C[1]);


        /* Round (round + 1): Exx -> A */

        C[0] = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        C[1] = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        C[2] = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        C[3] = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        C[4] = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        D[0] = C[4] ^ rol(C[1], 1);
        D[1] = C[0] ^ rol(C[2], 1);
        D[2] = C[1] ^ rol(C[3], 1);
        D[3] = C[2] ^ rol(C[4], 1);
        D[4] = C[3] ^ rol(C[0], 1);

        C[0] = Eba ^ D[0];
        C[1] = rol(Ege ^ D[1], 44);
        C[2] = rol(Eki ^ D[2], 43);
        C[3] = rol(Emo ^ D[3], 21);
        C[4] = rol(Esu ^ D[4], 14);
        A[0][0] = C[0] ^ (~C[1] & C[2]) ^ round_constants[round + 1];
        A[0][1] = C[1] ^ (~C[2] & C[3]);
        A[0][2] = C[2] ^ (~C[3] & C[4]);
        A[0][3] = C[3] ^ (~C[4] & C[0]);
        A[0][4] = C[4] ^ (~C[0] & C[1]);

        C[0] = rol(Ebo ^ D[3], 28);
        C[1] = rol(Egu ^ D[4], 20);
        C[2] = rol(Eka ^ D[0], 3);
        C[3] = rol(Eme ^ D[1], 45);
        C[4] = rol(Esi ^ D[2], 61);
        A[1][0] = C[0] ^ (~C[1] & C[2]);
        A[1][1] = C[1] ^ (~C[2] & C[3]);
        A[1][2] = C[2] ^ (~C[3] & C[4]);
        A[1][3] = C[3] ^ (~C[4] & C[0]);
        A[1][4] = C[4] ^ (~C[0] & C[1]);

        C[0] = rol(Ebe ^ D[1], 1);
        C[1] = rol(Egi ^ D[2], 6);
        C[2] = rol(Eko ^ D[3], 25);
        C[3] = rol(Emu ^ D[4], 8);
        C[4] = rol(Esa ^ D[0], 18);
        A[2][0] = C[0] ^ (~C[1] & C[2]);
        A[2][1] = C[1] ^ (~C[2] & C[3]);
        A[2][2] = C[2] ^ (~C[3] & C[4]);
        A[2][3] = C[3] ^ (~C[4] & C[0]);
        A[2][4] = C[4] ^ (~C[0] & C[1]);

        C[0] = rol(Ebu ^ D[4], 27);
        C[1] = rol(Ega ^ D[0], 36);
        C[2] = rol(Eke ^ D[1], 10);
        C[3] = rol(Emi ^ D[2], 15);
        C[4] = rol(Eso ^ D[3], 56);
        A[3][0] = C[0] ^ (~C[1] & C[2]);
        A[3][1] = C[1] ^ (~C[2] & C[3]);
        A[3][2] = C[2] ^ (~C[3] & C[4]);
        A[3][3] = C[3] ^ (~C[4] & C[0]);
        A[3][4] = C[4] ^ (~C[0] & C[1]);

        C[0] = rol(Ebi ^ D[2], 62);
        C[1] = rol(Ego ^ D[3], 55);
        C[2] = rol(Eku ^ D[4], 39);
        C[3] = rol(Ema ^ D[0], 41);
        C[4] = rol(Ese ^ D[1], 2);
        A[4][0] = C[0] ^ (~C[1] & C[2]);
        A[4][1] = C[1] ^ (~C[2] & C[3]);
        A[4][2] = C[2] ^ (~C[3] & C[4]);
        A[4][3] = C[3] ^ (~C[4] & C[0]);
        A[4][4] = C[4] ^ (~C[0] & C[1]);
    }
}
