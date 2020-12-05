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

    uint64_t Ba, Be, Bi, Bo, Bu;

    uint64_t Da, De, Di, Do, Du;

    for (int round = 0; round < 24; round += 2)
    {
        /* Round (round + 0): A -> Exx */

        Ba = A[0][0] ^ A[1][0] ^ A[2][0] ^ A[3][0] ^ A[4][0];
        Be = A[0][1] ^ A[1][1] ^ A[2][1] ^ A[3][1] ^ A[4][1];
        Bi = A[0][2] ^ A[1][2] ^ A[2][2] ^ A[3][2] ^ A[4][2];
        Bo = A[0][3] ^ A[1][3] ^ A[2][3] ^ A[3][3] ^ A[4][3];
        Bu = A[0][4] ^ A[1][4] ^ A[2][4] ^ A[3][4] ^ A[4][4];

        Da = Bu ^ rol(Be, 1);
        De = Ba ^ rol(Bi, 1);
        Di = Be ^ rol(Bo, 1);
        Do = Bi ^ rol(Bu, 1);
        Du = Bo ^ rol(Ba, 1);

        Ba = A[0][0] ^ Da;
        Be = rol(A[1][1] ^ De, 44);
        Bi = rol(A[2][2] ^ Di, 43);
        Bo = rol(A[3][3] ^ Do, 21);
        Bu = rol(A[4][4] ^ Du, 14);
        Eba = Ba ^ (~Be & Bi) ^ round_constants[round];
        Ebe = Be ^ (~Bi & Bo);
        Ebi = Bi ^ (~Bo & Bu);
        Ebo = Bo ^ (~Bu & Ba);
        Ebu = Bu ^ (~Ba & Be);

        Ba = rol(A[0][3] ^ Do, 28);
        Be = rol(A[1][4] ^ Du, 20);
        Bi = rol(A[2][0] ^ Da, 3);
        Bo = rol(A[3][1] ^ De, 45);
        Bu = rol(A[4][2] ^ Di, 61);
        Ega = Ba ^ (~Be & Bi);
        Ege = Be ^ (~Bi & Bo);
        Egi = Bi ^ (~Bo & Bu);
        Ego = Bo ^ (~Bu & Ba);
        Egu = Bu ^ (~Ba & Be);

        Ba = rol(A[0][1] ^ De, 1);
        Be = rol(A[1][2] ^ Di, 6);
        Bi = rol(A[2][3] ^ Do, 25);
        Bo = rol(A[3][4] ^ Du, 8);
        Bu = rol(A[4][0] ^ Da, 18);
        Eka = Ba ^ (~Be & Bi);
        Eke = Be ^ (~Bi & Bo);
        Eki = Bi ^ (~Bo & Bu);
        Eko = Bo ^ (~Bu & Ba);
        Eku = Bu ^ (~Ba & Be);

        Ba = rol(A[0][4] ^ Du, 27);
        Be = rol(A[1][0] ^ Da, 36);
        Bi = rol(A[2][1] ^ De, 10);
        Bo = rol(A[3][2] ^ Di, 15);
        Bu = rol(A[4][3] ^ Do, 56);
        Ema = Ba ^ (~Be & Bi);
        Eme = Be ^ (~Bi & Bo);
        Emi = Bi ^ (~Bo & Bu);
        Emo = Bo ^ (~Bu & Ba);
        Emu = Bu ^ (~Ba & Be);

        Ba = rol(A[0][2] ^ Di, 62);
        Be = rol(A[1][3] ^ Do, 55);
        Bi = rol(A[2][4] ^ Du, 39);
        Bo = rol(A[3][0] ^ Da, 41);
        Bu = rol(A[4][1] ^ De, 2);
        Esa = Ba ^ (~Be & Bi);
        Ese = Be ^ (~Bi & Bo);
        Esi = Bi ^ (~Bo & Bu);
        Eso = Bo ^ (~Bu & Ba);
        Esu = Bu ^ (~Ba & Be);


        /* Round (round + 1): Exx -> A */

        Ba = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        Be = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        Bi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        Bo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        Bu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        Da = Bu ^ rol(Be, 1);
        De = Ba ^ rol(Bi, 1);
        Di = Be ^ rol(Bo, 1);
        Do = Bi ^ rol(Bu, 1);
        Du = Bo ^ rol(Ba, 1);

        Ba = Eba ^ Da;
        Be = rol(Ege ^ De, 44);
        Bi = rol(Eki ^ Di, 43);
        Bo = rol(Emo ^ Do, 21);
        Bu = rol(Esu ^ Du, 14);
        A[0][0] = Ba ^ (~Be & Bi) ^ round_constants[round + 1];
        A[0][1] = Be ^ (~Bi & Bo);
        A[0][2] = Bi ^ (~Bo & Bu);
        A[0][3] = Bo ^ (~Bu & Ba);
        A[0][4] = Bu ^ (~Ba & Be);

        Ba = rol(Ebo ^ Do, 28);
        Be = rol(Egu ^ Du, 20);
        Bi = rol(Eka ^ Da, 3);
        Bo = rol(Eme ^ De, 45);
        Bu = rol(Esi ^ Di, 61);
        A[1][0] = Ba ^ (~Be & Bi);
        A[1][1] = Be ^ (~Bi & Bo);
        A[1][2] = Bi ^ (~Bo & Bu);
        A[1][3] = Bo ^ (~Bu & Ba);
        A[1][4] = Bu ^ (~Ba & Be);

        Ba = rol(Ebe ^ De, 1);
        Be = rol(Egi ^ Di, 6);
        Bi = rol(Eko ^ Do, 25);
        Bo = rol(Emu ^ Du, 8);
        Bu = rol(Esa ^ Da, 18);
        A[2][0] = Ba ^ (~Be & Bi);
        A[2][1] = Be ^ (~Bi & Bo);
        A[2][2] = Bi ^ (~Bo & Bu);
        A[2][3] = Bo ^ (~Bu & Ba);
        A[2][4] = Bu ^ (~Ba & Be);

        Ba = rol(Ebu ^ Du, 27);
        Be = rol(Ega ^ Da, 36);
        Bi = rol(Eke ^ De, 10);
        Bo = rol(Emi ^ Di, 15);
        Bu = rol(Eso ^ Do, 56);
        A[3][0] = Ba ^ (~Be & Bi);
        A[3][1] = Be ^ (~Bi & Bo);
        A[3][2] = Bi ^ (~Bo & Bu);
        A[3][3] = Bo ^ (~Bu & Ba);
        A[3][4] = Bu ^ (~Ba & Be);

        Ba = rol(Ebi ^ Di, 62);
        Be = rol(Ego ^ Do, 55);
        Bi = rol(Eku ^ Du, 39);
        Bo = rol(Ema ^ Da, 41);
        Bu = rol(Ese ^ De, 2);
        A[4][0] = Ba ^ (~Be & Bi);
        A[4][1] = Be ^ (~Bi & Bo);
        A[4][2] = Bi ^ (~Bo & Bu);
        A[4][3] = Bo ^ (~Bu & Ba);
        A[4][4] = Bu ^ (~Ba & Be);
    }
}
