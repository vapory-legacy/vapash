// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018 Pawel Bylica.
// SPDX-License-Identifier: Apache-2.0

#include "../support/attributes.h"
#include <ethash/keccak.h>

#if defined(_MSC_VER)
#include <string.h>
#define __builtin_memcpy memcpy
#endif

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define to_le64(X) __builtin_bswap64(X)
#else
#define to_le64(X) X
#endif

/// Loads 64-bit integer from given memory location as little-endian number.
static inline ALWAYS_INLINE uint64_t load_le(const uint8_t* data)
{
    /* memcpy is the best way of expressing the intention. Every compiler will
       optimize is to single load instruction if the target architecture
       supports unaligned memory access (GCC and clang even in O0).
       This is great trick because we are violating C/C++ memory alignment
       restrictions with no performance penalty. */
    uint64_t word;
    __builtin_memcpy(&word, data, sizeof(word));
    return to_le64(word);
}

/// Rotates the bits of x left by the count value specified by s.
/// The s must be in range <0, 64> exclusively, otherwise the result is undefined.
static inline uint64_t rol(uint64_t x, unsigned s)
{
    return (x << s) | (x >> (64 - s));
}

static const uint64_t round_constants[24] = {  //
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};


/// The Keccak-f[1600] function.
///
/// The implementation of the Keccak-f function with 1600-bit width of the permutation (b).
/// The size of the state is also 1600 bit what gives 25 64-bit words.
///
/// @param state  The state of 25 64-bit words on which the permutation is to be performed.
///
/// The implementation based on:
/// - "simple" implementation by Ronny Van Keer, included in "Reference and optimized code in C",
///   https://keccak.team/archives.html, CC0-1.0 / Public Domain.
static inline ALWAYS_INLINE void keccakf1600_implementation(uint64_t A[25])
{
    uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
    uint64_t Ega, Ege, Egi, Ego, Egu;
    uint64_t Eka, Eke, Eki, Eko, Eku;
    uint64_t Ema, Eme, Emi, Emo, Emu;
    uint64_t Esa, Ese, Esi, Eso, Esu;

    uint64_t Ba, Be, Bi, Bo, Bu;

    uint64_t Da, De, Di, Do, Du;

    for (size_t n = 0; n < 24; n += 2)
    {
        // Round (n + 0): Axx -> Exx

        Ba = A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20];
        Be = A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21];
        Bi = A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22];
        Bo = A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23];
        Bu = A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24];

        Da = Bu ^ rol(Be, 1);
        De = Ba ^ rol(Bi, 1);
        Di = Be ^ rol(Bo, 1);
        Do = Bi ^ rol(Bu, 1);
        Du = Bo ^ rol(Ba, 1);

        Ba = A[0] ^ Da;
        Be = rol(A[6] ^ De, 44);
        Bi = rol(A[12] ^ Di, 43);
        Bo = rol(A[18] ^ Do, 21);
        Bu = rol(A[24] ^ Du, 14);
        Eba = Ba ^ (~Be & Bi) ^ round_constants[n];
        Ebe = Be ^ (~Bi & Bo);
        Ebi = Bi ^ (~Bo & Bu);
        Ebo = Bo ^ (~Bu & Ba);
        Ebu = Bu ^ (~Ba & Be);

        Ba = rol(A[3] ^ Do, 28);
        Be = rol(A[9] ^ Du, 20);
        Bi = rol(A[10] ^ Da, 3);
        Bo = rol(A[16] ^ De, 45);
        Bu = rol(A[22] ^ Di, 61);
        Ega = Ba ^ (~Be & Bi);
        Ege = Be ^ (~Bi & Bo);
        Egi = Bi ^ (~Bo & Bu);
        Ego = Bo ^ (~Bu & Ba);
        Egu = Bu ^ (~Ba & Be);

        Ba = rol(A[1] ^ De, 1);
        Be = rol(A[7] ^ Di, 6);
        Bi = rol(A[13] ^ Do, 25);
        Bo = rol(A[19] ^ Du, 8);
        Bu = rol(A[20] ^ Da, 18);
        Eka = Ba ^ (~Be & Bi);
        Eke = Be ^ (~Bi & Bo);
        Eki = Bi ^ (~Bo & Bu);
        Eko = Bo ^ (~Bu & Ba);
        Eku = Bu ^ (~Ba & Be);

        Ba = rol(A[4] ^ Du, 27);
        Be = rol(A[5] ^ Da, 36);
        Bi = rol(A[11] ^ De, 10);
        Bo = rol(A[17] ^ Di, 15);
        Bu = rol(A[23] ^ Do, 56);
        Ema = Ba ^ (~Be & Bi);
        Eme = Be ^ (~Bi & Bo);
        Emi = Bi ^ (~Bo & Bu);
        Emo = Bo ^ (~Bu & Ba);
        Emu = Bu ^ (~Ba & Be);

        Ba = rol(A[2] ^ Di, 62);
        Be = rol(A[8] ^ Do, 55);
        Bi = rol(A[14] ^ Du, 39);
        Bo = rol(A[15] ^ Da, 41);
        Bu = rol(A[21] ^ De, 2);
        Esa = Ba ^ (~Be & Bi);
        Ese = Be ^ (~Bi & Bo);
        Esi = Bi ^ (~Bo & Bu);
        Eso = Bo ^ (~Bu & Ba);
        Esu = Bu ^ (~Ba & Be);


        // Round (n + 1): Exx -> Axx

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
        A[0] = Ba ^ (~Be & Bi) ^ round_constants[n + 1];
        A[1] = Be ^ (~Bi & Bo);
        A[2] = Bi ^ (~Bo & Bu);
        A[3] = Bo ^ (~Bu & Ba);
        A[4] = Bu ^ (~Ba & Be);

        Ba = rol(Ebo ^ Do, 28);
        Be = rol(Egu ^ Du, 20);
        Bi = rol(Eka ^ Da, 3);
        Bo = rol(Eme ^ De, 45);
        Bu = rol(Esi ^ Di, 61);
        A[5] = Ba ^ (~Be & Bi);
        A[6] = Be ^ (~Bi & Bo);
        A[7] = Bi ^ (~Bo & Bu);
        A[8] = Bo ^ (~Bu & Ba);
        A[9] = Bu ^ (~Ba & Be);

        Ba = rol(Ebe ^ De, 1);
        Be = rol(Egi ^ Di, 6);
        Bi = rol(Eko ^ Do, 25);
        Bo = rol(Emu ^ Du, 8);
        Bu = rol(Esa ^ Da, 18);
        A[10] = Ba ^ (~Be & Bi);
        A[11] = Be ^ (~Bi & Bo);
        A[12] = Bi ^ (~Bo & Bu);
        A[13] = Bo ^ (~Bu & Ba);
        A[14] = Bu ^ (~Ba & Be);

        Ba = rol(Ebu ^ Du, 27);
        Be = rol(Ega ^ Da, 36);
        Bi = rol(Eke ^ De, 10);
        Bo = rol(Emi ^ Di, 15);
        Bu = rol(Eso ^ Do, 56);
        A[15] = Ba ^ (~Be & Bi);
        A[16] = Be ^ (~Bi & Bo);
        A[17] = Bi ^ (~Bo & Bu);
        A[18] = Bo ^ (~Bu & Ba);
        A[19] = Bu ^ (~Ba & Be);

        Ba = rol(Ebi ^ Di, 62);
        Be = rol(Ego ^ Do, 55);
        Bi = rol(Eku ^ Du, 39);
        Bo = rol(Ema ^ Da, 41);
        Bu = rol(Ese ^ De, 2);
        A[20] = Ba ^ (~Be & Bi);
        A[21] = Be ^ (~Bi & Bo);
        A[22] = Bi ^ (~Bo & Bu);
        A[23] = Bo ^ (~Bu & Ba);
        A[24] = Bu ^ (~Ba & Be);
    }
}

static void keccakf1600_generic(uint64_t state[25])
{
    keccakf1600_implementation(state);
}

/// The pointer to the best Keccak-f[1600] function implementation,
/// selected during runtime initialization.
static void (*keccakf1600_best)(uint64_t[25]) = keccakf1600_generic;


#if defined(__x86_64__) && __has_attribute(target)
__attribute__((target("bmi,bmi2"))) static void keccakf1600_bmi(uint64_t state[25])
{
    keccakf1600_implementation(state);
}

__attribute__((constructor)) static void select_keccakf1600_implementation()
{
    if (__builtin_cpu_supports("bmi2"))
        keccakf1600_best = keccakf1600_bmi;
}
#endif


static inline ALWAYS_INLINE void keccak(
    uint64_t* out, size_t bits, const uint8_t* data, size_t size)
{
    static const size_t word_size = sizeof(uint64_t);
    const size_t hash_size = bits / 8;
    const size_t block_size = (1600 - bits * 2) / 8;

    size_t i;
    uint64_t* state_iter;
    uint64_t last_word = 0;
    uint8_t* last_word_iter = (uint8_t*)&last_word;

    uint64_t state[25] = {0};

    while (size >= block_size)
    {
        for (i = 0; i < (block_size / word_size); ++i)
        {
            state[i] ^= load_le(data);
            data += word_size;
        }

        keccakf1600_best(state);

        size -= block_size;
    }

    state_iter = state;

    while (size >= word_size)
    {
        *state_iter ^= load_le(data);
        ++state_iter;
        data += word_size;
        size -= word_size;
    }

    while (size > 0)
    {
        *last_word_iter = *data;
        ++last_word_iter;
        ++data;
        --size;
    }
    *last_word_iter = 0x01;
    *state_iter ^= to_le64(last_word);

    state[(block_size / word_size) - 1] ^= 0x8000000000000000;

    keccakf1600_best(state);

    for (i = 0; i < (hash_size / word_size); ++i)
        out[i] = to_le64(state[i]);
}

union ethash_hash256 ethash_keccak256(const uint8_t* data, size_t size)
{
    union ethash_hash256 hash;
    keccak(hash.word64s, 256, data, size);
    return hash;
}

union ethash_hash256 ethash_keccak256_32(const uint8_t data[32])
{
    union ethash_hash256 hash;
    keccak(hash.word64s, 256, data, 32);
    return hash;
}

union ethash_hash512 ethash_keccak512(const uint8_t* data, size_t size)
{
    union ethash_hash512 hash;
    keccak(hash.word64s, 512, data, size);
    return hash;
}

union ethash_hash512 ethash_keccak512_64(const uint8_t data[64])
{
    union ethash_hash512 hash;
    keccak(hash.word64s, 512, data, 64);
    return hash;
}
