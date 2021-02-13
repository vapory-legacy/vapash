// vapash: C/C++ implementation of Vapash, the Vapory Proof of Work algorithm.
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0. See the LICENSE file.

#pragma once

#include <vapash/keccak.h>
#include <vapash/hash_types.hpp>

namespace vapash
{
inline hash256 keccak256(const uint8_t* data, size_t size) noexcept
{
    return vapash_keccak256(data, size);
}

inline hash256 keccak256(const hash256& input) noexcept
{
    return vapash_keccak256_32(input.bytes);
}

inline hash512 keccak512(const uint8_t* data, size_t size) noexcept
{
    return vapash_keccak512(data, size);
}

inline hash512 keccak512(const hash512& input) noexcept
{
    return vapash_keccak512_64(input.bytes);
}

static constexpr auto keccak256_32 = vapash_keccak256_32;
static constexpr auto keccak512_64 = vapash_keccak512_64;

}  // namespace vapash
