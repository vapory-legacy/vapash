// vapash: C/C++ implementation of Vapash, the Vapory Proof of Work algorithm.
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0. See the LICENSE file.

#include <vapash/vapash.hpp>
#include <vapash/version.h>

int main()
{
    static_assert(sizeof(vapash::version) >= 6, "incorrect vapash::version");

    uint8_t seed_bytes[32] = {0};
    vapash::hash256 seed = vapash::hash256_from_bytes(seed_bytes);
    return vapash::find_epoch_number(seed);
}
