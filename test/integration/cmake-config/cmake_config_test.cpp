// vapash: C/C++ implementation of Vapash, the Vapory Proof of Work algorithm.
// Copyright 2018 Pawel Bylica.
// Licensed under the Apache License, Version 2.0. See the LICENSE file.

#include <vapash/vapash.hpp>

int main()
{
    uint8_t seed_bytes[32] = {0};
    vapash::hash256 seed = vapash::hash256_from_bytes(seed_bytes);
    return vapash::find_epoch_number(seed);
}
