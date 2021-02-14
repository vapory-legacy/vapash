/* vapash: C/C++ implementation of Vapash, the Vapory Proof of Work algorithm.
 * Copyright 2018 Pawel Bylica.
 * Licensed under the Apache License, Version 2.0. See the LICENSE file.
 */

#include <vapash/vapash.h>

int test()
{
    int sum = 0;
    sum += VAPASH_EPOCH_LENGTH;
    sum += VAPASH_LIGHT_CACHE_ITEM_SIZE;
    sum += VAPASH_FULL_DATASET_ITEM_SIZE;
    return sum;
}
