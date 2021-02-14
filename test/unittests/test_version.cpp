// vapash: C/C++ implementation of Vapash, the Vapory Proof of Work algorithm.
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include <vapash/version.h>

#include <gtest/gtest.h>

TEST(libvapash, version)
{
    static_assert(vapash::version[0] != 0, "incorrect vapash::version");

    EXPECT_EQ(VAPASH_VERSION, TEST_PROJECT_VERSION);
    EXPECT_EQ(vapash::version, TEST_PROJECT_VERSION);
}
