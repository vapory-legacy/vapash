# vapash: C/C++ implementation of Vapash, the Vapory Proof of Work algorithm.
# Copyright 2018 Pawel Bylica.
# Licensed under the Apache License, Version 2.0. See the LICENSE file.

hunter_add_package(GTest)
find_package(GTest CONFIG REQUIRED)

add_executable(
    vapash-test
    helpers.hpp
    test_bit_manipulation.cpp
    test_cases.hpp
    test_vapash.cpp
    test_keccak.cpp
    test_kiss.cpp
    test_managed.cpp
    test_primes.cpp
    test_progpow.cpp
    test_version.cpp
)

set_source_files_properties(test_version.cpp PROPERTIES COMPILE_DEFINITIONS TEST_PROJECT_VERSION="${PROJECT_VERSION}")

target_link_libraries(vapash-test PRIVATE vapash GTest::gtest GTest::main)
target_include_directories(vapash-test PRIVATE ${VAPASH_PRIVATE_INCLUDE_DIR})
set_target_properties(vapash-test PROPERTIES RUNTIME_OUTPUT_DIRECTORY ..)
