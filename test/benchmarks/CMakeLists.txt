# vapash: C/C++ implementation of Vapash, the Vapory Proof of Work algorithm.
# Copyright 2018 Pawel Bylica.
# Licensed under the Apache License, Version 2.0. See the LICENSE file.

hunter_add_package(benchmark)
find_package(benchmark CONFIG REQUIRED)

add_executable(vapash-bench
    vapash_benchmarks.cpp
    keccak_benchmarks.cpp
    keccak_utils.hpp
    keccak_utils.cpp
    managed_benchmarks.cpp
    progpow_benchmarks.cpp
    threadsync_benchmarks.cpp
    threadsync_utils.hpp
    threadsync_utils.cpp)
target_link_libraries(vapash-bench PRIVATE vapash benchmark::benchmark)
target_include_directories(vapash-bench PRIVATE ${VAPASH_PRIVATE_INCLUDE_DIR})
set_target_properties(vapash-bench PROPERTIES RUNTIME_OUTPUT_DIRECTORY ..)
