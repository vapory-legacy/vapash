# ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
# Copyright 2018 Pawel Bylica.
# Licensed under the Apache License, Version 2.0. See the LICENSE file.
#
#if(CABLE_COMPILER_CLANG)
#    set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=fuzzer,undefined ${CMAKE_EXE_LINKER_FLAGS}")
#    set(CMAKE_CXX_FLAGS "-g -fsanitize=fuzzer,address ${CMAKE_CXX_FLAGS}")
#endif()

add_executable(ethash-fuzzer fuzzer.cpp)
target_link_libraries(ethash-fuzzer PRIVATE ethash)
if(CABLE_COMPILER_CLANG)
#    target_compile_options(ethash-fuzzer PRIVATE -fsanitize=fuzzer,undefined,integer,nullability)
#    set_target_properties(ethash-fuzzer PROPERTIES LINK_FLAGS -fsanitize=fuzzer,undefined,integer,nullability)
endif()
