# vapash: C/C++ implementation of Vapash, the Vapory Proof of Work algorithm.
# Copyright 2018 Pawel Bylica.
# Licensed under the Apache License, Version 2.0. See the LICENSE file.

file(GLOB c_sources ${PROJECT_SOURCE_DIR}/lib/vapash/*.c)

foreach(c_std 0 90 99 11)
    set(target test-compile-c${c_std})
    add_library(${target} STATIC vapash_header_test.c ${c_sources})
    target_link_libraries(${target} PRIVATE vapash)
    if(c_std)
        set_target_properties(${target} PROPERTIES C_STANDARD ${c_std})
    endif()
    set_target_properties(${target} PROPERTIES C_EXTENSIONS OFF)
endforeach()
