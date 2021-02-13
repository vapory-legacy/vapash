# vapash: C/C++ implementation of Vapash, the Vapory Proof of Work algorithm.
# Copyright 2018 Pawel Bylica.
# Licensed under the Apache License, Version 2.0. See the LICENSE file.

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

set(include_dir ${PROJECT_SOURCE_DIR}/include)

add_library(
    vapash
    bit_manipulation.h
    builtins.h
    endianness.hpp
    ${include_dir}/vapash/vapash.h
    ${include_dir}/vapash/vapash.hpp
    vapash-internal.hpp
    vapash.cpp
    ${include_dir}/vapash/hash_types.h
    managed.cpp
    ${include_dir}/vapash/keccak.h
    ${include_dir}/vapash/keccak.hpp
    keccak.c
    keccakf800.c
    keccakf1600.c
    kiss99.hpp
    primes.h
    primes.c
    ${include_dir}/vapash/progpow.hpp
    progpow.cpp
)

target_include_directories(vapash PUBLIC $<BUILD_INTERFACE:${include_dir}>$<INSTALL_INTERFACE:include>)

write_basic_package_version_file(vapashConfigVersion.cmake COMPATIBILITY SameMajorVersion)

configure_package_config_file(
    ../../cmake/Config.cmake.in
    vapashConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vapash
)

install(
    TARGETS vapash
    EXPORT vapashTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(
    DIRECTORY
    ${include_dir}/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

if(VAPASH_INSTALL_CMAKE_CONFIG)
    install(
        EXPORT vapashTargets
        NAMESPACE vapash::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vapash
    )
    install(
        FILES
        ${CMAKE_CURRENT_BINARY_DIR}/vapashConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/vapashConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vapash
    )
endif()

get_filename_component(VAPASH_PRIVATE_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/.. ABSOLUTE)
set(VAPASH_PRIVATE_INCLUDE_DIR ${VAPASH_PRIVATE_INCLUDE_DIR} PARENT_SCOPE)