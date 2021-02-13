# Copyright 2018 Pawel Bylica.
# Licensed under the Apache License, Version 2.0. See the LICENSE file.

cmake_minimum_required(VERSION 3.5)

project(vapash-cmake-config-test)

find_package(vapash CONFIG REQUIRED)

add_executable(vapash-cmake-config-test cmake_config_test.cpp)
target_link_libraries(vapash-cmake-config-test vapash::vapash)
set_target_properties(vapash-cmake-config-test PROPERTIES CXX_STANDARD 11 CXX_EXTENSIONS OFF)
