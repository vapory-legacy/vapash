# vapash: C/C++ implementation of Vapash, the Vapory Proof of Work algorithm.
# Copyright 2018 Pawel Bylica.
# Licensed under the Apache License, Version 2.0. See the LICENSE file.

find_package(Threads)

add_executable(vapash-fakeminer fakeminer.cpp)
target_link_libraries(vapash-fakeminer PRIVATE vapash Threads::Threads)
set_target_properties(vapash-fakeminer PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
