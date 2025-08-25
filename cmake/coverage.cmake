# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

set(REMOVE_COVERAGE "'/usr/*'")
list(APPEND REMOVE_COVERAGE "'*/test/test_*'")

if(COVERAGE_TYPE MATCHES "gcov" AND CMAKE_BUILD_TYPE MATCHES "Debug")
    set(BUILD_TESTING true)
    set(CMAKE_CXX_OUTPUT_EXTENSION_REPLACE 1)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fprofile-arcs -ftest-coverage")

    add_custom_target(coverage
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMAND rm -f *.gcov coverage.info
        COMMAND find . -type f -name "*.gcno" -delete
        COMMAND find . -type f -name "*.gcda" -delete
        COMMAND ${CMAKE_COMMAND} --build . --target clean --config $<CONFIG>
        COMMAND ${CMAKE_COMMAND} --build . --config $<CONFIG>
        COMMAND ctest
        COMMAND lcov -q -c -d . -o active.info
        COMMAND lcov -q -c -i -d . -o initial.info >/dev/null
        COMMAND lcov -q -a initial.info -a active.info -o coverage.info
        COMMAND lcov -q -r coverage.info ${REMOVE_COVERAGE} -o coverage.info
        COMMAND lcov --summary coverage.info
        COMMAND rm -f initial.info active.info
    )
endif()
