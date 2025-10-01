# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

cmake_minimum_required(VERSION 3.16.0)
project(Kakusu VERSION 0.2.1 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)

file(
    GLOB LINT_SOURCES
    RELATIVE ${PROJECT_SOURCE_DIR}
    src/*.hpp src/*.cpp test/*.cpp)

include(cmake/custom.cmake OPTIONAL)
include(cmake/project.cmake)
include(cmake/features.cmake)
include(cmake/coverage.cmake)
include(cmake/linting.cmake)
include(cmake/deploy.cmake OPTIONAL)

file(GLOB optional .git[a-z]* *.json *.in *.yml .clang* cmake/*)
file(GLOB markdown *.md)
file(GLOB headers CONFIGURE_DEPENDS src/*.hpp)
file(GLOB sources CONFIGURE_DEPENDS src/*.cpp)
file(GLOB extras CONFIGURE_DEPENDS extra/*.hpp)

# Setup headers
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/kakusu.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/kakusu.pc
    @ONLY
)


# Testing
enable_testing()

add_executable(test_binary test/binary.cpp src/binary.hpp)
add_test(NAME test-binary COMMAND test_binary)
target_link_libraries(test_binary)

if(OPENSSL_FOUND)
add_executable(test_openssl test/openssl.cpp src/crypto.hpp)
add_test(NAME test-openssl COMMAND test_openssl)
target_link_libraries(test_openssl PRIVATE OpenSSL::Crypto)
endif()

if(WOLFSSL_FOUND)
add_executable(test_wolfssl test/wolfssl.cpp src/crypto.hpp)
add_test(NAME test-wolfssl COMMAND test_wolfssl)
target_link_libraries(test_wolfssl PRIVATE ${WOLFSSL_LIBRARIES})
endif()

if(SODIUM_FOUND)
add_executable(test_sodium test/sodium.cpp src/crypto.hpp)
add_test(NAME test-sodium COMMAND test_sodium)
target_link_libraries(test_sodium PRIVATE ${SODIUM_LIBRARIES})
endif()

if(MINICRYPT_FOUND)
add_executable(test_minicrypt test/minicrypt.cpp src/crypto.hpp)
add_test(NAME test-minicrypt COMMAND test_minicrypt)
target_link_libraries(test_minicrypt PRIVATE ${MINICRYPT_LIBRARIES})
endif()

# Extras amd install...
add_custom_target(header-files SOURCES ${headers} ${extras})
add_custom_target(support-files SOURCES ${markdown} ${optional})

install(FILES ${headers} ${extras}  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/kakusu")

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/kakusu.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

