# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

include(CheckCXXSourceCompiles)
include(CheckIncludeFileCXX)
include(CheckFunctionExists)
include(FindPkgConfig)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(OpenSSL)
pkg_check_modules(SODIUM libsodium)
pkg_check_modules(WOLFSSL wolfssl)
pkg_check_modules(MINICRYPT minicrypt)
pkg_check_modules(BUSUTO busuto)
pkg_check_modules(HITYCHO hitycho)

if(HITYCHO_FOUND)
    find_package(HPX)
    if(HPX_FOUND)
        pkg_check_modules(HPX_APPLICATION REQUIRED hpx_application)
    endif()
endif()

if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(BUILD_DEBUG true)
    add_compile_definitions(DEBUG=1)
else()
    add_compile_definitions(NDEBUG=1)
endif()
