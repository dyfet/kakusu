// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#undef NDEBUG
#include "binary.hpp"
#include <cassert>

using namespace kakusu;

namespace {
void test_hex_codec() {
    const std::string_view src{"hello"};
    auto hex = to_hex(src);
    assert(hex == "68656C6C6F");
}
} // end namespace

auto main(int /* argc */, char ** /* argv */) -> int {
    try {
        test_hex_codec();
    } catch (...) {
        return -1;
    }
    return 0;
}
