// Copyright (C) 2025 Tycho Softworks.
// This code is licensed under MIT license.

#undef NDEBUG
#include "binary.hpp"
#include <cassert>

using namespace kakusu;

namespace {
void test_hex_codec() {
    const byte_array src{"hello", 5};
    auto hex = src.to_hex();
    assert(hex == "68656C6C6F");

    auto restored = byte_array::from_hex(hex);
    assert(restored == src);
}

void test_b64_codec() {
    const byte_array src{"world", 5};
    auto b64 = src.to_string(); // uses b64 now
    assert(b64 == "d29ybGQ=");

    auto restored = byte_array::from_b64(b64);
    assert(restored == src);
}

void test_subspan_and_view_mutation() {
    const byte_array arr{"foobar", 6};
    auto sub = arr.subview(3, 3); // "bar"
    assert(sub.size() == 3);
    assert(sub[0] == 'b');
}

void test_swap_and_slice() {
    byte_array a{"123456", 6};
    byte_array b{"ABCDEF", 6};
    a.swap(b);

    assert(a.to_hex() == "414243444546"); // hex of "ABCDEF"
    assert(b.to_hex() == "313233343536"); // hex of "123456"

    auto sliced = a.slice(1, 4);
    assert(sliced.to_hex() == "424344");
}

void test_invalid_decode_inputs() {
    try {
        byte_array::from_hex("ABC"); // odd length
        assert(false && "Should throw on odd hex length");
    } catch (const std::invalid_argument&) {} // NOLINT

    try {
        byte_array::from_b64("****"); // breaks trigraph interpretation
        assert(false && "Should throw on bad b64");
    } catch (const std::invalid_argument&) {} // NOLINT
}
} // end namespace

auto main(int /* argc */, char ** /* argv */) -> int {
    try {
        test_hex_codec();
        test_b64_codec();
        test_subspan_and_view_mutation();
        test_swap_and_slice();
        test_invalid_decode_inputs();
    } catch (...) {
        return -1;
    }
    return 0;
}
