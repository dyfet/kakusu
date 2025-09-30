// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#define KAKUSU_CRYPTO_SODIUM

#undef NDEBUG
#include "hash.hpp"
#include <cassert>

using namespace kakusu;

namespace {
void test_random_keygen() {
    aes256_key_t b1, b2;
    assert(init_key(b1));
    assert(init_key(b2));
    assert(b1 != b2);

    salt_t s1, s2;
    assert(init_salt(s1));
    assert(init_salt(s2));
}

void test_hash_ring() {
    ring64<> ring;
    assert(ring.insert("nodeA"));
    assert(ring.insert("nodeB"));
    assert(ring.insert("nodeC"));
    assert(ring.size() == 3);
    assert(ring.usage() > 200);

    const std::string key = "user:67";
    assert(ring.get(key) == "nodeC");

    assert(ring.remove("nodeB"));
    assert(!ring.remove("nodeD"));
    assert(ring.usage() <= 200);
}
} // end namespace

auto main(int /* argc */, char ** /* argv */) -> int {
    try {
        startup();
        test_random_keygen();
        test_hash_ring();
    } catch (...) {
        return -1;
    }
    return 0;
}
