// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#define KAKUSU_CRYPTO_OPENSSL

#undef NDEBUG
#include "ring.hpp"
#include "legacy.hpp"
#include <cassert>

using namespace kakusu;

namespace {
void test_random_keygen() {
    aes256_key_t b1, b2;
    memset(b1.data(), 0, sizeof(b1));
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

void test_digest_stream() {
    digest_stream sha256;
    sha256 << "hello";
    auto hex = to_hex(sha256);
    sha256_digest_t verify;
    assert(init_digest(verify, std::string_view("hello")));
    auto out = verify.to_hex();
    assert(!verify.empty());
    assert(out == hex);
}
} // end namespace

auto main(int /* argc */, char ** /* argv */) -> int {
    try {
        startup();
        test_random_keygen();
        test_hash_ring();
        test_digest_stream();
    } catch (...) {
        return -1;
    }
    return 0;
}
