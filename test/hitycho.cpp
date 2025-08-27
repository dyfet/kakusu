// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#define KAKUSU_CRYPTO_OPENSSL
#define KAKUSU_RUNTIME_HITYCHO

#undef NDEBUG
#include "hash.hpp"
#include "legacy.hpp"
#include <cassert>

using namespace kakusu;
using namespace hitycho;

namespace {
void test_random_openssl() {
    byte_array b1(20);
    byte_array b2(20);
    random_context rng;
    rng.fill(b1);
    rng.fill(b2);
    assert(b1 != b2);
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
    digest_stream<sha256_t> digest;
    digest << "hello";
    auto hex = to_hex(digest);
    auto verify = kakusu::make_sha256(std::string_view("hello"));
    auto out = verify.to_hex();
    assert(out == hex);
}
} // end namespace

// cppcheck-suppress constParameterReference
auto hpx_main(hpx::program_options::variables_map& args) -> int { // NOLINT
    try {
        startup();
        test_random_openssl();
        test_hash_ring();
        test_digest_stream();
    } catch (...) {
        hpx::finalize();
        exit(-1);
    }
    return hpx::finalize();
    ;
}

auto main(int argc, char *argv[]) -> int {
    return hpx::init(argc, argv);
}
