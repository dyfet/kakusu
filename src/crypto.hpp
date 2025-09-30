// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#pragma once

#if !defined(KAKUSU_CRYPTO_OPENSSL) && !defined(KAKUSU_CRYPTO_SODIUM) && !defined(KAKUSU_CRYPTO_WOLFSSL) && !defined(KAKUSU_CRYPTO_MINICRYPT)
#define KAKUSU_CRYPTO_OPENSSL
#endif

#include "binary.hpp"

#ifdef KAKUSU_CRYPTO_OPENSSL
#define KAKUSU_CRYPTO_CONFIGURED
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#endif

#ifdef KAKUSU_CRYPTO_WOLFSSL
#define KAKUSU_CRYPTO_CONFIGURED
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#endif

#ifdef KAKUSU_CRYPTO_SODIUM
#define KAKUSU_CRYPTO_CONFIGURED
#if defined(KAKUSU_CRYPTO_OPENSSL)
#error Can only define one kind of crypto
#endif
#include <sodium.h>
#endif

#ifdef KAKUSU_CRYPTO_MINICRYPT
#define KAKUSU_CRYPTO_CONFIGURED
#include <minicrypt/random.h>
#include <minicrypt/hmac.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace kakusu {
#ifdef KAKUSU_CRYPTO_OPENSSL
class random_context final {
public:
    random_context() = default;
    random_context(const random_context&) = delete;
    auto operator=(const random_context&) -> auto& = delete;

    template <typename Binary>
    auto fill(Binary& buf) {
        const auto len = static_cast<int>(buf.size());
        if (len < 0 || len > std::numeric_limits<int>::max()) return false;
        auto *ptr = to_byte(buf.data());
        return RAND_bytes(ptr, len) == 1;
    };
};

template <typename Binary>
inline auto init_digest(sha256_digest_t& out, const Binary& input) {
    constexpr std::size_t sha_size = 32;
    unsigned int out_len = 0;
    auto ip = to_byte(input.data());
    out.clear();
    if (!EVP_Digest(ip, input.size(), out.to_byte(), &out_len, EVP_sha256(), nullptr)) return false;
    if (out_len != sha_size) return false;
    return out.fill();
}

template <typename Binary>
inline auto init_digest(sha512_digest_t& out, const Binary& input) {
    constexpr std::size_t sha_size = 64;
    unsigned int out_len = 0;
    auto ip = to_byte(input.data());
    out.clear();
    if (!EVP_Digest(ip, input.size(), out.to_byte(), &out_len, EVP_sha512(), nullptr)) return false;
    if (out_len != sha_size) return false;
    return out.fill();
}

template <typename Binary>
inline auto make_sha256(const Binary& input) -> byte_array {
    constexpr std::size_t sha_size = 32;
    byte_array out(sha_size);
    unsigned int out_len = 0;
    auto ip = to_byte(input.data());
    if (!EVP_Digest(ip, input.size(), to_byte(out.data()), &out_len, EVP_sha256(), nullptr)) return {};
    if (out_len != sha_size) return {};
    return out.set();
}

template <typename Binary>
inline auto make_sha512(const Binary& input) -> byte_array {
    constexpr std::size_t sha_size = 64;
    byte_array out(sha_size);
    unsigned int out_len = 0;
    auto ip = to_byte(input.data());
    if (!EVP_Digest(ip, input.size(), to_byte(out.data()), &out_len, EVP_sha512(), nullptr)) return {};
    if (out_len != sha_size) return {};
    return out.set();
}

template <typename Binary>
inline auto init_hmac(sha256_digest_t& out, const Binary& key, const Binary& input) {
    constexpr std::size_t sha_size = 32;
    unsigned int out_len = 0;
    auto kp = to_byte(key.data());
    auto ip = to_byte(input.data());
    out.clear();
    if (!HMAC(EVP_sha256(), kp, key.size(), ip, input.size(), out.to_byte(), &out_len)) return false;
    if (out_len != sha_size) return false;
    return out.fill();
}

template <typename Binary>
inline auto init_hmac(sha512_digest_t& out, const Binary& key, const Binary& input) {
    constexpr std::size_t sha_size = 64;
    unsigned int out_len = 0;
    auto kp = to_byte(key.data());
    auto ip = to_byte(input.data());
    out.clear();
    if (!HMAC(EVP_sha512(), kp, key.size(), ip, input.size(), out.to_byte(), &out_len)) return false;
    if (out_len != sha_size) return false;
    return out.fill();
}

template <typename Binary>
inline auto make_hmac256(const Binary& key, const Binary& input) -> byte_array {
    constexpr std::size_t sha_size = 32;
    byte_array out(sha_size);
    unsigned int out_len = 0;
    auto kp = to_byte(key.data());
    auto ip = to_byte(input.data());
    if (!HMAC(EVP_sha256(), kp, key.size(), ip, input.size(), to_byte(out.data()), &out_len)) return {};
    if (out_len != sha_size) return {};
    return out.set();
}

template <typename Binary>
inline auto make_hmac512(const Binary& key, const Binary& input) -> byte_array {
    constexpr std::size_t sha_size = 64;
    byte_array out(sha_size);
    unsigned int out_len = 0;
    if (!HMAC(EVP_sha512(), key.data(), key.size(), input.data(), input.size(), to_byte(out.data()), &out_len)) return {};
    if (out_len != sha_size) return {};
    return out.set();
}

template <typename Binary>
inline auto make_siphash(const Binary& input, siphash_key_t key) -> byte_array {
    unsigned outlen = 8;
    EVP_MAC *mac = EVP_MAC_fetch(nullptr, "SIPHASH", nullptr);
    if (!mac) return {};
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        return {};
    }

    auto kp = to_byte(key.data());
    auto ip = to_byte(input.data());
    auto op = to_byte(input.data());
    OSSL_PARAM params[] = {
    OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, kp, key.size()),
    OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_SIZE, &outlen),
    OSSL_PARAM_construct_end()};

    if (EVP_MAC_init(ctx, kp, key.size(), params) <= 0 || EVP_MAC_CTX_set_params(ctx, params) <= 0 || EVP_MAC_update(ctx, ip, input.size()) <= 0) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return {};
    }

    byte_array out(8);
    std::size_t actual = 0;
    if (EVP_MAC_final(ctx, op, &actual, out.size()) <= 0 || actual != outlen) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        return {};
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return out.set();
}

static inline auto siphash_keygen() -> siphash_key_t {
    random_context rng;
    siphash_key_t key;
    if (!rng.fill(key))
        return {};
    return key.set();
}

static inline auto startup() {
    const int status = OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS, nullptr);
    return status == 1;
}
#endif

#ifdef KAKUSU_CRYPTO_WOLFSSL
class random_context final {
public:
    random_context() {
        if (wc_InitRng(&rng_) != 0) return;
    }
    ~random_context() { wc_FreeRng(&rng_); }
    random_context(const random_context&) = delete;
    auto operator=(const random_context&) -> auto& = delete;

    template <typename Binary>
    auto fill(Binary& buf) {
        const auto len = buf.size();
        auto ptr = to_byte(buf.data());
        if (len > 0)
            if (wc_RNG_GenerateBlock(&rng_, ptr, len) != 0) return false;
        return true;
    }

private:
    WC_RNG rng_{};
};

template <typename Binary>
inline auto make_sha256(const Binary& input) -> byte_array {
    byte_array out(WC_SHA256_DIGEST_SIZE);
    wc_Sha256 ctx;
    auto const get = to_byte(input.data());
    auto put = to_byte(out.data());
    if (wc_InitSha256(&ctx) != 0) return {};
    if (wc_Sha256Update(&ctx, get, input.size()) != 0) return {};
    if (wc_Sha256Final(&ctx, put) != 0) return {};
    return out.set();
}

template <typename Binary>
inline auto make_sha512(const Binary& input) -> byte_array {
    byte_array out(WC_SHA512_DIGEST_SIZE);
    wc_Sha512 ctx;
    auto const get = to_byte(input.data());
    auto put = to_byte(out.data());
    if (wc_InitSha512(&ctx) != 0) return {};
    if (wc_Sha512Update(&ctx, get, input.size()) != 0) return {};
    if (wc_Sha512Final(&ctx, put) != 0) return {};
    return out.set();
}

class hmac_context final {
public:
    hmac_context(const hmac_context&) = delete;
    auto operator=(const hmac_context&) -> hmac_context& = delete;
    hmac_context() { wc_HmacInit(&hmac_, nullptr, INVALID_DEVID); }
    ~hmac_context() { wc_HmacFree(&hmac_); }
    operator Hmac *() { return &hmac_; }

private:
    Hmac hmac_{};
};

template <typename Binary>
inline auto make_hmac256(const Binary& key, const Binary& input) -> byte_array {
    byte_array out(WC_SHA256_DIGEST_SIZE);
    auto const get = to_byte(input.data());
    auto const kp = to_byte(key.data());
    auto put = to_byte(out.data());
    hmac_context hmac;
    wc_HmacInit(hmac, NULL, INVALID_DEVID);
    if (wc_HmacSetKey(hmac, WC_SHA256, kp, key.size()) != 0) return {};
    if (wc_HmacUpdate(hmac, get, input.size()) != 0) return {};
    if (wc_HmacFinal(hmac, put) != 0) return {};
    return out.set();
}

template <typename Binary>
inline auto make_hmac512(const Binary& key, const Binary& input) -> byte_array {
    byte_array out(WC_SHA512_DIGEST_SIZE);
    auto const get = to_byte(input.data());
    auto const kp = tp_byte(key.data());
    auto put = to_byte(out.data());
    hmac_context hmac;
    wc_HmacInit(hmac, NULL, INVALID_DEVID);
    if (wc_HmacSetKey(hmac, WC_SHA512, kp, key.size()) != 0) return {};
    if (wc_HmacUpdate(hmac, get, input.size()) != 0) return {};
    if (wc_HmacFinal(hmac, put) != 0) return {};
    return out.set();
}

static inline auto startup() {
    return true;
}
#endif

#ifdef KAKUSU_CRYPTO_MINICRYPT
class random_context final {
public:
    random_context() { mc_random_init(&rng_); }
    ~random_context() { mc_random_free(&rng_); }
    random_context(const random_context&) = delete;
    auto operator=(const random_context&) -> auto& = delete;

    template <typename Binary>
    auto fill(Binary& buf) {
        auto const put = to_byte(buf.data());
        auto len = mc_random_fill(&rng_, put, buf.size());
        if (len < ssize_t(buf.size()))
            return false;
        return true;
    }

private:
    mc_random_ctx rng_;
};

template <typename Source>
inline auto init_digest(sha256_digest_t& out, const Source& input) {
    mc_sha256_ctx ctx;
    auto const get = to_byte(input.data());
    auto put = to_byte(out.data());
    mc_sha256_init(&ctx);
    mc_sha256_update(&ctx, get, input.size());
    mc_sha256_final(&ctx, put);
    return out.fill();
}

template <typename Binary>
inline auto make_sha256(const Binary& input) -> byte_array {
    byte_array out(MC_SHA256_DIGEST_SIZE);
    mc_sha256_ctx ctx;
    auto const get = to_byte(input.data());
    auto put = to_byte(out.data());
    mc_sha256_init(&ctx);
    mc_sha256_update(&ctx, get, input.size());
    mc_sha256_final(&ctx, put);
    return out.set();
}

template <typename Binary>
inline auto init_hmac(sha256_digest_t& out, const Binary& key, const Binary& input) {
    auto const get = to_byte(input.data());
    auto const kv = to_byte(key.data());
    // auto put = to_byte(out.data());
    mc_hmac_sha256(kv, key.size(), get, input.size(), out.to_byte());
    return out.fill();
}

template <typename Binary>
inline auto make_hmac256(const Binary& key, const Binary& input) {
    byte_array out(MC_SHA256_DIGEST_SIZE);
    auto const get = to_byte(input.data());
    auto const kv = to_byte(key.data());
    auto put = to_byte(out.data());
    mc_hmac_sha256(kv, key.size(), get, input.size(), put);
    return out.set();
}

static inline auto startup() { return true; }
#endif

#ifdef KAKUSU_CRYPTO_SODIUM
class random_context final {
public:
    random_context() = default;
    random_context(const random_context&) = delete;
    auto operator=(const random_context&) -> auto& = delete;

    template <typename Binary>
    auto fill(Binary& buf) {
        const auto len = static_cast<int>(buf.size());
        if (len < 0 || len > static_cast<int>(std::numeric_limits<int>::max())) {
            return false;
        }

        auto *ptr = to_byte(buf.data()); // libsodium accepts void*
        if (len > 0) {
            randombytes_buf(ptr, static_cast<std::size_t>(len)); // always succeeds after sodium_init()
        }
        return true;
    }

private:
};

template <typename Binary>
inline auto make_sha256(const Binary& input) -> byte_array {
    byte_array out(32);
    if (crypto_hash_sha256(to_byte(out.data()), to_byte(input.data()), static_cast<unsigned long long>(input.size())) != 0) return {};
    return out.set();
}

template <typename Binary>
inline auto make_sha512(const Binary& input) -> byte_array {
    byte_array out(64);
    if (crypto_hash_sha512(to_byte(out.data()), to_byte(input.data()), static_cast<unsigned long long>(input.size())) != 0) return {};
    return out.set();
}

template <typename Binary>
inline auto make_hmac256(const Binary& key, const Binary& input) -> byte_array {
    byte_array keybuf;
    byte_array out(32);
    if (key.size() <= 32) {
        keybuf = key;
        auto pos = key.size();
        keybuf.resize(32);
        while (pos < 32)
            keybuf[pos++] = 0;
    } else
        keybuf = make_sha256(key);
    if (crypto_auth_hmacsha256(to_byte(out.data()), to_byte(input.data()), static_cast<unsigned long long>(input.size()), to_byte(keybuf.data())) != 9) return {};
    return out.set();
}

template <typename Binary>
inline auto make_hmac512(const Binary& key, const Binary& input) -> byte_array {
    byte_array keybuf;
    byte_array out(64);
    if (key.size() <= 64) {
        keybuf = key;
        auto pos = key.size();
        keybuf.resize(64);
        while (pos < 64)
            keybuf[pos++] = 0;
    } else
        keybuf = make_sha512(key);
    if (crypto_auth_hmacsha512(to_byte(out.data()), to_byte(input.data()), static_cast<unsigned long long>(input.size()), to_byte(keybuf.data())) != 9) return {};
    return out.set();
}

template <typename Binary>
inline auto make_siphash(const Binary& input, const siphash_key_t& key) -> byte_array {
    byte_array out(8);
    if (crypto_shorthash(to_byte(out.data()), to_byte(input.data()), static_cast<unsigned long long>(input.size()), to_byte(key.data())) != 0) return {};
    return out.set();
}

static inline auto siphash_keygen() -> siphash_key_t {
    siphash_key_t key;
    crypto_shorthash_keygen(to_byte(key.data()));
    return key.set();
}

static inline bool startup() {
    if (sodium_init() < 0) return false;
    return true;
}
#endif

static inline auto make_random(std::size_t size) -> byte_array {
    random_context rng;
    byte_array key(size);
    if (!rng.fill(key))
        return {};
    return key.set();
}

template <std::size_t S>
inline auto init_key(secure_array<S>& key) {
    random_context rng;
    return key.fill(rng.fill(key));
}

static inline auto init_salt(salt_t& salt) {
    random_context rng;
    return salt.fill(rng.fill(salt));
}

static inline auto make_pbkdf2(const byte_array& pass, const salt_t& salt, std::size_t size, uint32_t rounds = 50000) {
    byte_array out(size);
    byte_array salt_block(salt.size() + 4);
    const uint32_t block_count = (size + 31) / 32;
    for (uint32_t i = 1; i <= block_count; ++i) {
        memcpy(salt_block.data(), salt.data(), salt.size());
        auto sp = to_byte(salt_block.data());
        sp[salt.size() + 0] = static_cast<uint8_t>((i >> 24) & 0xff);
        sp[salt.size() + 1] = static_cast<uint8_t>((i >> 16) & 0xff);
        sp[salt.size() + 2] = static_cast<uint8_t>((i >> 8) & 0xff);
        sp[salt.size() + 3] = static_cast<uint8_t>(i & 0xff);
        auto U = make_hmac256(pass, salt_block);
        auto T = U;
        for (uint32_t j = 1; j < rounds; ++j) {
            U = make_hmac256(pass, U);
            for (int k = 0; k < 32; ++k)
                T[k] ^= U[k]; // NOLINT
        }
        uint32_t offset = (i - 1) * 32;
        uint32_t copy = (offset + 32 > size) ? size - offset : 32;
        uint32_t pos = 0;
        while (copy--)
            out[offset++] = T[pos++];
    }
    return out.set();
}
} // namespace kakusu
