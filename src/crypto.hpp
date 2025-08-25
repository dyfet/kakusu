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
#endif

#ifdef KAKUSU_CRYPTO_WOLFSSL
#define KAKUSU_CRYPTO_CONFIGURED
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
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
#include <minicrypt/sha256.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace kakusu {
template <std::size_t S>
class secure_array final {
public:
    secure_array() = default;
    secure_array(const secure_array&) = delete;
    auto operator=(const secure_array&) -> auto& = delete;

    template <typename Binary>
    explicit secure_array(const Binary& from) {
        auto len = std::min(S, from.size());
        if (len) {
            memcpy(&data_, from.data(), len);
            auto wp = const_cast<void *>(reinterpret_cast<const void *>(from.data()));
            memset(wp, 0, len);
        }
    }

    secure_array(secure_array&& other) noexcept {
        memcpy(data(), other.data(), S);
        other.erase();
    }

    ~secure_array() {
        erase();
    }

    auto operator=(secure_array&& other) noexcept -> auto& {
        if (this == &other) return *this;
        memcpy(data(), other.data(), S);
        other.erase();
        return *this;
    }

    auto data() const noexcept -> const std::byte * { return data_; };
    auto data() noexcept -> std::byte * { return data_; };
    auto size() const noexcept { return S; };

private:
    static_assert(S > 0, "Key size invalid");
    std::byte data_[S]{};

    void erase() noexcept {
        memset(data(), 0, S);
    }
};

using salt_t = secure_array<8>;
using siphash_key = secure_array<16>;
using aes128_key = secure_array<16>;
using aes256_key = secure_array<32>;

#ifdef KAKUSU_CRYPTO_OPENSSL
class random_context final {
public:
    random_context() = default;
    random_context(const random_context&) = delete;
    auto operator=(const random_context&) -> auto& = delete;

    template <typename Binary>
    void fill(Binary& buf) {
        const auto len = static_cast<int>(buf.size());
        if (len < 0 || len > std::numeric_limits<int>::max()) {
            throw error("Random fill size invalid");
        }

        auto *ptr = reinterpret_cast<std::uint8_t *>(buf.data());
        if (RAND_bytes(ptr, len) != 1) {
            throw error("Random fill failed");
        }
    };

private:
    // nothing for openssl...
};

template <typename Binary>
inline auto make_sha256(const Binary& input) -> byte_array {
    constexpr std::size_t sha1_size = 32;
    byte_array out(sha1_size);
    unsigned int out_len = 0;
    if (!EVP_Digest(input.data(), input.size(), reinterpret_cast<unsigned char *>(out.data()), &out_len, EVP_sha256(), nullptr)) throw error("SHA1 digest failed");
    if (out_len != sha1_size) error("ND5 Digest unexpected output size");
    return out;
}

template <typename Binary>
inline auto make_sha512(const Binary& input) -> byte_array {
    constexpr std::size_t sha1_size = 64;
    byte_array out(sha1_size);
    unsigned int out_len = 0;
    if (!EVP_Digest(input.data(), input.size(), reinterpret_cast<unsigned char *>(out.data()), &out_len, EVP_sha512(), nullptr)) throw error("SHA1 digest failed");
    if (out_len != sha1_size) error("ND5 Digest unexpected output size");
    return out;
}

template <typename Binary>
inline auto make_siphash(const Binary& input, siphash_key key) -> byte_array {
    unsigned outlen = 8;
    EVP_MAC *mac = EVP_MAC_fetch(nullptr, "SIPHASH", nullptr);
    if (!mac) throw error("EVP_MAC_fetch(SIPHASH) failed");
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        throw error("EVP_MAC_CTX_new failed");
    }

    auto kp = reinterpret_cast<unsigned char *>(key.data());
    auto ip = reinterpret_cast<unsigned char *>(input.data());
    auto op = reinterpret_cast<unsigned char *>(input.data());
    OSSL_PARAM params[] = {
    OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, kp, key.size()),
    OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_SIZE, &outlen),
    OSSL_PARAM_construct_end()};

    if (EVP_MAC_init(ctx, kp, key.size(), params) <= 0 || EVP_MAC_CTX_set_params(ctx, params) <= 0 || EVP_MAC_update(ctx, ip, input.size()) <= 0) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw error("EVP_MAC operation failed");
    }

    byte_array out(8);
    std::size_t actual = 0;
    if (EVP_MAC_final(ctx, op, &actual, out.size()) <= 0 || actual != outlen) {
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        throw error("EVP_MAC_final failed");
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return out;
}

inline auto siphash_keygen() -> siphash_key {
    random_context rng;
    siphash_key key;
    rng.fill(key);
    return key;
}

inline void startup() {
    const int status = OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS, nullptr);
    if (status != 1) {
        throw std::runtime_error("OpenSSL crypto initialization failed");
    }
}
#endif

#ifdef KAKUSU_CRYPTO_WOLFSSL
class random_context final {
public:
    random_context() {
        if (wc_InitRng(&rng) != 0) throw error("rng failed init");
    }

    ~random_context() {
        wc_FreeRng(&rng);
    }

    random_context(const random_context&) = delete;
    auto operator=(const random_context&) -> auto& = delete;

    template <typename Binary>
    void fill(Binary& buf) {
        const auto len = buf.size();
        auto ptr = reinterpret_cast<unsigned char *>(buf.data());
        if (len > 0)
            if (wc_RNG_GenerateBlock(&rng, ptr, len) != 0) throw error("Randon fill failed");
    }

private:
    WC_RNG rng{};
};

template <typename Binary>
inline auto make_sha256(const Binary& input) -> byte_array {
    byte_array out(WC_SHA256_DIGEST_SIZE);
    wc_Sha256 ctx;
    auto const get = reinterpret_cast<const unsigned char *>(input.data());
    auto put = reinterpret_cast<unsigned char *>(out.data());
    if (wc_InitSha256(&ctx) != 0)
        throw error("sha256: init failed");
    if (wc_Sha256Update(&ctx, get, input.size()) != 0)
        throw error("sha256: update failed");
    if (wc_Sha256Final(&ctx, put) != 0)
        throw error("sha256: final failed");
    return out;
}

template <typename Binary>
inline auto make_sha512(const Binary& input) -> byte_array {
    byte_array out(WC_SHA512_DIGEST_SIZE);
    wc_Sha512 ctx;
    auto const get = reinterpret_cast<const unsigned char *>(input.data());
    auto put = reinterpret_cast<unsigned char *>(out.data());
    if (wc_InitSha512(&ctx) != 0)
        throw error("sha512: init failed");
    if (wc_Sha512Update(&ctx, get, input.size()) != 0)
        throw error("sha512: update failed");
    if (wc_Sha512Final(&ctx, put) != 0)
        throw error("sha512: final failed");
    return out;
}

inline void startup() {
    // auto ret = wolfSSL_Init();
    // if(ret > 0) throw error("WolfSSL init failed: " + std::to_string(ret));
}
#endif

#ifdef KAKUSU_CRYPTO_MINICRYPT
class random_context final {
public:
    random_context() {
        fd_ = ::open("/dev/urandom", O_RDONLY);
        if (fd_ < 0) throw error("rng failed init");
    }

    ~random_context() {
        if (fd_ > 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

    random_context(const random_context&) = delete;
    auto operator=(const random_context&) -> auto& = delete;

    template <typename Binary>
    void fill(Binary& buf) {
        auto len = ::read(fd_, buf.data(), buf.size());
        if (len < ssize_t(buf.size()))
            throw error("Randon fill failed");
    }

private:
    int fd_{-1};
};

template <typename Binary>
inline auto make_sha256(const Binary& input) -> byte_array {
    byte_array out(MC_SHA256_DIGEST_SIZE);
    mc_sha256_ctx ctx;
    auto const get = reinterpret_cast<const uint8_t *>(input.data());
    auto put = reinterpret_cast<uint8_t *>(out.data());
    mc_sha256_init(&ctx);
    mc_sha256_update(&ctx, get, input.size());
    mc_sha256_final(&ctx, put);
    return out;
}

inline void startup() {
}
#endif

#ifdef KAKUSU_CRYPTO_SODIUM
class random_context final {
public:
    random_context() = default;
    random_context(const random_context&) = delete;
    auto operator=(const random_context&) -> auto& = delete;

    template <typename Binary>
    void fill(Binary& buf) {
        const auto len = static_cast<int>(buf.size());
        if (len < 0 || len > static_cast<int>(std::numeric_limits<int>::max())) {
            throw std::runtime_error("Random fill size invalid");
        }

        auto *ptr = reinterpret_cast<void *>(buf.data()); // libsodium accepts void*
        if (len > 0) {
            randombytes_buf(ptr, static_cast<std::size_t>(len)); // always succeeds after sodium_init()
        }
    }

private:
};

template <typename Binary>
inline auto make_sha256(const Binary& input) -> byte_array {
    byte_array out(32);
    if (crypto_hash_sha256(reinterpret_cast<unsigned char *>(out.data()), reinterpret_cast<const unsigned char *>(input.data()), static_cast<unsigned long long>(input.size())) != 0) throw error("libsodium SHA-512 digest failed");
    return out;
}

template <typename Binary>
inline auto make_sha512(const Binary& input) -> byte_array {
    byte_array out(64);
    if (crypto_hash_sha512(reinterpret_cast<unsigned char *>(out.data()), reinterpret_cast<const unsigned char *>(input.data()), static_cast<unsigned long long>(input.size())) != 0) throw error("libsodium SHA-512 digest failed");
    return out;
}

template <typename Binary>
inline auto make_siphash(const Binary& input, const siphash_key& key) -> byte_array {
    byte_array out(8);
    if (crypto_shorthash(reinterpret_cast<unsigned char *>(out.data()), reinterpret_cast<const unsigned char *>(input.data()), static_cast<unsigned long long>(input.size()), reinterpret_cast<const unsigned char *>(key.data())) != 0) throw error("libsodium crypto_shorthash failed");
    return out;
}

inline auto siphash_keygen() -> siphash_key {
    siphash_key key;
    crypto_shorthash_keygen(reinterpret_cast<unsigned char *>(key.data()));
    return key;
}

inline void startup() {
    if (sodium_init() < 0) throw error("libsodium initialization failed");
}
#endif

inline auto make_random(std::size_t size) -> byte_array {
    random_context rng;
    byte_array key(size);
    rng.fill(key);
    return key;
}

template <std::size_t S>
inline auto make_key() -> secure_array<S> {
    random_context rng;
    secure_array<S> key;
    rng.fill(key);
    return key;
}

inline auto make_salt() -> salt_t {
    random_context rng;
    salt_t salt;
    rng.fill(salt);
    return salt;
}
} // namespace kakusu
