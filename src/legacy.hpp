// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#pragma once

#include "digests.hpp"

#if defined(KAKUSU_CRYPTO_MINICRYPT)
#include <minicrypt/md5.h>
#include <minicrypt/sha1.h>

namespace kakusu {
template <typename Binary>
inline auto make_md5(const Binary& input) -> byte_array {
    byte_array out(MC_MD5_DIGEST_SIZE);
    mc_md5_ctx ctx;
    auto const get = reinterpret_cast<const uint8_t *>(input.data());
    auto put = reinterpret_cast<uint8_t *>(out.data());
    mc_md5_init(&ctx);
    mc_md5_update(&ctx, get, input.size());
    mc_md5_final(&ctx, put);
    return out;
}

class md5_t final : public streambuf<mc_md5_ctx, MC_MD5_DIGEST_SIZE> {
public:
    md5_t() : streambuf() { mc_md5_init(&ctx_); }

private:
    auto update(std::size_t size) -> bool final {
        return mc_md5_update(&ctx_, buf(), size) == 0;
    }

    auto finish() -> bool final { return mc_md5_final(&ctx_, out()) == 0; }
};

template <typename Binary>
inline auto make_sha1(const Binary& input) -> byte_array {
    byte_array out(MC_SHA1_DIGEST_SIZE);
    mc_sha1_ctx ctx;
    auto const get = reinterpret_cast<const uint8_t *>(input.data());
    auto put = reinterpret_cast<uint8_t *>(out.data());
    mc_sha1_init(&ctx);
    mc_sha1_update(&ctx, get, input.size());
    mc_sha1_final(&ctx, put);
    return out;
}

class sha1_t final : public streambuf<mc_sha1_ctx, MC_SHA1_DIGEST_SIZE> {
public:
    sha1_t() : streambuf() { mc_sha1_init(&ctx_); }

private:
    auto update(std::size_t size) -> bool final {
        return mc_sha1_update(&ctx_, buf(), size) == 0;
    }

    auto finish() -> bool final { return mc_sha1_final(&ctx_, out()) == 0; }
};
} // namespace kakusu

#elif defined(KAKUSU_CRYPTO_OPENSSL)
#include <openssl/md5.h>

namespace kakusu {
template <typename Binary>
inline auto make_md5(const Binary& input) -> byte_array {
    constexpr std::size_t md5_size = 16;
    byte_array out(md5_size);
    unsigned int out_len = 0;
    if (!EVP_Digest(input.data(), input.size(), reinterpret_cast<unsigned char *>(out.data()), &out_len, EVP_md5(), nullptr)) throw error("MD5 digest failed");
    if (out_len != md5_size) error("ND5 Digest unexpected output size");
    return out;
}

template <typename Binary>
inline auto make_sha1(const Binary& input) -> byte_array {
    constexpr std::size_t sha1_size = 20;
    byte_array out(sha1_size);
    unsigned int out_len = 0;
    if (!EVP_Digest(input.data(), input.size(), reinterpret_cast<unsigned char *>(out.data()), &out_len, EVP_sha1(), nullptr)) throw error("SHA1 digest failed");
    if (out_len != sha1_size) error("ND5 Digest unexpected output size");
    return out;
}

class md5_t final : public streambuf<EVP_MD_CTX *, 16> {
public:
    md5_t() {
        ctx_ = EVP_MD_CTX_create();
        if (!ctx_) {
            finished_ = true;
            return;
        }

        finished_ = EVP_DigestInit_ex(ctx_, EVP_md5(), nullptr) == 0;
    }

    ~md5_t() final {
        if (ctx_) EVP_MD_CTX_destroy(ctx_);
    }

private:
    auto update(std::size_t size) -> bool final {
        return EVP_DigestUpdate(ctx_, buf(), size) != 0;
    }

    auto finish() -> bool final {
        unsigned len{0};
        EVP_DigestFinal_ex(ctx_, out(), &len);
        return len == size();
    }
};

class sha1_t final : public streambuf<EVP_MD_CTX *, 20> {
public:
    sha1_t() {
        ctx_ = EVP_MD_CTX_create();
        if (!ctx_) {
            finished_ = true;
            return;
        }

        finished_ = EVP_DigestInit_ex(ctx_, EVP_sha1(), nullptr) == 0;
    }

    ~sha1_t() final {
        if (ctx_) EVP_MD_CTX_destroy(ctx_);
    }

private:
    auto update(std::size_t size) -> bool final {
        return EVP_DigestUpdate(ctx_, buf(), size) != 0;
    }

    auto finish() -> bool final {
        unsigned len{0};
        EVP_DigestFinal_ex(ctx_, out(), &len);
        return len == size();
    }
};
} // namespace kakusu
#elif defined(KAKUSU_CRYPTO_WOLFSSL)
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>

namespace kakusu {
template <typename Binary>
inline auto make_md5(const Binary& input) -> byte_array {
    byte_array out(WC_MD5_DIGEST_SIZE);
    wc_Md5 ctx;
    auto const get = reinterpret_cast<const unsigned char *>(input.data());
    auto put = reinterpret_cast<unsigned char *>(out.data());
    if (wc_InitMd5(&ctx) != 0)
        throw error("MD5: init failed");
    if (wc_Md5Update(&ctx, get, input.size()) != 0)
        throw error("KD5: update failed");
    if (wc_Md5Final(&ctx, put) != 0)
        throw error("KD5: final failed");
    return out;
}

template <typename Binary>
inline auto make_sha1(const Binary& input) -> byte_array {
    byte_array out(WC_SHA_DIGEST_SIZE);
    wc_Sha ctx;
    auto const get = reinterpret_cast<const unsigned char *>(input.data());
    auto put = reinterpret_cast<unsigned char *>(out.data());
    if (wc_InitSha(&ctx) != 0)
        throw error("SHA1: init failed");
    if (wc_ShaUpdate(&ctx, get, input.size()) != 0)
        throw error("SHA1: update failed");
    if (wc_ShaFinal(&ctx, put) != 0)
        throw error("SHA1: final failed");
    return out;
}

class sha1_t final : public streambuf<wc_Sha, WC_SHA_DIGEST_SIZE> {
public:
    sha1_t() : streambuf() { finished_ = wc_InitSha(&ctx_) != 0; }

private:
    auto update(std::size_t size) -> bool final {
        return wc_ShaUpdate(&ctx_, buf(), size) == 0;
    }

    auto finish() -> bool final { return wc_ShaFinal(&ctx_, out()) == 0; }
};

class md5_t final : public streambuf<wc_Md5, WC_MD5_DIGEST_SIZE> {
public:
    md5_t() : streambuf() { finished_ = wc_InitMd5(&ctx_) != 0; }

private:
    auto update(std::size_t size) -> bool final {
        return wc_Md5Update(&ctx_, buf(), size) == 0;
    }

    auto finish() -> bool final { return wc_Md5Final(&ctx_, out()) == 0; }
};
} // namespace kakusu
#else
#error Crypto backend does not support legacy algorithms
#endif
