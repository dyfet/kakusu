// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#pragma once

#include "digests.hpp"

#if defined(KAKUSU_CRYPTO_MINICRYPT)
#include <minicrypt/md5.h>
#include <minicrypt/sha1.h>

namespace kakusu {
template <typename Binary>
inline auto init_digest(md5_digest_t& out, const Binary& input) {
    auto const get = reinterpret_cast<const uint8_t *>(input.data());
    out.clear();
    mc_md5_ctx ctx;
    mc_md5_init(&ctx);
    mc_md5_update(&ctx, get, input.size());
    mc_md5_final(&ctx, out.to_byte());
    return out.fill();
}

class md5_stream_t final : public streambuf<mc_md5_ctx, MC_MD5_DIGEST_SIZE> {
public:
    md5_stream_t() : streambuf() { mc_md5_init(&ctx_); }

private:
    auto update(std::size_t size) -> bool final {
        return mc_md5_update(&ctx_, buf(), size) == 0;
    }

    auto finish() -> bool final { return mc_md5_final(&ctx_, out()) == 0; }
};

template <typename Binary>
inline auto init_digest(sha1_digest_t& out, const Binary& input) {
    auto const get = reinterpret_cast<const uint8_t *>(input.data());
    out.clear();
    mc_sha1_ctx ctx;
    mc_sha1_init(&ctx);
    mc_sha1_update(&ctx, get, input.size());
    mc_sha1_final(&ctx, out.to_byte());
    return out.fill();
}

class sha1_stream_t final : public streambuf<mc_sha1_ctx, MC_SHA1_DIGEST_SIZE> {
public:
    sha1_stream_t() : streambuf() { mc_sha1_init(&ctx_); }

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
inline auto init_digest(md5_digest_t& out, const Binary& input) {
    constexpr std::size_t md5_size = 16;
    unsigned int out_len = 0;
    out.clear();
    if (!EVP_Digest(input.data(), input.size(), out.to_byte(), &out_len, EVP_md5(), nullptr)) return false;
    if (out_len != md5_size) return false;
    return out.fill();
}

template <typename Binary>
inline auto init_digest(sha1_digest_t& out, const Binary& input) {
    constexpr std::size_t sha1_size = 20;
    unsigned int out_len = 0;
    out.clear();
    if (!EVP_Digest(input.data(), input.size(), out.to_byte(), &out_len, EVP_sha1(), nullptr)) return false;
    if (out_len != sha1_size) return false;
    return out.fill();
}

class md5_stream_t final : public streambuf<EVP_MD_CTX *, 16> {
public:
    md5_stream_t() {
        ctx_ = EVP_MD_CTX_create();
        if (!ctx_) {
            finished_ = true;
            return;
        }

        finished_ = EVP_DigestInit_ex(ctx_, EVP_md5(), nullptr) == 0;
    }

    ~md5_stream_t() final {
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

class sha1_stream_t final : public streambuf<EVP_MD_CTX *, 20> {
public:
    sha1_stream_t() {
        ctx_ = EVP_MD_CTX_create();
        if (!ctx_) {
            finished_ = true;
            return;
        }

        finished_ = EVP_DigestInit_ex(ctx_, EVP_sha1(), nullptr) == 0;
    }

    ~sha1_stream_t() final {
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
#else
#error Crypto backend does not support legacy algorithms
#endif
