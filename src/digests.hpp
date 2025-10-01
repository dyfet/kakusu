// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#pragma once

#include "crypto.hpp"
#include "binary.hpp"

#include <streambuf>
#include <iostream>

namespace kakusu {
template <typename C, std::size_t S>
class streambuf : public std::streambuf {
public:
    auto data() -> const uint8_t * {
        underflow();
        return out();
    }

    auto restart() {
        memset(&out_, 0, sizeof(out_));
        finished_ = !reinit();
        return !finished_;
    }

    explicit operator bool() const noexcept { return !finished_; }
    auto operator!() const noexcept { return finished_; }
    auto size() const noexcept -> std::size_t { return S; }
    auto is_finished() const noexcept -> bool { return finished_; }

protected:
    C ctx_{};
    bool finished_{false};

    auto out() noexcept { return reinterpret_cast<uint8_t *>(out_); }
    auto buf() noexcept { return reinterpret_cast<const uint8_t *>(pbase()); }

    streambuf() : std::streambuf() {
        setg(out_, out_, out_);
        setp(buf_, buf_ + sizeof(buf_));
    }

    virtual auto update(std::size_t size) -> bool = 0; // NOLINT
    virtual auto finish() -> bool = 0;                 // NOLINT
    virtual auto reinit() -> bool { return false; }

private:
    char out_[S]{};
    char buf_[1024]{};

    auto underflow() -> int_type final {
        if (!finished_) {
            sync();
            finish();
            setg(buf_, buf_, buf_ + S);
            finished_ = true;
        }

        if (gptr() >= egptr()) return traits_type::eof();
        auto ch = *gptr();
        gbump(1);
        return traits_type::to_int_type(ch);
    }

    auto overflow(int_type ch) -> int_type final {
        if (ch != traits_type::eof()) {
            *pptr() = ch;
            pbump(1);
        }
        return sync() == 0 ? ch : traits_type::eof();
    }

    auto xsputn(const char_type *s, std::streamsize count) -> std::streamsize final {
        std::streamsize written = 0;
        while (written < count) {
            std::streamsize space = epptr() - pptr();
            if (space == 0) {
                if (sync()) break;
                space = epptr() - pptr();
            }

            const std::streamsize chunk = std::min(space, count - written);
            std::memcpy(pptr(), s + written, chunk);
            pbump(static_cast<int>(chunk));
            written += chunk;
        }
        return written;
    }

    auto sync() -> int final {
        if (finished_) return -1;
        const ssize_t n = pptr() - pbase();
        if (n > 0) {
            if (!update(n))
                return -1;
        }
        setp(buf_, buf_ + sizeof(buf_));
        return 0;
    }
};

#if defined(KAKUSU_CRYPTO_WOLFSSL)
class sha256_stream_t final : public streambuf<wc_Sha256, WC_SHA256_DIGEST_SIZE> {
public:
    sha256_stream_t() : streambuf() { finished_ = wc_InitSha256(&ctx_) != 0; }

private:
    auto update(std::size_t size) -> bool final {
        return wc_Sha256Update(&ctx_, buf(), size) == 0;
    }

    auto finish() -> bool final { return wc_Sha256Final(&ctx_, out()) == 0; }
};

class sha512_t final : public streambuf<wc_Sha512, WC_SHA512_DIGEST_SIZE> {
public:
    sha512_t() : streambuf() { finished_ = wc_InitSha512(&ctx_) != 0; }

private:
    auto update(std::size_t size) -> bool final {
        return wc_Sha512Update(&ctx_, buf(), size) == 0;
    }

    auto finish() -> bool final { return wc_Sha512Final(&ctx_, out()) == 0; }
};

#elif defined(KAKUSU_CRYPTO_MINICRYPT)
class sha256_stream_t final : public streambuf<mc_sha256_ctx, MC_SHA256_DIGEST_SIZE> {
public:
    sha256_stream_t() : streambuf() { mc_sha256_init(&ctx_); }

private:
    auto update(std::size_t size) -> bool final {
        return mc_sha256_update(&ctx_, buf(), size) == 0;
    }

    auto finish() -> bool final { return mc_sha256_final(&ctx_, out()) == 0; }
};
#elif defined(KAKUSU_CRYPTO_OPENSSL)
class sha256_stream_t final : public streambuf<EVP_MD_CTX *, 32> {
public:
    sha256_stream_t() {
        ctx_ = EVP_MD_CTX_create();
        if (!ctx_) {
            finished_ = true;
            return;
        }

        finished_ = EVP_DigestInit_ex(ctx_, EVP_sha256(), nullptr) == 0;
    }

    ~sha256_stream_t() final {
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

class sha512_t final : public streambuf<EVP_MD_CTX *, 64> {
public:
    sha512_t() {
        ctx_ = EVP_MD_CTX_create();
        if (!ctx_) {
            finished_ = true;
            return;
        }

        finished_ = EVP_DigestInit_ex(ctx_, EVP_sha512(), nullptr) == 0;
    }

    ~sha512_t() final {
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
#else
#error No digest supported crypto backend selected
#endif

template <typename T>
struct is_streambuf {
private:
    template <typename C, std::size_t S>
    static auto test(const streambuf<C, S> *) -> std::true_type;
    static auto test(...) -> std::false_type;

public:
    static constexpr bool value = decltype(test(std::declval<T *>()))::value;
};

template <typename T>
inline constexpr bool is_streambuf_v = is_streambuf<T>::value;

template <typename B = sha256_stream_t, typename = std::enable_if_t<is_streambuf_v<B>>>
class digest_stream : public std::iostream {
public:
    digest_stream() : std::iostream(&buf_) {}

    digest_stream(const digest_stream&) = delete;
    auto operator=(const digest_stream&) -> digest_stream& = delete;

    auto restart() noexcept { return buf_.restart(); }
    auto is_finished() const noexcept -> bool { return buf_.is_finished(); }
    auto size() const noexcept { return buf_.size(); }
    auto data() const noexcept { return buf_.data(); }
    auto span() const noexcept { return byte_span(data(), size()); }

private:
    mutable B buf_;
};
} // namespace kakusu
