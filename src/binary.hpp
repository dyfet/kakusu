// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <type_traits>
#include <algorithm>
#include <limits>
#include <array>
#include <vector>
#include <ostream>
#include <cstring>

namespace kakusu {
template <std::size_t S>
class secure_array final {
public:
    secure_array() noexcept = default;
    secure_array(const secure_array& from) noexcept : empty_(from.empty_) {
        if (!empty_)
            memcpy(data_, from.data_, S);
    }

    template <typename Binary>
    explicit secure_array(const Binary& from) noexcept {
        auto len = std::min(S, from.size());
        if (len) {
            memcpy(&data_, from.data(), len);
            auto wp = const_cast<void *>(reinterpret_cast<const void *>(from.data()));
            memset(wp, 0, len);
            empty_ = false;
        }
    }

    ~secure_array() noexcept {
        erase();
    }

    auto operator=(const secure_array& from) noexcept -> auto& {
        if (this == &from) return *this;
        memcpy(data_, from.data_, S);
        empty_ = from.empty_;
        return *this;
    }

    template <typename Binary>
    auto operator=(const Binary& from) noexcept -> secure_array& {
        auto len = std::min(S, from.size());
        if (len) {
            empty_ = false;
            memcpy(&data_, from.data(), len);
            auto wp = const_cast<void *>(reinterpret_cast<const void *>(from.data()));
            memset(wp, 0, len);
        }
        return *this;
    }

    constexpr operator bool() const noexcept { return !empty_; }
    constexpr auto operator!() const noexcept { return empty_; }
    constexpr auto data() const noexcept -> const std::byte * { return data_; };
    constexpr auto data() noexcept -> std::byte * { return data_; };
    constexpr auto size() const noexcept { return S; };
    constexpr auto empty() const noexcept { return empty_; }

    auto operator==(const secure_array& other) const noexcept {
        if (other.empty_ != empty_) return false;
        return memcmp(data_, other.data_, S) == 0;
    }

    auto operator!=(const secure_array& other) const noexcept {
        if (other.empty_ != empty_) return true;
        return memcmp(data_, other.data_, S) != 0;
    }

    auto operator^=(const secure_array& other) noexcept {
        for (unsigned pos = 0; pos < S; ++pos) {
            data_[pos] ^= other.data_[pos];
        }
    }

    auto operator&=(const secure_array& other) noexcept {
        for (unsigned pos = 0; pos < S; ++pos) {
            data_[pos] &= other.data_[pos];
        }
    }

    auto operator|=(const secure_array& other) noexcept {
        for (unsigned pos = 0; pos < S; ++pos) {
            data_[pos] |= other.data_[pos];
        }
    }

    auto to_byte() noexcept {
        return reinterpret_cast<uint8_t *>(&data_);
    }

    auto to_byte() const noexcept {
        return reinterpret_cast<const uint8_t *>(&data_);
    }

    auto to_hex() const noexcept -> std::string {
        constexpr char hex[] = "0123456789ABCDEF";
        std::string out;
        out.reserve(S * 2);
        std::size_t pos{0};
        while (pos < S) {
            auto val = uint8_t(data_[pos++]);
            out.push_back(hex[val >> 4]);
            out.push_back(hex[val & 0x0f]);
        }
        return out;
    }

    // memory safe copy so we can remove [] operators
    template <typename Binary>
    auto merge(std::size_t offset, const Binary& from) -> std::size_t {
        if (offset >= S || from.size() < 1) return 0;
        std::size_t count = from.size();
        if (count + offset > S)
            count = S - offset;
        memcpy(data_, from.data(), count);
        return count;
    }

    auto fill(bool flag = true) noexcept {
        if (flag) empty_ = false;
        return flag;
    }

    void clear() noexcept {
        if (!empty_) erase();
        empty_ = true;
    }

private:
    static_assert(S > 0, "Secure data size invalid");
    std::byte data_[S]{};
    bool empty_{true};

    void erase() noexcept {
        memset(data(), 0, S);
    }
};

using salt_t = secure_array<8>;
using siphash_key_t = secure_array<16>;
using siphash_digest_t = secure_array<8>;
using aes128_key_t = secure_array<16>;
using aes192_key_t = secure_array<24>;
using aes256_key_t = secure_array<32>;
using sha512_digest_t = secure_array<65>;
using sha256_digest_t = secure_array<32>;
using sha1_digest_t = secure_array<20>;
using md5_digest_t = secure_array<16>;

template <std::size_t S>
auto make_secure() noexcept {
    return secure_array<S>();
}

constexpr auto to_byte(std::byte b) noexcept {
    return static_cast<uint8_t>(b);
}

constexpr auto to_byte(uint8_t u) noexcept {
    return static_cast<std::byte>(u);
}

constexpr auto to_byte(char u) noexcept {
    return static_cast<std::byte>(u);
}

static inline auto to_byte(const uint8_t *data) noexcept {
    return reinterpret_cast<const std::byte *>(data);
}

static inline auto to_byte(uint8_t *data) noexcept {
    return reinterpret_cast<std::byte *>(data);
}

static inline auto to_byte(const char *data) noexcept {
    return reinterpret_cast<const uint8_t *>(data);
}

static inline auto to_byte(char *data) noexcept {
    return reinterpret_cast<uint8_t *>(data);
}

static inline auto to_byte(const std::byte *data) noexcept {
    return reinterpret_cast<const uint8_t *>(data);
}

static inline auto to_byte(std::byte *data) noexcept {
    return reinterpret_cast<uint8_t *>(data);
}

static inline auto encode_hex(std::string_view input) noexcept -> std::string {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(input.size() * 2);
    for (const auto& b : input) {
        auto val = uint8_t(b);
        out.push_back(hex[val >> 4]);
        out.push_back(hex[val & 0x0f]);
    }
    return out;
}

template <typename T>
inline auto to_string_view(const T& obj) -> std::string_view {
    return std::string_view(reinterpret_cast<const char *>(obj.data()), obj.size());
}

template <typename Binary>
inline auto to_hex(const Binary& bin) {
    return encode_hex(to_string_view(bin));
}
} // namespace kakusu
