// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#pragma once

#include <stdexcept>
#include <cstddef>
#include <cstdint>

namespace kakusu {
using byte_view = std::string_view;
using error = std::runtime_error;
using range = std::out_of_range;
using invalid = std::invalid_argument;
using overflow = std::overflow_error;

constexpr auto to_byte(std::byte b) noexcept {
    return static_cast<uint8_t>(b);
}

constexpr auto to_byte(uint8_t u) noexcept {
    return static_cast<std::byte>(u);
}

constexpr auto to_byte(char u) noexcept {
    return static_cast<std::byte>(u);
}

inline auto to_byte(const uint8_t *data) {
    return reinterpret_cast<const std::byte *>(data);
}

inline auto to_byte(uint8_t *data) {
    return reinterpret_cast<std::byte *>(data);
}

inline auto to_byte(const char *data) {
    return reinterpret_cast<const uint8_t *>(data);
}

inline auto to_byte(char *data) {
    return reinterpret_cast<uint8_t *>(data);
}

inline auto to_byte(const std::byte *data) {
    return reinterpret_cast<const uint8_t *>(data);
}

inline auto to_byte(std::byte *data) {
    return reinterpret_cast<uint8_t *>(data);
}
} // namespace kakusu

#if defined(BUSUTO_RUNTIME_SYSTEM) || defined(KAKUSU_RUNTIME_BUSUTO)
#include <busuto/binary.hpp>

namespace kakusu {
using namespace busuto::util;
using byte_array = busuto::byte_array;
using byte_span = std::span<const std::byte>;

template <typename Binary>
inline auto to_byte_span(const Binary& obj) {
    return byte_span(reinterpret_cast<const std::byte *>(obj.data()), obj.size());
}

template <typename Binary>
inline auto to_hex(const Binary& bin) {
    return encode_hex(to_byte_span(bin));
}
} // namespace kakusu

#elif defined(HITYCHO_RUNTIME_SYSTEM) || defined(KAKUSU_RUNTIME_HITYCHO)

#include <hitycho/binary.hpp>
#include <hitycho/system.hpp>

namespace kakusu {
using namespace hitycho::util;
using byte_array = hitycho::byte_array;
} // namespace kakusu

#else

#include <utility>
#include <type_traits>
#include <algorithm>
#include <limits>
#include <array>
#include <vector>
#include <ostream>
#include <cstring>
#include <cstddef>
#include <cstdint>

namespace kakusu {
template <typename T>
constexpr auto is(const T& object) {
    return static_cast<bool>(object);
}

template <typename T>
constexpr auto is_null(const T& ptr) {
    if constexpr (std::is_pointer_v<T>)
        return ptr == nullptr;
    else
        return !static_cast<bool>(ptr);
}

inline auto make_b64_lookup() {
    std::array<uint8_t, 256> table{};
    table.fill(0xFF); // invalid by default

    const char *alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

    for (uint8_t i = 0; i < 64; ++i)
        table[static_cast<unsigned char>(alphabet[i])] = i;

    return table;
}

inline auto make_hex_lookup() {
    std::array<uint8_t, 256> table{};
    table.fill(0xFF); // Invalid by default

    for (char c = '0'; c <= '9'; ++c)
        table[static_cast<unsigned char>(c)] = c - '0';
    for (char c = 'A'; c <= 'F'; ++c)
        table[static_cast<unsigned char>(c)] = c - 'A' + 10;
    for (char c = 'a'; c <= 'f'; ++c)
        table[static_cast<unsigned char>(c)] = c - 'a' + 10;

    return table;
}

inline auto encode_b64(std::string_view input) -> std::string {
    static constexpr char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    const auto *data = reinterpret_cast<const uint8_t *>(input.data());
    const std::size_t len = input.size();
    out.reserve(((len + 2) / 3) * 4);

    std::size_t i = 0;
    while (i + 2 < len) {
        const uint32_t triple = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out.push_back(alphabet[(triple >> 18) & 0x3F]);
        out.push_back(alphabet[(triple >> 12) & 0x3F]);
        out.push_back(alphabet[(triple >> 6) & 0x3F]);
        out.push_back(alphabet[triple & 0x3F]);
        i += 3;
    }

    if (i < len) {
        uint32_t triple = data[i] << 16;
        if (i + 1 < len) triple |= data[i + 1] << 8;

        out.push_back(alphabet[(triple >> 18) & 0x3F]);
        out.push_back(alphabet[(triple >> 12) & 0x3F]);
        out.push_back(i + 1 < len ? alphabet[(triple >> 6) & 0x3F] : '=');
        out.push_back('=');
    }

    return out;
}

inline auto decode_b64(const std::string& in) -> std::vector<std::byte> {
    auto b64_lookup = make_b64_lookup();
    std::vector<std::byte> out;
    const std::size_t len = in.size();
    if (len % 4 != 0) throw invalid{"Invalid b64 length"};

    for (std::size_t i = 0; i < len; i += 4) {
        uint32_t val = 0;
        int pad = 0;
        for (int j = 0; j < 4; ++j) {
            const char c = in[i + j];
            if (c == '=') {
                val <<= 6;
                ++pad;
            } else {
                const uint8_t v = b64_lookup[static_cast<unsigned char>(c)];
                if (v == 0xFF) throw invalid{"Invalid b64 character"};
                val = (val << 6) | v;
            }
        }
        if (pad < 3) out.push_back(std::byte{static_cast<uint8_t>(val >> 16)});
        if (pad < 2) out.push_back(std::byte{static_cast<uint8_t>((val >> 8) & 0xFF)});
        if (pad < 1) out.push_back(std::byte{static_cast<uint8_t>(val & 0xFF)});
    }

    return out;
}

inline auto encode_hex(std::string_view input) -> std::string {
    const char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(input.size() * 2);
    for (const auto& b : input) {
        auto val = uint8_t(b);
        out.push_back(hex[val >> 4]);
        out.push_back(hex[val & 0x0f]);
    }
    return out;
}

inline auto decode_hex(const std::string& in) -> std::vector<std::byte> {
    auto hex_lookup = make_hex_lookup();
    if (in.size() % 2 != 0)
        throw invalid{"Hex string must have even length"};

    std::vector<std::byte> out;
    out.reserve(in.size() / 2);

    for (std::size_t i = 0; i < in.size(); i += 2) {
        const uint8_t hi = hex_lookup[static_cast<unsigned char>(in[i])];
        const uint8_t lo = hex_lookup[static_cast<unsigned char>(in[i + 1])];
        if (hi == 0xFF || lo == 0xFF)
            throw invalid{"Invalid hex character"};
        out.push_back(std::byte{static_cast<uint8_t>((hi << 4) | lo)});
    }

    return out;
}

class byte_array {
public:
    byte_array() = default;

    byte_array(const void *data, std::size_t size) : buffer_{static_cast<const char *>(data), static_cast<const char *>(data) + size} {}

    explicit byte_array(byte_view& view) : buffer_{view.begin(), view.end()} {}

    explicit byte_array(std::size_t size) : buffer_(size) {}

    byte_array(const char *cstr, std::size_t size) : buffer_{cstr, cstr + size} {}

    explicit byte_array(const std::vector<std::byte>& bytes) : buffer_(reinterpret_cast<const char *>(bytes.data()), reinterpret_cast<const char *>(bytes.data() + bytes.size())) {}

    byte_array(const byte_array&) = default;
    auto operator=(const byte_array&) -> byte_array& = default;
    byte_array(byte_array&&) noexcept = default;
    auto operator=(byte_array&&) noexcept -> byte_array& = default;

    operator std::string() const {
        return to_hex();
    }

    explicit operator bool() const noexcept { return !empty(); }
    auto operator!() const noexcept { return empty(); }

    auto operator==(const byte_array& other) const noexcept -> bool {
        return buffer_ == other.buffer_;
    }

    auto operator!=(const byte_array& other) const noexcept -> bool {
        return !(*this == other);
    }

    auto operator+=(const byte_array& other) noexcept -> byte_array& {
        append(other);
        return *this;
    }

    auto operator+(const byte_array& other) const noexcept {
        auto result = *this;
        result.append(other);
        return result;
    }

    auto u8data() const noexcept -> const uint8_t * {
        return reinterpret_cast<const uint8_t *>(data());
    }

    auto u8data() noexcept -> uint8_t * {
        return reinterpret_cast<uint8_t *>(data());
    }

    auto data() const noexcept -> const char * { return buffer_.data(); }
    auto data() noexcept -> char * { return buffer_.data(); }
    auto size() const noexcept -> std::size_t { return buffer_.size(); }
    auto capacity() const noexcept -> std::size_t { return buffer_.capacity(); }

    auto view() const noexcept -> byte_view {
        return byte_view{buffer_.data(), buffer_.size()};
    }

    void swap(byte_array& other) noexcept {
        buffer_.swap(other.buffer_);
    }

    void remove_prefix(std::size_t n) {
        if (n >= buffer_.size()) {
            buffer_.clear();
        } else {
            buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::vector<char>::difference_type>(n));
        }
    }

    void remove_suffix(std::size_t n) {
        if (n >= buffer_.size()) {
            buffer_.clear();
        } else {
            buffer_.resize(buffer_.size() - n);
        }
    }

    void append(const void *src, std::size_t n) {
        const auto *p = static_cast<const char *>(src);
        buffer_.insert(buffer_.end(), p, p + n);
    }

    void append(const byte_array& other) {
        if (!other.empty())
            buffer_.insert(buffer_.end(), other.data(), other.data() + other.size());
    }

    auto begin() noexcept -> std::vector<char>::iterator { return buffer_.begin(); }
    auto end() noexcept -> std::vector<char>::iterator { return buffer_.end(); }

    auto begin() const noexcept -> std::vector<char>::const_iterator { return buffer_.begin(); }
    auto end() const noexcept -> std::vector<char>::const_iterator { return buffer_.end(); }

    auto empty() const noexcept -> bool { return buffer_.empty(); }

    auto slice(std::size_t start = 0, std::size_t end = std::numeric_limits<std::size_t>::max()) const -> byte_array {
        const auto actual_end = std::min(end, size());
        if (start > actual_end)
            throw range{"Invalid slice range"};
        return byte_array{data() + start, actual_end - start};
    }

    auto subview(std::size_t offset, std::size_t count = std::numeric_limits<std::size_t>::max()) const -> byte_view {
        const auto actual_end = std::min(offset + count, size());
        if (offset > actual_end)
            throw range{"Invalid subspan range"};
        return byte_view{data() + offset, actual_end - offset};
    }

    void clear() noexcept { buffer_.clear(); }
    void resize(std::size_t n) { buffer_.resize(n); }
    void reserve(std::size_t n) { buffer_.reserve(n); }
    void shrink_to_fit() { buffer_.shrink_to_fit(); }
    void push_back(char b) { buffer_.push_back(b); }
    void pop_back() { buffer_.pop_back(); }

    auto operator[](std::size_t i) -> char& { return buffer_[i]; }
    auto operator[](std::size_t i) const -> const char& { return buffer_[i]; }
    auto front() -> char& { return buffer_.front(); }
    auto back() -> char& { return buffer_.back(); }
    auto front() const -> const char& { return buffer_.front(); }
    auto back() const -> const char& { return buffer_.back(); }

    void fill(char value) {
        std::fill(buffer_.begin(), buffer_.end(), value); // NOLINT
    }

    void replace(char from, char to) {
        std::replace(buffer_.begin(), buffer_.end(), from, to); // NOLINT
    }

    auto to_string() const -> std::string {
        return encode_b64(view());
    }

    auto to_hex() const -> std::string {
        return encode_hex(view());
    }

    static auto from_hex(const std::string& hex) -> byte_array {
        return byte_array{decode_hex(hex)};
    }

    static auto from_b64(const std::string& b64) -> byte_array {
        return byte_array{decode_b64(b64)};
    }

private:
    std::vector<char> buffer_;

    friend void swap(byte_array& a, byte_array& b) noexcept {
        a.swap(b);
    }
};

inline auto operator<<(std::ostream& out, const byte_array& bytes) -> std::ostream& {
    if (is(bytes))
        out << bytes.to_hex();
    else
        out << "nil";
    return out;
}

inline auto to_string(const kakusu::byte_array& ba) {
    return ba.to_hex();
}

template <typename T>
inline auto to_byte_view(const T& obj) -> byte_view {
    return std::string_view(reinterpret_cast<const char *>(obj.data()), obj.size());
}

template <typename Binary>
inline auto to_b64(const Binary& bin) {
    return encode_b64(to_byte_view(bin));
}

template <typename Binary>
inline auto to_hex(const Binary& bin) {
    return encode_hex(to_byte_view(bin));
}
} // namespace kakusu

namespace std {
template <>
struct hash<kakusu::byte_array> {
    auto operator()(const kakusu::byte_array& b) const noexcept {
        if (!is(b))
            return std::size_t(0);
        const auto *bytes = b.data();
        return std::hash<std::string_view>{}(std::string_view(
        reinterpret_cast<const char *>(bytes),
        b.size()));
    }
};
} // namespace std

#endif
