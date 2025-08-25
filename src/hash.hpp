// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

#pragma once

#include "crypto.hpp"

#include <shared_mutex>
#include <mutex>
#include <atomic>
#include <map>

#ifndef KAKUSU_CRYPTO_CONFIGURED
#error Requires a crypto backend to be selected
#endif

namespace kakusu {
template <typename Binary>
using hash_t = byte_array (*)(const Binary&);

template <typename Binary>
// std::enable_if_t<is_readable_binary_v<Binary>>>
inline auto make_u64(const Binary& input, hash_t<Binary> func = &make_sha256) {
    const auto& bin = func(input);
    if (bin.size() < 8) throw error("Crypto make_u64 digest function too small");
    uint64_t out{0};
    for (std::size_t i = 0; i < sizeof(out); ++i) {
        out = (out << 8) | static_cast<uint8_t>(bin[i]);
    }
    return out;
}

template <std::size_t Bits, typename Binary>
inline auto hash_reduce(const Binary& input, hash_t<Binary> func = &make_sha256) {
    static_assert(Bits >= 1 && Bits <= 64, "hash_reduce: Bits must be in the range [1, 64]");
    if constexpr (Bits == 64) {
        return make_u64(input, func);
    } else {
        return make_u64(input, func) & ((1ULL << Bits) - 1);
    }
}

template <typename T>
struct hash_index final {
    auto operator()(const T& key) const {
        return hash_reduce<sizeof(std::size_t) * 8>(key);
    }
};

template <typename Key = std::string, const hash_t<std::string> Hash = &make_sha256>
class ring64 {
public:
    explicit ring64(int vnodes = 100) : vnodes_(vnodes) {}

    ring64(std::initializer_list<std::string> nodes, int vnodes = 100) : vnodes_(vnodes) {
        for (const auto& node : nodes) {
            for (auto i = 0; i < vnodes_; ++i) {
                const std::string vnode = node + "#" + std::to_string(i);
                ring_.emplace(make_u64(vnode, Hash), node);
            }
        }
    }

    explicit operator bool() const {
        return !empty();
    }

    auto operator!() const {
        return empty();
    }

    auto operator*() const {
        return get();
    }

    auto operator+=(const std::string& node) -> auto& {
        insert(node);
        return *this;
    }

    auto operator-=(const std::string& node) -> auto& {
        remove(node);
        return *this;
    }

    auto empty() const -> bool {
        const std::shared_lock lock(mutex_);
        return ring_.empty();
    }

    auto size() const {
        return size_.load();
    }

    auto usage() const {
        const std::shared_lock lock(mutex_);
        return ring_.size();
    }

    auto insert(const std::string& node) {
        bool inserted = false;
        const std::unique_lock lock(mutex_);
        for (auto i = 0; i < vnodes_; ++i) {
            const std::string vnode = node + "#" + std::to_string(i);
            auto [_, success] = ring_.emplace(make_u64(vnode, Hash), node);
            if (success)
                inserted = true;
        }
        if (inserted)
            size_++;
        return inserted;
    }

    auto remove(const std::string& node) {
        bool removed = false;
        const std::unique_lock lock(mutex_);
        for (int i = 0; i < vnodes_; ++i) {
            const std::string vnode = node + "#" + std::to_string(i);
            auto index = make_u64(vnode, Hash);
            auto it = ring_.find(index);
            if (it != ring_.end() && it->second == node) {
                ring_.erase(it);
                removed = true;
            }
        }

        if (removed)
            --size_;
        return removed;
    }

    auto get(const Key& key) const -> const std::string& {
        const std::shared_lock lock(mutex_);
        auto hash = make_u64(to_string(key), Hash);
        auto it = ring_.lower_bound(hash);
        if (it == ring_.end())
            it = ring_.begin();
        return it->second;
    }

private:
    static_assert(std::is_convertible_v<Key, std::string>, "Key must be convertible to std::string.");

    auto to_string(const Key& key) const -> std::string {
        return key;
    }

    mutable std::shared_mutex mutex_;
    std::map<uint64_t, std::string> ring_;
    int vnodes_;
    std::atomic<unsigned long> size_{0};
};
} // namespace kakusu
