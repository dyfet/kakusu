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
template <typename Key = std::string, typename Digest = sha256_digest_t>
class ring64 {
public:
    explicit ring64(int vnodes = 100) : vnodes_(vnodes) {}

    ring64(std::initializer_list<std::string> nodes, int vnodes = 100) : vnodes_(vnodes) {
        Digest digest;
        for (const auto& node : nodes) {
            insert(node);
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

    auto insert(const std::string& node) -> bool {
        bool inserted = false;
        const std::unique_lock lock(mutex_);
        Digest digest;
        for (auto i = 0; i < vnodes_; ++i) {
            const std::string vnode = node + "#" + std::to_string(i);
            auto [_, success] = ring_.emplace(to_u64<Key, Digest>(vnode), node);
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
        Digest digest;
        for (int i = 0; i < vnodes_; ++i) {
            const std::string vnode = node + "#" + std::to_string(i);
            auto index = to_u64<Key, Digest>(vnode);
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
        auto hash = to_u64<Key, Digest>(to_string(key));
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
