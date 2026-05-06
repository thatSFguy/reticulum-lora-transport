// src/rns/tables/PacketHashList.h — SPEC §13.4 packet-hash dedup ring.
//
// Bounded set of recently-seen packet hashes. Transport calls
// `insert()` on every inbound packet's hash and drops the packet if
// `insert()` returns false (= already seen). `purge_if_over_cap()` is
// called from the periodic `jobs()` loop and drops the oldest half
// of entries when the ring exceeds capacity, matching the upstream
// `Transport.hashlist_maxsize = 1,000,000` policy.

#pragma once

#include <cstddef>
#include <string>
#include <unordered_set>
#include <vector>

#include "rns/Bytes.h"

namespace rns {

class PacketHashList {
public:
    // §13.4 — Transport.hashlist_maxsize default.
    static constexpr size_t DEFAULT_MAX_SIZE = 1000000;

    explicit PacketHashList(size_t max_size = DEFAULT_MAX_SIZE);

    // Try to insert a hash. Returns true if newly inserted, false if
    // it was already present (= packet has been seen before).
    bool insert(const Bytes& hash);

    // Membership test without insertion.
    bool contains(const Bytes& hash) const;

    // Number of distinct hashes currently held.
    size_t size() const { return _order.size(); }

    // Configured cap (not the live size).
    size_t max_size() const { return _max; }

    // §13.4 — if the ring is over capacity, drop the oldest half.
    // Returns the number of entries removed.
    size_t purge_if_over_cap();

private:
    size_t _max;
    std::vector<Bytes> _order;             // insertion order
    std::unordered_set<std::string> _set;  // hex-keyed lookup

    static std::string key_of(const Bytes& b);
};

} // namespace rns
