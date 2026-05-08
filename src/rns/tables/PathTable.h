// src/rns/tables/PathTable.h — SPEC §12.4.
//
// Passive store of per-destination path entries. Transport applies
// the §4.5 step 6.3 freshness rules (hop-count comparison, random_blob
// replay defence) and writes the resulting entry via `put()`.
//
// Entry shape mirrors `Transport.path_table[dest]` from §12.4:
//   timestamp, next_hop, hops, expires, random_blobs, receiving_interface, packet
//
// Differences from upstream: the `packet` field carries the cached
// announce **wire bytes** (Bytes) rather than a parsed Packet — this
// matches what we re-emit in path-response (§7.2), and avoids putting
// a Packet's parse-time view next to a stored copy that may outlive
// the parser.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "rns/Bytes.h"

namespace rns {

class Interface;  // forward decl — non-owning pointer in PathEntry

struct PathEntry {
    uint64_t   timestamp_ms      = 0;       // when last refreshed (caller's clock)
    Bytes      next_hop;                    // 16 bytes — transport_id of next hop
    uint8_t    hops              = 0;       // distance to destination
    uint64_t   expires_ms        = 0;       // absolute eviction time
    std::vector<Bytes> random_blobs;        // sliding window (capped, see PathTable::MAX_RANDOM_BLOBS)
    Interface* receiving_interface = nullptr;  // forward on this interface
    Bytes      announce_wire;               // cached announce wire bytes for path-response
};

class PathTable {
public:
    // §12.3.2 / §4.5 step 8 — `Transport.MAX_RANDOM_BLOBS` default.
    static constexpr size_t MAX_RANDOM_BLOBS = 32;

    // Insert or replace the entry for `dest_hash`. Caller has already
    // applied the §4.5 step 6.3 freshness logic.
    void put(const Bytes& dest_hash, PathEntry entry);

    // Fetch the entry. Returns nullptr if absent.
    const PathEntry* get(const Bytes& dest_hash) const;
    PathEntry*       get_mut(const Bytes& dest_hash);

    // Drop the entry for `dest_hash`. Returns true if it existed.
    bool remove(const Bytes& dest_hash);

    // §12.3.2 — record a `random_blob` for this destination.
    // Returns true if the blob is new (first sighting → caller may
    // forward / queue rebroadcast); false if it was already in the
    // window (= replay, drop). Manages the MAX_RANDOM_BLOBS sliding
    // window automatically.
    //
    // If `dest_hash` has no entry yet, returns false (nothing to
    // attach the blob to — caller should put() the entry first).
    bool note_random_blob(const Bytes& dest_hash, const Bytes& blob);

    // §12.4.2 — drop entries whose `expires_ms` is past `now_ms`.
    // Returns the count removed. The optional `on_evict` callback fires
    // once per removed entry with (dest_hash_hex, expires_ms, now_ms);
    // debug builds use it to surface premature evictions on the serial
    // log. Pass nullptr (default) to disable.
    using EvictObserverFn = std::function<void(const std::string&, uint64_t, uint64_t)>;
    size_t evict_expired(uint64_t now_ms, EvictObserverFn on_evict = nullptr);

    size_t size() const { return _entries.size(); }
    bool   empty() const { return _entries.empty(); }

private:
    std::unordered_map<std::string, PathEntry> _entries;

    static std::string key_of(const Bytes& b);
};

} // namespace rns
