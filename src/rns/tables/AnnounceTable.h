// src/rns/tables/AnnounceTable.h — SPEC §12.3.
//
// Tracks announces that have been validated and are queued for relay
// rebroadcast. Transport writes entries on validated, non-replay,
// non-PATH_RESPONSE inbound announces (when transport_enabled is on);
// `Transport.tick()` drains entries whose `retransmit_at_ms` has
// elapsed by queuing the wire bytes on every registered Interface
// except `received_from`.
//
// Entry shape mirrors `Transport.announce_table[dest_hash]` from
// §12.3 (subset — local_rebroadcasts, block_rebroadcasts and
// attached_interface aren't used by this first slice).

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "rns/Bytes.h"

namespace rns {

class Interface;  // forward decl — non-owning pointer

struct AnnounceEntry {
    Bytes      dest_hash;                  // self-keyed copy for iteration
    uint64_t   inserted_ms      = 0;       // when added to the table
    uint64_t   retransmit_at_ms = 0;       // absolute time of next emission
    uint8_t    retries          = 0;       // emissions so far
    Interface* received_from    = nullptr; // don't rebroadcast back here
    uint8_t    announce_hops    = 0;       // hops field from the inbound packet
    Bytes      announce_wire;              // wire bytes to rebroadcast (hops bumped at emit)
};

class AnnounceTable {
public:
    // §3161 — `Transport.PATHFINDER_R` default. Not enforced by this
    // first slice (single-shot rebroadcast); recorded for when
    // multi-retry policy lands.
    static constexpr uint8_t MAX_RETRIES = 4;

    void put(AnnounceEntry entry);
    bool remove(const Bytes& dest_hash);

    const AnnounceEntry* get(const Bytes& dest_hash) const;

    size_t size()  const { return _entries.size(); }
    bool   empty() const { return _entries.empty(); }

    // Atomically extracts entries whose `retransmit_at_ms <= now_ms`
    // and removes them from the table. Caller iterates the returned
    // vector to actually emit.
    std::vector<AnnounceEntry> pop_due(uint64_t now_ms);

private:
    std::unordered_map<std::string, AnnounceEntry> _entries;
    static std::string key_of(const Bytes& b);
};

} // namespace rns
