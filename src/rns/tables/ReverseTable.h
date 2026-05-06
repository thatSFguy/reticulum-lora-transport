// src/rns/tables/ReverseTable.h — SPEC §12.2.5, §12.5.3.
//
// Per-DATA-forward routing breadcrumb. When a relay forwards a non-
// LINKREQUEST DATA packet, it writes a ReverseEntry keyed by the
// truncated SHA-256 of the packet's hashable part (= the same value
// that will appear as the PROOF's dest_hash per §6.5). When the
// matching PROOF arrives, the relay pops the entry and forwards the
// PROOF back along `received_if`, completing the DATA → PROOF
// round-trip without re-consulting path_table.
//
// One-shot: pop on use. Aged out by Transport.tick() after
// `REVERSE_TIMEOUT_MS = 30s` per §12.5.3.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include "rns/Bytes.h"

namespace rns {

class Interface;  // forward decl — non-owning pointer

struct ReverseEntry {
    Bytes      packet_hash;          // 16 bytes — truncated hash, key
    Interface* received_if = nullptr;  // DATA arrived here ⇒ send PROOF back here
    Interface* outbound_if = nullptr;  // DATA was forwarded here ⇒ PROOF should arrive here
    uint64_t   timestamp_ms = 0;       // when forward happened (for aging)
};

class ReverseTable {
public:
    // §12.5.3 — `Transport.REVERSE_TIMEOUT` default 30s.
    static constexpr uint64_t REVERSE_TIMEOUT_MS = 30ULL * 1000ULL;

    void put(ReverseEntry entry);

    // Pop = lookup-and-remove. Returns nullopt if no entry for this
    // hash. One-shot routing per §12.5.3.
    std::optional<ReverseEntry> pop(const Bytes& packet_hash);

    // Read-only lookup (does not remove). Used by tests.
    const ReverseEntry* get(const Bytes& packet_hash) const;

    // §12.5.3 — drop entries whose `timestamp_ms + REVERSE_TIMEOUT_MS
    // <= now_ms`. Returns the count removed.
    size_t evict_aged(uint64_t now_ms);

    size_t size()  const { return _entries.size(); }
    bool   empty() const { return _entries.empty(); }

private:
    std::unordered_map<std::string, ReverseEntry> _entries;
    static std::string key_of(const Bytes& b);
};

} // namespace rns
