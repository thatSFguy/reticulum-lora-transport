// src/rns/tables/LinkTable.h — SPEC §12.2.4, §12.5.1, §12.5.2.
//
// Per-link relay state. When a relay forwards a LINKREQUEST, it
// writes a LinkEntry keyed by the §6.3 link_id. Every subsequent
// packet on that link (LRPROOF, Link DATA, KEEPALIVE, LINKCLOSE) is
// forwarded by the same relay via this entry.
//
// Two interfaces are tracked per entry — directionality:
//   nh_if  — the interface the LINKREQUEST was forwarded OUT on
//            (toward the responder). LRPROOF and responder→initiator
//            DATA arrive here.
//   rcvd_if — the interface the LINKREQUEST arrived IN on (toward
//            the initiator). LRPROOF and initiator→responder DATA
//            forward to here.
//
// `validated` flips to true when the relay validates the LRPROOF
// signature. Until validated, Link DATA forwarding is skipped — the
// link isn't established and there's no traffic to forward.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include "rns/Bytes.h"

namespace rns {

class Interface;  // forward decl — non-owning pointer

struct LinkEntry {
    Bytes      link_id;                 // 16 bytes — key
    uint64_t   timestamp_ms      = 0;
    Bytes      next_hop_id;             // 16 bytes — transport_id toward responder
    Interface* nh_if             = nullptr;  // toward responder
    uint8_t    rem_hops          = 0;
    Interface* rcvd_if           = nullptr;  // toward initiator
    uint8_t    taken_hops        = 0;
    Bytes      dst_hash;                // 16 bytes — responder's destination_hash
    bool       validated         = false;
    uint64_t   proof_timeout_ms  = 0;
    // §6.7.2 — last time we forwarded any traffic on this link
    // (LRPROOF, Link DATA, KEEPALIVE). evict_stale drops validated
    // entries whose last_activity is too old.
    uint64_t   last_activity_ms  = 0;
};

class LinkTable {
public:
    void put(LinkEntry entry);

    const LinkEntry* get(const Bytes& link_id) const;
    LinkEntry*       get_mut(const Bytes& link_id);

    bool remove(const Bytes& link_id);

    // Drop entries past `proof_timeout_ms` (un-validated only —
    // validated links are kept until LINKCLOSE or §6.7.2 staleness
    // aging via evict_stale). Returns count removed.
    size_t evict_unproven(uint64_t now_ms);

    // §6.7.2 — drop validated entries whose `last_activity_ms` is
    // older than `now_ms - stale_threshold_ms`. Catches links whose
    // peers wandered off without sending LINKCLOSE; without this,
    // _entries grows unboundedly in long-running deployments.
    // Returns count removed.
    size_t evict_stale(uint64_t now_ms, uint64_t stale_threshold_ms);

    size_t size()  const { return _entries.size(); }
    bool   empty() const { return _entries.empty(); }

private:
    std::unordered_map<std::string, LinkEntry> _entries;
    static std::string key_of(const Bytes& b);
};

} // namespace rns
