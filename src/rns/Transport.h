// src/rns/Transport.h — SPEC §4 (announce ingest), §13.4 (dedup).
//
// First slice. The full Transport (DATA forwarding §12.2, ANNOUNCE
// rebroadcasting §12.3, link/reverse tables §12.5, path requests §7)
// lands across subsequent PRs. This file establishes the skeleton:
//
//   - registers Interfaces (non-owning)
//   - inbound(): parse + dedup + dispatch by packet_type
//   - ANNOUNCE dispatch: §4.5 steps 1-4 (validate + collision check),
//     populate known_destinations + PathTable, fire app handlers
//   - tick(): drive interfaces, evict expired path entries,
//     purge hashlist over cap
//
// What's NOT here yet: DATA / LINKREQUEST / PROOF dispatch (drop on
// the floor for now), announce rebroadcast queuing, path requests,
// outbound packet construction, ratchet ring lookups, blackhole list.

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "rns/Bytes.h"
#include "rns/Identity.h"
#include "rns/tables/AnnounceTable.h"
#include "rns/tables/PacketHashList.h"
#include "rns/tables/PathTable.h"

namespace rns {

class Interface;
class Packet;

// Application callback. Fires once per validated, non-duplicate
// inbound announce. `received_on` is the interface the wire bytes
// arrived on (used for path-table provenance and per-interface
// filtering by the application).
using AnnounceHandler =
    std::function<void(const ValidatedAnnounce& va, Interface* received_on)>;

class Transport {
public:
    // The local node's identity. Required for self-announce filtering
    // (§9.5) and for future outbound paths (encryption, signing path
    // requests). For now we only use identity_hash for self-filter.
    //
    // `transport_enabled` (§12.1) gates relay-side ANNOUNCE
    // rebroadcasting. Leaves run with transport_enabled = false; relay
    // nodes pass true to populate AnnounceTable on validated announces
    // and rebroadcast them on each registered interface during tick().
    explicit Transport(Identity local_identity, bool transport_enabled = false);

    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;

    // Register an Interface. Non-owning — caller keeps the interface
    // alive for at least the Transport's lifetime.
    void register_interface(Interface* iface);

    // §4.5 + §13.4 entry. Called by an Interface impl when raw wire
    // bytes arrive. Drops on parse error, dedup hit, self-announce
    // (§9.5), or §4.5 validation failure.
    void inbound(Interface* received_on, const Bytes& wire, uint64_t now_ms);

    // Periodic driver. Walks each registered interface's `tick()`,
    // evicts path entries past their `expires_ms`, and purges the
    // hashlist if over cap (§13.4).
    void tick(uint64_t now_ms);

    // Application registers an announce handler. Multiple handlers
    // are supported; all fire on each validated announce in
    // registration order.
    void register_announce_handler(AnnounceHandler cb);

    // Introspection — used by tests and status pages.
    const Identity&       local_identity()     const { return _local; }
    bool                  transport_enabled()  const { return _transport_enabled; }
    const PathTable&      path_table()         const { return _paths; }
    const PacketHashList& hashlist()           const { return _hashlist; }
    const AnnounceTable&  announce_table()     const { return _announce_table; }
    size_t                known_count()        const { return _known_destinations.size(); }

    // §4.5 step 6.1 — `Identity.recall(dest_hash)` analogue. Returns
    // the cached 64-byte public_key for the destination, or nullptr
    // if we've never seen a valid announce for it.
    const Bytes* public_key_for(const Bytes& dest_hash) const;

    // Stat counters for tests / monitoring. None of these are wire
    // semantics — purely diagnostic.
    struct Stats {
        uint64_t inbound_packets        = 0;
        uint64_t parse_failures         = 0;
        uint64_t dedup_drops            = 0;
        uint64_t self_announce_drops    = 0;
        uint64_t announce_validated     = 0;
        uint64_t announce_rejected      = 0;
        uint64_t collisions_rejected    = 0;
        uint64_t announces_delivered    = 0;
        uint64_t announces_queued       = 0;  // AnnounceTable insertions
        uint64_t announces_rebroadcast  = 0;  // tick()-driven emissions
        uint64_t data_inbound           = 0;  // DATA packets entering forward dispatch
        uint64_t data_forwarded_header_2 = 0; // §12.2.1 emits
        uint64_t data_forwarded_header_1 = 0; // §12.2.2 emits
        uint64_t data_local_arrived     = 0;  // §12.2.3 local hand-off (deferred)
    };
    const Stats& stats() const { return _stats; }

private:
    Identity        _local;
    bool            _transport_enabled;
    PathTable       _paths;
    PacketHashList  _hashlist;
    AnnounceTable   _announce_table;
    std::unordered_map<std::string, Bytes> _known_destinations;  // dest_hash → 64B pub
    std::vector<Interface*>      _interfaces;
    std::vector<AnnounceHandler> _announce_handlers;
    Stats _stats;

    void handle_announce(Interface* received_on, const Packet& packet,
                         uint64_t now_ms);

    // §12.2 — relay DATA forwarding. Branches on `path.hops`:
    //   > 1  → §12.2.1 forward HEADER_2 with new transport_id
    //   == 1 → §12.2.2 strip transport_id, broadcast HEADER_1
    //   == 0 → §12.2.3 local destination (deferred)
    void handle_data_forward(Interface* received_on, const Packet& packet,
                             uint64_t now_ms);

    // §4.5 step 6.1 — record a freshly-validated announce's pubkey,
    // and update the path entry (timestamp / hops / next_hop /
    // receiving_interface / cached announce wire). Caller has
    // already cleared §4.5 step 4 collision check.
    //
    // Returns true if the announce's random_blob is new for this
    // destination (caller may queue rebroadcast per §12.3.2).
    bool cache_validated_announce(const ValidatedAnnounce& va,
                                  Interface* received_on,
                                  const Packet& packet,
                                  uint64_t now_ms);

    // §12.3 — fire all due AnnounceTable entries on every registered
    // interface except `received_from`, with hops byte incremented
    // per §2.4. Called from tick().
    void drive_announce_rebroadcast(uint64_t now_ms);

    static Bytes dedup_hash(const Packet& p);
    static std::string key_of(const Bytes& b);
};

} // namespace rns
