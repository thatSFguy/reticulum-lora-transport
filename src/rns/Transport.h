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
#include <unordered_set>
#include <utility>
#include <vector>

#include "rns/Bytes.h"
#include "rns/Destination.h"
#include "rns/Identity.h"
#include "rns/tables/AnnounceTable.h"
#include "rns/tables/LinkTable.h"
#include "rns/tables/PacketHashList.h"
#include "rns/tables/PathTable.h"
#include "rns/tables/ReverseTable.h"

namespace rns {

class Interface;
class Packet;

// Application callback. Fires once per validated, non-duplicate
// inbound announce. `received_on` is the interface the wire bytes
// arrived on (used for path-table provenance and per-interface
// filtering by the application).
using AnnounceHandler =
    std::function<void(const ValidatedAnnounce& va, Interface* received_on)>;

// Caller-supplied source of (random_prefix, unix_seconds) used to
// build outbound announces. random_prefix MUST be 5 bytes from a
// real entropy source (§4.1). Set once by firmware glue at startup.
// If unset, paths that need to build a fresh announce (currently
// §7.2 branch 1 path-response, telemetry beacon when it lands) drop
// with a stat counter rather than crashing.
struct AnnounceSeed { Bytes random_prefix; uint64_t unix_seconds; };
using AnnounceSeedFn = std::function<AnnounceSeed()>;

// Fired after a path-table entry is inserted or replaced (§4.5 step
// 6.3). Lets firmware glue surface a "route tracked" log without
// pulling Arduino headers into src/rns/. Not fired on rejected
// replacements (those bump the path_replacement_rejected stat).
struct PathUpdate {
    Bytes   destination_hash;
    uint8_t hops          = 0;
    Bytes   next_hop;        // empty when the dest is 1 hop away (HEADER_1 announce)
    bool    is_new         = false;  // true = first sighting, false = path replaced
};
using PathObserverFn = std::function<void(const PathUpdate&)>;

// Fired right before Transport hands a wire to an Interface for
// transmission. Lets firmware glue tag every TX line in the serial
// log with WHY the node is emitting (own scheduled announce vs.
// relay rebroadcast vs. path-response vs. DATA/PROOF/LINK forward),
// which is otherwise indistinguishable in the radio-layer log.
//
// Fires once per (Transport, Interface) emit decision. With one
// interface there's a 1:1 pairing with the Radio TX log. For a
// queued rebroadcast the actual on-air emission may lag the
// observer call by milliseconds (queue drained on next Interface
// tick); a missing Radio TX line after a tx-observer line means
// the queue rejected the entry.
enum class TxKind : uint8_t {
    OwnAnnounce,         // scheduled local announce (alive or telemetry beacon)
    PathResponse,        // §7.2 — answering a path request
    Rebroadcast,         // §12.3 — forwarding a peer's announce
    DataForward,         // §12.2 — forwarding a DATA packet
    ProofForward,        // §12.5 — forwarding a PROOF packet
    LinkForward,         // §6.x — forwarding LINKREQUEST, LINKPROOF, or link DATA
    PathRequestForward,  // §7.2 — forwarding an unanswered path request
};
using TxObserverFn = std::function<void(TxKind)>;

// Optional silent-drop observer. Used by the firmware-side debug
// instrumentation to surface link/data drop sites that would
// otherwise only tick a stat counter. The hook fires after the
// counter has incremented, with the relevant subject hash where
// available (link_id / dest_hash) — empty Bytes() if not.
enum class DropKind : uint8_t {
    LrNotHeader2,        // LR received but not HEADER_2
    LrNotForUs,          // LR transport_id != _local.identity_hash()
    LrNoPath,            // LR for destination we don't have a path for
    LrPathLocal,         // path->hops == 0 (dead-code branch — should never fire)
    LrComputeFailed,     // compute_relay_forward returned nullopt
    LrpUnknownLink,      // LRPROOF for unknown link_id
    LrpWrongIface,       // LRPROOF on wrong direction
    LrpBodySize,         // LRPROOF body size invalid
    LrpNoPubkey,         // No cached responder public_key
    LrpSigFail,          // Signature verification failed
    LrpNoRcvdIf,         // entry->rcvd_if is null
    LinkDataUnknown,     // Link DATA for unknown link
    LinkDataUnvalidated, // Link DATA before LRPROOF validated the link
    LinkDataWrongIface,  // Link DATA on neither rcvd_if nor nh_if
    DataNoPath,          // §12.2 DATA via us, but no path for the destination
    DataPathLocal,       // §12.2 DATA via us, path->hops == 0 (dead-code branch)
    DataComputeFailed,   // §12.2 DATA via us, compute_relay_forward returned nullopt
    PrTooShort,          // §7.2 path-request body < 16 bytes
    PrTagless,           // §7.2 path-request body == 16 bytes (no tag)
    PrDedup,             // §7.2 path-request target+tag already in _pr_tags
    PrLocalNoSeed,       // §7.2 path-request for our local destination but no announce seed
    PrUnanswered,        // §7.2 path-request fell through every branch
};
using DropObserverFn = std::function<void(DropKind, const Bytes& subject)>;

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

    // §7.1 — well-known PLAIN destination_hash for path-request
    // packets: SHA256(SHA256("rnstransport.path.request")[:10])[:16].
    // Constant value `6b9f66014d9853faab220fba47d02761`.
    static const Bytes& path_request_destination_hash();

    // §6.3 — link_id from a LINKREQUEST packet:
    // SHA256(hashable_part)[:16], with the 3-byte signalling trailer
    // stripped if present (§6.6). Same value at initiator (HEADER_1),
    // responder (post-relay HEADER_2), and any relay in between.
    // Static so tests, link initiators, and the relay all compute it
    // identically.
    static Bytes link_id_from_lr_packet(const Packet& packet);

    // §6.7.2 — validated link aging threshold. Default 10 minutes
    // matches RNS Link.LINK_TIMEOUT order-of-magnitude. tick() calls
    // _link_table.evict_stale with this threshold.
    static constexpr uint64_t LINK_STALE_THRESHOLD_MS = 10ULL * 60ULL * 1000ULL;

    // Periodic driver. Walks each registered interface's `tick()`,
    // evicts path entries past their `expires_ms`, and purges the
    // hashlist if over cap (§13.4).
    void tick(uint64_t now_ms);

    // Application registers an announce handler. Multiple handlers
    // are supported; all fire on each validated announce in
    // registration order.
    void register_announce_handler(AnnounceHandler cb);

    // Register a Destination that lives on this node. Inbound packets
    // (path requests targeting it, future DATA addressed to it) get
    // local-dispatch instead of forwarding. The Destination is moved
    // into Transport's storage; the Identity inside MUST own a
    // private key (so we can sign announces / decrypt for it).
    void register_local_destination(Destination dest);

    // Test/inspection.
    bool is_local_destination(const Bytes& dest_hash) const;
    size_t local_destination_count() const { return _local_destinations.size(); }

    // Set the (random_prefix, unix_seconds) source used to build
    // outbound announces. Without this, branch 1 of §7.2 silently
    // drops requests for our own destinations.
    void set_announce_seed_fn(AnnounceSeedFn fn);

    // Optional observer fired on every accepted path-table mutation
    // (§4.5 step 6.3). Firmware uses this to print a "route tracked"
    // log line. Setting nullptr (default) disables the hook.
    void set_path_observer(PathObserverFn fn) { _path_observer = std::move(fn); }

    // Optional observer fired before every Transport-level emit.
    // Firmware uses this to tag each TX line in the serial log with
    // its kind (own / relay / path-response / fwd-data / etc.), which
    // is otherwise indistinguishable in the radio-layer log. Setting
    // nullptr (default) disables the hook.
    void set_tx_observer(TxObserverFn fn) { _tx_observer = std::move(fn); }

    // Optional observer fired on every silent drop in the LR / LRPROOF
    // / Link DATA paths (i.e. a stat counter incremented but no other
    // visible side effect). Debug builds use this to make the failure
    // mode visible on the serial log instead of having to dump stats
    // out-of-band. Setting nullptr (default) disables the hook.
    void set_drop_observer(DropObserverFn fn) { _drop_observer = std::move(fn); }

    // Optional observer fired on every path-table eviction during
    // tick(). Debug-only — exists to confirm whether `evict_expired`
    // is removing entries before their stated TTL. Callback receives
    // (dest_hash_hex, expires_ms, now_ms); for a correct eviction
    // expires_ms <= now_ms.
    void set_path_evict_observer(PathTable::EvictObserverFn fn) { _evict_observer = std::move(fn); }

    // Build and emit an announce for a registered local destination.
    // Returns true if emitted, false if the dest_hash isn't local or
    // the announce_seed_fn isn't set.
    //
    //   only_on : if non-null, emit only on that interface;
    //             otherwise emit on every registered interface.
    //   path_response : sets the outer context byte to PATH_RESPONSE.
    //
    // Bypasses the announce-cap budget — these are caller-driven
    // emits (path-response answers, scheduled re-announces), not
    // queued for fairness.
    bool emit_announce_for_local(const Bytes& dest_hash,
                                 const Bytes& app_data    = {},
                                 bool path_response       = false,
                                 Interface* only_on       = nullptr);

    // Provider for app_data computed at emission time. Called every
    // time a scheduled announce fires. Returning an empty Bytes is
    // valid (= no app_data).
    using AppDataProvider = std::function<Bytes()>;

    // Schedule a periodic announce for a local destination. Caller
    // already registered the destination via register_local_destination.
    //   period_ms        — interval between emits
    //   fn               — called each emit to get app_data; nullable
    //   initial_offset_ms — first emit fires when tick(now_ms) sees
    //                      now_ms >= initial_offset_ms (default = 0,
    //                      i.e. on the very next tick).
    //
    // The schedule is stored with absolute "next_emit_ms"; tick()
    // drives emission. Multiple schedules may target the same
    // dest_hash with different periods (telemetry beacon's
    // 5min "alive" + 2h "full" pattern).
    void schedule_announce(const Bytes& dest_hash,
                           uint64_t period_ms,
                           AppDataProvider fn,
                           uint64_t initial_offset_ms = 0);

    // Introspection — used by tests and status pages.
    const Identity&       local_identity()     const { return _local; }
    bool                  transport_enabled()  const { return _transport_enabled; }
    const PathTable&      path_table()         const { return _paths; }
    const PacketHashList& hashlist()           const { return _hashlist; }
    const AnnounceTable&  announce_table()     const { return _announce_table; }
    const ReverseTable&   reverse_table()      const { return _reverse_table; }
    const LinkTable&      link_table()         const { return _link_table; }
    size_t                known_count()        const { return _known_destinations.size(); }

    // §4.5 step 6.1 — `Identity.recall(dest_hash)` analogue. Returns
    // the cached 64-byte public_key for the destination, or nullptr
    // if we've never seen a valid announce for it.
    const Bytes* public_key_for(const Bytes& dest_hash) const;

    // §4.5 step 5 — operator-controlled blackhole list keyed by
    // identity_hash (16 bytes). Announces from any identity_hash on
    // this list are dropped silently regardless of signature
    // validity. Use to suppress known-misbehaving peers without
    // changing the wire protocol.
    void blackhole_identity(const Bytes& identity_hash);
    bool unblackhole_identity(const Bytes& identity_hash);
    bool is_blackholed(const Bytes& identity_hash) const;

    // Stat counters for tests / monitoring. None of these are wire
    // semantics — purely diagnostic.
    struct Stats {
        uint64_t inbound_packets        = 0;
        uint64_t parse_failures         = 0;
        uint64_t ifac_unsupported_drops = 0;  // §2.1 bit 7 set; we don't implement IFAC
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
        uint64_t proof_inbound          = 0;  // PROOF packets entering reverse dispatch
        uint64_t proof_forwarded        = 0;  // §12.5.3 PROOF emits
        uint64_t proof_orphaned         = 0;  // PROOF whose dest_hash isn't in reverse_table
        uint64_t proof_wrong_interface  = 0;  // PROOF arrived on the wrong outbound_if
        uint64_t path_requests_received   = 0;  // valid §7.1 path-request packets
        uint64_t path_requests_tagless    = 0;  // §7.2.1 — dropped, no tag bytes
        uint64_t path_requests_deduped    = 0;  // §7.2.2 — (target||tag) seen before
        uint64_t path_requests_answered   = 0;  // §7.2.3 branch 2 emit
        uint64_t path_requests_forwarded  = 0;  // §7.2.3 branch 4 — relayed to other interfaces
        uint64_t path_requests_unanswered = 0;  // unknown target / leaf with no local match
        uint64_t link_requests_forwarded  = 0;  // §12.2.4 link_table written
        uint64_t link_proofs_forwarded    = 0;  // §12.5.1 LRPROOF validated + forwarded
        uint64_t link_proofs_invalid      = 0;  // bad signature or unknown responder pub
        uint64_t link_proofs_unknown_link = 0;  // link_id not in link_table
        uint64_t link_proofs_wrong_iface  = 0;  // arrived on the wrong direction
        uint64_t link_data_forwarded      = 0;  // §12.5.2 emits
        uint64_t link_data_unknown_link   = 0;  // dest_hash not in link_table
        uint64_t link_data_unvalidated    = 0;  // link not yet established
        uint64_t link_close_observed      = 0;  // §6.7.3 LINKCLOSE forwarded + cleaned up
        uint64_t path_requests_local_answered = 0; // §7.2 branch 1 — local dest match
        uint64_t path_requests_local_no_seed  = 0; // §7.2 branch 1 dropped (no seed fn)
        uint64_t scheduled_announces_emitted  = 0; // schedule_announce-driven emits
        uint64_t path_replacement_rejected    = 0; // §4.5 step 6.3 — kept stale-but-fresher cached entry
        uint64_t blackhole_drops              = 0; // §4.5 step 5 — announce from blackholed identity
    };
    const Stats& stats() const { return _stats; }

private:
    // §7.2.2 — `Transport.max_pr_tags` default 32000. We reuse
    // PacketHashList — same primitive: bounded set, dedup-on-insert,
    // half-purge on cap.
    static constexpr size_t MAX_PR_TAGS = 32000;

    Identity        _local;
    bool            _transport_enabled;
    PathTable       _paths;
    PacketHashList  _hashlist;
    AnnounceTable   _announce_table;
    ReverseTable    _reverse_table;
    LinkTable       _link_table;
    PacketHashList  _pr_tags{MAX_PR_TAGS};
    std::unordered_map<std::string, Bytes>      _known_destinations;  // dest_hash → 64B pub
    std::unordered_map<std::string, Destination> _local_destinations;  // dest_hash hex → Destination
    std::unordered_set<std::string>             _blackholed;           // identity_hash hex set
    std::vector<Interface*>      _interfaces;
    std::vector<AnnounceHandler> _announce_handlers;
    AnnounceSeedFn _announce_seed_fn;
    PathObserverFn _path_observer;
    TxObserverFn   _tx_observer;
    DropObserverFn _drop_observer;
    PathTable::EvictObserverFn _evict_observer;

    struct ScheduledAnnounce {
        Bytes           dest_hash;
        uint64_t        period_ms;
        uint64_t        next_emit_ms;
        AppDataProvider fn;
    };
    std::vector<ScheduledAnnounce> _scheduled_announces;

    Stats _stats;

    void drive_scheduled_announces(uint64_t now_ms);

    void handle_announce(Interface* received_on, const Packet& packet,
                         uint64_t now_ms);

    // §12.2 — relay DATA forwarding. Branches on `path.hops`:
    //   > 1  → §12.2.1 forward HEADER_2 with new transport_id
    //   == 1 → §12.2.2 strip transport_id, broadcast HEADER_1
    //   == 0 → §12.2.3 local destination (deferred)
    void handle_data_forward(Interface* received_on, const Packet& packet,
                             uint64_t now_ms);

    // §12.5.3 — PROOF receipt forwarding via reverse_table. Pops the
    // entry keyed by packet.destination_hash() (= truncated hash of
    // the original DATA packet, populated when we forwarded it),
    // verifies the PROOF arrived on the matching outbound_if, and
    // re-emits on received_if.
    void handle_proof_forward(Interface* received_on, const Packet& packet);

    // §7.2 — handle DATA packets addressed to the well-known
    // path_request_destination_hash. Parses payload per §7.2.1, dedups
    // by (target||tag) per §7.2.2, dispatches per §7.2.3 (branch 2 +
    // branch 5 only — local destinations and request-forwarding TBD).
    void handle_path_request(Interface* received_on, const Packet& packet);

    // Re-emit the cached announce for `path` on `out` with the outer
    // context byte mutated to PATH_RESPONSE (§7.2.4). Wire bytes
    // otherwise unchanged — including the hops byte, which carries
    // the cached distance from us. The receiver bumps it on inbound
    // and learns the destination is one further than that.
    void emit_path_response(Interface* out, const PathEntry& path);

    // §12.2.4 — relay forwards a LINKREQUEST and writes a link_table
    // entry. Same §12.2 entry conditions and §12.2.1/2 wire
    // transformation as DATA forwarding; the post-forward table is
    // the only difference.
    void handle_link_request_forward(Interface* received_on,
                                     const Packet& packet, uint64_t now_ms);

    // §12.5.1 — LRPROOF validation and forwarding. Looks up
    // link_table[packet.destination_hash() (= link_id)], peeks the
    // entry, validates the §6.2 signature against the responder's
    // known long-term Ed25519 public key, forwards on rcvd_if, and
    // marks `validated = true`. Failure modes drop without
    // consuming the link_table entry — peek-then-pop discipline
    // (see memory: table_peek_then_pop_pattern). now_ms is recorded
    // as the link's last_activity for §6.7.2 aging.
    void handle_link_proof_forward(Interface* received_on, const Packet& packet,
                                   uint64_t now_ms);

    // §12.5.2 — Link DATA forwarding. Bidirectional: forwards on
    // nh_if when the packet arrived on rcvd_if, and vice versa. Skips
    // unvalidated links (LRPROOF hasn't completed yet). Updates the
    // link's last_activity_ms so §6.7.2 aging counts from the most
    // recent traffic, not just from link establishment.
    void handle_link_data_forward(Interface* received_on, const Packet& packet,
                                  uint64_t now_ms);

    // Apply §12.2.1/2 wire transformation per the path entry's hops
    // value. Returns the outbound interface and the bytes ready to
    // emit. Returns std::nullopt if the wire couldn't be built
    // (path.hops==0 local, missing next_hop, no outbound iface).
    // Caller emits via outbound_if->transmit_now(wire) and may
    // mutate `wire` first (e.g. §6.6 MTU clamp on LINKREQUEST).
    struct RelayForward { Interface* outbound_if; Bytes wire; };
    std::optional<RelayForward> compute_relay_forward(const Packet& packet,
                                                      const PathEntry& path);

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
