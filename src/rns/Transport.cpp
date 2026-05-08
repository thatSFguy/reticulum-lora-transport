#include "rns/Transport.h"

#include <algorithm>
#include <optional>
#include <stdexcept>

#include "rns/Crypto.h"
#include "rns/Interface.h"
#include "rns/Packet.h"

namespace rns {

Transport::Transport(Identity local_identity, bool transport_enabled)
    : _local(std::move(local_identity)),
      _transport_enabled(transport_enabled) {}

const Bytes& Transport::path_request_destination_hash() {
    // §1.4.3 PLAIN destination recipe: SHA256(name_hash)[:16] when
    // identity == None. name_hash itself is SHA256(name)[:10] per §1.2.
    // Result for "rnstransport.path.request" is the constant
    // 6b9f66014d9853faab220fba47d02761 (verified by tests).
    static const Bytes hash = []() {
        Bytes nh = Identity::name_hash("rnstransport.path.request");
        return crypto::sha256(nh).slice(0, 16);
    }();
    return hash;
}

void Transport::register_interface(Interface* iface) {
    _interfaces.push_back(iface);
}

void Transport::register_announce_handler(AnnounceHandler cb) {
    _announce_handlers.push_back(std::move(cb));
}

void Transport::register_local_destination(Destination dest) {
    auto k = key_of(dest.destination_hash());
    _local_destinations.emplace(std::move(k), std::move(dest));
}

bool Transport::is_local_destination(const Bytes& dest_hash) const {
    return _local_destinations.find(key_of(dest_hash)) != _local_destinations.end();
}

void Transport::set_announce_seed_fn(AnnounceSeedFn fn) {
    _announce_seed_fn = std::move(fn);
}

bool Transport::emit_announce_for_local(const Bytes& dest_hash,
                                        const Bytes& app_data,
                                        bool path_response,
                                        Interface* only_on) {
    auto it = _local_destinations.find(key_of(dest_hash));
    if (it == _local_destinations.end()) return false;
    if (!_announce_seed_fn) return false;

    AnnounceSeed seed = _announce_seed_fn();
    Bytes wire = it->second.build_announce(seed.random_prefix,
                                           seed.unix_seconds,
                                           app_data,
                                           /*ratchet_pub=*/{},
                                           path_response);

    const TxKind kind = path_response ? TxKind::PathResponse
                                      : TxKind::OwnAnnounce;
    if (only_on) {
        if (_tx_observer) _tx_observer(kind);
        only_on->transmit_now(wire);
    } else {
        for (Interface* iface : _interfaces) {
            if (_tx_observer) _tx_observer(kind);
            iface->transmit_now(wire);
        }
    }
    return true;
}

void Transport::schedule_announce(const Bytes& dest_hash, uint64_t period_ms,
                                  AppDataProvider fn,
                                  uint64_t initial_offset_ms) {
    ScheduledAnnounce s;
    s.dest_hash    = dest_hash;
    s.period_ms    = period_ms;
    s.next_emit_ms = initial_offset_ms;
    s.fn           = std::move(fn);
    _scheduled_announces.push_back(std::move(s));
}

void Transport::drive_scheduled_announces(uint64_t now_ms) {
    for (auto& s : _scheduled_announces) {
        if (s.next_emit_ms > now_ms) continue;
        Bytes app_data = s.fn ? s.fn() : Bytes{};
        if (emit_announce_for_local(s.dest_hash, app_data,
                                    /*path_response=*/false,
                                    /*only_on=*/nullptr)) {
            _stats.scheduled_announces_emitted++;
        }
        // Advance even on emit failure — otherwise a missing seed_fn
        // would re-fire every tick. The next attempt is one period
        // later regardless.
        s.next_emit_ms = (s.period_ms > 0) ? now_ms + s.period_ms
                                           : UINT64_MAX;
    }
}

const Bytes* Transport::public_key_for(const Bytes& dest_hash) const {
    auto it = _known_destinations.find(key_of(dest_hash));
    return (it == _known_destinations.end()) ? nullptr : &it->second;
}

void Transport::blackhole_identity(const Bytes& identity_hash) {
    _blackholed.insert(key_of(identity_hash));
}

bool Transport::unblackhole_identity(const Bytes& identity_hash) {
    return _blackholed.erase(key_of(identity_hash)) != 0;
}

bool Transport::is_blackholed(const Bytes& identity_hash) const {
    return _blackholed.count(key_of(identity_hash)) != 0;
}

std::string Transport::key_of(const Bytes& b) { return b.to_hex(); }

Bytes Transport::dedup_hash(const Packet& p) {
    // §13.4 dedup over the §6.3 "hashable part" — full SHA-256 of the
    // bytes a relay can't rewrite (low nibble of flags + dest_hash +
    // context + body). Same primitive used for §12.2.5 reverse_table
    // keys (truncated to 16) and §6.5.1 PROOF packet_hash.
    return crypto::sha256(p.hashable_part());
}

void Transport::tick(uint64_t now_ms) {
    drive_announce_rebroadcast(now_ms);
    drive_scheduled_announces(now_ms);
    for (Interface* i : _interfaces) i->tick(now_ms);
    _paths.evict_expired(now_ms, _evict_observer);
    _reverse_table.evict_aged(now_ms);
    _link_table.evict_unproven(now_ms);
    _link_table.evict_stale(now_ms, LINK_STALE_THRESHOLD_MS);
    _hashlist.purge_if_over_cap();
    _pr_tags.purge_if_over_cap();
}

void Transport::drive_announce_rebroadcast(uint64_t now_ms) {
    auto due = _announce_table.pop_due(now_ms);
    for (auto& entry : due) {
        // hops byte was already incremented at inbound() entry per
        // §2.4; the cached announce_wire reflects the post-bump
        // value, so we re-emit it as-is.
        //
        // We DO re-emit on the receiving interface. LoRa is a
        // broadcast medium where the relay's whole purpose is to
        // re-emit on the same physical interface to extend reach
        // beyond the originator's direct radio range. Loop
        // protection comes from §13.4 hashlist dedup + §12.3.2
        // random_blob replay defence (both run in inbound() before
        // an announce ever reaches this queue), and self-announces
        // are filtered by identity match (§9.5).
        for (Interface* iface : _interfaces) {
            if (_tx_observer) _tx_observer(TxKind::Rebroadcast);
            iface->queue_announce(entry.announce_wire, entry.announce_hops);
        }
        _stats.announces_rebroadcast++;
    }
}

void Transport::inbound(Interface* received_on, const Bytes& wire, uint64_t now_ms) {
    _stats.inbound_packets++;

    // §2.1 IFAC drop. Bit 7 of the flags byte signals an
    // ifac_size-byte IFAC field appended after the hops byte;
    // without IFAC support we'd misparse downstream offsets
    // (dest_hash / transport_id) and fail signature verification.
    // Reject early so this counter distinguishes IFAC drops from
    // genuine parse failures.
    if (!wire.empty() && (wire[0] & Packet::IFAC_FLAG_BIT)) {
        _stats.ifac_unsupported_drops++;
        return;
    }

    // §2.4 — increment hops to count the hop just taken (matches
    // upstream Transport.inbound:1395). Mutate a copy of the wire so
    // every downstream consumer sees the post-bump value (path_table
    // hops, cached announce_wire, dedup hash, rebroadcast emit).
    // Saturate at 255 — overflow doesn't happen in real meshes.
    Bytes bumped = wire;
    if (bumped.size() >= 2 && bumped[1] < 255) bumped[1] = bumped[1] + 1;

    std::optional<Packet> parsed;
    try {
        parsed = Packet::from_wire_bytes(bumped);
    } catch (const std::invalid_argument&) {
        _stats.parse_failures++;
        return;
    }
    const Packet& packet = *parsed;

    // §13.4 — drop on dedup hit. insert() returns false if the hash
    // was already present. Computed AFTER the hops bump but the bump
    // doesn't enter the dedup material (hops is excluded), so two
    // copies via different paths still dedup.
    if (!_hashlist.insert(dedup_hash(packet))) {
        _stats.dedup_drops++;
        return;
    }

    // Dispatch by packet_type. LINKREQUEST / PROOF land in later PRs;
    // for now they're silently dropped (caller has done its job by
    // handing them to us).
    if (packet.packet_type() == Packet::PacketType::ANNOUNCE) {
        handle_announce(received_on, packet, now_ms);
    } else if (packet.packet_type() == Packet::PacketType::DATA) {
        // §7.1 path-request destination short-circuits the regular
        // DATA forward path — these are PLAIN BROADCAST packets
        // addressed to a well-known constant, not via transport_id.
        if (packet.destination_hash() == path_request_destination_hash()) {
            handle_path_request(received_on, packet);
        } else if (packet.destination_type() == Packet::DestinationType::LINK) {
            handle_link_data_forward(received_on, packet, now_ms);
        } else {
            handle_data_forward(received_on, packet, now_ms);
        }
    } else if (packet.packet_type() == Packet::PacketType::LINKREQUEST) {
        handle_link_request_forward(received_on, packet, now_ms);
    } else if (packet.packet_type() == Packet::PacketType::PROOF) {
        if (packet.context() == Packet::CONTEXT_LRPROOF) {
            handle_link_proof_forward(received_on, packet, now_ms);
        } else {
            handle_proof_forward(received_on, packet);
        }
    }
}

void Transport::handle_announce(Interface* received_on, const Packet& packet,
                                uint64_t now_ms) {
    // §9.5 — drop announces matching one of our own destinations.
    // We can't compare against destination_hash directly (we don't
    // know the announcer's full_name); the practical filter is
    // identity_hash equality. If the announcer's public_key hashes
    // to our local identity_hash, it's our own announce echoing back.
    // We compute that lazily after the body parse below.

    auto va_opt = Identity::validate_announce(packet);
    if (!va_opt.has_value()) {
        _stats.announce_rejected++;
        return;
    }
    const ValidatedAnnounce& va = *va_opt;

    // §9.5 — self-announce filter. SHA256(public_key)[:16] is the
    // announcer's identity_hash; if that matches ours, skip.
    Bytes announcer_id_hash =
        crypto::sha256(va.public_key).slice(0, Identity::IDENTITY_HASH_LEN);
    if (announcer_id_hash == _local.identity_hash()) {
        _stats.self_announce_drops++;
        return;
    }

    // §4.5 step 5 — operator-controlled blackhole. Drop announces
    // from any identity_hash on the operator's blackhole list,
    // regardless of cryptographic validity.
    if (is_blackholed(announcer_id_hash)) {
        _stats.blackhole_drops++;
        return;
    }

    // §4.5 step 4 — public-key collision rejection. If we've cached
    // a different public_key for this destination_hash, reject.
    if (const Bytes* known = public_key_for(va.destination_hash)) {
        if (*known != va.public_key) {
            _stats.collisions_rejected++;
            return;
        }
    }

    _stats.announce_validated++;

    const bool blob_is_new =
        cache_validated_announce(va, received_on, packet, now_ms);

    // §12.3 — relay-side rebroadcast. Skip if we're a leaf, if this is
    // a path-response (§12.3.3), or if the blob was already cached
    // (§12.3.2 random_blob replay defence).
    if (_transport_enabled
        && packet.context() != Packet::CONTEXT_PATH_RESPONSE
        && blob_is_new) {
        // §12.3 — a relay forwards the announce as HEADER_2 with its
        // own identity_hash as transport_id. HEADER_1 (originator's
        // first emission) gets converted; HEADER_2 (already relayed
        // by another node) gets the prior forwarder's id replaced by
        // ours. Without this conversion, 2-hop peers learn the
        // originator as "1 hop direct" via us but can't actually
        // reach it directly — a routing bug that breaks DATA send.
        const Bytes& our_id = _local.identity_hash();
        Packet to_forward = (packet.header_type() == Packet::HeaderType::HEADER_1)
            ? packet.originator_to_header_2(our_id)
            : packet.replace_transport_id(our_id);

        AnnounceEntry entry;
        entry.dest_hash        = va.destination_hash;
        entry.inserted_ms      = now_ms;
        entry.retransmit_at_ms = now_ms;  // immediate eligibility; tick drains
        entry.received_from    = received_on;
        entry.announce_hops    = to_forward.hops();
        entry.announce_wire    = to_forward.wire_bytes();
        _announce_table.put(std::move(entry));
        _stats.announces_queued++;
    }

    for (const auto& cb : _announce_handlers) {
        cb(va, received_on);
        _stats.announces_delivered++;
    }
}

std::optional<Transport::RelayForward>
Transport::compute_relay_forward(const Packet& packet, const PathEntry& path) {
    if (!path.receiving_interface) return std::nullopt;
    const uint8_t remaining = path.hops;
    if (remaining > 1) {
        // §12.2.1 — replace transport_id with path.next_hop.
        if (path.next_hop.size() != Packet::TRANSPORT_ID_LEN) return std::nullopt;
        Packet forwarded = packet.replace_transport_id(path.next_hop);
        return RelayForward{ path.receiving_interface, forwarded.wire_bytes() };
    }
    if (remaining == 1) {
        // §12.2.2 — strip transport_id, broadcast HEADER_1.
        Packet forwarded = packet.strip_transport_id_to_header_1();
        return RelayForward{ path.receiving_interface, forwarded.wire_bytes() };
    }
    return std::nullopt;  // §12.2.3 local — caller handles
}

// §6.6 — when forwarding a LINKREQUEST whose body carries a 3-byte
// signalling tail (body == 67 bytes), and the outbound interface's
// hw_mtu_bytes is smaller than the encoded MTU, rewrite the
// signalling in place. Mode bits are preserved; only the 21-bit
// MTU field is clamped. Spec §6.6.3 explicitly notes the rewrite
// happens in place on the wire — link_id derivation strips the
// signalling per §6.3, so it stays invariant.
static void maybe_clamp_lr_signalling(Bytes& wire, uint32_t hw_mtu_bytes) {
    constexpr size_t LINK_MTU_SIZE = 3;
    constexpr size_t ECPUBSIZE     = 64;
    std::optional<Packet> parsed;
    try {
        parsed = Packet::from_wire_bytes(wire);
    } catch (const std::invalid_argument&) {
        return;
    }
    if (parsed->data().size() != ECPUBSIZE + LINK_MTU_SIZE) return;  // no signalling

    const size_t off = wire.size() - LINK_MTU_SIZE;
    const uint32_t signalled_mtu =
        (((static_cast<uint32_t>(wire[off    ]) << 16)
        |  (static_cast<uint32_t>(wire[off + 1]) <<  8)
        |   static_cast<uint32_t>(wire[off + 2])) & 0x1FFFFFu);
    if (signalled_mtu <= hw_mtu_bytes) return;

    const uint8_t  mode_bits = wire[off] & 0xE0;             // top 3 bits
    const uint32_t clamped   = hw_mtu_bytes & 0x1FFFFFu;
    wire[off]     = mode_bits | static_cast<uint8_t>((clamped >> 16) & 0x1Fu);
    wire[off + 1] = static_cast<uint8_t>((clamped >>  8) & 0xFFu);
    wire[off + 2] = static_cast<uint8_t>( clamped        & 0xFFu);
}

void Transport::handle_data_forward(Interface* received_on, const Packet& packet,
                                    uint64_t now_ms) {
    _stats.data_inbound++;

    // §12.2 entry: HEADER_2 packet whose transport_id is us, AND we
    // have a path entry for the destination.
    //
    // The header-type and transport-id mismatches are silent on
    // purpose — every opportunistic DATA we overhear matches one of
    // them, and surfacing them would flood the log. Only instrument
    // the cases where we WERE addressed via us but couldn't relay.
    if (packet.header_type() != Packet::HeaderType::HEADER_2) return;
    if (packet.transport_id() != _local.identity_hash())     return;

    const PathEntry* path = _paths.get(packet.destination_hash());
    if (!path) {
        if (_drop_observer) _drop_observer(DropKind::DataNoPath, packet.destination_hash());
        return;
    }

    if (path->hops == 0) {
        // §12.2.3 — local destination. Hand-off to local Destination
        // dispatch lands when local destinations are registered on
        // Transport. No reverse_table entry here — PROOF for a local
        // destination would be locally generated, not forwarded.
        _stats.data_local_arrived++;
        if (_drop_observer) _drop_observer(DropKind::DataPathLocal, packet.destination_hash());
        return;
    }

    auto fwd = compute_relay_forward(packet, *path);
    if (!fwd) {
        if (_drop_observer) _drop_observer(DropKind::DataComputeFailed, packet.destination_hash());
        return;
    }
    if (_tx_observer) _tx_observer(TxKind::DataForward);
    fwd->outbound_if->transmit_now(fwd->wire);

    if (path->hops > 1) _stats.data_forwarded_header_2++;
    else                _stats.data_forwarded_header_1++;

    // §12.2.5 — record where to send the eventual PROOF receipt.
    ReverseEntry entry;
    entry.packet_hash  = dedup_hash(packet).slice(0, 16);
    entry.received_if  = received_on;
    entry.outbound_if  = fwd->outbound_if;
    entry.timestamp_ms = now_ms;
    _reverse_table.put(std::move(entry));
}

void Transport::handle_proof_forward(Interface* received_on, const Packet& packet) {
    _stats.proof_inbound++;

    // Peek first — only pop on a successful match. A PROOF arriving on
    // the wrong interface might be a spoof; the legitimate PROOF could
    // still arrive on the correct outbound_if before the entry ages
    // out. Popping on the spoof would drop the legitimate one.
    const ReverseEntry* entry = _reverse_table.get(packet.destination_hash());
    if (!entry) {
        _stats.proof_orphaned++;
        return;
    }
    if (entry->outbound_if != received_on) {
        _stats.proof_wrong_interface++;
        return;
    }
    if (!entry->received_if) {
        // Defensive — shouldn't happen because handle_data_forward
        // only writes entries with both interfaces set. Pop to clear.
        _reverse_table.pop(packet.destination_hash());
        return;
    }

    Interface* fwd = entry->received_if;
    _reverse_table.pop(packet.destination_hash());  // consume on success
    // hops byte was already incremented at inbound() entry; emit the
    // packet wire as-is (matches §12.5.3's "flags + new_hops + rest").
    if (_tx_observer) _tx_observer(TxKind::ProofForward);
    fwd->transmit_now(packet.wire_bytes());
    _stats.proof_forwarded++;
}

void Transport::handle_path_request(Interface* received_on, const Packet& packet) {
    // §7.2.1 — payload parse. Two valid layouts by length:
    //   16-32 bytes:  target(16) || tag(rest, capped to 16)        — leaf request
    //   33+   bytes:  target(16) || transport_id(16) || tag(rest)  — transport originator
    // Tagless requests (exactly 16 bytes) are dropped per spec.
    const Bytes& body = packet.data();
    if (body.size() < 16) {
        if (_drop_observer) _drop_observer(DropKind::PrTooShort, Bytes{});
        return;
    }

    Bytes target = body.slice(0, 16);
    Bytes tag;
    if (body.size() > 32) {
        // Originator embedded transport_id; tag follows.
        const size_t tag_len = std::min<size_t>(16, body.size() - 32);
        tag = body.slice(32, tag_len);
    } else if (body.size() > 16) {
        // Leaf form: tag immediately follows target.
        const size_t tag_len = std::min<size_t>(16, body.size() - 16);
        tag = body.slice(16, tag_len);
    }
    if (tag.size() == 0) {
        _stats.path_requests_tagless++;
        if (_drop_observer) _drop_observer(DropKind::PrTagless, target);
        return;
    }

    _stats.path_requests_received++;

    // §7.2.2 — dedup keyed by target_dest_hash || tag. Same tag bytes
    // for different targets are distinct; same target+tag from a
    // retransmit drops here.
    Bytes dedup_key;
    dedup_key.append(target);
    dedup_key.append(tag);
    if (!_pr_tags.insert(dedup_key)) {
        _stats.path_requests_deduped++;
        if (_drop_observer) _drop_observer(DropKind::PrDedup, target);
        return;
    }

    // §7.2.3 branch 1 — target matches a local destination. Answer
    // by building a fresh path-response announce. This MUST run
    // before branch 2 because we're authoritative for our own
    // destinations and shouldn't punt to a cached path entry.
    if (is_local_destination(target)) {
        if (!_announce_seed_fn) {
            _stats.path_requests_local_no_seed++;
            if (_drop_observer) _drop_observer(DropKind::PrLocalNoSeed, target);
            return;
        }
        // app_data is empty for path-response in this slice. Telemetry
        // and other apps that want app_data fidelity in path-responses
        // can extend Destination to track its "current" payload later.
        emit_announce_for_local(target, /*app_data=*/{},
                                /*path_response=*/true, received_on);
        _stats.path_requests_local_answered++;
        _stats.path_requests_answered++;
        return;
    }

    // §7.2.3 branch 2 — known path AND we're transport-enabled.
    const PathEntry* path = _paths.get(target);
    if (path && _transport_enabled) {
        emit_path_response(received_on, *path);
        _stats.path_requests_answered++;
        return;
    }

    // §7.2.3 branch 4 — transport-enabled, no path known: forward
    // the request on every other interface so the broader mesh can
    // answer. We re-emit the inbound wire as-is (the body's
    // transport_id stays as it was; spec's exact upstream behavior
    // would replace it with ours, but for flat LoRa meshes the
    // path-response gets broadcast back and everyone picks it up
    // regardless). pr_tags dedup catches loop-backs.
    //
    // discovery_path_requests bookkeeping (capped at PATH_REQUEST_TIMEOUT
    // = 15s) deferred — relevant for tree topologies where the
    // path-response needs deliberate reverse-routing through specific
    // relays. Flat-mesh deployments don't depend on it.
    if (_transport_enabled) {
        bool emitted_any = false;
        for (Interface* iface : _interfaces) {
            if (iface == received_on) continue;
            if (_tx_observer) _tx_observer(TxKind::PathRequestForward);
            iface->transmit_now(packet.wire_bytes());
            emitted_any = true;
        }
        if (emitted_any) {
            _stats.path_requests_forwarded++;
            return;
        }
    }

    // §7.2.3 branch 5 — leaf, or transport-enabled with no other
    // interface to forward to.
    _stats.path_requests_unanswered++;
    if (_drop_observer) _drop_observer(DropKind::PrUnanswered, target);
}

void Transport::emit_path_response(Interface* out, const PathEntry& path) {
    if (!out) return;
    // cache_validated_announce always stores the HEADER_2-with-our-id
    // form, so the context byte is always at the HEADER_2 offset.
    constexpr size_t H2_CTX_OFFSET = 1 + 1 + 16 + 16;
    if (path.announce_wire.size() <= H2_CTX_OFFSET) return;

    Bytes wire = path.announce_wire;

    // §7.2.4 — outer context byte → PATH_RESPONSE. Signature is over
    // body + outer dest_hash (§4.2), not context, so this mutation
    // doesn't break validation.
    wire[H2_CTX_OFFSET] = Packet::CONTEXT_PATH_RESPONSE;

    // §7.2.5 PATH_REQUEST_GRACE timing is deferred — we respond
    // immediately. transmit_now bypasses the announce-cap budget,
    // which matches branch 2's "this is a path-resolver answer, not
    // a periodic re-announce" semantic.
    if (_tx_observer) _tx_observer(TxKind::PathResponse);
    out->transmit_now(wire);
}

Bytes Transport::link_id_from_lr_packet(const Packet& packet) {
    // §6.3 hashable_part with the LINKREQUEST-specific quirk: the
    // trailing 3-byte signalling field (when present, body > 64
    // bytes) is stripped before hashing so the link_id is invariant
    // under §6.6 MTU-discovery signalling.
    Bytes hp = packet.hashable_part();
    constexpr size_t ECPUBSIZE = 64;  // X25519(32) + Ed25519(32)
    if (packet.data().size() > ECPUBSIZE && hp.size() >= 3) {
        hp.resize(hp.size() - 3);
    }
    return crypto::sha256(hp).slice(0, 16);
}

void Transport::handle_link_request_forward(Interface* received_on,
                                            const Packet& packet,
                                            uint64_t now_ms) {
    // §12.2 entry conditions, same as DATA forwarding: HEADER_2 with
    // our identity_hash as transport_id, and a path entry exists.
    if (packet.header_type() != Packet::HeaderType::HEADER_2) {
        if (_drop_observer) _drop_observer(DropKind::LrNotHeader2, packet.destination_hash());
        return;
    }
    if (packet.transport_id() != _local.identity_hash()) {
        if (_drop_observer) _drop_observer(DropKind::LrNotForUs, packet.transport_id());
        return;
    }

    const PathEntry* path = _paths.get(packet.destination_hash());
    if (!path) {
        if (_drop_observer) _drop_observer(DropKind::LrNoPath, packet.destination_hash());
        return;
    }
    if (path->hops == 0) {
        if (_drop_observer) _drop_observer(DropKind::LrPathLocal, packet.destination_hash());
        return;  // local responder — TBD
    }

    auto fwd = compute_relay_forward(packet, *path);
    if (!fwd) {
        if (_drop_observer) _drop_observer(DropKind::LrComputeFailed, packet.destination_hash());
        return;
    }

    // §6.6 / §12.2.4 — clamp signalling MTU in place if the outbound
    // interface can't carry the requested value. Done BEFORE emit so
    // the responder receives the clamped form and signs over it in
    // LRPROOF (§6.6.5).
    maybe_clamp_lr_signalling(fwd->wire, fwd->outbound_if->hw_mtu_bytes());
    if (_tx_observer) _tx_observer(TxKind::LinkForward);
    fwd->outbound_if->transmit_now(fwd->wire);

    // §12.2.4 — write link_table entry keyed by §6.3 link_id. The
    // hashable_part for the link_id is computed from the packet as
    // received (post inbound hops bump), but link_id strips fields
    // a relay rewrites — so the value matches what initiator and
    // responder compute on their own copies.
    LinkEntry entry;
    entry.link_id          = link_id_from_lr_packet(packet);
    entry.timestamp_ms     = now_ms;
    entry.next_hop_id      = path->next_hop;        // toward responder
    entry.nh_if            = fwd->outbound_if;
    entry.rem_hops         = (path->hops > 0) ? path->hops - 1 : 0;
    entry.rcvd_if          = received_on;
    entry.taken_hops       = packet.hops();
    entry.dst_hash         = packet.destination_hash();
    entry.validated        = false;
    // Un-validated entries age out via tick(). 60s default matches
    // upstream Link.LINK_ESTABLISHMENT_TIMEOUT order-of-magnitude.
    entry.proof_timeout_ms = now_ms + 60ULL * 1000ULL;
    entry.last_activity_ms = now_ms;
    _link_table.put(std::move(entry));
    _stats.link_requests_forwarded++;
}

void Transport::handle_link_proof_forward(Interface* received_on,
                                          const Packet& packet,
                                          uint64_t now_ms) {
    // packet.destination_hash() carries the link_id (§6.2 — LRPROOF's
    // dest_hash IS the link_id, unlike opportunistic-DATA PROOFs).
    const LinkEntry* entry = _link_table.get(packet.destination_hash());
    if (!entry) {
        _stats.link_proofs_unknown_link++;
        if (_drop_observer) _drop_observer(DropKind::LrpUnknownLink, packet.destination_hash());
        return;
    }
    if (entry->nh_if != received_on) {
        // §12.5.1 — LRPROOF must arrive on the responder direction
        // (nh_if). Anything else is a spoof; drop without consuming
        // the entry (peek-then-pop).
        _stats.link_proofs_wrong_iface++;
        if (_drop_observer) _drop_observer(DropKind::LrpWrongIface, packet.destination_hash());
        return;
    }

    // §6.2 signature verification. Body layout:
    //   signature(64) || responder_X25519_pub(32) || [signalling(3)]
    const Bytes& body = packet.data();
    if (body.size() != 96 && body.size() != 99) {
        _stats.link_proofs_invalid++;
        if (_drop_observer) _drop_observer(DropKind::LrpBodySize, packet.destination_hash());
        return;
    }
    Bytes signature       = body.slice(0, 64);
    Bytes responder_x_pub = body.slice(64, 32);
    Bytes signalling      = (body.size() == 99) ? body.slice(96, 3) : Bytes{};

    // Pull the responder's long-term Ed25519 pub from the cached
    // public_key (X25519(32) || Ed25519(32) per §1.1).
    const Bytes* responder_pub = public_key_for(entry->dst_hash);
    if (!responder_pub || responder_pub->size() != Identity::PUB_KEY_LEN) {
        _stats.link_proofs_invalid++;
        if (_drop_observer) _drop_observer(DropKind::LrpNoPubkey, entry->dst_hash);
        return;
    }
    Bytes responder_ed_pub = responder_pub->slice(32, 32);

    Bytes signed_data;
    signed_data.append(packet.destination_hash());  // link_id
    signed_data.append(responder_x_pub);
    signed_data.append(responder_ed_pub);
    signed_data.append(signalling);                 // empty if absent
    if (!crypto::ed25519_verify(responder_ed_pub, signature,
                                signed_data.data(), signed_data.size())) {
        _stats.link_proofs_invalid++;
        if (_drop_observer) _drop_observer(DropKind::LrpSigFail, packet.destination_hash());
        return;
    }

    // Forward back toward the initiator. hops byte was already bumped
    // on inbound, so emit the wire as-is.
    Interface* fwd = entry->rcvd_if;
    if (!fwd) {
        _stats.link_proofs_invalid++;
        if (_drop_observer) _drop_observer(DropKind::LrpNoRcvdIf, packet.destination_hash());
        return;
    }
    if (_tx_observer) _tx_observer(TxKind::LinkForward);
    fwd->transmit_now(packet.wire_bytes());
    _stats.link_proofs_forwarded++;

    // Mark validated and refresh activity — subsequent Link DATA
    // forwards either way, and §6.7.2 staleness counts from the most
    // recent traffic.
    if (LinkEntry* mut = _link_table.get_mut(packet.destination_hash())) {
        mut->validated        = true;
        mut->last_activity_ms = now_ms;
    }
}

void Transport::handle_link_data_forward(Interface* received_on,
                                         const Packet& packet,
                                         uint64_t now_ms) {
    const LinkEntry* entry = _link_table.get(packet.destination_hash());
    if (!entry) {
        _stats.link_data_unknown_link++;
        if (_drop_observer) _drop_observer(DropKind::LinkDataUnknown, packet.destination_hash());
        return;
    }
    if (!entry->validated) {
        // §12.5.2 implicit — pre-LRPROOF Link DATA shouldn't exist.
        _stats.link_data_unvalidated++;
        if (_drop_observer) _drop_observer(DropKind::LinkDataUnvalidated, packet.destination_hash());
        return;
    }

    // §12.5.2 — direction: opposite of the interface this arrived on.
    Interface* fwd = nullptr;
    if (received_on == entry->rcvd_if)      fwd = entry->nh_if;
    else if (received_on == entry->nh_if)   fwd = entry->rcvd_if;
    if (!fwd) {
        if (_drop_observer) _drop_observer(DropKind::LinkDataWrongIface, packet.destination_hash());
        return;  // arrived on a third interface — drop silently
    }

    if (_tx_observer) _tx_observer(TxKind::LinkForward);
    fwd->transmit_now(packet.wire_bytes());
    _stats.link_data_forwarded++;

    // §6.7.2 — refresh activity so this validated link's staleness
    // counter resets. KEEPALIVE traffic (context 0xFA) flows through
    // this same path, so it implicitly resets the timer.
    if (LinkEntry* mut = _link_table.get_mut(packet.destination_hash())) {
        mut->last_activity_ms = now_ms;
    }

    // §6.7.3 — LINKCLOSE tears down the link. The relay can't read
    // the encrypted body but it can see the context byte. After
    // forwarding the close, drop the link_table entry so subsequent
    // Link DATA on this link_id is correctly classified as
    // "unknown_link" rather than continuing to forward.
    if (packet.context() == Packet::CONTEXT_LINKCLOSE) {
        _link_table.remove(packet.destination_hash());
        _stats.link_close_observed++;
    }
}

// §4.1 — random_hash[5:10] is a 5-byte big-endian uint40 unix-seconds
// timestamp. Parses for the §4.5 step 6.3 freshness comparison.
static uint64_t parse_random_blob_timestamp(const Bytes& blob) {
    if (blob.size() < 10) return 0;
    uint64_t ts = 0;
    for (int i = 5; i < 10; ++i) ts = (ts << 8) | blob[i];
    return ts;
}

bool Transport::cache_validated_announce(const ValidatedAnnounce& va,
                                         Interface* received_on,
                                         const Packet& packet,
                                         uint64_t now_ms) {
    // §4.5 step 6.1 — known_destinations[dest_hash] = public_key
    // unconditionally (identity correctness, independent of routing).
    _known_destinations[key_of(va.destination_hash)] = va.public_key;

    // §4.5 step 6.3 — path-table replacement rules. We REPLACE iff:
    //   - no existing entry (first sighting), OR
    //   - new hops <= existing hops (better-or-equal path), OR
    //   - existing has expired, OR
    //   - new emission timestamp > every cached blob's timestamp
    //     (newer announce from the same destination via a longer
    //     path — accept but only if strictly fresher).
    // Otherwise: KEEP the existing entry. The §12.3.2 random_blob
    // replay record still happens regardless (caller still needs
    // blob_is_new for rebroadcast decisions).
    const PathEntry* existing = _paths.get(va.destination_hash);
    bool replace = !existing;
    if (existing) {
        const uint8_t new_hops = packet.hops();
        if (new_hops <= existing->hops) {
            replace = true;
        } else if (existing->expires_ms <= now_ms) {
            replace = true;
        } else {
            const uint64_t new_ts = parse_random_blob_timestamp(va.random_hash);
            bool newer_than_all = true;
            for (const Bytes& blob : existing->random_blobs) {
                if (new_ts <= parse_random_blob_timestamp(blob)) {
                    newer_than_all = false;
                    break;
                }
            }
            replace = newer_than_all;
        }
    }

    if (replace) {
        PathEntry e;
        e.timestamp_ms        = now_ms;
        e.hops                = packet.hops();
        e.expires_ms          = now_ms + 60ULL * 60ULL * 1000ULL;  // §12.4.1 AP_PATH_TIME default
        // For HEADER_2 announces the wire's transport_id is the relay
        // that forwarded the announce to us — that's our next hop on
        // the way back to the destination. For HEADER_1 announces the
        // dest is 1 hop away on `received_on`; no transport_id is
        // needed for forwarding (we'd strip it via §12.2.2 anyway).
        e.next_hop            = (packet.header_type() == Packet::HeaderType::HEADER_2)
                              ? packet.transport_id()
                              : Bytes();
        e.receiving_interface = received_on;
        // §7.2 — cache the wire we'd RE-EMIT as a path-response, not
        // the wire as we received it. A path-response answers a
        // requester who needs to send DATA *through us* to reach the
        // destination — so the response's transport_id must be OUR
        // identity_hash. Storing the converted form here means
        // emit_path_response can just flip the context byte and emit;
        // it also matches the §12.3 invariant for the rebroadcast
        // cache (AnnounceTable).
        const Bytes& our_id = _local.identity_hash();
        Packet to_cache = (packet.header_type() == Packet::HeaderType::HEADER_1)
            ? packet.originator_to_header_2(our_id)
            : packet.replace_transport_id(our_id);
        e.announce_wire = to_cache.wire_bytes();
        if (existing) e.random_blobs = existing->random_blobs;  // preserve window
        const bool was_new = (existing == nullptr);
        _paths.put(va.destination_hash, std::move(e));

        if (_path_observer) {
            PathUpdate u;
            u.destination_hash = va.destination_hash;
            u.hops             = packet.hops();
            u.next_hop         = (packet.header_type() == Packet::HeaderType::HEADER_2)
                               ? packet.transport_id()
                               : Bytes();
            u.is_new           = was_new;
            _path_observer(u);
        }
    } else {
        _stats.path_replacement_rejected++;
    }

    // §12.3.2 random_blob replay defence — record the blob for this
    // dest regardless of whether the path entry was replaced.
    // note_random_blob returns true if the blob is new (caller should
    // rebroadcast), false on replay.
    return _paths.note_random_blob(va.destination_hash, va.random_hash);
}

} // namespace rns
