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

void Transport::register_interface(Interface* iface) {
    _interfaces.push_back(iface);
}

void Transport::register_announce_handler(AnnounceHandler cb) {
    _announce_handlers.push_back(std::move(cb));
}

const Bytes* Transport::public_key_for(const Bytes& dest_hash) const {
    auto it = _known_destinations.find(key_of(dest_hash));
    return (it == _known_destinations.end()) ? nullptr : &it->second;
}

std::string Transport::key_of(const Bytes& b) { return b.to_hex(); }

Bytes Transport::dedup_hash(const Packet& p) {
    // SPEC: upstream RNS hashes a "hashable part" that excludes the
    // hops byte (and for HEADER_2 the transport_id) so that the same
    // logical packet seen via different paths dedups. We approximate
    // by hashing flags || dest_hash || context || body — fields that
    // are stable across hops. This will need verification once the
    // spec section pins the exact definition.
    Bytes material;
    material.append(p.flags());
    material.append(p.destination_hash());
    material.append(p.context());
    material.append(p.data());
    return crypto::sha256(material);
}

void Transport::tick(uint64_t now_ms) {
    drive_announce_rebroadcast(now_ms);
    for (Interface* i : _interfaces) i->tick(now_ms);
    _paths.evict_expired(now_ms);
    _hashlist.purge_if_over_cap();
}

void Transport::drive_announce_rebroadcast(uint64_t now_ms) {
    auto due = _announce_table.pop_due(now_ms);
    for (auto& entry : due) {
        // §2.4 — relay increments the hops byte. Clone the cached wire
        // bytes (we may emit on multiple interfaces — each gets its
        // own buffer because Interface::queue_announce takes by value).
        Bytes wire = entry.announce_wire;
        if (wire.size() >= 2) {
            // Saturate at 255 rather than wrapping. Real meshes never
            // come anywhere near this, but UB on overflow is its own
            // problem.
            if (wire[1] < 255) wire[1] = wire[1] + 1;
        }
        const uint8_t fwd_hops = (entry.announce_hops < 255)
                               ? entry.announce_hops + 1 : 255;
        for (Interface* iface : _interfaces) {
            if (iface == entry.received_from) continue;  // don't echo back
            iface->queue_announce(wire, fwd_hops);
        }
        _stats.announces_rebroadcast++;
    }
}

void Transport::inbound(Interface* received_on, const Bytes& wire, uint64_t now_ms) {
    _stats.inbound_packets++;

    std::optional<Packet> parsed;
    try {
        parsed = Packet::from_wire_bytes(wire);
    } catch (const std::invalid_argument&) {
        _stats.parse_failures++;
        return;
    }
    const Packet& packet = *parsed;

    // §13.4 — drop on dedup hit. insert() returns false if the hash
    // was already present.
    if (!_hashlist.insert(dedup_hash(packet))) {
        _stats.dedup_drops++;
        return;
    }

    // Dispatch by packet_type. DATA / LINKREQUEST / PROOF land in
    // later PRs; for now they're silently dropped (caller has done
    // its job by handing them to us).
    if (packet.packet_type() == Packet::PacketType::ANNOUNCE) {
        handle_announce(received_on, packet, now_ms);
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
        AnnounceEntry entry;
        entry.dest_hash        = va.destination_hash;
        entry.inserted_ms      = now_ms;
        entry.retransmit_at_ms = now_ms;  // immediate eligibility; tick drains
        entry.received_from    = received_on;
        entry.announce_hops    = packet.hops();
        entry.announce_wire    = packet.wire_bytes();
        _announce_table.put(std::move(entry));
        _stats.announces_queued++;
    }

    for (const auto& cb : _announce_handlers) {
        cb(va, received_on);
        _stats.announces_delivered++;
    }
}

bool Transport::cache_validated_announce(const ValidatedAnnounce& va,
                                         Interface* received_on,
                                         const Packet& packet,
                                         uint64_t now_ms) {
    // §4.5 step 6.1 — known_destinations[dest_hash] = public_key (we
    // store just the pub for now; ratchet caching lands with §7.4).
    _known_destinations[key_of(va.destination_hash)] = va.public_key;

    // §4.5 step 6.3 — path_table update. We don't yet apply the full
    // hop-comparison freshness rules (those need timestamp parsing
    // from random_hash[5:10] per §4.1, and they cross-reference the
    // existing path entry's hop count). For this first slice we
    // unconditionally write the latest announce's data — but preserve
    // the existing random_blobs window across replacement so §12.3.2
    // replay defence works across multiple announces from the same
    // destination.
    PathEntry e;
    e.timestamp_ms        = now_ms;
    e.hops                = packet.hops();
    e.expires_ms          = now_ms + 60ULL * 60ULL * 1000ULL;  // §12.4.1 AP_PATH_TIME default
    e.next_hop            = Bytes(16);  // unknown until DATA forwarding learns it
    e.receiving_interface = received_on;
    e.announce_wire       = packet.wire_bytes();
    if (const PathEntry* existing = _paths.get(va.destination_hash)) {
        e.random_blobs = existing->random_blobs;
    }
    _paths.put(va.destination_hash, std::move(e));

    // §12.3.2 random_blob replay defence — record the blob for this
    // dest. note_random_blob returns true if the blob is new (caller
    // should rebroadcast), false on replay.
    return _paths.note_random_blob(va.destination_hash, va.random_hash);
}

} // namespace rns
