// src/rns/Packet.h — SPEC §2 wire format.
//
// A Packet is the parsed view of a Reticulum on-wire packet. Storage
// model: keep the original wire bytes around (`_raw`) and expose
// header fields as accessors that index into them. This keeps the
// "round-trip" property cheap (forwarding a packet is just bumping
// the hops byte and re-emitting `_raw`) and avoids re-allocating the
// body slice for every consumer.
//
// HEADER_1 / HEADER_2 are both supported on parse (§2.2). Only HEADER_1
// is emitted today; HEADER_1→HEADER_2 conversion (§2.3, originator and
// relay) lands when the Transport layer needs it.

#pragma once

#include <cstdint>
#include <cstddef>
#include "rns/Bytes.h"

namespace rns {

class Packet {
public:
    // §2.1 flag-byte sub-fields. Values are the on-wire bit values.
    enum class HeaderType      : uint8_t { HEADER_1 = 0, HEADER_2 = 1 };
    enum class TransportType   : uint8_t { BROADCAST = 0, TRANSPORT = 1 };
    enum class DestinationType : uint8_t { SINGLE = 0, GROUP = 1, PLAIN = 2, LINK = 3 };
    enum class PacketType      : uint8_t { DATA = 0, ANNOUNCE = 1, LINKREQUEST = 2, PROOF = 3 };

    // §2.5 context constants — partial. Full inventory lives in the spec
    // table; entries land here as the corresponding code path is
    // implemented.
    static constexpr uint8_t CONTEXT_NONE          = 0x00;
    static constexpr uint8_t CONTEXT_PATH_RESPONSE = 0x0B;
    static constexpr uint8_t CONTEXT_KEEPALIVE     = 0xFA;
    static constexpr uint8_t CONTEXT_LINKCLOSE     = 0xFC;
    static constexpr uint8_t CONTEXT_LRPROOF       = 0xFF;

    static constexpr size_t  DEST_HASH_LEN     = 16;
    static constexpr size_t  TRANSPORT_ID_LEN  = 16;
    static constexpr size_t  HEADER_1_MIN_LEN  = 1 + 1 + 16 + 1;       // 19 bytes
    static constexpr size_t  HEADER_2_MIN_LEN  = 1 + 1 + 16 + 16 + 1;  // 35 bytes

    // §2.1 bit 7 of the flags byte. Set by the egress side of an
    // IFAC-protected interface; signals an `ifac_size`-byte IFAC field
    // is appended after the hops byte. We don't implement IFAC (per
    // memory `ifac_out_of_scope`) — `from_wire_bytes` rejects packets
    // with this bit set so they don't mis-parse downstream.
    static constexpr uint8_t IFAC_FLAG_BIT     = 0x80;

    // Parse a complete on-wire packet. Throws std::invalid_argument if
    // the buffer is shorter than the header form indicated by `flags`.
    static Packet from_wire_bytes(const Bytes& raw);

    // §2.2 — pack a HEADER_1 packet from its constituent fields. The
    // header_type bits in `flags` must encode HEADER_1 (the caller
    // sets all flag-byte sub-fields per §2.1); we don't override.
    // Throws std::invalid_argument if dest_hash isn't 16 bytes.
    static Bytes pack_header_1(uint8_t flags, uint8_t hops,
                               const Bytes& dest_hash,
                               uint8_t context,
                               const Bytes& body);

    // §2.2 — pack a HEADER_2 packet. transport_id and dest_hash both
    // 16 bytes; throws std::invalid_argument otherwise.
    static Bytes pack_header_2(uint8_t flags, uint8_t hops,
                               const Bytes& transport_id,
                               const Bytes& dest_hash,
                               uint8_t context,
                               const Bytes& body);

    // §2.3 — originator HEADER_1 → HEADER_2 conversion. Used when an
    // originator (not a relay) sends to a destination known to be
    // more than 1 hop away. Sets bits 7-6 to HEADER_2, bit 4 to
    // TRANSPORT, clears bit 5, preserves bits 3-0; inserts
    // transport_id at offset 2; hops byte and body unchanged. Throws
    // std::invalid_argument if `*this` is already HEADER_2 or
    // transport_id isn't 16 bytes.
    Packet originator_to_header_2(const Bytes& transport_id) const;

    // §12.2.1 — relay forward of an already-HEADER_2 packet, replacing
    // the transport_id with the next-hop transport_id from the path
    // table. Flags / hops / dest_hash / context / body are preserved
    // (caller has already incremented hops on inbound). Throws if
    // `*this` isn't HEADER_2 or transport_id isn't 16 bytes.
    Packet replace_transport_id(const Bytes& new_transport_id) const;

    // §12.2.2 — relay forward of a HEADER_2 packet as HEADER_1
    // BROADCAST. Used when remaining_hops to destination is 1: the
    // next hop IS the destination, so transport_id is stripped.
    // Flag-byte transformation: bits 7-6 → HEADER_1, bit 4 → BROADCAST,
    // bit 5 cleared, bits 3-0 preserved. Throws if `*this` isn't
    // HEADER_2.
    Packet strip_transport_id_to_header_1() const;

    // §2.1 flag accessors. header_type is a 1-bit field at bit 6;
    // bit 7 is the separate ifac_flag (see IFAC_FLAG_BIT). Earlier
    // revisions of the spec wrongly described header_type as a
    // 2-bit field — see SPEC.md §2.1 erratum.
    HeaderType      header_type()      const { return static_cast<HeaderType>     ((_flags >> 6) & 0x01); }
    bool            ifac_flag()        const { return (_flags & IFAC_FLAG_BIT) != 0; }
    bool            context_flag()     const { return ((_flags >> 5) & 0x01) != 0; }
    TransportType   transport_type()   const { return static_cast<TransportType>  ((_flags >> 4) & 0x01); }
    DestinationType destination_type() const { return static_cast<DestinationType>((_flags >> 2) & 0x03); }
    PacketType      packet_type()      const { return static_cast<PacketType>     ( _flags       & 0x03); }

    uint8_t        flags()            const { return _flags; }
    uint8_t        hops()             const { return _hops; }
    const Bytes&   transport_id()     const { return _transport_id; }   // empty for HEADER_1
    const Bytes&   destination_hash() const { return _dest_hash; }      // 16 bytes
    uint8_t        context()          const { return _context; }
    const Bytes&   data()             const { return _data; }           // body (everything after context)
    const Bytes&   wire_bytes()       const { return _raw; }

    // SPEC §6.3 — the "hashable part" used as the common substrate for
    //   §13.4 dedup hash
    //   §12.2.5 reverse_table key (truncated)
    //   §6.3 link_id derivation (with LINKREQUEST signalling strip)
    //   §6.5.1 PROOF packet_hash
    // Strips header_type / context_flag / transport_type bits (top
    // nibble of flags), the hops byte, and the HEADER_2 transport_id —
    // every field a relay can rewrite. Result is invariant across
    // HEADER_1↔HEADER_2 conversion and per-hop rewriting.
    Bytes hashable_part() const;

private:
    Packet() = default;

    Bytes   _raw;            // full packed wire bytes
    uint8_t _flags   = 0;
    uint8_t _hops    = 0;
    Bytes   _transport_id;   // 16 bytes if HEADER_2, empty otherwise
    Bytes   _dest_hash;      // 16 bytes
    uint8_t _context = 0;
    Bytes   _data;           // body
};

// SPEC §4.1 — sliced view of an announce body.
//
// `ratchet_pub` is empty when the packet's context_flag is 0; `app_data`
// may be empty (announces without app_data are wire-legal). All other
// fields are required and have fixed lengths.
struct AnnounceBody {
    Bytes public_key;     // 64 bytes  (X25519 || Ed25519)
    Bytes name_hash;      // 10 bytes
    Bytes random_hash;    // 10 bytes  (5-byte random prefix || 5-byte BE uint40 unix-seconds)
    Bytes ratchet_pub;    // 32 bytes if context_flag, else empty
    Bytes signature;      // 64 bytes
    Bytes app_data;       // remainder, may be empty
};

// Parse the body of an announce packet per §4.5 step 1. Throws
// std::invalid_argument if `body` is too short for the layout selected
// by `context_flag`.
AnnounceBody parse_announce_body(const Bytes& body, bool context_flag);

} // namespace rns
