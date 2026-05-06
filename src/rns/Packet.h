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

    static constexpr size_t  DEST_HASH_LEN     = 16;
    static constexpr size_t  TRANSPORT_ID_LEN  = 16;
    static constexpr size_t  HEADER_1_MIN_LEN  = 1 + 1 + 16 + 1;       // 19 bytes
    static constexpr size_t  HEADER_2_MIN_LEN  = 1 + 1 + 16 + 16 + 1;  // 35 bytes

    // Parse a complete on-wire packet. Throws std::invalid_argument if
    // the buffer is shorter than the header form indicated by `flags`.
    static Packet from_wire_bytes(const Bytes& raw);

    // §2.1 flag accessors.
    HeaderType      header_type()      const { return static_cast<HeaderType>     ((_flags >> 6) & 0x03); }
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
