#include "rns/Packet.h"

#include <stdexcept>

namespace rns {

Packet Packet::from_wire_bytes(const Bytes& raw) {
    if (raw.size() < HEADER_1_MIN_LEN) {
        throw std::invalid_argument("Packet::from_wire_bytes: shorter than HEADER_1 minimum");
    }
    // §2.1 bit 7 = ifac_flag. An IFAC field would be appended after the
    // hops byte (between byte 2 and the start of addresses), shifting
    // all downstream offsets. We don't implement IFAC; rejecting here
    // avoids misparsing the IFAC bytes as part of the dest_hash /
    // transport_id and getting a garbled body that fails signature
    // verification several layers later.
    if (raw[0] & IFAC_FLAG_BIT) {
        throw std::invalid_argument(
            "Packet::from_wire_bytes: IFAC-flagged packets not supported (bit 7 set)");
    }

    Packet p;
    p._raw    = raw;
    p._flags  = raw[0];
    p._hops   = raw[1];

    // §2.2 header form selected by flag-byte bits 7-6.
    const bool is_header_2 = (p.header_type() == HeaderType::HEADER_2);
    const size_t min_len   = is_header_2 ? HEADER_2_MIN_LEN : HEADER_1_MIN_LEN;
    if (raw.size() < min_len) {
        throw std::invalid_argument("Packet::from_wire_bytes: shorter than HEADER_2 minimum");
    }

    size_t off = 2;
    if (is_header_2) {
        p._transport_id = raw.slice(off, TRANSPORT_ID_LEN);
        off += TRANSPORT_ID_LEN;
    }
    p._dest_hash = raw.slice(off, DEST_HASH_LEN);
    off += DEST_HASH_LEN;
    p._context   = raw[off];
    off += 1;
    p._data      = raw.slice(off);  // body — may be empty

    return p;
}

Bytes Packet::pack_header_1(uint8_t flags, uint8_t hops,
                            const Bytes& dest_hash, uint8_t context,
                            const Bytes& body) {
    if (dest_hash.size() != DEST_HASH_LEN) {
        throw std::invalid_argument("Packet::pack_header_1: dest_hash must be 16 bytes");
    }
    Bytes out;
    out.append(flags);
    out.append(hops);
    out.append(dest_hash);
    out.append(context);
    out.append(body);
    return out;
}

Bytes Packet::pack_header_2(uint8_t flags, uint8_t hops,
                            const Bytes& transport_id,
                            const Bytes& dest_hash, uint8_t context,
                            const Bytes& body) {
    if (transport_id.size() != TRANSPORT_ID_LEN) {
        throw std::invalid_argument("Packet::pack_header_2: transport_id must be 16 bytes");
    }
    if (dest_hash.size() != DEST_HASH_LEN) {
        throw std::invalid_argument("Packet::pack_header_2: dest_hash must be 16 bytes");
    }
    Bytes out;
    out.append(flags);
    out.append(hops);
    out.append(transport_id);
    out.append(dest_hash);
    out.append(context);
    out.append(body);
    return out;
}

Packet Packet::originator_to_header_2(const Bytes& transport_id) const {
    if (header_type() != HeaderType::HEADER_1) {
        throw std::invalid_argument("originator_to_header_2: source must be HEADER_1");
    }
    if (transport_id.size() != TRANSPORT_ID_LEN) {
        throw std::invalid_argument("originator_to_header_2: transport_id must be 16 bytes");
    }
    // §2.3 transformation for a relay forwarding an originator's
    // announce per §12.3:
    //   bits 7-6 → HEADER_2
    //   bit 5    → preserved (context_flag — for ANNOUNCE this is
    //              the "ratchet present" bit and MUST survive the
    //              hop, otherwise the receiver mis-parses the body
    //              and signature verification fails)
    //   bit 4    → TRANSPORT
    //   bits 3-0 → preserved (destination_type, packet_type)
    constexpr uint8_t HEADER_2_BITS    = static_cast<uint8_t>(HeaderType::HEADER_2) << 6;
    constexpr uint8_t TRANSPORT_BIT    = static_cast<uint8_t>(TransportType::TRANSPORT) << 4;
    constexpr uint8_t CONTEXT_FLAG_BIT = 0x20;
    constexpr uint8_t LOW_NIBBLE_MASK  = 0x0F;
    const uint8_t new_flags = HEADER_2_BITS | TRANSPORT_BIT
                            | (_flags & CONTEXT_FLAG_BIT)
                            | (_flags & LOW_NIBBLE_MASK);

    Bytes new_raw = pack_header_2(new_flags, _hops, transport_id,
                                  _dest_hash, _context, _data);
    return from_wire_bytes(new_raw);
}

Packet Packet::replace_transport_id(const Bytes& new_transport_id) const {
    if (header_type() != HeaderType::HEADER_2) {
        throw std::invalid_argument("replace_transport_id: source must be HEADER_2");
    }
    if (new_transport_id.size() != TRANSPORT_ID_LEN) {
        throw std::invalid_argument("replace_transport_id: transport_id must be 16 bytes");
    }
    Bytes new_raw = pack_header_2(_flags, _hops, new_transport_id,
                                  _dest_hash, _context, _data);
    return from_wire_bytes(new_raw);
}

Packet Packet::strip_transport_id_to_header_1() const {
    if (header_type() != HeaderType::HEADER_2) {
        throw std::invalid_argument("strip_transport_id_to_header_1: source must be HEADER_2");
    }
    // §12.2.2 transformation:
    //   bits 7-6 → HEADER_1 (00)
    //   bit 4    → BROADCAST (0)
    //   bit 5    → cleared
    //   bits 3-0 → preserved
    constexpr uint8_t LOW_NIBBLE_MASK = 0x0F;
    const uint8_t new_flags = _flags & LOW_NIBBLE_MASK;
    Bytes new_raw = pack_header_1(new_flags, _hops, _dest_hash, _context, _data);
    return from_wire_bytes(new_raw);
}

Bytes Packet::hashable_part() const {
    // §6.3: low nibble of flags || raw[N:]
    //   N = 2  for HEADER_1   (strip flags + hops)
    //   N = 18 for HEADER_2   (strip flags + hops + transport_id)
    Bytes out;
    out.append(static_cast<uint8_t>(_flags & 0x0F));
    const size_t n = (header_type() == HeaderType::HEADER_1) ? 2 : 18;
    if (_raw.size() > n) out.append(_raw.slice(n));
    return out;
}

AnnounceBody parse_announce_body(const Bytes& body, bool context_flag) {
    // §4.5 step 1 — slice offsets keyed by context_flag.
    constexpr size_t PUB_LEN     = 64;
    constexpr size_t NAME_LEN    = 10;
    constexpr size_t RAND_LEN    = 10;
    constexpr size_t RATCHET_LEN = 32;
    constexpr size_t SIG_LEN     = 64;

    const size_t fixed_len = PUB_LEN + NAME_LEN + RAND_LEN
                           + (context_flag ? RATCHET_LEN : 0) + SIG_LEN;
    if (body.size() < fixed_len) {
        throw std::invalid_argument("parse_announce_body: body shorter than fixed-length fields");
    }

    AnnounceBody a;
    size_t off = 0;
    a.public_key  = body.slice(off, PUB_LEN);   off += PUB_LEN;
    a.name_hash   = body.slice(off, NAME_LEN);  off += NAME_LEN;
    a.random_hash = body.slice(off, RAND_LEN);  off += RAND_LEN;
    if (context_flag) {
        a.ratchet_pub = body.slice(off, RATCHET_LEN);
        off += RATCHET_LEN;
    }
    a.signature   = body.slice(off, SIG_LEN);   off += SIG_LEN;
    a.app_data    = body.slice(off);            // may be empty
    return a;
}

} // namespace rns
