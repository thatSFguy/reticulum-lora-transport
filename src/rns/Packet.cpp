#include "rns/Packet.h"

#include <stdexcept>

namespace rns {

Packet Packet::from_wire_bytes(const Bytes& raw) {
    if (raw.size() < HEADER_1_MIN_LEN) {
        throw std::invalid_argument("Packet::from_wire_bytes: shorter than HEADER_1 minimum");
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
