// src/rns/Destination.h — SPEC §1.2 / §4.1 / §4.2.
//
// Pairs an Identity with an app-name string, computes the §1.2
// destination_hash, and builds §4 announce wire bytes (signed with
// the Identity's long-term Ed25519 priv per §4.2).
//
// Construction is cheap (one SHA-256 each for name_hash and
// destination_hash). A node typically registers a small number of
// these on Transport for local-dispatch + announce purposes:
//   - the transport node's own SINGLE destination ("rnstransport.<...>")
//   - a telemetry destination ("transport.telemetry")
//   - any application-level destination (lxmf.delivery, etc.)
//
// Random + timestamp inputs to build_announce are caller-supplied so
// this layer stays portable C++17 (CLAUDE.md "no Arduino headers in
// src/rns/"). Firmware glue provides them; tests hardcode them to
// reproduce announces.json byte-for-byte.

#pragma once

#include <cstdint>
#include <string>

#include "rns/Bytes.h"
#include "rns/Identity.h"

namespace rns {

class Destination {
public:
    Destination(Identity identity, std::string app_name);

    const Identity&    identity()         const { return _identity; }
    const std::string& app_name()         const { return _app_name; }
    const Bytes&       name_hash()        const { return _name_hash; }
    const Bytes&       destination_hash() const { return _dest_hash; }

    // SPEC §4 — build a complete HEADER_1 BROADCAST SINGLE ANNOUNCE
    // wire packet.
    //
    //   random_prefix : exactly 5 bytes — the random half of §4.1's
    //                   random_hash. Caller draws from a real entropy
    //                   source.
    //   timestamp_secs: unix-seconds, packed into the trailing 5
    //                   bytes of random_hash as big-endian uint40
    //                   (§4.1).
    //   app_data      : optional; appended to body and to signed_data.
    //   ratchet_pub   : optional 32-byte X25519; if present, sets
    //                   the context_flag bit and inserts the
    //                   ratchet between random_hash and signature.
    //   path_response : if true, sets the outer context byte to
    //                   PATH_RESPONSE (§7.2.4) instead of NONE.
    //
    // Throws std::invalid_argument on size mismatches. Identity must
    // own a private key (i.e. constructed via from_private_bytes) —
    // a public-only Identity can't sign.
    Bytes build_announce(const Bytes& random_prefix,
                         uint64_t timestamp_secs,
                         const Bytes& app_data    = {},
                         const Bytes& ratchet_pub = {},
                         bool path_response       = false) const;

private:
    Identity    _identity;
    std::string _app_name;
    Bytes       _name_hash;   // SHA256(app_name)[:10]
    Bytes       _dest_hash;   // SHA256(name_hash || identity_hash)[:16]
};

} // namespace rns
