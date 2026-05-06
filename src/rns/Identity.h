// src/rns/Identity.h — SPEC §1.1, §1.2, §1.3, §4.5.
//
// An Identity owns a 64-byte private blob (X25519_priv || Ed25519_priv,
// §1.3) OR just the 64-byte public blob (built from a received announce
// — `from_public_bytes`) and exposes the derived identity_hash + the
// helper that computes a destination_hash for a given app-name string.
//
// validate_announce (§4.5) is on Identity rather than Packet because
// the spec section is "Identity validation" — Packet just slices the
// announce body and hands the slices over.

#pragma once

#include <optional>
#include <string>
#include "rns/Bytes.h"

namespace rns {

class Packet;  // forward decl — full def in Packet.h

// Cryptographically-validated announce contents per §4.5 steps 1-3.
// Returned by Identity::validate_announce on success. The caller is
// responsible for §4.5 steps 4-6 (collision check, blackhole list,
// caching) — those need Transport-layer state and live there.
struct ValidatedAnnounce {
    Bytes destination_hash;  // 16 bytes — copy of outer packet header field
    Bytes public_key;        // 64 bytes (X25519 || Ed25519)
    Bytes name_hash;         // 10 bytes
    Bytes random_hash;       // 10 bytes (prefix || timestamp; see §4.1)
    Bytes ratchet_pub;       // 32 bytes if announce carried a ratchet, else empty
    Bytes app_data;          // possibly empty
    bool  is_path_response;  // packet.context == 0x0B — see §7.2 / §4.5 step 7
};

class Identity {
public:
    // Constants from SPEC §1.1.
    static constexpr size_t PRIV_KEY_LEN     = 64;  // X25519(32) || Ed25519(32)
    static constexpr size_t PUB_KEY_LEN      = 64;  // X25519(32) || Ed25519(32)
    static constexpr size_t IDENTITY_HASH_LEN = 16;  // SHA256(public_key)[:16]
    static constexpr size_t NAME_HASH_LEN     = 10;  // SHA256(app_name)[:10]
    static constexpr size_t DEST_HASH_LEN     = 16;  // SHA256(name||identity)[:16]

    // Build from a 64-byte private blob (§1.3 on-disk format).
    static Identity from_private_bytes(const Bytes& priv);

    // Build from a 64-byte public blob (no private key associated). Used
    // after a successful validate_announce to materialize a sender
    // identity for outbound encryption.
    static Identity from_public_bytes(const Bytes& pub);

    const Bytes& private_key()   const { return _priv; }   // empty if from_public_bytes
    const Bytes& public_key()    const { return _pub; }
    const Bytes& identity_hash() const { return _hash; }

    // Returns the X25519/Ed25519 sub-keys as 32-byte slices.
    Bytes x25519_priv()  const { return _priv.slice(0, 32); }
    Bytes ed25519_priv() const { return _priv.slice(32, 32); }
    Bytes x25519_pub()   const { return _pub.slice(0, 32); }
    Bytes ed25519_pub()  const { return _pub.slice(32, 32); }

    // SPEC §1.2 — destination_hash for this identity under a given
    // full app-name string (e.g. "lxmf.delivery"). Static helper too,
    // for cases where you only have a public_key.
    Bytes destination_hash(const std::string& full_name) const;
    static Bytes destination_hash_for(const std::string& full_name,
                                      const Bytes& identity_hash);

    // SPEC §1.2 — name_hash = SHA256(full_name)[:10]. Static because
    // it only depends on the app-name string.
    static Bytes name_hash(const std::string& full_name);

    // SPEC §4.5 steps 1-3 — pure cryptographic validation of a received
    // ANNOUNCE packet. Returns the parsed contents on success; nullopt
    // on any failure (size mismatch, bad signature, dest_hash mismatch,
    // wrong packet_type/destination_type). Does NOT perform the
    // stateful checks — collision against cached public_key (step 4),
    // blackhole list (step 5), or cache writes (step 6).
    static std::optional<ValidatedAnnounce> validate_announce(const Packet& packet);

private:
    Identity() = default;
    Bytes _priv;
    Bytes _pub;
    Bytes _hash;
};

} // namespace rns
