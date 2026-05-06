#include "rns/Identity.h"
#include "rns/Crypto.h"
#include "rns/Packet.h"

#include <stdexcept>

namespace rns {

Identity Identity::from_private_bytes(const Bytes& priv) {
    if (priv.size() != PRIV_KEY_LEN) {
        throw std::invalid_argument("Identity::from_private_bytes: priv must be 64 bytes");
    }

    Identity id;
    id._priv = priv;

    // §1.1 — public_key = X25519_pub(32) || Ed25519_pub(32), in that order.
    Bytes x_pub = crypto::x25519_public_from_private(priv.slice(0, 32));
    Bytes e_pub = crypto::ed25519_public_from_private(priv.slice(32, 32));
    id._pub.append(x_pub);
    id._pub.append(e_pub);

    // §1.1 — identity_hash = SHA256(public_key)[:16].
    Bytes full = crypto::sha256(id._pub);
    id._hash = full.slice(0, IDENTITY_HASH_LEN);

    return id;
}

Identity Identity::from_public_bytes(const Bytes& pub) {
    if (pub.size() != PUB_KEY_LEN) {
        throw std::invalid_argument("Identity::from_public_bytes: pub must be 64 bytes");
    }
    Identity id;
    id._pub  = pub;
    id._hash = crypto::sha256(pub).slice(0, IDENTITY_HASH_LEN);
    return id;
}

Bytes Identity::name_hash(const std::string& full_name) {
    Bytes full = crypto::sha256(reinterpret_cast<const uint8_t*>(full_name.data()),
                                full_name.size());
    return full.slice(0, NAME_HASH_LEN);
}

Bytes Identity::destination_hash_for(const std::string& full_name,
                                     const Bytes& identity_hash) {
    if (identity_hash.size() != IDENTITY_HASH_LEN) {
        throw std::invalid_argument("destination_hash_for: identity_hash must be 16 bytes");
    }
    Bytes nh = name_hash(full_name);
    Bytes material;
    material.append(nh);
    material.append(identity_hash);
    Bytes full = crypto::sha256(material);
    return full.slice(0, DEST_HASH_LEN);
}

Bytes Identity::destination_hash(const std::string& full_name) const {
    return destination_hash_for(full_name, _hash);
}

std::optional<ValidatedAnnounce> Identity::validate_announce(const Packet& packet) {
    // §4.1 — announce header MUST be packet_type=ANNOUNCE,
    // destination_type=SINGLE. Other shapes are not valid announces.
    if (packet.packet_type()      != Packet::PacketType::ANNOUNCE) return std::nullopt;
    if (packet.destination_type() != Packet::DestinationType::SINGLE) return std::nullopt;

    // §4.5 step 1 — body parse, branched on context_flag.
    AnnounceBody body;
    try {
        body = parse_announce_body(packet.data(), packet.context_flag());
    } catch (const std::invalid_argument&) {
        return std::nullopt;
    }

    // §4.5 step 2 — signature verification. signed_data uses the OUTER
    // header's destination_hash (NOT a body field) and the empty
    // ratchet slot when context_flag is 0. app_data is appended even
    // if empty (in which case it contributes zero bytes).
    Bytes signed_data;
    signed_data.append(packet.destination_hash());  // 16
    signed_data.append(body.public_key);             // 64
    signed_data.append(body.name_hash);              // 10
    signed_data.append(body.random_hash);            // 10
    signed_data.append(body.ratchet_pub);            // 32 or 0
    signed_data.append(body.app_data);               // n  (may be 0)

    Bytes ed_pub = body.public_key.slice(32, 32);    // §1.1: pub = X25519(32) || Ed25519(32)
    if (!crypto::ed25519_verify(ed_pub, body.signature,
                                signed_data.data(), signed_data.size())) {
        return std::nullopt;
    }

    // §4.5 step 3 — recompute destination_hash from announced inputs and
    // compare against the outer header's value. Defends against an
    // attacker who pairs a valid signature with an unrelated dest_hash.
    Bytes expected_id_hash = crypto::sha256(body.public_key).slice(0, IDENTITY_HASH_LEN);
    Bytes recompute_material;
    recompute_material.append(body.name_hash);
    recompute_material.append(expected_id_hash);
    Bytes expected_dest_hash = crypto::sha256(recompute_material).slice(0, DEST_HASH_LEN);
    if (expected_dest_hash != packet.destination_hash()) {
        return std::nullopt;
    }

    ValidatedAnnounce out;
    out.destination_hash  = packet.destination_hash();
    out.public_key        = body.public_key;
    out.name_hash         = body.name_hash;
    out.random_hash       = body.random_hash;
    out.ratchet_pub       = body.ratchet_pub;
    out.app_data          = body.app_data;
    out.is_path_response  = (packet.context() == Packet::CONTEXT_PATH_RESPONSE);
    return out;
}

} // namespace rns
