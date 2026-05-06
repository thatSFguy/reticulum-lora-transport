#include "rns/Identity.h"
#include "rns/Crypto.h"

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

} // namespace rns
