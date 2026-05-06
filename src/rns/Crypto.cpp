#include "rns/Crypto.h"

#include <SHA256.h>
#include <Ed25519.h>
#include <Curve25519.h>

#include <cstring>
#include <stdexcept>

namespace rns { namespace crypto {

Bytes sha256(const uint8_t* data, size_t len) {
    SHA256 h;
    h.update(data, len);
    Bytes out(32);
    h.finalize(out.data(), 32);
    return out;
}

Bytes ed25519_public_from_private(const Bytes& priv) {
    if (priv.size() != 32) {
        throw std::invalid_argument("ed25519_public_from_private: priv must be 32 bytes");
    }
    Bytes pub(32);
    Ed25519::derivePublicKey(pub.data(), priv.data());
    return pub;
}

Bytes ed25519_sign(const Bytes& priv, const uint8_t* msg, size_t msg_len) {
    if (priv.size() != 32) {
        throw std::invalid_argument("ed25519_sign: priv must be 32 bytes");
    }
    uint8_t pub[32];
    Ed25519::derivePublicKey(pub, priv.data());
    Bytes sig(64);
    Ed25519::sign(sig.data(), priv.data(), pub, msg, msg_len);
    return sig;
}

bool ed25519_verify(const Bytes& pub, const Bytes& sig,
                    const uint8_t* msg, size_t msg_len) {
    if (pub.size() != 32 || sig.size() != 64) return false;
    return Ed25519::verify(sig.data(), pub.data(), msg, msg_len);
}

// X25519 basepoint (u = 9, little-endian).
static constexpr uint8_t X25519_BASEPOINT[32] = {
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

Bytes x25519_public_from_private(const Bytes& priv) {
    if (priv.size() != 32) {
        throw std::invalid_argument("x25519_public_from_private: priv must be 32 bytes");
    }
    // Curve25519::eval modifies the 's' (scalar) input via clamping. RNS stores
    // the clamped key on disk (§1.3) so re-clamping is a no-op, but we copy
    // into a scratch buffer to keep the input Bytes immutable.
    uint8_t scalar[32];
    std::memcpy(scalar, priv.data(), 32);
    Bytes pub(32);
    if (!Curve25519::eval(pub.data(), scalar, X25519_BASEPOINT)) {
        // eval returns false only on weak-point inputs; basepoint isn't weak,
        // so this is unreachable for valid private keys.
        throw std::runtime_error("x25519_public_from_private: eval failed");
    }
    return pub;
}

Bytes x25519_shared_secret(const Bytes& priv, const Bytes& peer_pub) {
    if (priv.size() != 32 || peer_pub.size() != 32) {
        throw std::invalid_argument("x25519_shared_secret: 32-byte inputs required");
    }
    uint8_t scalar[32];
    std::memcpy(scalar, priv.data(), 32);
    Bytes ss(32);
    if (!Curve25519::eval(ss.data(), scalar, peer_pub.data())) {
        throw std::runtime_error("x25519_shared_secret: peer_pub is a weak point");
    }
    return ss;
}

} } // namespace rns::crypto
