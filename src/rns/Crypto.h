// src/rns/Crypto.h — narrow crypto API used by the RNS stack.
//
// Implementations live in Crypto.cpp and wrap rweather/Crypto, which
// is portable C++ and links cleanly on both native (host tests) and
// arduino-nrf52 (firmware). Anything platform-specific (RNG, AES
// hardware acceleration) is hidden behind this header.
//
// This header grows as the stack grows. Current scope is what
// Identity.cpp needs — SHA256, Ed25519, X25519. HKDF (link KDF,
// IFAC mask) and AES-256-CBC (Token, Link encryption) land when
// the corresponding spec layer is implemented and test-vector-pinned.

#pragma once

#include <cstdint>
#include <cstddef>
#include "rns/Bytes.h"

namespace rns { namespace crypto {

// SPEC §1.1 — full SHA-256, returns 32 bytes.
Bytes sha256(const uint8_t* data, size_t len);
inline Bytes sha256(const Bytes& b) { return sha256(b.data(), b.size()); }

// Ed25519 — SPEC §1.1 signing key. Deterministic.
//   priv:   32 bytes (Ed25519 seed)
//   pub:    32 bytes
//   sig:    64 bytes
//   msg:    arbitrary
Bytes ed25519_public_from_private(const Bytes& priv);
Bytes ed25519_sign(const Bytes& priv, const uint8_t* msg, size_t msg_len);
bool  ed25519_verify(const Bytes& pub, const Bytes& sig,
                     const uint8_t* msg, size_t msg_len);

// X25519 / Curve25519 — SPEC §1.1 ECDH key. The 32-byte private input
// is the raw X25519 scalar as stored on disk per §1.3. RNS does NOT
// guarantee on-disk privs are pre-clamped (Python's X25519 accepts
// un-clamped bytes and clamps during scalar mult per RFC 7748 §5);
// these functions clamp internally before calling out to Curve25519.
Bytes x25519_public_from_private(const Bytes& priv);
Bytes x25519_shared_secret(const Bytes& priv, const Bytes& peer_pub);

// HKDF-SHA256 per RFC 5869. Used by §6.4 link session key derivation
// and §3 Token-encrypt key schedule.
//   ikm    — input keying material (e.g. ECDH shared secret)
//   salt   — caller-supplied salt (per §6.4: link_id; per §3: recipient identity_hash)
//   info   — context info (empty for both §3 and §6.4)
//   length — desired output length in bytes (e.g. 64 for §6.4)
Bytes hkdf_sha256(const Bytes& ikm, const Bytes& salt,
                  const Bytes& info, size_t length);

// SPEC §6.4 — convenience wrapper for the link session key.
// Computes ECDH(my_priv, peer_pub) then HKDF with link_id as salt.
// Returns 64 bytes: result[0..32] is the signing key, result[32..64]
// is the encryption key (AES-256).
Bytes link_session_key(const Bytes& my_x25519_priv,
                       const Bytes& peer_x25519_pub,
                       const Bytes& link_id);

} } // namespace rns::crypto
