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
// is the clamped X25519 scalar (Reticulum stores it pre-clamped on disk
// per §1.3, so callers pass it through unmodified).
Bytes x25519_public_from_private(const Bytes& priv);
Bytes x25519_shared_secret(const Bytes& priv, const Bytes& peer_pub);

} } // namespace rns::crypto
