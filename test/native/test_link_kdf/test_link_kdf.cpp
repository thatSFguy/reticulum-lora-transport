// test/native/test_link_kdf/test_link_kdf.cpp
//
// Pinned to ../reticulum-specifications/test-vectors/links.json:
// reproduces the alice→bob link handshake byte-for-byte and verifies
// the §6.4 ECDH + HKDF derivation matches the recorded
// shared_secret + derived_key.
//
// Spec sections covered:
//   §6.1 — LINKREQUEST construction (with §6.6 signalling)
//   §6.2 — LRPROOF construction + Ed25519 signature
//   §6.3 — link_id from a LINKREQUEST packet
//   §6.4 — link session key (ECDH + HKDF-SHA256)
//
// Last synced against test-vectors/links.json at:
//   reticulum-specifications @ rns_version_at_generation = 1.2.0

#include <unity.h>
#include <cstdint>

#include "rns/Bytes.h"
#include "rns/Crypto.h"
#include "rns/Destination.h"
#include "rns/Identity.h"
#include "rns/Packet.h"
#include "rns/Transport.h"

using rns::Bytes;

void setUp() {}
void tearDown() {}

namespace {

// Identities: alice = initiator, bob = responder. From identities.json.
constexpr const char* BOB_PRIV_HEX =
    "0f453e75d564532f2fa671aea79e9a714e4564e1ff833d1df19986fe8a36aa21"
    "9a6acdad966af7d006cfd393ca8278c608978bcaefa5b5f24db867179f83a863";

constexpr const char* DESTINATION_FULL_NAME = "vectors.link";

// Pinned ephemeral / random inputs from the vector.
constexpr const char* INITIATOR_X25519_PRIV_HEX =
    "1111111111111111111111111111111111111111111111111111111111111111";
constexpr const char* INITIATOR_ED25519_PRIV_HEX =
    "2222222222222222222222222222222222222222222222222222222222222222";
constexpr const char* RESPONDER_X25519_PRIV_HEX =
    "3333333333333333333333333333333333333333333333333333333333333333";

// Expected outputs from the vector.
constexpr const char* EXPECTED_LINKREQUEST_RAW_HEX =
    "02008c670c64308e0325ea0fd7c72787449d007b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f02001f4";
constexpr const char* EXPECTED_LINK_ID_HEX =
    "7ee5fe3e4952c9ac4519b537f6278474";
constexpr const char* EXPECTED_LRPROOF_RAW_HEX =
    "0f007ee5fe3e4952c9ac4519b537f6278474ff1de2168a36a816163aec0bb0749ff6792f78eb4f7b39156f8ee5c8693e83ebd67439ac28d9e4603334428713154edd04395b0b8acec2f703c05c3d38af133e0c7b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b142001f4";
constexpr const char* EXPECTED_SHARED_SECRET_HEX =
    "5bf22caf31c0316785b0b9bc60e56d48582ce59435ce5b3c028052be42631e0f";
constexpr const char* EXPECTED_DERIVED_KEY_HEX =
    "d4c8238d23a1810c3dbe4caec15253d5a86d7fe6afa8dfa76f915579723fd88cbcd2ab3a0cd96f5b6ffd8abec8307f05cd791dc9c4fca900f706b0313a51ab65";
// 3-byte signalling = (mode<<5)|(mtu_high) || mtu_mid || mtu_low.
// mode=0x01 (AES256_CBC), mtu=500=0x0001f4 → 0x20 0x01 0xf4.
constexpr const char* EXPECTED_SIGNALLING_HEX = "2001f4";

// alice_identity() exists in the vector inputs but isn't used by any
// of these tests — the vector's expected outputs only need bob's
// (responder's) keys. Kept as a comment for traceability.
//   rns::Identity::from_private_bytes(Bytes::from_hex(ALICE_PRIV_HEX))
rns::Identity bob_identity() {
    return rns::Identity::from_private_bytes(Bytes::from_hex(BOB_PRIV_HEX));
}

} // namespace

// §6.1 — LINKREQUEST wire reproduction. Pack the same flags / dest_hash
// / context / body as upstream and confirm byte-for-byte match.
//
// Body: initiator_X25519_pub(32) || initiator_Ed25519_pub(32) || signalling(3)
// flags: HEADER_1 (00) | BROADCAST (0) | SINGLE (00) | LINKREQUEST (10) = 0x02
void test_linkrequest_wire_matches_vector() {
    rns::Destination dest(bob_identity(), DESTINATION_FULL_NAME);
    Bytes init_x_pub = rns::crypto::x25519_public_from_private(
        Bytes::from_hex(INITIATOR_X25519_PRIV_HEX));
    Bytes init_ed_pub = rns::crypto::ed25519_public_from_private(
        Bytes::from_hex(INITIATOR_ED25519_PRIV_HEX));

    Bytes body;
    body.append(init_x_pub);
    body.append(init_ed_pub);
    body.append(Bytes::from_hex(EXPECTED_SIGNALLING_HEX));

    Bytes wire = rns::Packet::pack_header_1(
        /*flags=*/0x02, /*hops=*/0, dest.destination_hash(),
        rns::Packet::CONTEXT_NONE, body);
    TEST_ASSERT_EQUAL_STRING(EXPECTED_LINKREQUEST_RAW_HEX,
                             wire.to_hex().c_str());
}

// §6.3 — link_id derived from the LINKREQUEST packet.
void test_link_id_matches_vector() {
    Bytes raw = Bytes::from_hex(EXPECTED_LINKREQUEST_RAW_HEX);
    rns::Packet pkt = rns::Packet::from_wire_bytes(raw);
    Bytes link_id = rns::Transport::link_id_from_lr_packet(pkt);
    TEST_ASSERT_EQUAL_STRING(EXPECTED_LINK_ID_HEX, link_id.to_hex().c_str());
}

// §6.2 — LRPROOF wire reproduction. signed_data is link_id ||
// responder_X25519_pub || responder_long_term_Ed25519_pub ||
// signalling. Body = signature || responder_X25519_pub || signalling.
void test_lrproof_wire_matches_vector() {
    Bytes link_id = Bytes::from_hex(EXPECTED_LINK_ID_HEX);
    Bytes responder_x_pub = rns::crypto::x25519_public_from_private(
        Bytes::from_hex(RESPONDER_X25519_PRIV_HEX));
    Bytes signalling = Bytes::from_hex(EXPECTED_SIGNALLING_HEX);

    Bytes signed_data;
    signed_data.append(link_id);
    signed_data.append(responder_x_pub);
    signed_data.append(bob_identity().ed25519_pub());
    signed_data.append(signalling);

    Bytes signature = rns::crypto::ed25519_sign(
        bob_identity().ed25519_priv(),
        signed_data.data(), signed_data.size());

    Bytes body;
    body.append(signature);
    body.append(responder_x_pub);
    body.append(signalling);

    // flags: HEADER_1 (00) | BROADCAST (0) | LINK (11) | PROOF (11) = 0x0F
    Bytes wire = rns::Packet::pack_header_1(
        /*flags=*/0x0F, /*hops=*/0, link_id,
        rns::Packet::CONTEXT_LRPROOF, body);
    TEST_ASSERT_EQUAL_STRING(EXPECTED_LRPROOF_RAW_HEX,
                             wire.to_hex().c_str());
}

// §6.4 — shared_secret = X25519(initiator_eph_priv, responder_eph_pub).
// (Either side computes this; we use initiator's view here.)
void test_shared_secret_matches_vector() {
    Bytes init_x_priv = Bytes::from_hex(INITIATOR_X25519_PRIV_HEX);
    Bytes resp_x_pub  = rns::crypto::x25519_public_from_private(
        Bytes::from_hex(RESPONDER_X25519_PRIV_HEX));
    Bytes shared = rns::crypto::x25519_shared_secret(init_x_priv, resp_x_pub);
    TEST_ASSERT_EQUAL_STRING(EXPECTED_SHARED_SECRET_HEX,
                             shared.to_hex().c_str());
}

// §6.4 — derived_key = HKDF-SHA256(shared_secret, salt=link_id, info="", L=64).
void test_derived_key_matches_vector() {
    Bytes shared  = Bytes::from_hex(EXPECTED_SHARED_SECRET_HEX);
    Bytes link_id = Bytes::from_hex(EXPECTED_LINK_ID_HEX);
    Bytes derived = rns::crypto::hkdf_sha256(shared, link_id, /*info=*/Bytes{}, /*length=*/64);
    TEST_ASSERT_EQUAL_STRING(EXPECTED_DERIVED_KEY_HEX,
                             derived.to_hex().c_str());
}

// link_session_key composes ECDH + HKDF; full-pipeline check.
void test_link_session_key_full_pipeline() {
    Bytes init_x_priv = Bytes::from_hex(INITIATOR_X25519_PRIV_HEX);
    Bytes resp_x_pub  = rns::crypto::x25519_public_from_private(
        Bytes::from_hex(RESPONDER_X25519_PRIV_HEX));
    Bytes link_id     = Bytes::from_hex(EXPECTED_LINK_ID_HEX);

    Bytes derived = rns::crypto::link_session_key(init_x_priv, resp_x_pub, link_id);
    TEST_ASSERT_EQUAL_STRING(EXPECTED_DERIVED_KEY_HEX,
                             derived.to_hex().c_str());

    // Both sides produce the same key — exercise responder's view too.
    Bytes resp_x_priv = Bytes::from_hex(RESPONDER_X25519_PRIV_HEX);
    Bytes init_x_pub  = rns::crypto::x25519_public_from_private(
        Bytes::from_hex(INITIATOR_X25519_PRIV_HEX));
    Bytes derived2 = rns::crypto::link_session_key(resp_x_priv, init_x_pub, link_id);
    TEST_ASSERT_EQUAL_STRING(EXPECTED_DERIVED_KEY_HEX,
                             derived2.to_hex().c_str());
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    UNITY_BEGIN();
    RUN_TEST(test_linkrequest_wire_matches_vector);
    RUN_TEST(test_link_id_matches_vector);
    RUN_TEST(test_lrproof_wire_matches_vector);
    RUN_TEST(test_shared_secret_matches_vector);
    RUN_TEST(test_derived_key_matches_vector);
    RUN_TEST(test_link_session_key_full_pipeline);
    return UNITY_END();
}
