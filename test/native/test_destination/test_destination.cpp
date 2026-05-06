// test/native/test_destination/test_destination.cpp
//
// Pinned to ../reticulum-specifications/test-vectors/announces.json:
// reproduces alice's two announce wire-byte vectors byte-for-byte
// using the same inputs the spec generator used. Catches any drift
// in:
//   §1.2 destination_hash recipe
//   §1.1 X25519 ratchet pub derivation (with-ratchet vector)
//   §4.1 announce body layout (public_key || name_hash || random_hash
//                              || [ratchet] || signature || app_data)
//   §4.2 signed_data layout (dest_hash || public_key || name_hash ||
//                            random_hash || [ratchet] || app_data)
//   §4.1 random_hash construction (5-byte prefix || 5-byte BE uint40)
//   §2.1 flags byte for HEADER_1 BROADCAST SINGLE ANNOUNCE (with /
//                            without context_flag for ratchet)
//
// Last synced against test-vectors/announces.json at:
//   reticulum-specifications @ rns_version_at_generation = 1.2.0

#include <unity.h>
#include <cstdint>
#include <stdexcept>

#include "rns/Bytes.h"
#include "rns/Crypto.h"
#include "rns/Destination.h"
#include "rns/Identity.h"
#include "rns/Packet.h"

using rns::Bytes;
using rns::Destination;
using rns::Identity;

void setUp() {}
void tearDown() {}

namespace {

constexpr const char* ALICE_PRIV_HEX =
    "587e730a70d24e971efa8c146e554996d70bff45b2033d336e2c078dc63d3645"
    "bef79d95bf6b253827a2e7e81a13ab0b10a908fd158581d1827095b788169e93";

constexpr const char* ALICE_NO_RATCHET_FULL_NAME =
    "vectors.alice_announce_no_ratchet";
constexpr const char* ALICE_WITH_RATCHET_FULL_NAME =
    "vectors.alice_announce_with_ratchet";

constexpr const char* ALICE_RANDOM_PREFIX_HEX = "a1a2a3a4a5";
constexpr uint64_t    ALICE_TIMESTAMP_SECS    = 1700000000ULL;
constexpr const char* ALICE_APP_DATA_HEX      = "92c409416c6963655465737400";

constexpr const char* ALICE_NO_RATCHET_WIRE_HEX =
    "0100d9587f0be518490591c181755404d8510076fce269b2356a51b6a832a1a25099155acb20733b453f9538aaa8069e854d5a780708b44424373474ee1607c3f2b4a1cd5643de508e106e6b8cf4a10f00ec7c8b5739ff0fe7afaf7157a1a2a3a4a5006553f1009b0f121c51fda21cbce043b5b9d89b09817f29d320d2027c0f6c67144ace9d577722791e9ca1c5d24678ced4166862d77650756a98369c48a8455865c279e20092c409416c6963655465737400";
constexpr const char* ALICE_NO_RATCHET_DEST_HASH =
    "d9587f0be518490591c181755404d851";

constexpr const char* ALICE_RATCHET_PRIV_HEX =
    "b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0";
constexpr const char* ALICE_EXPECTED_RATCHET_PUB_HEX =
    "cd700e88f9e99b19c1a8a8dcd58182fd101e5e032a69ce317fde23e8ee265c51";

constexpr const char* ALICE_WITH_RATCHET_WIRE_HEX =
    "2100141410d233872609cf7b9f075afb4ebb0076fce269b2356a51b6a832a1a25099155acb20733b453f9538aaa8069e854d5a780708b44424373474ee1607c3f2b4a1cd5643de508e106e6b8cf4a10f00ec7c5130f0a9b2e01f693bd0a1a2a3a4a5006553f100cd700e88f9e99b19c1a8a8dcd58182fd101e5e032a69ce317fde23e8ee265c51e4985b2edb0694b51ddcb9e1aa73f60acd297bf8dd087056f90c2c9ee1e47587feef3b5f6f18de160bad45e49abe5f8c7d74ccb893e207061136f5222434620392c409416c6963655465737400";
constexpr const char* ALICE_WITH_RATCHET_DEST_HASH =
    "141410d233872609cf7b9f075afb4ebb";

Identity alice_identity() {
    return Identity::from_private_bytes(Bytes::from_hex(ALICE_PRIV_HEX));
}

} // namespace

// §1.2 — destination_hash for alice + the no-ratchet name matches the
// announces.json `expected.destination_hash_hex`.
void test_destination_hash_matches_no_ratchet_vector() {
    Destination d(alice_identity(), ALICE_NO_RATCHET_FULL_NAME);
    TEST_ASSERT_EQUAL_STRING(ALICE_NO_RATCHET_DEST_HASH,
                             d.destination_hash().to_hex().c_str());
}

void test_destination_hash_matches_with_ratchet_vector() {
    Destination d(alice_identity(), ALICE_WITH_RATCHET_FULL_NAME);
    TEST_ASSERT_EQUAL_STRING(ALICE_WITH_RATCHET_DEST_HASH,
                             d.destination_hash().to_hex().c_str());
}

// §4 — full reproduction of alice's no-ratchet announce wire bytes.
// If ANY of {flags, hops, dest_hash, context, public_key, name_hash,
// random_hash recipe, signed_data layout, signature, app_data
// placement} drifts, this fails. The signature is deterministic
// (Ed25519) so the wire is byte-identical to the generator's output.
void test_build_announce_no_ratchet_matches_vector() {
    Destination d(alice_identity(), ALICE_NO_RATCHET_FULL_NAME);
    Bytes wire = d.build_announce(
        Bytes::from_hex(ALICE_RANDOM_PREFIX_HEX),
        ALICE_TIMESTAMP_SECS,
        Bytes::from_hex(ALICE_APP_DATA_HEX));
    TEST_ASSERT_EQUAL_STRING(ALICE_NO_RATCHET_WIRE_HEX,
                             wire.to_hex().c_str());
}

// §4 + §1.1 — full reproduction of alice's with-ratchet announce.
// The ratchet_pub is derived from the JSON's ratchet_priv via the
// X25519 base-point multiplication; this exercises both the
// derivation (against the vector's expected ratchet_pub_hex) and the
// announce builder's context_flag + ratchet placement.
void test_build_announce_with_ratchet_matches_vector() {
    // §1.1 — ratchet_pub = X25519_base_mult(ratchet_priv).
    Bytes ratchet_priv = Bytes::from_hex(ALICE_RATCHET_PRIV_HEX);
    Bytes ratchet_pub  = rns::crypto::x25519_public_from_private(ratchet_priv);
    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        ALICE_EXPECTED_RATCHET_PUB_HEX, ratchet_pub.to_hex().c_str(),
        "X25519 ratchet pub derivation diverged from the vector");

    Destination d(alice_identity(), ALICE_WITH_RATCHET_FULL_NAME);
    Bytes wire = d.build_announce(
        Bytes::from_hex(ALICE_RANDOM_PREFIX_HEX),
        ALICE_TIMESTAMP_SECS,
        Bytes::from_hex(ALICE_APP_DATA_HEX),
        ratchet_pub);
    TEST_ASSERT_EQUAL_STRING(ALICE_WITH_RATCHET_WIRE_HEX,
                             wire.to_hex().c_str());
}

// §7.2.4 — same announce body, context byte mutated to PATH_RESPONSE
// (0x0B). Everything past the context byte (offset 19 in HEADER_1)
// matches the no-ratchet vector; only byte 18 differs.
void test_build_path_response_announce_mutates_only_context_byte() {
    Destination d(alice_identity(), ALICE_NO_RATCHET_FULL_NAME);
    Bytes wire = d.build_announce(
        Bytes::from_hex(ALICE_RANDOM_PREFIX_HEX),
        ALICE_TIMESTAMP_SECS,
        Bytes::from_hex(ALICE_APP_DATA_HEX),
        /*ratchet_pub=*/{},
        /*path_response=*/true);

    Bytes expected = Bytes::from_hex(ALICE_NO_RATCHET_WIRE_HEX);
    expected[18] = rns::Packet::CONTEXT_PATH_RESPONSE;
    TEST_ASSERT_EQUAL_STRING(expected.to_hex().c_str(), wire.to_hex().c_str());
}

void test_build_announce_rejects_short_random_prefix() {
    Destination d(alice_identity(), ALICE_NO_RATCHET_FULL_NAME);
    try {
        (void)d.build_announce(Bytes::from_hex("a1a2a3a4"),  // 4 bytes (need 5)
                               ALICE_TIMESTAMP_SECS,
                               Bytes::from_hex(ALICE_APP_DATA_HEX));
        TEST_FAIL_MESSAGE("expected throw — random_prefix too short");
    } catch (const std::invalid_argument&) {
        // expected
    }
}

void test_build_announce_rejects_wrong_size_ratchet() {
    Destination d(alice_identity(), ALICE_WITH_RATCHET_FULL_NAME);
    try {
        Bytes bad_ratchet(31);  // 31 bytes, must be 32 (or empty)
        (void)d.build_announce(Bytes::from_hex(ALICE_RANDOM_PREFIX_HEX),
                               ALICE_TIMESTAMP_SECS,
                               {},
                               bad_ratchet);
        TEST_FAIL_MESSAGE("expected throw — ratchet_pub wrong size");
    } catch (const std::invalid_argument&) {
        // expected
    }
}

void test_build_announce_rejects_public_only_identity() {
    Identity pub_only = Identity::from_public_bytes(alice_identity().public_key());
    Destination d(pub_only, ALICE_NO_RATCHET_FULL_NAME);
    try {
        (void)d.build_announce(Bytes::from_hex(ALICE_RANDOM_PREFIX_HEX),
                               ALICE_TIMESTAMP_SECS,
                               Bytes::from_hex(ALICE_APP_DATA_HEX));
        TEST_FAIL_MESSAGE("expected throw — identity has no private key");
    } catch (const std::invalid_argument&) {
        // expected
    }
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    UNITY_BEGIN();
    RUN_TEST(test_destination_hash_matches_no_ratchet_vector);
    RUN_TEST(test_destination_hash_matches_with_ratchet_vector);
    RUN_TEST(test_build_announce_no_ratchet_matches_vector);
    RUN_TEST(test_build_announce_with_ratchet_matches_vector);
    RUN_TEST(test_build_path_response_announce_mutates_only_context_byte);
    RUN_TEST(test_build_announce_rejects_short_random_prefix);
    RUN_TEST(test_build_announce_rejects_wrong_size_ratchet);
    RUN_TEST(test_build_announce_rejects_public_only_identity);
    return UNITY_END();
}
