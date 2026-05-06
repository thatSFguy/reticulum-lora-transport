// test/native/test_identity/test_identity.cpp
//
// Unity tests pinned to ../reticulum-specifications/test-vectors/identities.json.
// Each `vectors[i]` entry in that JSON becomes one test below — when the
// JSON grows, add a parallel test here. We hardcode the expected values
// rather than parse JSON in C++ at runtime, so a divergence between the
// two surfaces as a build/test failure rather than a silent skip.
//
// Last synced against test-vectors/identities.json at:
//   reticulum-specifications @ rns_version_at_generation = 1.2.0
//
// Spec sections covered:
//   §1.1 — Identity (private→public, identity_hash)
//   §1.2 — Destination hash (name_hash, dest_hash for "lxmf.delivery")
//   §1.3 — On-disk private key blob layout (X25519 || Ed25519)

#include <unity.h>
#include "rns/Bytes.h"
#include "rns/Identity.h"

using rns::Bytes;
using rns::Identity;

void setUp() {}
void tearDown() {}

namespace {

struct Vector {
    const char* label;
    const char* full_name;
    const char* priv_hex;
    const char* pub_hex;
    const char* identity_hash_hex;
    const char* name_hash_hex;
    const char* destination_hash_hex;
};

// vectors/0 — alice
constexpr Vector ALICE = {
    "alice",
    "lxmf.delivery",
    "587e730a70d24e971efa8c146e554996d70bff45b2033d336e2c078dc63d3645"
    "bef79d95bf6b253827a2e7e81a13ab0b10a908fd158581d1827095b788169e93",
    "76fce269b2356a51b6a832a1a25099155acb20733b453f9538aaa8069e854d5a"
    "780708b44424373474ee1607c3f2b4a1cd5643de508e106e6b8cf4a10f00ec7c",
    "28d43a11abc1094301a59ed3b44f127b",
    "6ec60bc318e2c0f0d908",
    "c33c40a5b030596d95617dc4ca163aae",
};

// vectors/1 — bob
constexpr Vector BOB = {
    "bob",
    "lxmf.delivery",
    "0f453e75d564532f2fa671aea79e9a714e4564e1ff833d1df19986fe8a36aa21"
    "9a6acdad966af7d006cfd393ca8278c608978bcaefa5b5f24db867179f83a863",
    "92331490ac7c5db96102f80ffc64d71330907a5aea969b8617b7b2f3e0f8352a"
    "274e3172cbb18bdb14ccc1178fd66a8a811be97690d30985c75649a2b07dc76a",
    "c090410e5b5bf8956194c1872dccec3b",
    "6ec60bc318e2c0f0d908",
    "9695d17f22fa6e45d2b0cd3439a7ca7e",
};

void check_vector(const Vector& v) {
    Bytes priv = Bytes::from_hex(v.priv_hex);
    Identity id = Identity::from_private_bytes(priv);

    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        v.pub_hex, id.public_key().to_hex().c_str(),
        "public_key mismatch — §1.1 X25519 || Ed25519 derivation");

    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        v.identity_hash_hex, id.identity_hash().to_hex().c_str(),
        "identity_hash mismatch — §1.1 SHA256(public_key)[:16]");

    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        v.name_hash_hex,
        Identity::name_hash(v.full_name).to_hex().c_str(),
        "name_hash mismatch — §1.2 SHA256(full_name)[:10]");

    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        v.destination_hash_hex,
        id.destination_hash(v.full_name).to_hex().c_str(),
        "destination_hash mismatch — §1.2 SHA256(name_hash || identity_hash)[:16]");
}

} // namespace

void test_identity_alice() { check_vector(ALICE); }
void test_identity_bob()   { check_vector(BOB);   }

// SPEC §1.2 also pins the dest_hash for the path-request control
// destination. This one has no associated identity (PLAIN destination),
// so we exercise it via a different code path once Destination is
// implemented. For now we just check that the canonical name_hash from
// SPEC §1.2 table is what we compute.
void test_canonical_name_hashes() {
    TEST_ASSERT_EQUAL_STRING("6ec60bc318e2c0f0d908",
        Identity::name_hash("lxmf.delivery").to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING("e03a09b77ac21b22258e",
        Identity::name_hash("lxmf.propagation").to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING("213e6311bcec54ab4fde",
        Identity::name_hash("nomadnetwork.node").to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING("7926bbe7dd7f9aba88b0",
        Identity::name_hash("rnstransport.path.request").to_hex().c_str());
}

void test_bytes_hex_roundtrip() {
    const char* h = "00ff1234deadbeef";
    Bytes b = Bytes::from_hex(h);
    TEST_ASSERT_EQUAL_UINT(8, b.size());
    TEST_ASSERT_EQUAL_STRING(h, b.to_hex().c_str());
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    UNITY_BEGIN();
    RUN_TEST(test_bytes_hex_roundtrip);
    RUN_TEST(test_canonical_name_hashes);
    RUN_TEST(test_identity_alice);
    RUN_TEST(test_identity_bob);
    return UNITY_END();
}
