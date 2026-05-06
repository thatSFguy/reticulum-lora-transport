// test/native/test_packet/test_packet.cpp
//
// Unity tests pinned to ../reticulum-specifications/test-vectors/announces.json.
// Each vector becomes one validate_announce test; field-level slice
// expectations (header + body decomposition per SPEC §2 / §4.1) are
// asserted alongside.
//
// Last synced against test-vectors/announces.json at:
//   reticulum-specifications @ rns_version_at_generation = 1.2.0
//
// Spec sections covered:
//   §2.1 — Flag byte layout
//   §2.2 — HEADER_1 form
//   §4.1 — Announce body
//   §4.2 — Signed data
//   §4.3 — app_data shape (msgpack — only checked as opaque bytes here)
//   §4.5 — validate_announce (steps 1-3: body parse, sig, dest_hash recompute)

#include <unity.h>
#include <stdexcept>
#include "rns/Bytes.h"
#include "rns/Identity.h"
#include "rns/Packet.h"

using rns::AnnounceBody;
using rns::Bytes;
using rns::Identity;
using rns::Packet;
using rns::ValidatedAnnounce;

void setUp() {}
void tearDown() {}

namespace {

struct AnnounceVector {
    const char* label;
    bool        with_ratchet;
    uint8_t     flags;
    uint8_t     hops;
    uint8_t     context;
    const char* destination_hash_hex;
    const char* wire_bytes_hex;

    // §4.1 body decomposition — JSON `expected.fields`.
    const char* body_public_key_hex;
    const char* body_name_hash_hex;
    const char* body_random_hash_hex;
    const char* body_ratchet_pub_hex;   // null for no-ratchet vector
    const char* body_signature_hex;
    const char* body_app_data_hex;
};

constexpr AnnounceVector ALICE_NO_RATCHET = {
    "alice_lxmf_no_ratchet",
    false, 0x01, 0x00, 0x00,
    "d9587f0be518490591c181755404d851",
    "0100d9587f0be518490591c181755404d8510076fce269b2356a51b6a832a1a25099155acb20733b453f9538aaa8069e854d5a780708b44424373474ee1607c3f2b4a1cd5643de508e106e6b8cf4a10f00ec7c8b5739ff0fe7afaf7157a1a2a3a4a5006553f1009b0f121c51fda21cbce043b5b9d89b09817f29d320d2027c0f6c67144ace9d577722791e9ca1c5d24678ced4166862d77650756a98369c48a8455865c279e20092c409416c6963655465737400",
    "76fce269b2356a51b6a832a1a25099155acb20733b453f9538aaa8069e854d5a780708b44424373474ee1607c3f2b4a1cd5643de508e106e6b8cf4a10f00ec7c",
    "8b5739ff0fe7afaf7157",
    "a1a2a3a4a5006553f100",
    nullptr,
    "9b0f121c51fda21cbce043b5b9d89b09817f29d320d2027c0f6c67144ace9d577722791e9ca1c5d24678ced4166862d77650756a98369c48a8455865c279e200",
    "92c409416c6963655465737400",
};

constexpr AnnounceVector ALICE_WITH_RATCHET = {
    "alice_lxmf_with_ratchet",
    true, 0x21, 0x00, 0x00,
    "141410d233872609cf7b9f075afb4ebb",
    "2100141410d233872609cf7b9f075afb4ebb0076fce269b2356a51b6a832a1a25099155acb20733b453f9538aaa8069e854d5a780708b44424373474ee1607c3f2b4a1cd5643de508e106e6b8cf4a10f00ec7c5130f0a9b2e01f693bd0a1a2a3a4a5006553f100cd700e88f9e99b19c1a8a8dcd58182fd101e5e032a69ce317fde23e8ee265c51e4985b2edb0694b51ddcb9e1aa73f60acd297bf8dd087056f90c2c9ee1e47587feef3b5f6f18de160bad45e49abe5f8c7d74ccb893e207061136f5222434620392c409416c6963655465737400",
    "76fce269b2356a51b6a832a1a25099155acb20733b453f9538aaa8069e854d5a780708b44424373474ee1607c3f2b4a1cd5643de508e106e6b8cf4a10f00ec7c",
    "5130f0a9b2e01f693bd0",
    "a1a2a3a4a5006553f100",
    "cd700e88f9e99b19c1a8a8dcd58182fd101e5e032a69ce317fde23e8ee265c51",
    "e4985b2edb0694b51ddcb9e1aa73f60acd297bf8dd087056f90c2c9ee1e47587feef3b5f6f18de160bad45e49abe5f8c7d74ccb893e207061136f52224346203",
    "92c409416c6963655465737400",
};

void check_header_decode(const AnnounceVector& v, const Packet& p) {
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(v.flags,   p.flags(),
        "flags byte mismatch — §2.1");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(v.hops,    p.hops(),
        "hops byte mismatch — §2.4");
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(v.context, p.context(),
        "context byte mismatch — §2.5");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        v.destination_hash_hex, p.destination_hash().to_hex().c_str(),
        "dest_hash slice mismatch — §2.2 HEADER_1");
    TEST_ASSERT_TRUE_MESSAGE(p.header_type() == Packet::HeaderType::HEADER_1,
        "expected HEADER_1 — §2.1 bits 7-6");
    TEST_ASSERT_TRUE_MESSAGE(p.transport_type() == Packet::TransportType::BROADCAST,
        "expected BROADCAST — §2.1 bit 4");
    TEST_ASSERT_TRUE_MESSAGE(p.destination_type() == Packet::DestinationType::SINGLE,
        "expected SINGLE — §2.1 bits 3-2");
    TEST_ASSERT_TRUE_MESSAGE(p.packet_type() == Packet::PacketType::ANNOUNCE,
        "expected ANNOUNCE — §2.1 bits 1-0");
    TEST_ASSERT_EQUAL_MESSAGE(v.with_ratchet, p.context_flag(),
        "context_flag bit doesn't match vector's with_ratchet — §2.1 bit 5");
    TEST_ASSERT_EQUAL_UINT(0, p.transport_id().size());
}

void check_body_decode(const AnnounceVector& v, const AnnounceBody& body) {
    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        v.body_public_key_hex, body.public_key.to_hex().c_str(),
        "public_key slice — §4.1");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        v.body_name_hash_hex, body.name_hash.to_hex().c_str(),
        "name_hash slice — §4.1");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        v.body_random_hash_hex, body.random_hash.to_hex().c_str(),
        "random_hash slice — §4.1");
    if (v.with_ratchet) {
        TEST_ASSERT_EQUAL_STRING_MESSAGE(
            v.body_ratchet_pub_hex, body.ratchet_pub.to_hex().c_str(),
            "ratchet_pub slice — §4.1 (context_flag = 1)");
    } else {
        TEST_ASSERT_EQUAL_UINT_MESSAGE(0, body.ratchet_pub.size(),
            "ratchet_pub must be empty when context_flag = 0 — §4.1");
    }
    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        v.body_signature_hex, body.signature.to_hex().c_str(),
        "signature slice — §4.1");
    TEST_ASSERT_EQUAL_STRING_MESSAGE(
        v.body_app_data_hex, body.app_data.to_hex().c_str(),
        "app_data slice — §4.1 (remainder)");
}

void check_validated(const AnnounceVector& v, const ValidatedAnnounce& va) {
    TEST_ASSERT_EQUAL_STRING(v.destination_hash_hex, va.destination_hash.to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING(v.body_public_key_hex,  va.public_key.to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING(v.body_name_hash_hex,   va.name_hash.to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING(v.body_random_hash_hex, va.random_hash.to_hex().c_str());
    if (v.with_ratchet) {
        TEST_ASSERT_EQUAL_STRING(v.body_ratchet_pub_hex, va.ratchet_pub.to_hex().c_str());
    } else {
        TEST_ASSERT_EQUAL_UINT(0, va.ratchet_pub.size());
    }
    TEST_ASSERT_EQUAL_STRING(v.body_app_data_hex, va.app_data.to_hex().c_str());
    TEST_ASSERT_FALSE_MESSAGE(va.is_path_response,
        "context = NONE in vectors, so is_path_response must be false");
}

void check_vector(const AnnounceVector& v) {
    Bytes raw = Bytes::from_hex(v.wire_bytes_hex);
    Packet p  = Packet::from_wire_bytes(raw);

    check_header_decode(v, p);

    AnnounceBody body = rns::parse_announce_body(p.data(), p.context_flag());
    check_body_decode(v, body);

    auto va = Identity::validate_announce(p);
    TEST_ASSERT_TRUE_MESSAGE(va.has_value(),
        "validate_announce must accept a generator-emitted vector — §4.5");
    check_validated(v, *va);
}

} // namespace

void test_announce_alice_no_ratchet() { check_vector(ALICE_NO_RATCHET); }
void test_announce_alice_with_ratchet() { check_vector(ALICE_WITH_RATCHET); }

// §4.5 step 2 — flipping a single byte of the signature must reject.
void test_validate_rejects_bad_signature() {
    Bytes raw = Bytes::from_hex(ALICE_NO_RATCHET.wire_bytes_hex);
    // Body starts at offset 19 (HEADER_1). public_key(64) + name_hash(10)
    // + random_hash(10) = 84, so signature[0] is at wire offset 19+84 = 103.
    raw[103] ^= 0x01;
    Packet p = Packet::from_wire_bytes(raw);
    auto va = Identity::validate_announce(p);
    TEST_ASSERT_FALSE_MESSAGE(va.has_value(),
        "validate_announce must reject when signature is mutated");
}

// §4.5 step 3 — flipping a byte of dest_hash must reject (signature
// covers it; recompute step would also catch it).
void test_validate_rejects_dest_hash_tamper() {
    Bytes raw = Bytes::from_hex(ALICE_NO_RATCHET.wire_bytes_hex);
    raw[2] ^= 0x01;  // first byte of dest_hash, offset 2 in HEADER_1
    Packet p = Packet::from_wire_bytes(raw);
    auto va = Identity::validate_announce(p);
    TEST_ASSERT_FALSE_MESSAGE(va.has_value(),
        "validate_announce must reject when outer dest_hash is mutated");
}

// §2.1 — a packet whose packet_type isn't ANNOUNCE must not be
// accepted by validate_announce.
void test_validate_rejects_non_announce_type() {
    Bytes raw = Bytes::from_hex(ALICE_NO_RATCHET.wire_bytes_hex);
    raw[0] = (raw[0] & 0xFC) | 0x00;  // force packet_type = DATA (00)
    Packet p = Packet::from_wire_bytes(raw);
    auto va = Identity::validate_announce(p);
    TEST_ASSERT_FALSE_MESSAGE(va.has_value(),
        "validate_announce must reject non-ANNOUNCE packets");
}

// Round-trip: from_wire_bytes ; wire_bytes() == original.
void test_packet_wire_roundtrip() {
    Bytes raw = Bytes::from_hex(ALICE_WITH_RATCHET.wire_bytes_hex);
    Packet p  = Packet::from_wire_bytes(raw);
    TEST_ASSERT_EQUAL_STRING(ALICE_WITH_RATCHET.wire_bytes_hex,
                             p.wire_bytes().to_hex().c_str());
}

// §4.5 step 1 — short body (less than fixed-length fields) must throw.
void test_parse_announce_body_rejects_short() {
    Bytes too_short(40);  // way less than 148 (no-ratchet minimum)
    try {
        (void)rns::parse_announce_body(too_short, false);
        TEST_FAIL_MESSAGE("expected parse_announce_body to throw on short input");
    } catch (const std::invalid_argument&) {
        // expected
    }
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    UNITY_BEGIN();
    RUN_TEST(test_announce_alice_no_ratchet);
    RUN_TEST(test_announce_alice_with_ratchet);
    RUN_TEST(test_validate_rejects_bad_signature);
    RUN_TEST(test_validate_rejects_dest_hash_tamper);
    RUN_TEST(test_validate_rejects_non_announce_type);
    RUN_TEST(test_packet_wire_roundtrip);
    RUN_TEST(test_parse_announce_body_rejects_short);
    return UNITY_END();
}
