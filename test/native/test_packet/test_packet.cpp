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

// §2.2 — pack_header_1 is the inverse of from_wire_bytes for both
// announce vectors. Round-trip the parsed fields and verify the
// repacked wire bytes equal the originals.
void test_pack_header_1_round_trip() {
    for (const AnnounceVector* v : {&ALICE_NO_RATCHET, &ALICE_WITH_RATCHET}) {
        Bytes raw = Bytes::from_hex(v->wire_bytes_hex);
        Packet p  = Packet::from_wire_bytes(raw);
        Bytes packed = Packet::pack_header_1(p.flags(), p.hops(),
                                             p.destination_hash(),
                                             p.context(), p.data());
        TEST_ASSERT_EQUAL_STRING_MESSAGE(
            v->wire_bytes_hex, packed.to_hex().c_str(),
            "pack_header_1 must reproduce parsed wire bytes");
    }
}

// §2.2 — synthesize a HEADER_2 packet from scratch, parse it back,
// and verify all fields round-trip cleanly.
void test_pack_header_2_round_trip() {
    Bytes tid  = Bytes::from_hex("00112233445566778899aabbccddeeff");
    Bytes dh   = Bytes::from_hex("11111111222222223333333344444444");
    Bytes body = Bytes::from_hex("deadbeefcafef00d");
    // flags: HEADER_2 (bit 6) | TRANSPORT (bit 4) | DATA (00) = 0x50
    Bytes packed = Packet::pack_header_2(0x50, 0x05, tid, dh,
                                         Packet::CONTEXT_NONE, body);
    Packet p = Packet::from_wire_bytes(packed);
    TEST_ASSERT_TRUE(p.header_type() == Packet::HeaderType::HEADER_2);
    TEST_ASSERT_EQUAL_UINT8(0x05, p.hops());
    TEST_ASSERT_EQUAL_STRING(tid.to_hex().c_str(), p.transport_id().to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING(dh.to_hex().c_str(),  p.destination_hash().to_hex().c_str());
    TEST_ASSERT_EQUAL_UINT8(Packet::CONTEXT_NONE, p.context());
    TEST_ASSERT_EQUAL_STRING(body.to_hex().c_str(), p.data().to_hex().c_str());
}

// §2.3 — originator HEADER_1→HEADER_2 conversion preserves the body
// and dest_hash, inserts transport_id, sets HEADER_2 + TRANSPORT
// bits, and preserves bits 3-0 (destination_type, packet_type).
void test_originator_to_header_2() {
    Bytes raw = Bytes::from_hex(ALICE_NO_RATCHET.wire_bytes_hex);
    Packet p  = Packet::from_wire_bytes(raw);
    Bytes tid = Bytes::from_hex("aabbccddeeff00112233445566778899");
    Packet p2 = p.originator_to_header_2(tid);

    // old flags 0x01 (HEADER_1, BROADCAST, SINGLE, ANNOUNCE) →
    // new flags 0x40 | 0x10 | (0x01 & 0x0F) = 0x51
    TEST_ASSERT_EQUAL_UINT8(0x51, p2.flags());
    TEST_ASSERT_TRUE(p2.header_type()    == Packet::HeaderType::HEADER_2);
    TEST_ASSERT_TRUE(p2.transport_type() == Packet::TransportType::TRANSPORT);
    TEST_ASSERT_FALSE(p2.context_flag());
    TEST_ASSERT_TRUE(p2.destination_type() == Packet::DestinationType::SINGLE);
    TEST_ASSERT_TRUE(p2.packet_type()      == Packet::PacketType::ANNOUNCE);

    TEST_ASSERT_EQUAL_UINT8(p.hops(), p2.hops());
    TEST_ASSERT_EQUAL_STRING(tid.to_hex().c_str(), p2.transport_id().to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING(p.destination_hash().to_hex().c_str(),
                             p2.destination_hash().to_hex().c_str());
    TEST_ASSERT_EQUAL_UINT8(p.context(), p2.context());
    TEST_ASSERT_EQUAL_STRING(p.data().to_hex().c_str(), p2.data().to_hex().c_str());
}

// §2.3 — context_flag (bit 5) is dropped during conversion. The
// ratchet-bearing vector exercises this.
void test_originator_to_header_2_clears_context_flag() {
    Bytes raw = Bytes::from_hex(ALICE_WITH_RATCHET.wire_bytes_hex);
    Packet p  = Packet::from_wire_bytes(raw);
    TEST_ASSERT_TRUE(p.context_flag());  // 0x21 source flag
    Packet p2 = p.originator_to_header_2(
        Bytes::from_hex("aabbccddeeff00112233445566778899"));
    // 0x21 & 0x0F = 0x01 → 0x40 | 0x10 | 0x01 = 0x51
    TEST_ASSERT_EQUAL_UINT8(0x51, p2.flags());
    TEST_ASSERT_FALSE(p2.context_flag());
}

void test_originator_to_header_2_rejects_already_header_2() {
    Bytes tid = Bytes::from_hex("00112233445566778899aabbccddeeff");
    Bytes dh  = Bytes::from_hex("22222222333333334444444455555555");
    Bytes packed = Packet::pack_header_2(0x40, 0, tid, dh, 0, Bytes{});
    Packet p = Packet::from_wire_bytes(packed);
    try {
        (void)p.originator_to_header_2(
            Bytes::from_hex("ffffffffffffffffffffffffffffffff"));
        TEST_FAIL_MESSAGE("expected throw — source already HEADER_2");
    } catch (const std::invalid_argument&) {
        // expected
    }
}

void test_pack_rejects_wrong_size_inputs() {
    Bytes good_dh  = Bytes::from_hex("11111111111111111111111111111111");
    Bytes good_tid = Bytes::from_hex("22222222222222222222222222222222");
    Bytes short_hash(15);

    try {
        (void)Packet::pack_header_1(0x00, 0, short_hash, 0, Bytes{});
        TEST_FAIL_MESSAGE("pack_header_1 must reject short dest_hash");
    } catch (const std::invalid_argument&) {}

    try {
        (void)Packet::pack_header_2(0x40, 0, short_hash, good_dh, 0, Bytes{});
        TEST_FAIL_MESSAGE("pack_header_2 must reject short transport_id");
    } catch (const std::invalid_argument&) {}

    try {
        (void)Packet::pack_header_2(0x40, 0, good_tid, short_hash, 0, Bytes{});
        TEST_FAIL_MESSAGE("pack_header_2 must reject short dest_hash");
    } catch (const std::invalid_argument&) {}
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
    RUN_TEST(test_pack_header_1_round_trip);
    RUN_TEST(test_pack_header_2_round_trip);
    RUN_TEST(test_originator_to_header_2);
    RUN_TEST(test_originator_to_header_2_clears_context_flag);
    RUN_TEST(test_originator_to_header_2_rejects_already_header_2);
    RUN_TEST(test_pack_rejects_wrong_size_inputs);
    return UNITY_END();
}
