// test/native/test_transport/test_transport.cpp
//
// Unity tests for Transport's inbound-announce path. Pinned to
// `../reticulum-specifications/test-vectors/announces.json` for the
// real announce wire bytes (alice_no_ratchet vector) and to
// `identities.json` for the local node's keypair (bob).
//
// Spec sections covered (first slice):
//   §4.5 step 1-4 — announce parse, signature, dest_hash recompute,
//                    public_key collision logic
//   §4.5 step 6.1 — known_destinations cache update
//   §4.5 step 6.3 — random_blob replay defence (delegated to PathTable)
//   §9.5         — self-announce filter
//   §13.4        — packet-hash dedup ring
//
// Last synced against test-vectors/{identities,announces}.json at
//   reticulum-specifications @ rns_version_at_generation = 1.2.0

#include <unity.h>
#include <cstdint>

#include "rns/Bytes.h"
#include "rns/Identity.h"
#include "rns/Interface.h"
#include "rns/Packet.h"
#include "rns/Transport.h"

using rns::AnnounceHandler;
using rns::Bytes;
using rns::Identity;
using rns::Interface;
using rns::Packet;
using rns::Transport;
using rns::ValidatedAnnounce;

void setUp() {}
void tearDown() {}

namespace {

// Stub Interface — never actually transmits anything. Used so
// Transport.register_interface() has something to register.
class StubInterface : public Interface {
public:
    StubInterface() : Interface(make_cfg()) {}
protected:
    void on_transmit(const Bytes&) override {}
private:
    static Config make_cfg() {
        Config c;
        c.bitrate_bps = 8000;
        c.airtime_window_ms = 1000;
        return c;
    }
};

// Bob — local node identity. Distinct from alice (the announcer in
// the test vector), so alice's announce isn't filtered as self.
constexpr const char* BOB_PRIV_HEX =
    "0f453e75d564532f2fa671aea79e9a714e4564e1ff833d1df19986fe8a36aa21"
    "9a6acdad966af7d006cfd393ca8278c608978bcaefa5b5f24db867179f83a863";

// Alice's no-ratchet announce — full wire bytes from announces.json.
constexpr const char* ALICE_NO_RATCHET_WIRE =
    "0100d9587f0be518490591c181755404d8510076fce269b2356a51b6a832a1a25099155acb20733b453f9538aaa8069e854d5a780708b44424373474ee1607c3f2b4a1cd5643de508e106e6b8cf4a10f00ec7c8b5739ff0fe7afaf7157a1a2a3a4a5006553f1009b0f121c51fda21cbce043b5b9d89b09817f29d320d2027c0f6c67144ace9d577722791e9ca1c5d24678ced4166862d77650756a98369c48a8455865c279e20092c409416c6963655465737400";

// Alice's expected destination_hash + public_key (from the JSON).
constexpr const char* ALICE_DEST_HASH = "d9587f0be518490591c181755404d851";
constexpr const char* ALICE_PUB_KEY   =
    "76fce269b2356a51b6a832a1a25099155acb20733b453f9538aaa8069e854d5a"
    "780708b44424373474ee1607c3f2b4a1cd5643de508e106e6b8cf4a10f00ec7c";

Identity bob_identity() {
    return Identity::from_private_bytes(Bytes::from_hex(BOB_PRIV_HEX));
}

} // namespace

void test_inbound_validates_and_caches_announce() {
    Transport t(bob_identity());
    StubInterface iface;
    t.register_interface(&iface);

    Bytes wire = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    t.inbound(&iface, wire, /*now_ms=*/1'000'000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().announce_validated);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().announce_rejected);
    TEST_ASSERT_EQUAL_UINT(1, t.known_count());

    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);
    const Bytes* pub = t.public_key_for(alice_dest);
    TEST_ASSERT_NOT_NULL(pub);
    TEST_ASSERT_EQUAL_STRING(ALICE_PUB_KEY, pub->to_hex().c_str());

    // Path entry should exist with our stub as the receiving interface
    // and the announce wire cached.
    const auto* path = t.path_table().get(alice_dest);
    TEST_ASSERT_NOT_NULL(path);
    TEST_ASSERT_EQUAL_PTR(&iface, path->receiving_interface);
    TEST_ASSERT_EQUAL_STRING(ALICE_NO_RATCHET_WIRE,
                             path->announce_wire.to_hex().c_str());
    TEST_ASSERT_EQUAL_UINT(1, path->random_blobs.size());
}

void test_inbound_dedups_duplicate_announces() {
    Transport t(bob_identity());
    StubInterface iface;
    t.register_interface(&iface);

    Bytes wire = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    t.inbound(&iface, wire, 1000);
    t.inbound(&iface, wire, 1001);  // same bytes, slightly later

    TEST_ASSERT_EQUAL_UINT(2, t.stats().inbound_packets);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().dedup_drops);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().announce_validated);
    TEST_ASSERT_EQUAL_UINT(1, t.known_count());
}

// Same announce arriving with a different `hops` byte — dedup hash
// excludes hops so it should still be dropped.
void test_dedup_ignores_hops_byte() {
    Transport t(bob_identity());
    StubInterface iface;
    t.register_interface(&iface);

    Bytes wire1 = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    Bytes wire2 = wire1;
    wire2[1] = 0x05;  // mutate hops only

    t.inbound(&iface, wire1, 100);
    t.inbound(&iface, wire2, 200);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().dedup_drops);
}

void test_self_announce_is_filtered() {
    // Local identity = alice. Alice's announce hits the §9.5 filter.
    constexpr const char* ALICE_PRIV_HEX =
        "587e730a70d24e971efa8c146e554996d70bff45b2033d336e2c078dc63d3645"
        "bef79d95bf6b253827a2e7e81a13ab0b10a908fd158581d1827095b788169e93";
    Transport t(Identity::from_private_bytes(Bytes::from_hex(ALICE_PRIV_HEX)));
    StubInterface iface;
    t.register_interface(&iface);

    Bytes wire = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    t.inbound(&iface, wire, 1000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().self_announce_drops);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().announce_validated);
    TEST_ASSERT_EQUAL_UINT(0, t.known_count());
}

void test_announce_handler_fires() {
    Transport t(bob_identity());
    StubInterface iface;
    t.register_interface(&iface);

    int call_count = 0;
    Bytes seen_dest;
    Bytes seen_pub;
    Interface* seen_iface = nullptr;
    t.register_announce_handler(
        [&](const ValidatedAnnounce& va, Interface* on) {
            call_count++;
            seen_dest = va.destination_hash;
            seen_pub  = va.public_key;
            seen_iface = on;
        });

    Bytes wire = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    t.inbound(&iface, wire, 1000);

    TEST_ASSERT_EQUAL_INT(1, call_count);
    TEST_ASSERT_EQUAL_STRING(ALICE_DEST_HASH, seen_dest.to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING(ALICE_PUB_KEY,   seen_pub.to_hex().c_str());
    TEST_ASSERT_EQUAL_PTR(&iface, seen_iface);
}

void test_inbound_rejects_malformed_packet() {
    Transport t(bob_identity());
    StubInterface iface;
    t.register_interface(&iface);

    Bytes too_short(5);  // way under HEADER_1_MIN_LEN
    t.inbound(&iface, too_short, 1000);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().parse_failures);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().announce_validated);
}

void test_tampered_announce_is_rejected() {
    Transport t(bob_identity());
    StubInterface iface;
    t.register_interface(&iface);

    Bytes wire = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    wire[103] ^= 0x01;  // signature tamper (offset confirmed in test_packet.cpp)

    t.inbound(&iface, wire, 1000);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().announce_rejected);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().announce_validated);
    TEST_ASSERT_EQUAL_UINT(0, t.known_count());
}

void test_tick_evicts_expired_paths() {
    Transport t(bob_identity());
    StubInterface iface;
    t.register_interface(&iface);

    Bytes wire = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    t.inbound(&iface, wire, /*now=*/1000);
    TEST_ASSERT_EQUAL_UINT(1, t.path_table().size());

    // The default expires is now + 1 hour (§12.4.1 AP_PATH_TIME).
    // Ticking past that should evict.
    t.tick(1000 + 60ULL * 60ULL * 1000ULL + 1);
    TEST_ASSERT_EQUAL_UINT(0, t.path_table().size());
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    UNITY_BEGIN();
    RUN_TEST(test_inbound_validates_and_caches_announce);
    RUN_TEST(test_inbound_dedups_duplicate_announces);
    RUN_TEST(test_dedup_ignores_hops_byte);
    RUN_TEST(test_self_announce_is_filtered);
    RUN_TEST(test_announce_handler_fires);
    RUN_TEST(test_inbound_rejects_malformed_packet);
    RUN_TEST(test_tampered_announce_is_rejected);
    RUN_TEST(test_tick_evicts_expired_paths);
    return UNITY_END();
}
