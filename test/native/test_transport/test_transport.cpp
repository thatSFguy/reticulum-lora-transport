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
#include "rns/Crypto.h"
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

// Stub Interface — captures emissions for rebroadcast tests. Wide
// announce-cap so tick() drains everything queued without throttling.
class StubInterface : public Interface {
public:
    StubInterface() : Interface(make_cfg()) {}
    std::vector<Bytes> emitted;
protected:
    void on_transmit(const Bytes& wire) override { emitted.push_back(wire); }
private:
    static Config make_cfg() {
        Config c;
        c.bitrate_bps         = 1'000'000;  // 1 Mbps — nothing throttles in tests
        c.announce_cap_pct    = 100.0f;
        c.airtime_window_ms   = 1000;
        c.max_queued_announces = 32;
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

// flags: HEADER_2 (0x40) | TRANSPORT (0x10) | SINGLE (00) | DATA (00) = 0x50
constexpr uint8_t DATA_HEADER_2_FLAGS = 0x50;

Bytes synth_data_packet(const Bytes& transport_id, const Bytes& dest_hash,
                        const Bytes& body, uint8_t hops = 0) {
    return Packet::pack_header_2(DATA_HEADER_2_FLAGS, hops,
                                 transport_id, dest_hash,
                                 Packet::CONTEXT_NONE, body);
}

// Convert the alice_no_ratchet announce wire to HEADER_2 form with a
// caller-supplied transport_id. Used to seed path entries with hops > 1
// for §12.2.1 tests. Sets the wire's hops byte to `hops` before
// returning so the caller controls what value Transport sees.
Bytes alice_announce_header_2(const Bytes& transport_id, uint8_t hops) {
    Packet h1 = Packet::from_wire_bytes(Bytes::from_hex(ALICE_NO_RATCHET_WIRE));
    Packet h2 = h1.originator_to_header_2(transport_id);
    Bytes wire = h2.wire_bytes();
    wire[1] = hops;
    return wire;
}

// Construct the truncated-hash key the relay uses for reverse_table
// entries — must match Transport::dedup_hash()[:16] computed over the
// post-bump form of the DATA packet that the relay observed.
Bytes reverse_key_for(const Bytes& data_wire_post_bump) {
    Packet p = Packet::from_wire_bytes(data_wire_post_bump);
    Bytes material;
    material.append(p.flags());
    material.append(p.destination_hash());
    material.append(p.context());
    material.append(p.data());
    return rns::crypto::sha256(material).slice(0, 16);
}

// Synthesize a PROOF packet whose dest_hash is the truncated hash of
// a previously-forwarded DATA. body is opaque (relay doesn't sig-check).
Bytes synth_proof_packet(const Bytes& truncated_hash, const Bytes& body,
                         uint8_t hops = 0) {
    // flags: HEADER_1 (00) | BROADCAST (0) | SINGLE (00) | PROOF (11) = 0x03
    return Packet::pack_header_1(/*flags=*/0x03, hops, truncated_hash,
                                 Packet::CONTEXT_NONE, body);
}

// Build a §7.1 path-request DATA packet. Layout depends on whether
// `transport_id` is supplied (transport-mode originator vs leaf).
// flags: HEADER_1 (00) | BROADCAST (0) | PLAIN (10) | DATA (00) = 0x08
Bytes synth_path_request(const Bytes& target, const Bytes& tag,
                         const Bytes* transport_id = nullptr) {
    Bytes body;
    body.append(target);
    if (transport_id) body.append(*transport_id);
    body.append(tag);
    return Packet::pack_header_1(/*flags=*/0x08, /*hops=*/0,
                                 Transport::path_request_destination_hash(),
                                 Packet::CONTEXT_NONE, body);
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
    // and the announce wire cached. The wire has had its hops byte
    // bumped to 1 by §2.4 inbound increment.
    const auto* path = t.path_table().get(alice_dest);
    TEST_ASSERT_NOT_NULL(path);
    TEST_ASSERT_EQUAL_PTR(&iface, path->receiving_interface);
    TEST_ASSERT_EQUAL_UINT8(1, path->hops);
    Bytes expected_cached_wire = wire;
    expected_cached_wire[1] = 0x01;
    TEST_ASSERT_EQUAL_STRING(expected_cached_wire.to_hex().c_str(),
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

// §12.3 — leaf node (transport_enabled = false) does NOT queue
// announces for rebroadcast.
void test_leaf_does_not_rebroadcast() {
    Transport t(bob_identity(), /*transport_enabled=*/false);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);

    t.inbound(&in_iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().announce_validated);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().announces_queued);
    TEST_ASSERT_TRUE(t.announce_table().empty());

    t.tick(2000);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().announces_rebroadcast);
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, out_iface.emitted.size());
}

// §12.3 — relay rebroadcasts on every interface except `received_from`,
// with the hops byte incremented per §2.4.
void test_relay_rebroadcasts_on_other_interfaces() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);

    Bytes wire = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    const uint8_t orig_hops = wire[1];
    t.inbound(&in_iface, wire, /*now=*/1000);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().announces_queued);
    TEST_ASSERT_EQUAL_UINT(1, t.announce_table().size());

    // tick at retransmit_at_ms (= now_ms = 1000) — entry is due.
    t.tick(1000);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().announces_rebroadcast);
    TEST_ASSERT_TRUE(t.announce_table().empty());  // single-shot

    // Rebroadcast went to out_iface only (received_from filter).
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(1, out_iface.emitted.size());

    // §2.4 — hops byte incremented on the wire we just emitted.
    TEST_ASSERT_EQUAL_UINT8(orig_hops + 1, out_iface.emitted[0][1]);
    // Body untouched: everything from offset 19 onwards is identical.
    TEST_ASSERT_EQUAL_UINT(wire.size(), out_iface.emitted[0].size());
    for (size_t i = 19; i < wire.size(); i++) {
        TEST_ASSERT_EQUAL_UINT8(wire[i], out_iface.emitted[0][i]);
    }
}

// §12.3.3 — PATH_RESPONSE announces don't rebroadcast.
void test_path_response_announce_does_not_rebroadcast() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);

    // Synthesize a PATH_RESPONSE announce by mutating the cached
    // wire's context byte to 0x0B. The signature was computed over
    // the body and outer dest_hash only (§4.2) — context isn't in
    // signed_data, so this stays valid.
    Bytes wire = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    wire[18] = Packet::CONTEXT_PATH_RESPONSE;  // context byte at offset 18 in HEADER_1

    t.inbound(&iface, wire, 1000);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().announce_validated);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().announces_queued);
    TEST_ASSERT_TRUE(t.announce_table().empty());

    t.tick(2000);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().announces_rebroadcast);
    TEST_ASSERT_EQUAL_UINT(0, iface.emitted.size());
}

// §12.3.2 — the random_blob replay defence prevents queueing the same
// announce twice. A direct identical-wire replay is caught earlier by
// §13.4 dedup, so we exercise the random_blob path by injecting the
// same body via a wire that survives dedup (mutate context byte ⇒
// different dedup hash, but signature still valid because context
// isn't in signed_data).
void test_relay_does_not_rebroadcast_random_blob_replay() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);

    Bytes wire = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    t.inbound(&iface, wire, 1000);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().announces_queued);

    // Same announce body, different context byte → different dedup
    // hash → reaches handle_announce. random_blob check should reject.
    Bytes wire2 = wire;
    wire2[18] = 0x05;  // any non-default context that isn't PATH_RESPONSE
    t.inbound(&iface, wire2, 1001);
    TEST_ASSERT_EQUAL_UINT(2, t.stats().announce_validated);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().announces_queued);  // unchanged
}

// §12.2.2 — relay receives DATA addressed to a destination 1 hop
// away. Strips transport_id, broadcasts as HEADER_1 on the path's
// receiving_interface.
void test_data_forward_last_hop_strips_transport_id() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);

    // Alice's announce arrives on out_iface (HEADER_1, hops=0). After
    // the §2.4 inbound bump, path[alice].hops = 1.
    Bytes announce_wire = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    t.inbound(&out_iface, announce_wire, 1000);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);
    TEST_ASSERT_EQUAL_UINT8(1, t.path_table().get(alice_dest)->hops);

    // Synthesize DATA packet for alice, transport_id = us.
    Bytes body = Bytes::from_hex("11223344aabbccdd");
    Bytes data_wire = synth_data_packet(t.local_identity().identity_hash(),
                                        alice_dest, body, /*hops=*/0);

    // Clear emitted from the announce-rebroadcast queueing — but
    // those don't touch emitted yet (no tick called).
    in_iface.emitted.clear();
    out_iface.emitted.clear();

    t.inbound(&in_iface, data_wire, 1500);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().data_inbound);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().data_forwarded_header_1);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().data_forwarded_header_2);

    // Forward went out on out_iface (path.receiving_interface).
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(1, out_iface.emitted.size());

    // Parse the emitted wire — must be HEADER_1, no transport_id,
    // dest_hash and body unchanged, hops bumped to 1.
    Packet emitted = Packet::from_wire_bytes(out_iface.emitted[0]);
    TEST_ASSERT_TRUE(emitted.header_type() == Packet::HeaderType::HEADER_1);
    TEST_ASSERT_TRUE(emitted.transport_type() == Packet::TransportType::BROADCAST);
    TEST_ASSERT_EQUAL_UINT8(1, emitted.hops());
    TEST_ASSERT_EQUAL_UINT(0, emitted.transport_id().size());
    TEST_ASSERT_EQUAL_STRING(ALICE_DEST_HASH,
                             emitted.destination_hash().to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING(body.to_hex().c_str(),
                             emitted.data().to_hex().c_str());
}

// §12.2.1 — relay receives DATA addressed to a destination >1 hop
// away. Replaces transport_id with path.next_hop, keeps HEADER_2.
void test_data_forward_multi_hop_replaces_transport_id() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);

    // Seed path[alice] with hops > 1 by feeding a HEADER_2 announce
    // whose transport_id is some upstream relay (R_id). Wire arrives
    // on in_iface with hops=2; inbound bump puts it at 3.
    Bytes upstream_id = Bytes::from_hex("aabbccddeeff00112233445566778899");
    Bytes announce_wire = alice_announce_header_2(upstream_id, /*hops=*/2);
    t.inbound(&in_iface, announce_wire, 1000);

    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);
    const auto* path = t.path_table().get(alice_dest);
    TEST_ASSERT_NOT_NULL(path);
    TEST_ASSERT_EQUAL_UINT8(3, path->hops);
    TEST_ASSERT_EQUAL_STRING(upstream_id.to_hex().c_str(),
                             path->next_hop.to_hex().c_str());

    // DATA for alice with our identity as transport_id, on out_iface.
    Bytes body = Bytes::from_hex("cafef00d");
    Bytes data_wire = synth_data_packet(t.local_identity().identity_hash(),
                                        alice_dest, body);

    in_iface.emitted.clear();
    out_iface.emitted.clear();

    t.inbound(&out_iface, data_wire, 1500);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().data_inbound);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().data_forwarded_header_2);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().data_forwarded_header_1);

    // Forward went out on in_iface (path.receiving_interface — the
    // direction we learned alice from).
    TEST_ASSERT_EQUAL_UINT(1, in_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, out_iface.emitted.size());

    Packet emitted = Packet::from_wire_bytes(in_iface.emitted[0]);
    TEST_ASSERT_TRUE(emitted.header_type() == Packet::HeaderType::HEADER_2);
    TEST_ASSERT_EQUAL_UINT8(1, emitted.hops());  // bumped from 0 on inbound
    TEST_ASSERT_EQUAL_STRING(upstream_id.to_hex().c_str(),
                             emitted.transport_id().to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING(ALICE_DEST_HASH,
                             emitted.destination_hash().to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING(body.to_hex().c_str(),
                             emitted.data().to_hex().c_str());
}

// DATA with transport_id pointing to someone else — not for us, drop.
void test_data_not_for_us_is_ignored() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);

    // Seed a path entry so the lookup wouldn't fail for the wrong reason.
    Bytes announce_wire = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    t.inbound(&iface, announce_wire, 1000);

    Bytes someone_else_id =
        Bytes::from_hex("ffffffffffffffffffffffffffffffff");
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);
    Bytes data_wire = synth_data_packet(someone_else_id, alice_dest,
                                        Bytes::from_hex("aa"));
    iface.emitted.clear();
    t.inbound(&iface, data_wire, 1500);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().data_inbound);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().data_forwarded_header_1);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().data_forwarded_header_2);
    TEST_ASSERT_EQUAL_UINT(0, iface.emitted.size());
}

// DATA for an unknown destination — no path entry, drop.
void test_data_for_unknown_dest_is_ignored() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);

    Bytes unknown_dest =
        Bytes::from_hex("99999999999999999999999999999999");
    Bytes data_wire = synth_data_packet(t.local_identity().identity_hash(),
                                        unknown_dest, Bytes::from_hex("bb"));
    t.inbound(&iface, data_wire, 1000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().data_inbound);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().data_forwarded_header_1);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().data_forwarded_header_2);
    TEST_ASSERT_EQUAL_UINT(0, iface.emitted.size());
}

// HEADER_1 broadcast DATA — not addressed via transport, doesn't
// enter §12.2's forward dispatch.
void test_data_header_1_does_not_forward() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);

    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);
    // Seed path so unknown-dest isn't the reason for the no-op.
    t.inbound(&iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);

    // HEADER_1 DATA: flags = SINGLE | DATA = 0x00.
    Bytes data_wire = Packet::pack_header_1(
        /*flags=*/0x00, /*hops=*/0, alice_dest,
        Packet::CONTEXT_NONE, Bytes::from_hex("dd"));
    iface.emitted.clear();
    t.inbound(&iface, data_wire, 1500);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().data_inbound);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().data_forwarded_header_1);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().data_forwarded_header_2);
    TEST_ASSERT_EQUAL_UINT(0, iface.emitted.size());
}

// §12.2.5 — DATA forward writes a reverse_table entry whose key is
// the truncated hash of the forwarded packet, with received_if /
// outbound_if set correctly.
void test_data_forward_writes_reverse_table_entry() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);

    // alice's announce on out_iface → path[alice].hops=1.
    t.inbound(&out_iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);

    Bytes body = Bytes::from_hex("aabbccdd");
    Bytes data_wire = synth_data_packet(t.local_identity().identity_hash(),
                                        alice_dest, body, /*hops=*/0);

    in_iface.emitted.clear();
    out_iface.emitted.clear();
    TEST_ASSERT_TRUE(t.reverse_table().empty());

    t.inbound(&in_iface, data_wire, /*now_ms=*/2000);

    TEST_ASSERT_EQUAL_UINT(1, t.reverse_table().size());

    // Recompute the key the relay would have used. data_wire's hops
    // byte is bumped to 1 inside inbound(), so the hash is over the
    // bumped wire's flags/dest/context/body.
    Bytes data_wire_post_bump = data_wire;
    data_wire_post_bump[1] = 0x01;
    Bytes expected_key = reverse_key_for(data_wire_post_bump);

    const auto* entry = t.reverse_table().get(expected_key);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL_PTR(&in_iface,  entry->received_if);
    TEST_ASSERT_EQUAL_PTR(&out_iface, entry->outbound_if);
    TEST_ASSERT_EQUAL_UINT(2000, entry->timestamp_ms);
}

// §12.5.3 — PROOF arrives whose dest_hash matches a reverse_table
// entry. Relay forwards on the entry's received_if (back toward the
// originator) and pops the entry (one-shot routing).
void test_proof_forward_uses_reverse_table_entry() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);

    // Seed: announce, then DATA forward through us creates the entry.
    t.inbound(&out_iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);
    Bytes body       = Bytes::from_hex("11223344");
    Bytes data_wire  = synth_data_packet(t.local_identity().identity_hash(),
                                         alice_dest, body, 0);
    t.inbound(&in_iface, data_wire, 2000);
    TEST_ASSERT_EQUAL_UINT(1, t.reverse_table().size());

    // Compute the same truncated-hash key.
    Bytes data_wire_post_bump = data_wire;
    data_wire_post_bump[1] = 0x01;
    Bytes proof_dest = reverse_key_for(data_wire_post_bump);

    Bytes proof_body = Bytes::from_hex("c0ffee");
    Bytes proof_wire = synth_proof_packet(proof_dest, proof_body);

    in_iface.emitted.clear();
    out_iface.emitted.clear();

    // PROOF arrives on out_iface (the direction we forwarded DATA).
    t.inbound(&out_iface, proof_wire, 2500);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().proof_inbound);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().proof_forwarded);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().proof_orphaned);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().proof_wrong_interface);

    // Forwarded back on in_iface (the direction DATA originally came in).
    TEST_ASSERT_EQUAL_UINT(1, in_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, out_iface.emitted.size());

    // hops bumped on inbound (was 0 → 1).
    TEST_ASSERT_EQUAL_UINT8(0x01, in_iface.emitted[0][1]);

    // Entry was popped — a SECOND PROOF for the same dest_hash is
    // orphaned. Use a different body so the wire passes §13.4 dedup
    // (identical wires would be silently dropped before reaching
    // handle_proof_forward).
    TEST_ASSERT_TRUE(t.reverse_table().empty());
    in_iface.emitted.clear();
    Bytes proof_wire2 = synth_proof_packet(proof_dest, Bytes::from_hex("d00d"));
    t.inbound(&out_iface, proof_wire2, 2600);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().proof_orphaned);
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());
}

// PROOF whose dest_hash isn't in the reverse_table is dropped.
void test_proof_orphaned_when_no_reverse_entry() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);

    Bytes proof_wire = synth_proof_packet(
        Bytes::from_hex("00000000000000000000000000000000"),
        Bytes::from_hex("aa"));
    t.inbound(&iface, proof_wire, 1000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().proof_inbound);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().proof_orphaned);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().proof_forwarded);
    TEST_ASSERT_EQUAL_UINT(0, iface.emitted.size());
}

// PROOF arriving on the wrong interface (not the outbound_if from
// the reverse_table entry) is dropped per §12.5.3 anti-spoof check.
void test_proof_dropped_when_arriving_on_wrong_interface() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface, third_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);
    t.register_interface(&third_iface);

    // Seed: DATA forward via in_iface → out_iface.
    t.inbound(&out_iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);
    Bytes data_wire  = synth_data_packet(t.local_identity().identity_hash(),
                                         alice_dest, Bytes::from_hex("01"), 0);
    t.inbound(&in_iface, data_wire, 2000);

    Bytes data_post = data_wire;
    data_post[1] = 1;
    Bytes proof_dest = reverse_key_for(data_post);
    Bytes proof_wire = synth_proof_packet(proof_dest, Bytes::from_hex("ff"));

    in_iface.emitted.clear();
    out_iface.emitted.clear();
    third_iface.emitted.clear();

    // PROOF arrives on third_iface — wrong direction, drop. Entry
    // stays in the table (we don't pop on a failed validation).
    t.inbound(&third_iface, proof_wire, 2500);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().proof_inbound);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().proof_wrong_interface);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().proof_forwarded);
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, out_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, third_iface.emitted.size());

    // Reverse-table entry stays — the legitimate PROOF arriving on
    // out_iface should still be deliverable. Use a different body so
    // it passes §13.4 dedup (the spoof and the real PROOF can't share
    // a wire — different dedup hashes).
    TEST_ASSERT_EQUAL_UINT(1, t.reverse_table().size());
    Bytes legit_proof = synth_proof_packet(proof_dest, Bytes::from_hex("ee"));
    t.inbound(&out_iface, legit_proof, 2600);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().proof_forwarded);
    TEST_ASSERT_EQUAL_UINT(1, in_iface.emitted.size());
    TEST_ASSERT_TRUE(t.reverse_table().empty());
}

// §12.5.3 — tick() evicts reverse_table entries older than
// REVERSE_TIMEOUT_MS (30s default).
void test_reverse_table_aging() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);

    t.inbound(&out_iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);
    Bytes data_wire  = synth_data_packet(t.local_identity().identity_hash(),
                                         alice_dest, Bytes::from_hex("ee"), 0);
    t.inbound(&in_iface, data_wire, /*now_ms=*/10'000);
    TEST_ASSERT_EQUAL_UINT(1, t.reverse_table().size());

    // Just inside timeout — entry stays.
    t.tick(10'000 + rns::ReverseTable::REVERSE_TIMEOUT_MS - 1);
    TEST_ASSERT_EQUAL_UINT(1, t.reverse_table().size());

    // Past timeout — evicted.
    t.tick(10'000 + rns::ReverseTable::REVERSE_TIMEOUT_MS + 1);
    TEST_ASSERT_EQUAL_UINT(0, t.reverse_table().size());
}

// §7.1 — well-known path-request destination_hash is the constant
// from §1.2 / §1.4.3. Verifies the SHA256(name_hash)[:16] derivation.
void test_path_request_destination_hash_is_canonical() {
    TEST_ASSERT_EQUAL_STRING(
        "6b9f66014d9853faab220fba47d02761",
        Transport::path_request_destination_hash().to_hex().c_str());
}

// §7.2.3 branch 2 — transit relay answers a known target by replaying
// the cached announce wire with context byte set to PATH_RESPONSE on
// the interface the request arrived on.
void test_path_request_for_known_target_emits_path_response() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface req_iface, learn_iface;
    t.register_interface(&req_iface);
    t.register_interface(&learn_iface);

    // Learn alice via learn_iface.
    t.inbound(&learn_iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);

    Bytes tag = Bytes::from_hex("11111111111111111111111111111111");
    Bytes pr  = synth_path_request(alice_dest, tag);

    req_iface.emitted.clear();
    learn_iface.emitted.clear();

    t.inbound(&req_iface, pr, 2000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_received);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_answered);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().path_requests_unanswered);

    // Path-response went out the way the request came in (req_iface).
    TEST_ASSERT_EQUAL_UINT(1, req_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, learn_iface.emitted.size());

    Packet emitted = Packet::from_wire_bytes(req_iface.emitted[0]);
    TEST_ASSERT_TRUE(emitted.packet_type() == Packet::PacketType::ANNOUNCE);
    TEST_ASSERT_EQUAL_UINT8(Packet::CONTEXT_PATH_RESPONSE, emitted.context());
    TEST_ASSERT_EQUAL_STRING(ALICE_DEST_HASH,
                             emitted.destination_hash().to_hex().c_str());

    // Body bytes (post-context) match the cached announce — the body
    // is the immutable signed-data carrier; only the outer context
    // byte was mutated.
    Bytes cached = t.path_table().get(alice_dest)->announce_wire;
    TEST_ASSERT_EQUAL_UINT(cached.size(), req_iface.emitted[0].size());
    for (size_t i = 19; i < cached.size(); i++) {
        TEST_ASSERT_EQUAL_UINT8(cached[i], req_iface.emitted[0][i]);
    }
}

// §7.2.3 branch 5 — leaf (transport_enabled=false) doesn't fulfil
// path requests for non-local destinations. Drop, no emit.
void test_path_request_leaf_does_not_answer() {
    Transport t(bob_identity(), /*transport_enabled=*/false);
    StubInterface iface;
    t.register_interface(&iface);

    // Even with the path entry populated, a leaf shouldn't answer.
    t.inbound(&iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);

    Bytes tag = Bytes::from_hex("22222222222222222222222222222222");
    Bytes pr  = synth_path_request(Bytes::from_hex(ALICE_DEST_HASH), tag);

    iface.emitted.clear();
    t.inbound(&iface, pr, 2000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_received);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().path_requests_answered);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_unanswered);
    TEST_ASSERT_EQUAL_UINT(0, iface.emitted.size());
}

// Path request for a target we don't have a path entry for — drop.
void test_path_request_for_unknown_target_drops() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);

    Bytes unknown = Bytes::from_hex("0123456789abcdef0123456789abcdef");
    Bytes tag     = Bytes::from_hex("33333333333333333333333333333333");
    Bytes pr      = synth_path_request(unknown, tag);
    t.inbound(&iface, pr, 1000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_received);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().path_requests_answered);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_unanswered);
    TEST_ASSERT_EQUAL_UINT(0, iface.emitted.size());
}

// §7.2.1 — path requests with no tag bytes (16-byte body, just the
// target_dest_hash) are silently dropped.
void test_path_request_tagless_drop() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);

    Bytes target = Bytes::from_hex(ALICE_DEST_HASH);
    Bytes pr     = Packet::pack_header_1(
        /*flags=*/0x08, /*hops=*/0,
        Transport::path_request_destination_hash(),
        Packet::CONTEXT_NONE, target);  // body = just 16 bytes target, no tag
    t.inbound(&iface, pr, 1000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_tagless);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().path_requests_received);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().path_requests_answered);
}

// §7.2.2 — duplicate (target||tag) drops on the second arrival.
// Use different transport_id slots to bypass §13.4 dedup so we
// exercise the pr_tags ring directly.
void test_path_request_dedup_by_target_and_tag() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);
    t.inbound(&iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);

    Bytes target = Bytes::from_hex(ALICE_DEST_HASH);
    Bytes tag    = Bytes::from_hex("44444444444444444444444444444444");
    Bytes tid_a  = Bytes::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    Bytes tid_b  = Bytes::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    Bytes pr1 = synth_path_request(target, tag, &tid_a);
    Bytes pr2 = synth_path_request(target, tag, &tid_b);  // different body, same target+tag

    iface.emitted.clear();
    t.inbound(&iface, pr1, 2000);
    t.inbound(&iface, pr2, 2001);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_received);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_deduped);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_answered);
    TEST_ASSERT_EQUAL_UINT(1, iface.emitted.size());
}

// §7.2.1 — transport-mode originator request (target || transport_id ||
// tag) parses correctly and answers.
void test_path_request_transport_mode_payload_parses() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);
    t.inbound(&iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);

    Bytes target = Bytes::from_hex(ALICE_DEST_HASH);
    Bytes tid    = Bytes::from_hex("cccccccccccccccccccccccccccccccc");  // 16 bytes
    Bytes tag    = Bytes::from_hex("55555555555555555555555555555555");
    Bytes pr     = synth_path_request(target, tag, &tid);

    iface.emitted.clear();
    t.inbound(&iface, pr, 2000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_received);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_answered);
    TEST_ASSERT_EQUAL_UINT(1, iface.emitted.size());
}

// Single-interface relay node. Receives an announce on its only
// interface. Rebroadcast must NOT echo back — emitted stays at 0.
void test_relay_with_single_interface_does_not_echo() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);

    t.inbound(&iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);
    t.tick(1000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().announces_rebroadcast);
    TEST_ASSERT_EQUAL_UINT(0, iface.emitted.size());  // single-iface, no echo
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
    RUN_TEST(test_leaf_does_not_rebroadcast);
    RUN_TEST(test_relay_rebroadcasts_on_other_interfaces);
    RUN_TEST(test_path_response_announce_does_not_rebroadcast);
    RUN_TEST(test_relay_does_not_rebroadcast_random_blob_replay);
    RUN_TEST(test_data_forward_last_hop_strips_transport_id);
    RUN_TEST(test_data_forward_multi_hop_replaces_transport_id);
    RUN_TEST(test_data_not_for_us_is_ignored);
    RUN_TEST(test_data_for_unknown_dest_is_ignored);
    RUN_TEST(test_data_header_1_does_not_forward);
    RUN_TEST(test_data_forward_writes_reverse_table_entry);
    RUN_TEST(test_proof_forward_uses_reverse_table_entry);
    RUN_TEST(test_proof_orphaned_when_no_reverse_entry);
    RUN_TEST(test_proof_dropped_when_arriving_on_wrong_interface);
    RUN_TEST(test_reverse_table_aging);
    RUN_TEST(test_path_request_destination_hash_is_canonical);
    RUN_TEST(test_path_request_for_known_target_emits_path_response);
    RUN_TEST(test_path_request_leaf_does_not_answer);
    RUN_TEST(test_path_request_for_unknown_target_drops);
    RUN_TEST(test_path_request_tagless_drop);
    RUN_TEST(test_path_request_dedup_by_target_and_tag);
    RUN_TEST(test_path_request_transport_mode_payload_parses);
    RUN_TEST(test_relay_with_single_interface_does_not_echo);
    return UNITY_END();
}
