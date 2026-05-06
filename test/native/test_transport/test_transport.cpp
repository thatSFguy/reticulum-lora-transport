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
#include "rns/Destination.h"
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
// entries — Transport.dedup_hash() over the post-bump packet,
// truncated to 16 bytes. Both compute SHA-256 of the §6.3 hashable
// part, so the helper just calls into Packet::hashable_part.
Bytes reverse_key_for(const Bytes& data_wire_post_bump) {
    Packet p = Packet::from_wire_bytes(data_wire_post_bump);
    return rns::crypto::sha256(p.hashable_part()).slice(0, 16);
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

constexpr const char* ALICE_PRIV_HEX_FOR_LINK =
    "587e730a70d24e971efa8c146e554996d70bff45b2033d336e2c078dc63d3645"
    "bef79d95bf6b253827a2e7e81a13ab0b10a908fd158581d1827095b788169e93";

Identity alice_identity() {
    return Identity::from_private_bytes(Bytes::from_hex(ALICE_PRIV_HEX_FOR_LINK));
}

// flags for HEADER_2 LINKREQUEST: HEADER_2 (0x40) | TRANSPORT (0x10) |
// SINGLE (00) | LINKREQUEST (10) = 0x52
constexpr uint8_t LR_HEADER_2_FLAGS = 0x52;

// 64-byte body: initiator_X25519_pub(32) || initiator_Ed25519_pub(32).
// Relays don't validate these — keys can be arbitrary.
Bytes synth_link_request(const Bytes& transport_id, const Bytes& dest_hash,
                         uint8_t hops = 0) {
    Bytes body;
    body.append(Bytes(32));  // init_x25519_pub — zeros are fine for relay tests
    body.append(Bytes(32));  // init_ed25519_pub
    return Packet::pack_header_2(LR_HEADER_2_FLAGS, hops, transport_id,
                                 dest_hash, Packet::CONTEXT_NONE, body);
}

// flags for HEADER_1 LRPROOF: HEADER_1 (00) | BROADCAST (0) | LINK (11) |
// PROOF (11) = 0x0F
constexpr uint8_t LRPROOF_FLAGS = 0x0F;

// Build an LRPROOF wire bytes signed by `responder`'s long-term
// Ed25519 priv. body = signature(64) || responder_x25519_pub(32).
Bytes synth_lrproof(const Bytes& link_id, const Bytes& responder_x_pub,
                    const Identity& responder, uint8_t hops = 0) {
    Bytes signed_data;
    signed_data.append(link_id);
    signed_data.append(responder_x_pub);
    signed_data.append(responder.ed25519_pub());

    Bytes ed_priv = responder.ed25519_priv();
    Bytes sig = rns::crypto::ed25519_sign(ed_priv,
                                           signed_data.data(),
                                           signed_data.size());

    Bytes body;
    body.append(sig);
    body.append(responder_x_pub);
    return Packet::pack_header_1(LRPROOF_FLAGS, hops, link_id,
                                 Packet::CONTEXT_LRPROOF, body);
}

// flags for HEADER_1 Link DATA: HEADER_1 (00) | BROADCAST (0) | LINK (11) |
// DATA (00) = 0x0C
constexpr uint8_t LINK_DATA_FLAGS = 0x0C;

Bytes synth_link_data(const Bytes& link_id, const Bytes& body, uint8_t hops = 0) {
    return Packet::pack_header_1(LINK_DATA_FLAGS, hops, link_id,
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

// §12.3 — relay rebroadcasts on EVERY registered interface, including
// the one the announce arrived on. LoRa is a broadcast medium where
// re-emitting on the receiving interface is the whole point of being
// a relay (peers in different range pockets need it). Loop protection
// is the §13.4 hashlist + §12.3.2 random_blob replay defence, both
// run in inbound() before the announce reaches this queue. Hops byte
// is incremented per §2.4.
void test_relay_rebroadcasts_on_all_interfaces() {
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

    // Rebroadcast went to BOTH interfaces — including the receiving
    // one. The §13.4 / §12.3.2 dedup gates handle loop prevention.
    TEST_ASSERT_EQUAL_UINT(1, in_iface.emitted.size());
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

    // Both packets pass §13.4 dedup (different bodies — different
    // transport_id slots). path_requests_received counts every
    // parse-valid request, and the second one then drops at the
    // §7.2.2 (target||tag) ring — that's what _deduped reports.
    TEST_ASSERT_EQUAL_UINT(2, t.stats().path_requests_received);
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

// §12.2.4 + §6.3 — relay forwards a LINKREQUEST and writes a
// link_table entry keyed by the link_id. 1-hop case (path.hops == 1)
// strips the transport_id per §12.2.2.
void test_link_request_forward_last_hop() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);

    // Alice on out_iface, 1 hop away after the inbound bump.
    t.inbound(&out_iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);

    Bytes lr_wire = synth_link_request(t.local_identity().identity_hash(),
                                       alice_dest, /*hops=*/0);

    in_iface.emitted.clear();
    out_iface.emitted.clear();
    TEST_ASSERT_TRUE(t.link_table().empty());

    t.inbound(&in_iface, lr_wire, /*now_ms=*/2000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_requests_forwarded);
    TEST_ASSERT_EQUAL_UINT(1, t.link_table().size());

    // Forwarded as HEADER_1 broadcast on out_iface.
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(1, out_iface.emitted.size());
    Packet emitted = Packet::from_wire_bytes(out_iface.emitted[0]);
    TEST_ASSERT_TRUE(emitted.header_type() == Packet::HeaderType::HEADER_1);
    TEST_ASSERT_TRUE(emitted.packet_type() == Packet::PacketType::LINKREQUEST);
    TEST_ASSERT_EQUAL_UINT8(1, emitted.hops());

    // link_id is invariant across header form — compute from the wire
    // we sent in (post-bump, but link_id excludes hops anyway).
    Bytes wire_post_bump = lr_wire;
    wire_post_bump[1] = 1;
    Packet inbound_pkt = Packet::from_wire_bytes(wire_post_bump);
    Bytes expected_link_id = Transport::link_id_from_lr_packet(inbound_pkt);

    const auto* entry = t.link_table().get(expected_link_id);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_EQUAL_PTR(&in_iface,  entry->rcvd_if);
    TEST_ASSERT_EQUAL_PTR(&out_iface, entry->nh_if);
    TEST_ASSERT_FALSE(entry->validated);
    TEST_ASSERT_EQUAL_STRING(ALICE_DEST_HASH, entry->dst_hash.to_hex().c_str());
}

// §4.5 step 5 — blackhole list silently drops announces from a
// specific identity_hash, regardless of cryptographic validity.
void test_blackhole_drops_announce_from_blocked_identity() {
    Transport t(bob_identity(), false);
    StubInterface iface;
    t.register_interface(&iface);

    // Alice's identity_hash from identities.json.
    Bytes alice_id_hash = Bytes::from_hex("28d43a11abc1094301a59ed3b44f127b");
    t.blackhole_identity(alice_id_hash);
    TEST_ASSERT_TRUE(t.is_blackholed(alice_id_hash));

    Bytes wire = Bytes::from_hex(ALICE_NO_RATCHET_WIRE);
    t.inbound(&iface, wire, 1000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().blackhole_drops);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().announce_validated);
    TEST_ASSERT_EQUAL_UINT(0, t.known_count());
    TEST_ASSERT_NULL(t.path_table().get(Bytes::from_hex(ALICE_DEST_HASH)));
}

// Unblacklisting restores normal processing.
void test_unblackhole_restores_processing() {
    Transport t(bob_identity(), false);
    StubInterface iface;
    t.register_interface(&iface);

    Bytes alice_id_hash = Bytes::from_hex("28d43a11abc1094301a59ed3b44f127b");
    t.blackhole_identity(alice_id_hash);
    TEST_ASSERT_TRUE(t.unblackhole_identity(alice_id_hash));
    TEST_ASSERT_FALSE(t.is_blackholed(alice_id_hash));
    TEST_ASSERT_FALSE(t.unblackhole_identity(alice_id_hash));  // already removed

    t.inbound(&iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().blackhole_drops);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().announce_validated);
}

// §7.2.3 branch 4 — transport-enabled, no path known: forward the
// path-request to every other interface. Body is re-emitted as-is.
void test_path_request_branch_4_forwards_to_other_interfaces() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_a, out_b;
    t.register_interface(&in_iface);
    t.register_interface(&out_a);
    t.register_interface(&out_b);

    Bytes unknown_target =
        Bytes::from_hex("0123456789abcdef0123456789abcdef");
    Bytes tag = Bytes::from_hex("99999999999999999999999999999999");
    Bytes pr  = synth_path_request(unknown_target, tag);

    in_iface.emitted.clear();
    out_a.emitted.clear();
    out_b.emitted.clear();

    t.inbound(&in_iface, pr, 1000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_forwarded);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().path_requests_unanswered);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().path_requests_answered);

    // Forwarded on out_a + out_b, NOT echoed back on in_iface.
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(1, out_a.emitted.size());
    TEST_ASSERT_EQUAL_UINT(1, out_b.emitted.size());
}

// Branch 4 with only one interface — nowhere to forward to. Falls
// through to branch 5 (unanswered) instead of incrementing the
// forwarded counter.
void test_path_request_branch_4_single_iface_falls_to_unanswered() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface only_iface;
    t.register_interface(&only_iface);

    Bytes pr = synth_path_request(
        Bytes::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Bytes::from_hex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
    t.inbound(&only_iface, pr, 1000);

    TEST_ASSERT_EQUAL_UINT(0, t.stats().path_requests_forwarded);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_unanswered);
    TEST_ASSERT_EQUAL_UINT(0, only_iface.emitted.size());
}

// §6.6 / §12.2.4 — when the outbound interface's hw_mtu is smaller
// than the LINKREQUEST's signalled MTU, the relay rewrites the
// signalling in place. Mode bits preserved; only the 21-bit MTU
// field clamps.
void test_link_request_signalling_mtu_clamped_to_outbound_iface() {
    Transport t(bob_identity(), /*transport_enabled=*/true);

    // out_iface has a tight HW_MTU — 250 bytes — vs the request's 500.
    StubInterface in_iface;
    Interface::Config out_cfg;
    out_cfg.bitrate_bps   = 1'000'000;
    out_cfg.airtime_window_ms = 1000;
    out_cfg.announce_cap_pct  = 100.0f;
    out_cfg.hw_mtu_bytes  = 250;
    class TightOutIface : public Interface {
    public:
        explicit TightOutIface(const Config& c) : Interface(c) {}
        std::vector<Bytes> emitted;
    protected:
        void on_transmit(const Bytes& w) override { emitted.push_back(w); }
    } out_iface(out_cfg);

    t.register_interface(&in_iface);
    t.register_interface(&out_iface);

    // Alice on out_iface, 1 hop away (HEADER_1 announce → post-bump 1).
    t.inbound(&out_iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);

    // Synthesize a LINKREQUEST with signalling encoding mode=1
    // (AES256_CBC) + mtu=500. signalling = 0x20 0x01 0xf4 — same as
    // the links.json vector.
    Bytes body;
    body.append(Bytes(32));                           // init_x25519_pub
    body.append(Bytes(32));                           // init_ed25519_pub
    body.append(Bytes::from_hex("2001f4"));           // signalling: mode=1, mtu=500
    Bytes lr_wire = Packet::pack_header_2(
        LR_HEADER_2_FLAGS, /*hops=*/0,
        t.local_identity().identity_hash(), alice_dest,
        Packet::CONTEXT_NONE, body);

    in_iface.emitted.clear();
    out_iface.emitted.clear();

    t.inbound(&in_iface, lr_wire, /*now_ms=*/2000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_requests_forwarded);
    TEST_ASSERT_EQUAL_UINT(1, out_iface.emitted.size());

    // Forward came out as HEADER_1 broadcast (path.hops=1 → §12.2.2).
    Packet emitted = Packet::from_wire_bytes(out_iface.emitted[0]);
    TEST_ASSERT_TRUE(emitted.header_type() == Packet::HeaderType::HEADER_1);

    // Body should still be 67 bytes (signalling preserved). Last 3
    // bytes = clamped signalling. mtu=250 → 0x0000fa, mode=1 stays.
    // byte0 = 0x20 | (250 >> 16 & 0x1F) = 0x20 | 0 = 0x20.
    // byte1 = (250 >> 8) & 0xFF = 0.
    // byte2 = 250 & 0xFF = 0xfa.
    TEST_ASSERT_EQUAL_UINT(67, emitted.data().size());
    Bytes signalling = emitted.data().slice(64, 3);
    TEST_ASSERT_EQUAL_STRING("2000fa", signalling.to_hex().c_str());
}

// §6.6 — when the outbound interface's hw_mtu is >= the requested
// MTU, signalling stays untouched.
void test_link_request_signalling_not_clamped_when_iface_larger() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;  // default hw_mtu = UINT32_MAX
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);
    t.inbound(&out_iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);

    Bytes body;
    body.append(Bytes(32));
    body.append(Bytes(32));
    body.append(Bytes::from_hex("2001f4"));  // mode=1, mtu=500
    Bytes lr_wire = Packet::pack_header_2(
        LR_HEADER_2_FLAGS, 0, t.local_identity().identity_hash(),
        Bytes::from_hex(ALICE_DEST_HASH), Packet::CONTEXT_NONE, body);

    out_iface.emitted.clear();
    t.inbound(&in_iface, lr_wire, 2000);

    TEST_ASSERT_EQUAL_UINT(1, out_iface.emitted.size());
    Packet emitted = Packet::from_wire_bytes(out_iface.emitted[0]);
    Bytes signalling = emitted.data().slice(64, 3);
    TEST_ASSERT_EQUAL_STRING("2001f4", signalling.to_hex().c_str());  // unchanged
}

// §12.2.4 + §12.2.1 — multi-hop LINKREQUEST forward: path.hops > 1
// keeps HEADER_2 and replaces transport_id with path.next_hop.
void test_link_request_forward_multi_hop() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);

    // Seed alice via HEADER_2 announce with hops=2 → post-bump 3,
    // path.hops=3, path.next_hop=upstream_id.
    Bytes upstream_id = Bytes::from_hex("aabbccddeeff00112233445566778899");
    t.inbound(&out_iface, alice_announce_header_2(upstream_id, 2), 1000);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);

    Bytes lr_wire = synth_link_request(t.local_identity().identity_hash(),
                                       alice_dest);
    in_iface.emitted.clear();
    out_iface.emitted.clear();

    t.inbound(&in_iface, lr_wire, 2000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_requests_forwarded);
    TEST_ASSERT_EQUAL_UINT(1, out_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());

    Packet emitted = Packet::from_wire_bytes(out_iface.emitted[0]);
    TEST_ASSERT_TRUE(emitted.header_type() == Packet::HeaderType::HEADER_2);
    TEST_ASSERT_EQUAL_STRING(upstream_id.to_hex().c_str(),
                             emitted.transport_id().to_hex().c_str());
    TEST_ASSERT_EQUAL_UINT8(1, emitted.hops());
}

// Helper for the LRPROOF / Link-DATA tests: returns Transport with
// alice's announce + LINKREQUEST forwarded, link_table populated but
// not yet validated. Returns the link_id via out param.
struct LinkSetup {
    Bytes link_id;
    Bytes initiator_x_pub;  // never used by relay but tests might
};
LinkSetup setup_link_pending(Transport& t,
                             StubInterface& in_iface,
                             StubInterface& out_iface) {
    t.inbound(&out_iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);

    Bytes lr_wire = synth_link_request(t.local_identity().identity_hash(),
                                       alice_dest);
    t.inbound(&in_iface, lr_wire, 2000);

    Bytes wire_post_bump = lr_wire;
    wire_post_bump[1] = 1;
    Packet pkt = Packet::from_wire_bytes(wire_post_bump);

    LinkSetup s;
    s.link_id = Transport::link_id_from_lr_packet(pkt);
    s.initiator_x_pub = Bytes(32);
    return s;
}

// §12.5.1 — valid LRPROOF arriving on nh_if (responder direction)
// gets forwarded on rcvd_if and marks the link_table entry validated.
void test_link_proof_validates_and_forwards() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);
    LinkSetup s = setup_link_pending(t, in_iface, out_iface);

    Bytes responder_eph_x = Bytes::from_hex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    Bytes lrproof = synth_lrproof(s.link_id, responder_eph_x, alice_identity());

    in_iface.emitted.clear();
    out_iface.emitted.clear();
    t.inbound(&out_iface, lrproof, /*now_ms=*/3000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_proofs_forwarded);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().link_proofs_invalid);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().link_proofs_wrong_iface);

    // Forwarded back toward the initiator (in_iface).
    TEST_ASSERT_EQUAL_UINT(1, in_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, out_iface.emitted.size());

    // Entry now validated.
    const auto* entry = t.link_table().get(s.link_id);
    TEST_ASSERT_NOT_NULL(entry);
    TEST_ASSERT_TRUE(entry->validated);
}

// §12.5.1 — bad signature on LRPROOF: drop, no forward, not validated.
void test_link_proof_bad_signature_rejected() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);
    LinkSetup s = setup_link_pending(t, in_iface, out_iface);

    Bytes responder_eph_x = Bytes(32);
    Bytes lrproof = synth_lrproof(s.link_id, responder_eph_x, alice_identity());
    // Tamper one byte of the signature (offset 19 in HEADER_1 wire =
    // start of body; signature is body[0:64]).
    lrproof[19] ^= 0x01;

    in_iface.emitted.clear();
    out_iface.emitted.clear();
    t.inbound(&out_iface, lrproof, 3000);

    TEST_ASSERT_EQUAL_UINT(0, t.stats().link_proofs_forwarded);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_proofs_invalid);
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());
    TEST_ASSERT_FALSE(t.link_table().get(s.link_id)->validated);
}

// §12.5.1 — LRPROOF arriving on the wrong interface (not nh_if):
// drop, count link_proofs_wrong_iface, entry stays for the legitimate
// PROOF that may follow.
void test_link_proof_wrong_interface_drops_without_consuming() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface, third_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);
    t.register_interface(&third_iface);
    LinkSetup s = setup_link_pending(t, in_iface, out_iface);

    Bytes responder_eph_x = Bytes(32);
    Bytes lrproof = synth_lrproof(s.link_id, responder_eph_x, alice_identity());

    third_iface.emitted.clear();
    in_iface.emitted.clear();
    out_iface.emitted.clear();
    t.inbound(&third_iface, lrproof, 3000);

    TEST_ASSERT_EQUAL_UINT(0, t.stats().link_proofs_forwarded);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_proofs_wrong_iface);
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());

    // Entry is still there. A subsequent legitimate PROOF on out_iface
    // (= nh_if) must work — use a different responder ephemeral so
    // §13.4 dedup doesn't catch the resend.
    Bytes responder_eph_x2 = Bytes::from_hex(
        "0202020202020202020202020202020202020202020202020202020202020202");
    Bytes lrproof2 = synth_lrproof(s.link_id, responder_eph_x2, alice_identity());
    t.inbound(&out_iface, lrproof2, 3100);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_proofs_forwarded);
    TEST_ASSERT_EQUAL_UINT(1, in_iface.emitted.size());
    TEST_ASSERT_TRUE(t.link_table().get(s.link_id)->validated);
}

// LRPROOF for a link_id we never forwarded a LINKREQUEST for: drop.
void test_link_proof_unknown_link() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);

    Bytes fake_link_id = Bytes::from_hex("00112233445566778899aabbccddeeff");
    Bytes lrproof = synth_lrproof(fake_link_id, Bytes(32), alice_identity());

    t.inbound(&iface, lrproof, 1000);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_proofs_unknown_link);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().link_proofs_forwarded);
}

// §12.5.2 — Link DATA forwarding: initiator → responder direction.
void test_link_data_initiator_to_responder() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);
    LinkSetup s = setup_link_pending(t, in_iface, out_iface);

    // Validate the link first (otherwise Link DATA is rejected).
    Bytes lrproof = synth_lrproof(s.link_id, Bytes(32), alice_identity());
    t.inbound(&out_iface, lrproof, 3000);
    in_iface.emitted.clear();
    out_iface.emitted.clear();

    Bytes link_data = synth_link_data(s.link_id, Bytes::from_hex("deadbeef"));
    t.inbound(&in_iface, link_data, 3500);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_data_forwarded);
    TEST_ASSERT_EQUAL_UINT(1, out_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());
}

// §6.7.2 — validated link with no traffic for the staleness window
// gets evicted by tick(). Catches links whose peers wandered off
// without sending LINKCLOSE.
void test_link_table_evicts_stale_validated_links() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);
    LinkSetup s = setup_link_pending(t, in_iface, out_iface);
    Bytes lrproof = synth_lrproof(s.link_id, Bytes(32), alice_identity());
    t.inbound(&out_iface, lrproof, /*now_ms=*/3000);
    TEST_ASSERT_TRUE(t.link_table().get(s.link_id)->validated);

    // tick() just inside the window — entry stays.
    t.tick(3000 + Transport::LINK_STALE_THRESHOLD_MS - 1);
    TEST_ASSERT_NOT_NULL(t.link_table().get(s.link_id));

    // tick() just past the window — evicted.
    t.tick(3000 + Transport::LINK_STALE_THRESHOLD_MS + 1);
    TEST_ASSERT_NULL(t.link_table().get(s.link_id));
}

// §6.7.2 — Link DATA traffic resets last_activity, so an active
// link is NOT aged out even past the original threshold.
void test_link_table_traffic_resets_staleness_clock() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);
    LinkSetup s = setup_link_pending(t, in_iface, out_iface);
    Bytes lrproof = synth_lrproof(s.link_id, Bytes(32), alice_identity());
    t.inbound(&out_iface, lrproof, /*now_ms=*/3000);

    // Some traffic 5 minutes in.
    Bytes link_data = synth_link_data(s.link_id, Bytes::from_hex("aa"));
    t.inbound(&in_iface, link_data, 3000 + 5ULL * 60ULL * 1000ULL);

    // tick() at 12 minutes from establishment — would have evicted if
    // staleness counted from establishment, but the data refreshed
    // last_activity to 5min, so the 10-min window resets and we're
    // only 7 min past the last activity. Entry stays.
    t.tick(3000 + 12ULL * 60ULL * 1000ULL);
    TEST_ASSERT_NOT_NULL(t.link_table().get(s.link_id));

    // tick() at 16 minutes — now 11 min past the last activity. Evicted.
    t.tick(3000 + 16ULL * 60ULL * 1000ULL);
    TEST_ASSERT_NULL(t.link_table().get(s.link_id));
}

// §6.7.3 — LINKCLOSE arrives on a validated link: forward
// bidirectionally per §12.5.2, then drop the link_table entry.
void test_link_close_forwards_and_clears_link_table() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);
    LinkSetup s = setup_link_pending(t, in_iface, out_iface);
    Bytes lrproof = synth_lrproof(s.link_id, Bytes(32), alice_identity());
    t.inbound(&out_iface, lrproof, 3000);
    in_iface.emitted.clear();
    out_iface.emitted.clear();
    TEST_ASSERT_EQUAL_UINT(1, t.link_table().size());

    // LINKCLOSE wire — Link DATA with context = 0xFC. Body would be
    // Token-encrypted link_id; the relay can't decrypt and doesn't
    // need to. Use arbitrary opaque body bytes for the test.
    Bytes body = Bytes::from_hex("0011223344556677");
    Bytes link_close = Packet::pack_header_1(
        /*flags=*/LINK_DATA_FLAGS, /*hops=*/0, s.link_id,
        Packet::CONTEXT_LINKCLOSE, body);

    t.inbound(&in_iface, link_close, 3500);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_data_forwarded);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_close_observed);
    TEST_ASSERT_EQUAL_UINT(1, out_iface.emitted.size());

    // link_table entry was popped — subsequent Link DATA for the
    // same link_id should be classified as unknown.
    TEST_ASSERT_EQUAL_UINT(0, t.link_table().size());
    Bytes followup_data = synth_link_data(s.link_id, Bytes::from_hex("99"));
    out_iface.emitted.clear();
    in_iface.emitted.clear();
    t.inbound(&in_iface, followup_data, 3600);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_data_unknown_link);
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, out_iface.emitted.size());
}

// §12.5.2 — Link DATA forwarding: responder → initiator direction.
void test_link_data_responder_to_initiator() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);
    LinkSetup s = setup_link_pending(t, in_iface, out_iface);
    Bytes lrproof = synth_lrproof(s.link_id, Bytes(32), alice_identity());
    t.inbound(&out_iface, lrproof, 3000);
    in_iface.emitted.clear();
    out_iface.emitted.clear();

    Bytes link_data = synth_link_data(s.link_id, Bytes::from_hex("cafef00d"));
    t.inbound(&out_iface, link_data, 3500);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_data_forwarded);
    TEST_ASSERT_EQUAL_UINT(1, in_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, out_iface.emitted.size());
}

// §12.5.2 — Link DATA before the link is validated drops; link_table
// entry exists but pre-LRPROOF traffic isn't forwarded.
void test_link_data_before_validation_is_dropped() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface in_iface, out_iface;
    t.register_interface(&in_iface);
    t.register_interface(&out_iface);
    LinkSetup s = setup_link_pending(t, in_iface, out_iface);
    in_iface.emitted.clear();
    out_iface.emitted.clear();

    Bytes link_data = synth_link_data(s.link_id, Bytes::from_hex("11"));
    t.inbound(&in_iface, link_data, 2500);

    TEST_ASSERT_EQUAL_UINT(0, t.stats().link_data_forwarded);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_data_unvalidated);
    TEST_ASSERT_EQUAL_UINT(0, in_iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, out_iface.emitted.size());
}

// Link DATA for an unknown link_id drops.
void test_link_data_unknown_link() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);

    Bytes fake = Bytes::from_hex("ffffffffffffffffffffffffffffffff");
    Bytes link_data = synth_link_data(fake, Bytes::from_hex("22"));
    t.inbound(&iface, link_data, 1000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().link_data_unknown_link);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().link_data_forwarded);
}

// §7.2.3 branch 1 — register a local Destination, send a path-request
// for it, expect a path-response announce on the requesting interface.
void test_path_request_branch_1_local_destination() {
    Transport t(bob_identity(), /*transport_enabled=*/false);  // even leaves answer for local
    StubInterface iface;
    t.register_interface(&iface);

    rns::Destination local(bob_identity(), "test.local.dest");
    Bytes local_hash = local.destination_hash();
    t.register_local_destination(local);

    t.set_announce_seed_fn([]() {
        return rns::AnnounceSeed{
            Bytes::from_hex("0102030405"), /*unix_seconds=*/2'000'000'000ULL };
    });

    Bytes tag = Bytes::from_hex("66666666666666666666666666666666");
    Bytes pr  = synth_path_request(local_hash, tag);

    iface.emitted.clear();
    t.inbound(&iface, pr, /*now_ms=*/1000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_local_answered);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_answered);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().path_requests_local_no_seed);
    TEST_ASSERT_EQUAL_UINT(1, iface.emitted.size());

    // Parse the emitted wire — it should be a valid PATH_RESPONSE
    // announce for `local_hash`.
    Packet emitted = Packet::from_wire_bytes(iface.emitted[0]);
    TEST_ASSERT_TRUE(emitted.packet_type() == Packet::PacketType::ANNOUNCE);
    TEST_ASSERT_EQUAL_UINT8(Packet::CONTEXT_PATH_RESPONSE, emitted.context());
    TEST_ASSERT_EQUAL_STRING(local_hash.to_hex().c_str(),
                             emitted.destination_hash().to_hex().c_str());

    // Signature is valid — route the emitted packet through
    // Identity::validate_announce. is_path_response should also flip.
    auto va = Identity::validate_announce(emitted);
    TEST_ASSERT_TRUE_MESSAGE(va.has_value(),
        "emitted path-response must satisfy §4.5 cryptographic validation");
    TEST_ASSERT_TRUE(va->is_path_response);
}

// Without an announce_seed_fn, branch 1 drops with a stat counter
// instead of crashing.
void test_path_request_local_no_seed_drops() {
    Transport t(bob_identity(), /*transport_enabled=*/false);
    StubInterface iface;
    t.register_interface(&iface);

    rns::Destination local(bob_identity(), "test.no.seed");
    t.register_local_destination(local);
    // Intentionally NO set_announce_seed_fn.

    Bytes pr = synth_path_request(
        local.destination_hash(),
        Bytes::from_hex("88888888888888888888888888888888"));

    iface.emitted.clear();
    t.inbound(&iface, pr, 1000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_requests_local_no_seed);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().path_requests_local_answered);
    TEST_ASSERT_EQUAL_UINT(0, iface.emitted.size());
}

// is_local_destination accessor / registration sanity.
void test_local_destination_registry() {
    Transport t(bob_identity(), false);
    rns::Destination d1(bob_identity(), "first");
    rns::Destination d2(bob_identity(), "second");
    Bytes h1 = d1.destination_hash();
    Bytes h2 = d2.destination_hash();
    TEST_ASSERT_FALSE(t.is_local_destination(h1));

    t.register_local_destination(d1);
    TEST_ASSERT_TRUE(t.is_local_destination(h1));
    TEST_ASSERT_FALSE(t.is_local_destination(h2));
    TEST_ASSERT_EQUAL_UINT(1, t.local_destination_count());

    t.register_local_destination(d2);
    TEST_ASSERT_EQUAL_UINT(2, t.local_destination_count());
    TEST_ASSERT_TRUE(t.is_local_destination(h2));
}

// emit_announce_for_local on every interface when only_on is null.
void test_emit_announce_for_local_fans_to_all_interfaces() {
    Transport t(bob_identity(), false);
    StubInterface a, b, c;
    t.register_interface(&a);
    t.register_interface(&b);
    t.register_interface(&c);

    rns::Destination d(bob_identity(), "test.fanout");
    t.register_local_destination(d);
    t.set_announce_seed_fn([]() {
        return rns::AnnounceSeed{ Bytes::from_hex("0a0a0a0a0a"), 1700000000ULL };
    });

    bool ok = t.emit_announce_for_local(d.destination_hash());
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_UINT(1, a.emitted.size());
    TEST_ASSERT_EQUAL_UINT(1, b.emitted.size());
    TEST_ASSERT_EQUAL_UINT(1, c.emitted.size());

    // Each iface received the same wire bytes (same seed → same output).
    TEST_ASSERT_EQUAL_STRING(a.emitted[0].to_hex().c_str(),
                             b.emitted[0].to_hex().c_str());
}

// emit_announce_for_local with only_on hits exactly one interface.
void test_emit_announce_for_local_only_on() {
    Transport t(bob_identity(), false);
    StubInterface a, b;
    t.register_interface(&a);
    t.register_interface(&b);
    rns::Destination d(bob_identity(), "test.only_on");
    t.register_local_destination(d);
    t.set_announce_seed_fn([]() {
        return rns::AnnounceSeed{ Bytes::from_hex("0b0b0b0b0b"), 1700000000ULL };
    });

    bool ok = t.emit_announce_for_local(d.destination_hash(),
                                        /*app_data=*/{},
                                        /*path_response=*/false,
                                        /*only_on=*/&b);
    TEST_ASSERT_TRUE(ok);
    TEST_ASSERT_EQUAL_UINT(0, a.emitted.size());
    TEST_ASSERT_EQUAL_UINT(1, b.emitted.size());
}

// Without a seed_fn, emit_announce_for_local returns false cleanly.
void test_emit_announce_for_local_without_seed_returns_false() {
    Transport t(bob_identity(), false);
    StubInterface a;
    t.register_interface(&a);
    rns::Destination d(bob_identity(), "test.no_seed");
    t.register_local_destination(d);
    // seed_fn intentionally not set

    bool ok = t.emit_announce_for_local(d.destination_hash());
    TEST_ASSERT_FALSE(ok);
    TEST_ASSERT_EQUAL_UINT(0, a.emitted.size());
}

// Unknown dest_hash → false.
void test_emit_announce_for_local_unknown_dest() {
    Transport t(bob_identity(), false);
    StubInterface a;
    t.register_interface(&a);
    t.set_announce_seed_fn([]() {
        return rns::AnnounceSeed{ Bytes::from_hex("0102030405"), 1700000000ULL };
    });

    Bytes never_registered = Bytes::from_hex("00112233445566778899aabbccddeeff");
    TEST_ASSERT_FALSE(t.emit_announce_for_local(never_registered));
    TEST_ASSERT_EQUAL_UINT(0, a.emitted.size());
}

// schedule_announce fires at multiples of period_ms.
void test_schedule_announce_fires_at_period_boundaries() {
    Transport t(bob_identity(), false);
    StubInterface iface;
    t.register_interface(&iface);
    rns::Destination d(bob_identity(), "test.schedule");
    t.register_local_destination(d);
    t.set_announce_seed_fn([]() {
        return rns::AnnounceSeed{ Bytes::from_hex("0102030405"), 1700000000ULL };
    });

    t.schedule_announce(d.destination_hash(),
                        /*period_ms=*/1000,
                        /*fn=*/nullptr,
                        /*initial_offset_ms=*/0);

    // tick(0) — first emit (next_emit_ms started at 0).
    t.tick(0);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().scheduled_announces_emitted);

    // tick(500) — well before next period boundary.
    t.tick(500);
    TEST_ASSERT_EQUAL_UINT(1, t.stats().scheduled_announces_emitted);

    // tick(1000) — at next period.
    t.tick(1000);
    TEST_ASSERT_EQUAL_UINT(2, t.stats().scheduled_announces_emitted);

    // tick(2500) — past two more boundaries; the scheduler advances
    // by `period_ms` from `now_ms`, so tick(2500) consumes one slot
    // and the next fires at 3500.
    t.tick(2500);
    TEST_ASSERT_EQUAL_UINT(3, t.stats().scheduled_announces_emitted);

    TEST_ASSERT_EQUAL_UINT(3, iface.emitted.size());
}

// AppDataProvider is called fresh every emit (data captured at emit
// time, not at registration time).
void test_schedule_announce_calls_provider_each_emit() {
    Transport t(bob_identity(), false);
    StubInterface iface;
    t.register_interface(&iface);
    rns::Destination d(bob_identity(), "test.provider");
    t.register_local_destination(d);
    t.set_announce_seed_fn([]() {
        return rns::AnnounceSeed{ Bytes::from_hex("0102030405"), 1700000000ULL };
    });

    int call_count = 0;
    t.schedule_announce(d.destination_hash(),
                        /*period_ms=*/100,
                        [&]() {
                            call_count++;
                            return Bytes::from_hex(
                                (call_count == 1) ? "aa" : "bb");
                        });

    t.tick(0);     // emit 1, provider called → "aa"
    t.tick(100);   // emit 2, provider called → "bb"
    TEST_ASSERT_EQUAL_INT(2, call_count);
    TEST_ASSERT_EQUAL_UINT(2, iface.emitted.size());

    // Each emit's wire bytes carry the provider's app_data at the
    // tail. Body offset for HEADER_1 announce, no ratchet:
    //   pub(64) + name_hash(10) + random_hash(10) + signature(64)
    //   = 148 bytes; app_data starts at body[148:].
    Packet e1 = Packet::from_wire_bytes(iface.emitted[0]);
    Packet e2 = Packet::from_wire_bytes(iface.emitted[1]);
    TEST_ASSERT_EQUAL_STRING("aa", e1.data().slice(148).to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING("bb", e2.data().slice(148).to_hex().c_str());
}

// Helpers for §4.5 step 6.3 tests — need to feed a sequence of
// announces for the same dest with controlled hops + timestamp.
namespace {
constexpr const char* ALICE_PRIV_HEX_FRESHNESS =
    "587e730a70d24e971efa8c146e554996d70bff45b2033d336e2c078dc63d3645"
    "bef79d95bf6b253827a2e7e81a13ab0b10a908fd158581d1827095b788169e93";

rns::Identity alice_freshness_identity() {
    return Identity::from_private_bytes(Bytes::from_hex(ALICE_PRIV_HEX_FRESHNESS));
}

// Build alice's announce for a controlled timestamp + hops byte. The
// signature is over the body (which excludes hops), so mutating
// wire[1] keeps validation passing.
Bytes build_alice_announce(const Bytes& random_prefix,
                           uint64_t timestamp_secs,
                           uint8_t wire_hops) {
    rns::Destination dest(alice_freshness_identity(),
                          "vectors.alice_announce_no_ratchet");
    Bytes wire = dest.build_announce(random_prefix, timestamp_secs);
    if (wire.size() >= 2) wire[1] = wire_hops;
    return wire;
}
} // namespace

// §4.5 step 6.3 — same destination, NEW announce has equal-or-fewer
// hops than the cached entry: ALWAYS replace.
void test_path_replacement_equal_or_fewer_hops_always_replaces() {
    Transport t(bob_identity(), false);
    StubInterface iface;
    t.register_interface(&iface);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);

    // First: hops byte = 0 → post-bump path.hops = 1.
    t.inbound(&iface,
              build_alice_announce(Bytes::from_hex("0101010101"), 1700000000ULL, 0),
              1000);
    TEST_ASSERT_EQUAL_UINT8(1, t.path_table().get(alice_dest)->hops);

    // Second: same hops (= equal), DIFFERENT random_prefix so the
    // wire body differs and we pass §13.4 dedup. Should replace.
    t.inbound(&iface,
              build_alice_announce(Bytes::from_hex("0202020202"), 1700000050ULL, 0),
              1100);
    TEST_ASSERT_EQUAL_UINT8(1, t.path_table().get(alice_dest)->hops);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().path_replacement_rejected);
}

// §4.5 step 6.3 — new announce has MORE hops + NEWER timestamp:
// replaces (newer_than_all_cached is true).
void test_path_replacement_more_hops_newer_timestamp_replaces() {
    Transport t(bob_identity(), false);
    StubInterface iface;
    t.register_interface(&iface);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);

    t.inbound(&iface,
              build_alice_announce(Bytes::from_hex("0101010101"), 1700000000ULL, 0),
              1000);
    TEST_ASSERT_EQUAL_UINT8(1, t.path_table().get(alice_dest)->hops);

    // Second: hops byte = 1 → would-be path.hops=2 (more than 1).
    // ts = 1700000100 > 1700000000 (newer). Replace.
    t.inbound(&iface,
              build_alice_announce(Bytes::from_hex("0202020202"), 1700000100ULL, 1),
              1100);
    TEST_ASSERT_EQUAL_UINT8(2, t.path_table().get(alice_dest)->hops);
    TEST_ASSERT_EQUAL_UINT(0, t.stats().path_replacement_rejected);
}

// §4.5 step 6.3 — new announce has MORE hops + OLDER timestamp:
// keep existing entry (the protective rule). The blob still gets
// recorded for §12.3.2 replay defense.
void test_path_replacement_more_hops_older_timestamp_kept() {
    Transport t(bob_identity(), false);
    StubInterface iface;
    t.register_interface(&iface);
    Bytes alice_dest = Bytes::from_hex(ALICE_DEST_HASH);

    t.inbound(&iface,
              build_alice_announce(Bytes::from_hex("0101010101"), 1700000000ULL, 0),
              1000);
    TEST_ASSERT_EQUAL_UINT8(1, t.path_table().get(alice_dest)->hops);
    const size_t blobs_before = t.path_table().get(alice_dest)->random_blobs.size();
    TEST_ASSERT_EQUAL_UINT(1, blobs_before);

    // Second: more hops (2), OLDER timestamp (1699999900 < 1700000000).
    // Keep existing entry.
    t.inbound(&iface,
              build_alice_announce(Bytes::from_hex("0202020202"), 1699999900ULL, 1),
              1100);

    const auto* path = t.path_table().get(alice_dest);
    TEST_ASSERT_EQUAL_UINT8(1, path->hops);  // unchanged
    TEST_ASSERT_EQUAL_UINT(1, t.stats().path_replacement_rejected);
    // Blob still recorded — replay defense doesn't depend on whether
    // the path entry was replaced.
    TEST_ASSERT_EQUAL_UINT(2, path->random_blobs.size());
}

// Single-interface relay node (the deployment topology — one LoRa
// radio per node). Receives an announce on its only interface. The
// rebroadcast MUST go back out on that same interface — that's how
// relays extend reach on a broadcast medium. Loop prevention is the
// §13.4 hashlist + §12.3.2 random_blob defence, both already exercised
// in the dedup tests above.
void test_relay_with_single_interface_re_emits() {
    Transport t(bob_identity(), /*transport_enabled=*/true);
    StubInterface iface;
    t.register_interface(&iface);

    t.inbound(&iface, Bytes::from_hex(ALICE_NO_RATCHET_WIRE), 1000);
    t.tick(1000);

    TEST_ASSERT_EQUAL_UINT(1, t.stats().announces_rebroadcast);
    TEST_ASSERT_EQUAL_UINT(1, iface.emitted.size());  // re-emit on the receiving interface
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
    RUN_TEST(test_relay_rebroadcasts_on_all_interfaces);
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
    RUN_TEST(test_link_request_forward_last_hop);
    RUN_TEST(test_blackhole_drops_announce_from_blocked_identity);
    RUN_TEST(test_unblackhole_restores_processing);
    RUN_TEST(test_path_request_branch_4_forwards_to_other_interfaces);
    RUN_TEST(test_path_request_branch_4_single_iface_falls_to_unanswered);
    RUN_TEST(test_link_request_signalling_mtu_clamped_to_outbound_iface);
    RUN_TEST(test_link_request_signalling_not_clamped_when_iface_larger);
    RUN_TEST(test_link_request_forward_multi_hop);
    RUN_TEST(test_link_proof_validates_and_forwards);
    RUN_TEST(test_link_proof_bad_signature_rejected);
    RUN_TEST(test_link_proof_wrong_interface_drops_without_consuming);
    RUN_TEST(test_link_proof_unknown_link);
    RUN_TEST(test_link_data_initiator_to_responder);
    RUN_TEST(test_link_data_responder_to_initiator);
    RUN_TEST(test_link_close_forwards_and_clears_link_table);
    RUN_TEST(test_link_table_evicts_stale_validated_links);
    RUN_TEST(test_link_table_traffic_resets_staleness_clock);
    RUN_TEST(test_link_data_before_validation_is_dropped);
    RUN_TEST(test_link_data_unknown_link);
    RUN_TEST(test_path_request_branch_1_local_destination);
    RUN_TEST(test_path_request_local_no_seed_drops);
    RUN_TEST(test_local_destination_registry);
    RUN_TEST(test_emit_announce_for_local_fans_to_all_interfaces);
    RUN_TEST(test_emit_announce_for_local_only_on);
    RUN_TEST(test_emit_announce_for_local_without_seed_returns_false);
    RUN_TEST(test_emit_announce_for_local_unknown_dest);
    RUN_TEST(test_schedule_announce_fires_at_period_boundaries);
    RUN_TEST(test_schedule_announce_calls_provider_each_emit);
    RUN_TEST(test_path_replacement_equal_or_fewer_hops_always_replaces);
    RUN_TEST(test_path_replacement_more_hops_newer_timestamp_replaces);
    RUN_TEST(test_path_replacement_more_hops_older_timestamp_kept);
    RUN_TEST(test_relay_with_single_interface_re_emits);
    return UNITY_END();
}
