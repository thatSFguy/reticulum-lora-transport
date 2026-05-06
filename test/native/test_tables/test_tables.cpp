// test/native/test_tables/test_tables.cpp
//
// Unity tests for the table primitives — PacketHashList (§13.4) and
// PathTable (§12.4). No JSON test vectors yet (these are state, not
// wire format), so coverage is structural:
//   - PacketHashList: dedup contract, half-purge on cap.
//   - PathTable: put/get/remove, random_blob window cap and replay
//     defence, TTL-based eviction.

#include <unity.h>
#include <cstdint>
#include <vector>

#include "rns/Bytes.h"
#include "rns/tables/PacketHashList.h"
#include "rns/tables/PathTable.h"

using rns::Bytes;
using rns::PacketHashList;
using rns::PathEntry;
using rns::PathTable;

void setUp() {}
void tearDown() {}

namespace {

// Make a deterministic 32-byte "hash" from a single-byte tag.
Bytes tag_hash(uint8_t tag) {
    Bytes out(32);
    for (size_t i = 0; i < 32; i++) out[i] = tag;
    return out;
}

// 16-byte "destination hash" from a single tag.
Bytes tag_dest(uint8_t tag) {
    Bytes out(16);
    for (size_t i = 0; i < 16; i++) out[i] = tag;
    return out;
}

// 10-byte "random_blob" from two tag bytes.
Bytes tag_blob(uint8_t a, uint8_t b) {
    Bytes out(10);
    for (size_t i = 0; i < 10; i++) out[i] = (i & 1) ? b : a;
    return out;
}

} // namespace

// ---- PacketHashList -----------------------------------------------

void test_hashlist_insert_dedupes() {
    PacketHashList hl(8);
    Bytes h = tag_hash(0x42);
    TEST_ASSERT_TRUE(hl.insert(h));
    TEST_ASSERT_EQUAL_UINT(1, hl.size());
    TEST_ASSERT_TRUE(hl.contains(h));
    TEST_ASSERT_FALSE(hl.insert(h));        // second insert is a no-op
    TEST_ASSERT_EQUAL_UINT(1, hl.size());
}

void test_hashlist_purge_drops_oldest_half() {
    PacketHashList hl(/*max=*/4);
    // Fill past the cap.
    for (uint8_t i = 0; i < 6; i++) {
        TEST_ASSERT_TRUE(hl.insert(tag_hash(i)));
    }
    TEST_ASSERT_EQUAL_UINT(6, hl.size());

    // §13.4 — purge halves only after the cap is exceeded.
    const size_t dropped = hl.purge_if_over_cap();
    TEST_ASSERT_EQUAL_UINT(3, dropped);  // 6 / 2 = 3
    TEST_ASSERT_EQUAL_UINT(3, hl.size());

    // Oldest three hashes (tags 0-2) are gone; newest three (3-5) remain.
    for (uint8_t i = 0; i < 3; i++) {
        TEST_ASSERT_FALSE_MESSAGE(hl.contains(tag_hash(i)), "expected oldest evicted");
    }
    for (uint8_t i = 3; i < 6; i++) {
        TEST_ASSERT_TRUE_MESSAGE(hl.contains(tag_hash(i)), "expected newest retained");
    }
}

void test_hashlist_purge_noop_under_cap() {
    PacketHashList hl(/*max=*/8);
    for (uint8_t i = 0; i < 4; i++) hl.insert(tag_hash(i));
    TEST_ASSERT_EQUAL_UINT(0, hl.purge_if_over_cap());
    TEST_ASSERT_EQUAL_UINT(4, hl.size());
}

// ---- PathTable ----------------------------------------------------

void test_pathtable_put_get_remove() {
    PathTable pt;
    Bytes dest = tag_dest(0xAB);
    PathEntry e;
    e.timestamp_ms = 1000;
    e.hops         = 3;
    e.expires_ms   = 2000;
    e.next_hop     = tag_dest(0xCD);
    e.announce_wire = Bytes::from_hex("deadbeef");
    pt.put(dest, e);

    TEST_ASSERT_EQUAL_UINT(1, pt.size());
    const PathEntry* got = pt.get(dest);
    TEST_ASSERT_NOT_NULL(got);
    TEST_ASSERT_EQUAL_UINT8(3, got->hops);
    TEST_ASSERT_EQUAL_STRING(tag_dest(0xCD).to_hex().c_str(),
                             got->next_hop.to_hex().c_str());
    TEST_ASSERT_EQUAL_STRING("deadbeef", got->announce_wire.to_hex().c_str());

    TEST_ASSERT_TRUE(pt.remove(dest));
    TEST_ASSERT_NULL(pt.get(dest));
    TEST_ASSERT_FALSE(pt.remove(dest));  // second remove is a no-op
    TEST_ASSERT_TRUE(pt.empty());
}

void test_pathtable_random_blob_replay_defence() {
    PathTable pt;
    Bytes dest = tag_dest(0x11);
    pt.put(dest, PathEntry{});

    Bytes blob_a = tag_blob(0xA1, 0xA2);
    Bytes blob_b = tag_blob(0xB1, 0xB2);

    TEST_ASSERT_TRUE(pt.note_random_blob(dest, blob_a));   // first sighting
    TEST_ASSERT_FALSE(pt.note_random_blob(dest, blob_a));  // replay → false
    TEST_ASSERT_TRUE(pt.note_random_blob(dest, blob_b));   // different blob

    const PathEntry* e = pt.get(dest);
    TEST_ASSERT_EQUAL_UINT(2, e->random_blobs.size());
}

void test_pathtable_random_blob_window_cap() {
    PathTable pt;
    Bytes dest = tag_dest(0x22);
    pt.put(dest, PathEntry{});

    // Push MAX_RANDOM_BLOBS + 5 distinct blobs; window must hold the
    // most recent MAX_RANDOM_BLOBS, dropping the oldest 5.
    constexpr size_t N = PathTable::MAX_RANDOM_BLOBS + 5;
    for (size_t i = 0; i < N; i++) {
        TEST_ASSERT_TRUE(pt.note_random_blob(
            dest, tag_blob(static_cast<uint8_t>(i), static_cast<uint8_t>(i + 1))));
    }
    const PathEntry* e = pt.get(dest);
    TEST_ASSERT_EQUAL_UINT(PathTable::MAX_RANDOM_BLOBS, e->random_blobs.size());

    // Oldest 5 are gone — re-noting them must succeed (treated as new).
    for (size_t i = 0; i < 5; i++) {
        TEST_ASSERT_TRUE(pt.note_random_blob(
            dest, tag_blob(static_cast<uint8_t>(i), static_cast<uint8_t>(i + 1))));
    }
}

void test_pathtable_note_blob_for_unknown_dest() {
    PathTable pt;
    Bytes dest = tag_dest(0x33);  // never put()
    Bytes blob = tag_blob(1, 2);
    // No entry → can't attach a blob; returns false but does not crash.
    TEST_ASSERT_FALSE(pt.note_random_blob(dest, blob));
    TEST_ASSERT_NULL(pt.get(dest));
}

void test_pathtable_evict_expired() {
    PathTable pt;
    PathEntry early; early.expires_ms = 100;
    PathEntry mid;   mid.expires_ms   = 500;
    PathEntry late;  late.expires_ms  = 1000;

    pt.put(tag_dest(1), early);
    pt.put(tag_dest(2), mid);
    pt.put(tag_dest(3), late);
    TEST_ASSERT_EQUAL_UINT(3, pt.size());

    // now = 600 → evicts entries with expires_ms <= 600
    const size_t removed = pt.evict_expired(600);
    TEST_ASSERT_EQUAL_UINT(2, removed);
    TEST_ASSERT_EQUAL_UINT(1, pt.size());
    TEST_ASSERT_NULL(pt.get(tag_dest(1)));
    TEST_ASSERT_NULL(pt.get(tag_dest(2)));
    TEST_ASSERT_NOT_NULL(pt.get(tag_dest(3)));
}

void test_pathtable_put_replaces_existing() {
    PathTable pt;
    Bytes dest = tag_dest(0x77);

    PathEntry first; first.hops = 4; first.timestamp_ms = 100;
    pt.put(dest, first);

    PathEntry second; second.hops = 2; second.timestamp_ms = 200;
    pt.put(dest, second);

    TEST_ASSERT_EQUAL_UINT(1, pt.size());
    TEST_ASSERT_EQUAL_UINT8(2, pt.get(dest)->hops);
    TEST_ASSERT_EQUAL_UINT(200, pt.get(dest)->timestamp_ms);
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    UNITY_BEGIN();
    RUN_TEST(test_hashlist_insert_dedupes);
    RUN_TEST(test_hashlist_purge_drops_oldest_half);
    RUN_TEST(test_hashlist_purge_noop_under_cap);
    RUN_TEST(test_pathtable_put_get_remove);
    RUN_TEST(test_pathtable_random_blob_replay_defence);
    RUN_TEST(test_pathtable_random_blob_window_cap);
    RUN_TEST(test_pathtable_note_blob_for_unknown_dest);
    RUN_TEST(test_pathtable_evict_expired);
    RUN_TEST(test_pathtable_put_replaces_existing);
    return UNITY_END();
}
