// test/native/test_lora_interface/test_lora_interface.cpp
//
// Sanity tests for LoRaInterface — confirms the Interface base's
// queue / transmit_now hooks route to the supplied TransmitFn
// callback. Crypto / packet / Transport behavior is exercised by
// the other test binaries; this one is just the wire between the
// spec-layer Interface base and a hardware-layer transmit primitive.

#include <unity.h>
#include <cstdint>
#include <vector>

#include "rns/Bytes.h"
#include "rns/LoRaInterface.h"

using rns::Bytes;
using rns::Interface;
using rns::LoRaInterface;

void setUp() {}
void tearDown() {}

namespace {

Interface::Config small_cfg() {
    Interface::Config c;
    c.bitrate_bps          = 8000;
    c.announce_cap_pct     = 100.0f;
    c.airtime_window_ms    = 1000;
    c.max_queued_announces = 4;
    return c;
}

} // namespace

void test_transmit_now_invokes_callback_with_wire_bytes() {
    std::vector<Bytes> sent;
    LoRaInterface iface(small_cfg(),
        [&](const uint8_t* p, size_t n) -> int {
            sent.emplace_back(p, n);
            return static_cast<int>(n);
        });

    Bytes payload = Bytes::from_hex("aabbccddeeff");
    iface.transmit_now(payload);

    TEST_ASSERT_EQUAL_UINT(1, sent.size());
    TEST_ASSERT_EQUAL_STRING("aabbccddeeff", sent[0].to_hex().c_str());
}

void test_queue_drain_invokes_callback_per_emit() {
    std::vector<Bytes> sent;
    LoRaInterface iface(small_cfg(),
        [&](const uint8_t* p, size_t n) -> int {
            sent.emplace_back(p, n);
            return static_cast<int>(n);
        });

    Bytes a(20); for (size_t i = 0; i < 20; i++) a[i] = 0xAA;
    Bytes b(20); for (size_t i = 0; i < 20; i++) b[i] = 0xBB;
    iface.queue_announce(a, /*hops=*/3);
    iface.queue_announce(b, /*hops=*/1);

    iface.tick(0);  // budget allows both at this bitrate / cap

    TEST_ASSERT_EQUAL_UINT(2, sent.size());
    // hops=1 (b) drains first per §12.3.1 lowest-hops priority.
    TEST_ASSERT_EQUAL_UINT8(0xBB, sent[0][0]);
    TEST_ASSERT_EQUAL_UINT8(0xAA, sent[1][0]);
}

void test_null_callback_is_safe() {
    LoRaInterface iface(small_cfg(), /*tx=*/nullptr);
    iface.transmit_now(Bytes::from_hex("11"));   // must not crash
    iface.queue_announce(Bytes::from_hex("22"), 0);
    iface.tick(0);                               // ditto
    TEST_PASS();
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    UNITY_BEGIN();
    RUN_TEST(test_transmit_now_invokes_callback_with_wire_bytes);
    RUN_TEST(test_queue_drain_invokes_callback_per_emit);
    RUN_TEST(test_null_callback_is_safe);
    return UNITY_END();
}
