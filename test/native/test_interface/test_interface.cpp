// test/native/test_interface/test_interface.cpp
//
// Unity tests for the abstract Interface base class — outbound
// announce queue + 2% airtime cap (SPEC §12.3.1, §3177).
//
// No JSON test vectors yet — the spec describes the cap mechanism
// but doesn't pin a wire round-trip we could test against. Behavior
// is verified structurally:
//   - queue admission respects MAX_QUEUED_ANNOUNCES
//   - tick() drains lowest-hops-first
//   - tick() honors the rolling-window airtime cap
//   - the budget refills as old emits leave the window
//   - transmit_now() bypasses the queue and the cap

#include <unity.h>
#include <vector>

#include "rns/Bytes.h"
#include "rns/Interface.h"

using rns::Bytes;
using rns::Interface;

void setUp() {}
void tearDown() {}

namespace {

// Captures every outbound emission so tests can inspect order and
// count. Same constructor surface as Interface; tests parameterize
// via Config.
class CaptureInterface : public Interface {
public:
    explicit CaptureInterface(const Config& cfg) : Interface(cfg) {}
    std::vector<Bytes> emitted;
protected:
    void on_transmit(const Bytes& wire) override { emitted.push_back(wire); }
};

// Default config tuned for fast cap exhaustion in tests:
//   bitrate 8000 bps  → 1 byte/ms
//   announce_cap 10%  → 100ms airtime per 1000ms window
//   max queue 4
Interface::Config small_cfg() {
    Interface::Config c;
    c.bitrate_bps          = 8000;
    c.announce_cap_pct     = 10.0f;
    c.max_queued_announces = 4;
    c.airtime_window_ms    = 1000;
    return c;
}

// 50-byte payload → 50ms airtime under the small_cfg bitrate.
Bytes make_payload(size_t n, uint8_t fill) {
    Bytes b(n);
    for (size_t i = 0; i < n; i++) b[i] = fill;
    return b;
}

} // namespace

void test_queue_drains_when_budget_allows() {
    CaptureInterface iface(small_cfg());
    Bytes a = make_payload(50, 0xA);
    Bytes b = make_payload(50, 0xB);
    TEST_ASSERT_TRUE(iface.queue_announce(a, /*hops=*/3));
    TEST_ASSERT_TRUE(iface.queue_announce(b, /*hops=*/3));
    TEST_ASSERT_EQUAL_UINT(2, iface.queue_depth());

    iface.tick(0);
    // 100ms budget; each announce consumes 50ms — both fit.
    TEST_ASSERT_EQUAL_UINT(2, iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, iface.queue_depth());
    TEST_ASSERT_EQUAL_UINT(100, iface.airtime_used_ms_in_window(0));
}

void test_queue_drains_lowest_hops_first() {
    CaptureInterface iface(small_cfg());
    Bytes p_hops5  = make_payload(50, 0x55);
    Bytes p_hops2  = make_payload(50, 0x22);
    Bytes p_hops10 = make_payload(50, 0xAA);
    Bytes p_hops1  = make_payload(50, 0x11);
    iface.queue_announce(p_hops5,  5);
    iface.queue_announce(p_hops2,  2);
    iface.queue_announce(p_hops10, 10);
    iface.queue_announce(p_hops1,  1);

    // Budget 100ms / 50ms-per-announce = 2 emissions per window.
    iface.tick(0);
    TEST_ASSERT_EQUAL_UINT(2, iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT8(0x11, iface.emitted[0][0]);  // hops=1 first
    TEST_ASSERT_EQUAL_UINT8(0x22, iface.emitted[1][0]);  // hops=2 second
    TEST_ASSERT_EQUAL_UINT(2, iface.queue_depth());      // 5 and 10 still queued
}

void test_tick_withholds_when_budget_exceeded() {
    CaptureInterface iface(small_cfg());
    // Three 50ms announces, only 2 fit in the 100ms cap.
    for (int i = 0; i < 3; i++) {
        iface.queue_announce(make_payload(50, static_cast<uint8_t>(i)), 0);
    }
    iface.tick(0);
    TEST_ASSERT_EQUAL_UINT(2, iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(1, iface.queue_depth());

    // Same tick time, budget unchanged — no further drain.
    iface.tick(0);
    TEST_ASSERT_EQUAL_UINT(2, iface.emitted.size());
}

void test_budget_refills_after_window_passes() {
    CaptureInterface iface(small_cfg());
    iface.queue_announce(make_payload(50, 0xAA), 0);
    iface.queue_announce(make_payload(50, 0xBB), 0);
    iface.queue_announce(make_payload(50, 0xCC), 0);
    iface.tick(0);
    TEST_ASSERT_EQUAL_UINT(2, iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(1, iface.queue_depth());

    // Advance past the rolling window — emits at t=0 fall off.
    iface.tick(1001);
    TEST_ASSERT_EQUAL_UINT(3, iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, iface.queue_depth());
    TEST_ASSERT_EQUAL_UINT8(0xCC, iface.emitted[2][0]);
}

void test_queue_admission_respects_max_queued() {
    CaptureInterface iface(small_cfg());  // max_queued = 4
    for (int i = 0; i < 4; i++) {
        TEST_ASSERT_TRUE(iface.queue_announce(make_payload(10, 0), 0));
    }
    // 5th must be refused.
    TEST_ASSERT_FALSE(iface.queue_announce(make_payload(10, 0), 0));
    TEST_ASSERT_EQUAL_UINT(4, iface.queue_depth());
}

void test_tick_on_empty_queue_is_noop() {
    CaptureInterface iface(small_cfg());
    iface.tick(0);
    iface.tick(1000);
    TEST_ASSERT_EQUAL_UINT(0, iface.emitted.size());
}

void test_transmit_now_bypasses_queue_and_cap() {
    CaptureInterface iface(small_cfg());
    // Saturate the announce-cap budget first.
    for (int i = 0; i < 2; i++) {
        iface.queue_announce(make_payload(50, 0xAA), 0);
    }
    iface.tick(0);
    TEST_ASSERT_EQUAL_UINT(2, iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(100, iface.airtime_used_ms_in_window(0));

    // transmit_now should fire regardless of remaining budget and
    // not show up in the announce-cap accounting.
    iface.transmit_now(make_payload(80, 0xFF));
    TEST_ASSERT_EQUAL_UINT(3, iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT8(0xFF, iface.emitted[2][0]);
    TEST_ASSERT_EQUAL_UINT(100, iface.airtime_used_ms_in_window(0));
}

// Burst-then-drain pattern: queue a flood, tick over time, verify
// the cap holds across multiple windows and everything eventually drains.
void test_long_run_respects_cap() {
    CaptureInterface iface(small_cfg());
    constexpr int N = 4;  // max_queued = 4
    for (int i = 0; i < N; i++) {
        iface.queue_announce(make_payload(50, static_cast<uint8_t>(i)), 0);
    }

    // Drive ticks every 500ms for 4 seconds.
    for (uint64_t t = 0; t <= 4000; t += 500) {
        iface.tick(t);
    }

    TEST_ASSERT_EQUAL_UINT(N, iface.emitted.size());
    TEST_ASSERT_EQUAL_UINT(0, iface.queue_depth());

    // No window of length 1000ms should ever have contained > 100ms of
    // emit airtime. With 50ms-per-emit, that's at most 2 emits in any
    // 1s window. We can't directly inspect history but `iface` exposes
    // the rolling-window total at any time — checking late-window
    // values is a reasonable smoke check.
    TEST_ASSERT_TRUE(iface.airtime_used_ms_in_window(4000) <= 100);
}

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    UNITY_BEGIN();
    RUN_TEST(test_queue_drains_when_budget_allows);
    RUN_TEST(test_queue_drains_lowest_hops_first);
    RUN_TEST(test_tick_withholds_when_budget_exceeded);
    RUN_TEST(test_budget_refills_after_window_passes);
    RUN_TEST(test_queue_admission_respects_max_queued);
    RUN_TEST(test_tick_on_empty_queue_is_noop);
    RUN_TEST(test_transmit_now_bypasses_queue_and_cap);
    RUN_TEST(test_long_run_respects_cap);
    return UNITY_END();
}
