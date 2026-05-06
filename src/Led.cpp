#include "Led.h"

#if HAS_LED && defined(PIN_LED)

#include <Arduino.h>

namespace rlr { namespace led {

namespace {
constexpr uint64_t HEARTBEAT_PERIOD_MS = 500;  // ~1 Hz blink
uint64_t s_next_toggle_ms = 0;
bool     s_state          = false;
}

void init() {
    pinMode(PIN_LED, OUTPUT);
    digitalWrite(PIN_LED, LOW);
    s_state = false;
    s_next_toggle_ms = 0;
}

void tick(uint64_t now_ms) {
    if (now_ms < s_next_toggle_ms) return;
    s_state = !s_state;
    digitalWrite(PIN_LED, s_state ? HIGH : LOW);
    s_next_toggle_ms = now_ms + HEARTBEAT_PERIOD_MS;
}

}} // namespace rlr::led

#else

// HAS_LED == 0 — no-op stubs so callers don't need #ifdefs.
namespace rlr { namespace led {
void init() {}
void tick(uint64_t) {}
}}

#endif
