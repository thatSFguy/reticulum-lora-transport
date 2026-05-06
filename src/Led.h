#pragma once
// src/Led.h — periodic heartbeat blink. Visual confirmation that
// loop() is running. Driven from the firmware's tick cadence so we
// don't burn a timer / interrupt for it.
//
// Board-conditional: boards with `HAS_LED == 0` get no-op stubs so
// the code compiles on every variant without per-board #ifdefs at
// the call site.

#include <cstdint>

namespace rlr { namespace led {

// Configure PIN_LED as output and drive it low. No-op on boards
// without an LED. Call once from setup().
void init();

// Toggle the LED at HEARTBEAT_PERIOD_MS cadence based on `now_ms`
// (typically `millis()`). Internal state holds the next toggle
// time. Idempotent — safe to call as often as the loop wants.
void tick(uint64_t now_ms);

}} // namespace rlr::led
