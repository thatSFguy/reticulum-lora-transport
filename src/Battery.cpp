#include "Battery.h"

#if HAS_BATTERY_SENSE && defined(PIN_BATTERY)

#include <Arduino.h>

namespace rlr { namespace battery {

void init() {
    // Internal 3.0V reference + 12-bit ADC matches what the nRF52
    // BSP's analogRead expects; both calls are idempotent so
    // re-init() is harmless.
    analogReference(AR_INTERNAL_3_0);
    analogReadResolution(12);
    pinMode(PIN_BATTERY, INPUT);
}

uint16_t read_mv(float batt_mult) {
    const int raw = analogRead(PIN_BATTERY);
    if (raw < 0) return 0;
    // raw is 0..4095. Reference 3000 mV. batt_mult applies the
    // divider scaling (e.g. 2.198 for the RAK4631's voltage divider).
    const float mv = static_cast<float>(raw) * (3000.0f / 4095.0f) * batt_mult;
    if (mv < 0.0f)        return 0;
    if (mv > 65535.0f)    return 65535;  // clamp to uint16_t range
    return static_cast<uint16_t>(mv + 0.5f);
}

}} // namespace rlr::battery

#else

namespace rlr { namespace battery {
void init() {}
uint16_t read_mv(float) { return 0; }
}}

#endif
