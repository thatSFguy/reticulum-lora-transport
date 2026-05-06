#pragma once
// src/Battery.h — battery voltage read via the nRF52's ADC.
//
// All five supported boards (ProMicroDIY / RAK4631 / XIAO_nRF52840 /
// Heltec_T114 / RAK3401) expose a battery sense pin via PIN_BATTERY
// and a divider scaling factor via DEFAULT_CONFIG_BATT_MULT in their
// header. Board-conditional: boards with `HAS_BATTERY_SENSE == 0`
// get a no-op stub returning 0.

#include <cstdint>

namespace rlr { namespace battery {

// Configure analog reference (internal 3.0V) and 12-bit resolution.
// Call once from setup() before read_mv().
void init();

// Read the battery sense pin and convert raw ADC counts to
// millivolts via:
//   mv = raw * (3000 / 4095) * batt_mult
// where batt_mult is the board's resistor-divider scaling factor
// (typically Config.batt_mult, originally seeded from the board
// header's DEFAULT_CONFIG_BATT_MULT and tunable via the webapp's
// CALIBRATE BATTERY flow when persistence + serial console land).
//
// Returns 0 on boards without HAS_BATTERY_SENSE.
uint16_t read_mv(float batt_mult);

}} // namespace rlr::battery
