#pragma once
// src/Config.h — runtime configuration struct.
//
// Mirrors the schema from the predecessor repo's `rlr::Config` so a
// later port of Config.cpp / Storage.cpp (flash persistence) drops
// in without restructuring callers. Fields that aren't meaningful to
// the v0 firmware (telemetry / lxmf intervals, BLE PIN, display name)
// stay as defaults.
//
// Pure portable C++ — no Arduino headers — so the spec-layer Tests
// can include this if/when they need to construct a Config for
// future LoRaInterface unit tests.

#include <cstdint>

namespace rlr {

#pragma pack(push, 1)
struct Config {
    // ---- schema ----
    uint16_t version           = 2;
    uint8_t  log_level         = 1;     // 0=quiet, 1=normal, 2=verbose
    uint8_t  _reserved         = 0;

    // ---- radio (consumed by src/Radio.cpp) ----
    // Deployment defaults: 904.375 MHz / BW 250 kHz / SF10 / CR 4/5 /
    // +22 dBm at the SX1262 core. SF10 trades throughput for range
    // (~1.95 kbps effective, vs ~10.9 kbps at SF7); tune via the
    // webapp once SerialConsole / BLE lands. +22 dBm is the chip's
    // ceiling; modules with an external PA (e.g. ProMicroDIY's E22) push
    // radiated power to ~30 dBm.
    uint32_t freq_hz           = 904375000u;  // 904.375 MHz (US ISM)
    uint32_t bw_hz             = 250000u;     // 250 kHz
    uint8_t  sf                = 10;          // SF10
    uint8_t  cr                = 5;           // CR 4/5 (denominator)
    int8_t   txp_dbm           = 22;          // +22 dBm at SX1262 core
    uint8_t  flags             = 0;           // bit 0 telemetry, bit 1 lxmf, bit 2 heartbeat

    // ---- battery ----
    float    batt_mult         = 1.0f;        // ADC-raw → mV scaling factor

    // ---- periodic tasks ----
    uint32_t tele_interval_ms  = 0;           // 0 = disabled until firmware glue wires it
    uint32_t lxmf_interval_ms  = 0;

    // ---- bluetooth ----
    uint32_t bt_pin            = 0;           // 0..999999, 0 = no PIN

    // ---- location (manually set via webapp per memory:
    //                 transport_node_telemetry_beacon) ----
    int32_t  latitude_udeg     = 0;           // microdegrees, 0 = not set
    int32_t  longitude_udeg    = 0;
    int32_t  altitude_m        = 0;

    // ---- identity ----
    char     display_name[32]  = {0};         // NUL-terminated UTF-8

    // ---- integrity (used when persistence lands) ----
    uint32_t crc32             = 0;
};
#pragma pack(pop)

static_assert(sizeof(Config) <= 128,
              "Config grew unexpectedly — bump version + review storage layout");

} // namespace rlr
