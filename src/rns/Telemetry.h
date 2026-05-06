// src/rns/Telemetry.h — transport-node telemetry beacon payload.
//
// Per memory `transport_node_telemetry_beacon`: the transport node
// emits a 5-element msgpack array carrying lat/lon (or nil), battery
// status, route count, and a packets-forwarded counter. The shape
// here is the **frozen wire schema** — Stats fields can come and go
// internally, but this published payload stays stable.
//
// Index layout (msgpack array):
//   [0] lat            — float32 or nil  (manually configured via webapp)
//   [1] lon            — float32 or nil
//   [2] battery_mv     — uint16 (millivolts)
//   [3] route_count    — uint16 (PathTable size at emit)
//   [4] packets_fwd    — uint32 (cumulative since boot)
//
// "Alive" lightweight announces use empty app_data; only the 2h full
// beacon emits this payload.

#pragma once

#include <cstdint>

#include "rns/Bytes.h"

namespace rns { namespace telemetry {

struct Snapshot {
    bool     have_position    = false;  // true if lat/lon are set
    float    lat              = 0.0f;
    float    lon              = 0.0f;
    uint16_t battery_mv       = 0;
    uint16_t route_count      = 0;
    uint32_t packets_forwarded = 0;
};

// Encode a Snapshot as the frozen msgpack payload defined above.
Bytes encode(const Snapshot& s);

} } // namespace rns::telemetry
