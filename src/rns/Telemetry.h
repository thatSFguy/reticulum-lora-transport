// src/rns/Telemetry.h — transport-node telemetry beacon payload.
//
// Per memory `transport_node_telemetry_beacon`: the transport node
// emits a msgpack array carrying lat/lon (or nil), battery status,
// route count, and forwarding counters. The shape here is the
// **frozen wire schema** — indices 0..4 are stable, indices 5+ are
// forward-compatible extensions. Stats fields can come and go
// internally, but this published payload stays stable.
//
// Index layout (msgpack array):
//   [0] lat                  — float32 or nil  (manually configured via webapp)
//   [1] lon                  — float32 or nil
//   [2] battery_mv           — uint16 (millivolts)
//   [3] route_count          — uint16 (PathTable size at emit)
//   [4] packets_fwd          — uint32 (cumulative aggregate; legacy/quick-look)
//   [5] announces_rebroadcast— uint32 (just §12.3 announce relays — proves
//                              the relay path itself is alive)
//   [6] data_forwarded       — uint32 (DATA forwards across both header forms)
//   [7] inbound_packets      — uint32 (every packet we successfully parsed —
//                              context for the rebroadcast/inbound ratio)
//   [8] name                 — str    (Config.display_name — operator-set
//                              label or the auto-stamped "Rptr-XXXXXXXX"
//                              default; always present, may be empty)
//
// "Alive" lightweight announces use empty app_data; only the 2h full
// beacon emits this payload.

#pragma once

#include <cstdint>
#include <string>

#include "rns/Bytes.h"

namespace rns { namespace telemetry {

struct Snapshot {
    bool        have_position        = false;  // true if lat/lon are set
    float       lat                  = 0.0f;
    float       lon                  = 0.0f;
    uint16_t    battery_mv           = 0;
    uint16_t    route_count          = 0;
    uint32_t    packets_forwarded    = 0;     // [4] aggregate
    uint32_t    announces_rebroadcast = 0;    // [5] §12.3 relay-only counter
    uint32_t    data_forwarded       = 0;     // [6] DATA forwards (h1+h2 combined)
    uint32_t    inbound_packets      = 0;     // [7] total parsed inbound — the denominator
    std::string name;                          // [8] operator-set / auto-default label
};

// Encode a Snapshot as the frozen msgpack payload defined above.
Bytes encode(const Snapshot& s);

} } // namespace rns::telemetry
