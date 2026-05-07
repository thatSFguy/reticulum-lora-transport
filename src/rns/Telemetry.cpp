#include "rns/Telemetry.h"

#include "rns/Msgpack.h"

namespace rns { namespace telemetry {

Bytes encode(const Snapshot& s) {
    msgpack::Writer w;
    w.array_header(9);
    if (s.have_position) {
        w.float32(s.lat);
        w.float32(s.lon);
    } else {
        w.nil();
        w.nil();
    }
    w.uint16(s.battery_mv);
    w.uint16(s.route_count);
    w.uint32(s.packets_forwarded);
    w.uint32(s.announces_rebroadcast);
    w.uint32(s.data_forwarded);
    w.uint32(s.inbound_packets);
    w.str(s.name);
    return w.bytes();
}

} } // namespace rns::telemetry
