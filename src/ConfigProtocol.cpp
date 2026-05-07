#include "ConfigProtocol.h"

#include <cstring>
#include <string>

#include "rns/Msgpack.h"
#include "rns/Transport.h"

namespace rlr { namespace config_protocol {

namespace {

using rns::Bytes;
using rns::msgpack::Reader;
using rns::msgpack::Writer;

// Injected by scripts/inject_fw_version.py — git tag for tagged builds
// (e.g. "v0.1.5"), `git describe --tags --always --dirty` for dev
// builds (e.g. "v0.1.5-3-gabcdef0-dirty"), or "dev" if neither is
// available. The fallback covers builds that bypass the script
// (someone invoking the toolchain directly).
#ifndef FW_VERSION
#define FW_VERSION "dev"
#endif
constexpr const char* FIRMWARE_VERSION = FW_VERSION;

Bytes error_response(const char* msg) {
    Writer w;
    w.map_header(2);
    w.str("ok");  w.bool_val(false);
    w.str("err"); w.str(msg);
    return w.bytes();
}

// Ping — confirms the device is alive and exposes its identity_hash
// so the webapp can label the connection. Includes firmware_version
// so the webapp can degrade gracefully if older firmware lacks
// fields it expects.
Bytes handle_ping(rns::Transport* transport) {
    Writer w;
    if (transport) {
        w.map_header(3);
        w.str("ok");            w.bool_val(true);
        w.str("identity_hash"); w.bin(transport->local_identity().identity_hash());
        w.str("version");       w.str(FIRMWARE_VERSION);
    } else {
        w.map_header(2);
        w.str("ok");      w.bool_val(true);
        w.str("version"); w.str(FIRMWARE_VERSION);
    }
    return w.bytes();
}

// Dump the entire Config struct. Webapp populates its form from
// this. Numeric fields go out as msgpack uints — int32 fields
// (lat / lon / alt) are sent as their bit-pattern uint32 so the
// wire stays unambiguous; webapp re-casts on the JS side.
Bytes handle_get_config(const Config& cfg) {
    Writer w;
    w.map_header(11);
    w.str("ok");           w.bool_val(true);
    w.str("freq_hz");      w.uint32(cfg.freq_hz);
    w.str("bw_hz");        w.uint32(cfg.bw_hz);
    w.str("sf");           w.uint8(cfg.sf);
    w.str("cr");           w.uint8(cfg.cr);
    w.str("txp_dbm");      w.uint32(static_cast<uint32_t>(static_cast<int32_t>(cfg.txp_dbm)));
    w.str("lat_udeg");     w.uint32(static_cast<uint32_t>(cfg.latitude_udeg));
    w.str("lon_udeg");     w.uint32(static_cast<uint32_t>(cfg.longitude_udeg));
    w.str("alt_m");        w.uint32(static_cast<uint32_t>(cfg.altitude_m));
    w.str("batt_mult");    w.float32(cfg.batt_mult);
    w.str("display_name"); w.str(std::string(cfg.display_name));
    return w.bytes();
}

// Apply `pairs_remaining` key/value pairs from the request map onto
// the in-memory Config. Caller has already consumed the "cmd" pair
// (and decremented pairs_remaining accordingly). Unknown keys are
// silently skipped (forward-compat: a newer webapp won't break an
// older firmware). Type mismatches on known fields trip the
// reader's sticky error and terminate the apply.
//
// Returns the number of recognised fields applied, or -1 on parse
// error.
int apply_set_fields(Reader& r, Config& cfg, size_t pairs_remaining) {
    int applied = 0;
    for (size_t i = 0; i < pairs_remaining; ++i) {
        std::string key;
        if (!r.read_str(key)) return -1;

        // All integer fields use read_int — accepts both unsigned
        // (positive fixint, uint8/16/32/64) AND signed (negative
        // fixint, int8/16/32/64) msgpack encodings. JS / Python
        // encoders pick the smallest signed form by default for
        // negative values, so a webclient `lat_udeg: -122419400`
        // arrives as msgpack int32. Without read_int we'd reject
        // it as malformed.
        if (key == "freq_hz") {
            int64_t v; if (!r.read_int(v)) return -1;
            cfg.freq_hz = static_cast<uint32_t>(v); applied++;
        } else if (key == "bw_hz") {
            int64_t v; if (!r.read_int(v)) return -1;
            cfg.bw_hz = static_cast<uint32_t>(v); applied++;
        } else if (key == "sf") {
            int64_t v; if (!r.read_int(v)) return -1;
            cfg.sf = static_cast<uint8_t>(v); applied++;
        } else if (key == "cr") {
            int64_t v; if (!r.read_int(v)) return -1;
            cfg.cr = static_cast<uint8_t>(v); applied++;
        } else if (key == "txp_dbm") {
            int64_t v; if (!r.read_int(v)) return -1;
            cfg.txp_dbm = static_cast<int8_t>(v); applied++;
        } else if (key == "lat_udeg") {
            int64_t v; if (!r.read_int(v)) return -1;
            cfg.latitude_udeg = static_cast<int32_t>(v); applied++;
        } else if (key == "lon_udeg") {
            int64_t v; if (!r.read_int(v)) return -1;
            cfg.longitude_udeg = static_cast<int32_t>(v); applied++;
        } else if (key == "alt_m") {
            int64_t v; if (!r.read_int(v)) return -1;
            cfg.altitude_m = static_cast<int32_t>(v); applied++;
        } else if (key == "batt_mult") {
            float v; if (!r.read_float32(v)) return -1;
            cfg.batt_mult = v; applied++;
        } else if (key == "display_name") {
            std::string v; if (!r.read_str(v)) return -1;
            const size_t n = v.size() < (sizeof(cfg.display_name) - 1)
                           ? v.size() : (sizeof(cfg.display_name) - 1);
            std::memcpy(cfg.display_name, v.data(), n);
            cfg.display_name[n] = '\0';
            applied++;
        } else {
            // Unknown key — skip its value; don't fail the whole
            // request. Forward-compat for older firmware seeing a
            // newer webapp's extra fields.
            if (!r.skip_value()) return -1;
        }
    }
    return applied;
}

Bytes handle_set_config(Reader& r, Config& cfg, size_t pairs_remaining) {
    int applied = apply_set_fields(r, cfg, pairs_remaining);
    if (applied < 0) return error_response("malformed set_config payload");
    Writer w;
    w.map_header(2);
    w.str("ok");  w.bool_val(true);
    w.str("set"); w.uint16(static_cast<uint16_t>(applied));
    return w.bytes();
}

Bytes handle_commit(const Config& cfg, const SaveFn& save) {
    if (!save) return error_response("commit not configured");
    if (!save(cfg)) return error_response("commit failed");
    Writer w;
    w.map_header(1);
    w.str("ok"); w.bool_val(true);
    return w.bytes();
}

} // namespace

Bytes handle_request(const Bytes& request, Config& cfg,
                     rns::Transport* transport, SaveFn save) {
    Reader r(request);

    size_t n_pairs = 0;
    if (!r.read_map_header(n_pairs)) {
        return error_response("expected msgpack map at top level");
    }

    // We need to find "cmd" before we know how to handle the rest.
    // For ping / get_config / commit the entire payload is
    // {"cmd": "..."} — nothing else. For set_config we need to
    // walk the rest of the map applying fields. Strategy: snapshot
    // the reader state, scan for "cmd", then either dispatch the
    // simple cases or rewind and run apply_set_fields.
    //
    // Simplest implementation: require "cmd" to be the first key.
    // Webapp ergonomics: build the request map with "cmd" first.
    if (n_pairs == 0) return error_response("empty request map");

    std::string first_key;
    if (!r.read_str(first_key)) {
        return error_response("expected string key at position 0");
    }
    if (first_key != "cmd") {
        return error_response("first map key must be 'cmd'");
    }
    std::string cmd;
    if (!r.read_str(cmd)) {
        return error_response("'cmd' value must be a string");
    }

    if (cmd == "ping") {
        return handle_ping(transport);
    }
    if (cmd == "get_config") {
        return handle_get_config(cfg);
    }
    if (cmd == "commit") {
        return handle_commit(cfg, save);
    }
    if (cmd == "set_config") {
        return handle_set_config(r, cfg, /*pairs_remaining=*/n_pairs - 1);
    }
    return error_response("unknown command");
}

}} // namespace rlr::config_protocol
