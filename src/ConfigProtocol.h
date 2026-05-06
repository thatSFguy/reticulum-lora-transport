#pragma once
// src/ConfigProtocol.h — webapp ↔ firmware command dispatcher.
//
// Transport-agnostic. Takes a msgpack request frame, returns a
// msgpack response frame. SerialConsole and BLE GATT both call into
// this with raw decoded msgpack bytes; framing concerns (length-
// prefix on Serial, characteristic-write atomicity on BLE) live in
// the per-transport adapters.
//
// Pure C++17 — tests run on native_san. Per memory
// `config_via_ble_or_serial`: same protocol over both transports;
// commit-style writes; tolerate slack in request shape so a
// progressive webapp doesn't need lockstep with firmware versions.
//
// Wire shapes (msgpack maps; key order is illustrative — readers
// are field-name driven, not positional):
//
// REQUEST                          RESPONSE
// ──────────────────────────────── ────────────────────────────────
// {"cmd": "ping"}                  {"ok": true,
//                                   "identity_hash": <bin 16>,
//                                   "version": "v0.1"}
//
// {"cmd": "get_config"}            {"ok": true,
//                                   "freq_hz": uint, "bw_hz": uint,
//                                   "sf": uint, "cr": uint,
//                                   "txp_dbm": int (encoded uint),
//                                   "lat_udeg": int  (likewise),
//                                   "lon_udeg": int,
//                                   "alt_m": int,
//                                   "batt_mult": float32,
//                                   "display_name": str}
//
// {"cmd": "set_config",            {"ok": true, "set": uint}
//  "freq_hz": ..., ...}            (count of recognised fields applied)
//
// {"cmd": "commit"}                {"ok": true}  | {"ok": false,
//                                                   "err": "..."}
//
// All numeric fields are unsigned msgpack uints. Negative values
// (lat/lon/alt) are stored in the int32_t Config fields; the wire
// encoding is the cast-to-uint32 bit pattern. Webapp side does the
// same cast in JS to recover the int.

#include <cstdint>
#include <functional>

#include "Config.h"
#include "rns/Bytes.h"

namespace rns { class Transport; }

namespace rlr { namespace config_protocol {

// Save callback used by the "commit" command. Firmware provides a
// closure around config_store::save; tests use a lambda that
// records the call and returns whatever success/failure they want
// to exercise. Returning false produces the standard error
// response. Pass nullptr to disable commit (returns error
// "commit not configured").
using SaveFn = std::function<bool(const Config&)>;

// Parse `request` as a msgpack map, dispatch on the "cmd" field,
// and produce a msgpack response. `cfg` is the in-memory staging
// area — set_config mutates it in place; commit calls `save` to
// persist.
//
// `transport` is optional: if non-null, ping's response includes
// the local identity_hash. Pass nullptr in unit tests where a
// Transport hasn't been constructed.
//
// Errors are reported in-band as {"ok": false, "err": "<reason>"}
// rather than thrown — webapp callers should always be able to
// decode a response, even when their request was garbage.
rns::Bytes handle_request(const rns::Bytes& request,
                          Config& cfg,
                          rns::Transport* transport,
                          SaveFn save = nullptr);

}} // namespace rlr::config_protocol
