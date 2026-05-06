#pragma once
// src/SerialConsole.h — USB-serial transport adapter for the
// ConfigProtocol.
//
// Frames on the wire: [u16_be_length][msgpack bytes]. The webapp's
// JS side sends one of these per request and reads one per response;
// the matching codec on the JS side is ~10 lines of state machine.
//
// Per memory `config_via_ble_or_serial`:
//   - Light: msgpack inside, no extra protocol layer.
//   - Stable: bogus length / oversize frame just resets state and
//     waits for the next valid frame; no aggressive timeouts.
//   - Same protocol on BLE — only the per-transport adapter differs.
//   - No unsolicited pushes; this code only emits in response to
//     a fully-received request.

#include <cstdint>

#include "Config.h"
#include "ConfigProtocol.h"

namespace rns { class Transport; }

namespace rlr { namespace serial_console {

// Drive from loop(). Drains pending bytes from `Serial`, accumulates
// into a frame buffer, dispatches each complete frame to
// ConfigProtocol::handle_request, and writes the framed response
// back. Caller passes the live Config (mutated by set_config), the
// Transport (for ping's identity_hash; null is OK), and the
// save callback (for commit; null disables commit).
void tick(rlr::Config& cfg,
          rns::Transport* transport,
          rlr::config_protocol::SaveFn save);

}} // namespace rlr::serial_console
