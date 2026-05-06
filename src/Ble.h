#pragma once
// src/Ble.h — BLE GATT config surface for the webapp.
//
// Custom service with two characteristics:
//   request_chr   (write-without-response, max 244 bytes per write):
//                 webapp writes a msgpack-encoded ConfigProtocol
//                 request. Single GATT write = single config command.
//   response_chr  (notify):
//                 firmware notifies a msgpack-encoded response
//                 immediately after each request_chr write.
//
// Same ConfigProtocol layer as SerialConsole — only the transport
// adapter differs. Per memory `config_via_ble_or_serial`: shared
// framing + light + stable.
//
// Currently does NOT include the NUS log stream (deferred). Service
// + characteristic UUIDs reuse the predecessor's `a5a5-524c-7272`
// custom family for continuity with operators familiar with the
// predecessor firmware.

#include <cstdint>

#include "Config.h"
#include "ConfigProtocol.h"

namespace rns { class Transport; }

namespace rlr { namespace ble {

// Bring up Bluefruit, register the custom GATT service + 2
// characteristics, start advertising. Holds references to cfg /
// transport / save so the request write callback can dispatch
// synchronously without the caller having to pump anything.
//
// Returns true on success. Failure is non-fatal — the firmware
// continues without BLE config available; SerialConsole still works.
//
// BLE runs autonomously after init() — Bluefruit handles events via
// the SoftDevice scheduler. loop() does not need to drive it.
bool init(rlr::Config& cfg,
          rns::Transport* transport,
          rlr::config_protocol::SaveFn save);

}} // namespace rlr::ble
